// Package httpclient is the only place in XAMMU that may open a network
// connection. Every other module produces or transforms data; this one touches
// the target, and it re-validates the effective destination against the
// authorization before a socket exists and again at dial time.
//
// The single-egress property is checked mechanically by
// test/acceptance/egress_test.go, not by convention.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"xammu/internal/contracts"
)

// HardBodyCap bounds how much of a response body this process will hold. Bodies
// beyond it are marked truncated; retention policy is applied downstream by the
// observer, which may keep even less.
const HardBodyCap = 8 << 20

// Request is one planned exchange. The plan fields travel with it so the
// observation ties back to the probe without a second lookup.
type Request struct {
	Method      string
	URL         string
	ProbeRef    string
	CorpusRef   string
	AttackClass string
	Vector      string
	Encoding    string
	ControlRole string
	Headers     []contracts.HeaderEntry
	Body        []byte
}

// Response is what came back, as facts. Classification does not happen here.
type Response struct {
	Seq             int
	RequestURL      string
	Method          string
	Status          int
	Reason          string
	Headers         []contracts.HeaderEntry
	Body            []byte
	BodyBytes       int
	BodyDigest      string
	BodyTruncated   bool
	Hops            []string
	RedirectCount   int
	ResolvedAddr    string
	Protocol        string
	TLSVerified     bool
	HTTP2           bool
	ConnectMS       int64
	TotalMS         int64
	SentAt          time.Time
	RateLimited     bool
	TransportError  string
	TransportDetail string
}

// Refusal records an attempt the policy stopped, so a reviewer can see that an
// unauthorized destination produced no traffic at all.
type Refusal struct {
	At     time.Time
	URL    string
	Probe  string
	Reason string
	Stage  string
	IPs    []string
}

// Dialer is the socket-level dependency, replaced in tests so the resolved
// address gate is verifiable without touching DNS. It sits *below* the policy
// check: injecting one must never skip validation, or the test double would
// become the bypass the check exists to prevent.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client is the egress point.
type Client struct {
	scope   *Scope
	ledger  *Ledger
	limiter *Limiter
	agent   *http.Client

	mu       sync.Mutex
	refusals []Refusal
	socket   Dialer
}

// New builds a client from a scope and a request budget.
func New(scope *Scope, budget int) *Client {
	timeout := scope.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c := &Client{
		scope:   scope,
		ledger:  NewLedger(budget),
		limiter: NewLimiter(scope.RatePerSecond),
	}
	transport := &http.Transport{
		// Deliberately nil: honouring HTTP_PROXY would hand the request to an
		// unvalidated third party and defeat the destination checks this package
		// exists to perform.
		Proxy:               nil,
		DialContext:         c.dialHook,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	c.agent = &http.Client{
		Transport: transport,
		// No client-level deadline: every request carries its own context, so the
		// pacing wait is not charged against the exchange timeout.
		CheckRedirect: c.checkRedirect,
	}
	return c
}

// SetDialer replaces the socket layer beneath the address check. Tests use it to
// count connections, proving a host which resolves outside the authorized ranges
// never reaches the operating system at all.
func (c *Client) SetDialer(d Dialer) { c.socket = d }

// Scope exposes the policy for reporting.
func (c *Client) Scope() *Scope { return c.scope }

// Ledger exposes the budget state to the orchestrator.
func (c *Client) Ledger() *Ledger { return c.ledger }

// RestoreUsage re-applies the requests already charged to a resumed run, so a
// restart cannot buy traffic the authorization did not grant.
func (c *Client) RestoreUsage(used int) error { return c.ledger.Restore(used) }

// Refusals returns the policy-stopped attempts.
func (c *Client) Refusals() []Refusal {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Refusal(nil), c.refusals...)
}

func (c *Client) recordRefusal(r Refusal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refusals = append(c.refusals, r)
}

type hopState struct {
	mu       sync.Mutex
	hops     []string
	resolved string
	connect  int64
}

type hopKey struct{}

// Do performs one exchange under the scope's policy. ErrBudgetExhausted or
// ErrHalted means nothing was sent and no budget was spent.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if halted, reason := c.ledger.Halted(); halted {
		err := errors.New(ErrHalted.Error() + ": " + reason)
		c.recordRefusal(Refusal{At: time.Now().UTC(), URL: req.URL, Probe: req.ProbeRef,
			Reason: err.Error(), Stage: "halted"})
		return nil, err
	}
	// The scope is checked before any waiting: a destination the authorization
	// forbids must not consume pacing time, and a refusal must not make the
	// caller think a request slot was spent.
	if err := c.scope.CheckRequest(method, req.URL, req.ProbeRef); err != nil {
		c.recordRefusal(Refusal{At: time.Now().UTC(), URL: req.URL, Probe: req.ProbeRef,
			Reason: err.Error(), Stage: "pre_dial"})
		return nil, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if err := c.ledger.Reserve(); err != nil {
		c.recordRefusal(Refusal{At: time.Now().UTC(), URL: req.URL, Probe: req.ProbeRef,
			Reason: err.Error(), Stage: "budget"})
		return nil, err
	}

	timeout := c.scope.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hops := &hopState{}
	reqCtx = context.WithValue(reqCtx, hopKey{}, hops)

	parsed, err := url.Parse(req.URL)
	if err != nil {
		c.ledger.Release()
		return nil, ErrHostUnparsable
	}
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, method, parsed.String(), body)
	if err != nil {
		c.ledger.Release()
		return nil, err
	}
	httpReq.Header.Set("User-Agent", orDefault(c.scope.UserAgent, "xammu/1.0.0"))
	for _, h := range req.Headers {
		// Hop-by-hop and framing headers are not copyable: letting a probe set
		// Content-Length or Transfer-Encoding is how a diagnostic request turns
		// into a request-smuggling test, which is out of scope by design.
		if isHopByHopHeader(h.Name) {
			c.recordRefusal(Refusal{At: time.Now().UTC(), URL: req.URL, Probe: req.ProbeRef,
				Reason: "header withheld: " + h.Name, Stage: "header_filter"})
			continue
		}
		httpReq.Header.Set(h.Name, h.Value)
	}

	resp := &Response{
		Seq:        c.ledger.NextSequence(),
		RequestURL: parsed.String(),
		Method:     method,
		SentAt:     time.Now().UTC(),
	}
	started := time.Now()
	httpResp, doErr := c.agent.Do(httpReq)
	resp.TotalMS = time.Since(started).Milliseconds()

	hops.mu.Lock()
	resp.Hops = append([]string(nil), hops.hops...)
	resp.ResolvedAddr = hops.resolved
	resp.ConnectMS = hops.connect
	hops.mu.Unlock()
	if len(resp.Hops) > 0 {
		resp.RedirectCount = len(resp.Hops)
	}

	if doErr != nil {
		// No release: the request left this process, so the target was contacted
		// and the budget is spent. Refunding a timeout would let a run with many
		// failures exceed the request count the operator authorized.
		resp.TransportError = c.classifyTransportError(doErr)
		resp.TransportDetail = doErr.Error()
		resp.BodyDigest = contracts.NewDigest(nil)
		return resp, doErr
	}
	defer func() { _, _ = io.Copy(io.Discard, httpResp.Body); _ = httpResp.Body.Close() }()

	respBody, truncated, readErr := readCapped(httpResp.Body)
	if readErr != nil {
		resp.TransportError = "body_read"
		resp.TransportDetail = readErr.Error()
	}
	resp.Body = respBody
	resp.BodyBytes = len(respBody)
	resp.BodyTruncated = truncated
	resp.BodyDigest = contracts.NewDigest(respBody)
	resp.Status = httpResp.StatusCode
	// http.Response carries no reason phrase; StatusText is the canonical text
	// for the code and is what a signature detector can match on.
	resp.Reason = http.StatusText(httpResp.StatusCode)
	resp.Protocol = httpResp.Proto
	resp.HTTP2 = httpResp.ProtoMajor == 2
	// InsecureSkipVerify is never enabled, so a completed TLS handshake is a
	// verified one.
	resp.TLSVerified = httpResp.TLS != nil
	resp.Headers = collectHeaders(httpResp.Header)

	if httpResp.StatusCode == 429 {
		resp.RateLimited = true
		// Criterion 24: a limit halts the run. The response is still returned so
		// the observer records it, but no further request may leave this client.
		c.ledger.Halt(string(contracts.TriggerRateLimited))
	}
	return resp, nil
}

// checkRedirect re-validates every hop: entering the chain legitimately says
// nothing about where the next hop points.
func (c *Client) checkRedirect(hop *http.Request, via []*http.Request) error {
	if err := c.scope.CheckRedirect(hop.URL, len(via)); err != nil {
		c.recordRefusal(Refusal{At: time.Now().UTC(), URL: hop.URL.String(),
			Reason: err.Error(), Stage: "redirect"})
		return err
	}
	if state := hopStateFrom(hop.Context()); state != nil {
		state.mu.Lock()
		state.hops = append(state.hops, via[len(via)-1].URL.String())
		state.mu.Unlock()
	}
	return nil
}

func (c *Client) dialHook(ctx context.Context, network, addr string) (net.Conn, error) {
	// No bypass branch: the injected socket is used only after the resolved
	// address has cleared the policy, so a test double cannot forward traffic the
	// authorization forbids.
	return c.dialValidated(ctx, network, addr)
}

// dialValidated resolves the host, checks every answer against the authorized
// ranges, then dials the checked answer itself. Letting the stack choose the
// address after the check would reopen the rebinding window the check closes.
func (c *Client) dialValidated(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []string
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else {
		if c.scope.Lookup != nil {
			ips, err = c.scope.Lookup(ctx, host)
		} else {
			ips, err = net.DefaultResolver.LookupHost(ctx, host)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := c.scope.CheckResolvedAddress(host, ips); err != nil {
		c.recordRefusal(Refusal{At: time.Now().UTC(), URL: addr,
			Reason: err.Error(), Stage: "dial", IPs: ips})
		return nil, err
	}
	chosen, err := c.scope.ChooseAddress(host, ips)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: c.scope.Timeout, KeepAlive: 15 * time.Second}
	started := time.Now()
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(chosen, port))
	if state := hopStateFrom(ctx); state != nil {
		state.mu.Lock()
		state.resolved = net.JoinHostPort(chosen, port)
		state.connect = time.Since(started).Milliseconds()
		state.mu.Unlock()
	}
	return conn, err
}

func hopStateFrom(ctx context.Context) *hopState {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(hopKey{}).(*hopState)
	return state
}

func collectHeaders(h http.Header) []contracts.HeaderEntry {
	out := make([]contracts.HeaderEntry, 0, len(h))
	for name, values := range h {
		for _, v := range values {
			out = append(out, contracts.HeaderEntry{
				Name: name, Value: v, Digest: contracts.NewDigest([]byte(v)),
			})
		}
	}
	contracts.SortHeaders(out)
	return out
}

// readCapped reads at most HardBodyCap bytes and reports whether more existed.
func readCapped(r io.Reader) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, HardBodyCap+1))
	if err != nil {
		return body, false, err
	}
	if len(body) > HardBodyCap {
		return body[:HardBodyCap], true, nil
	}
	return body, false, nil
}

func (c *Client) classifyTransportError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrResponseTooLarge):
		return "size_cap"
	default:
		if strings.Contains(err.Error(), ErrResolvedAddrBlocked.Error()) ||
			strings.Contains(err.Error(), ErrNoAuthorizedAddress.Error()) {
			return "destination_refused"
		}
		if strings.Contains(err.Error(), ErrRedirectLimit.Error()) {
			return "redirect_limit"
		}
		for _, sentinel := range []error{ErrPathNotAllowed, ErrHostNotAllowed,
			ErrSchemeNotAllowed, ErrPathEscape, ErrPathExcluded, ErrMethodNotAllowed} {
			if strings.Contains(err.Error(), sentinel.Error()) {
				return "policy_refused"
			}
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return "dns_failure"
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return "connection_refused"
		}
		return "transport_error"
	}
}

// isHopByHopHeader names the headers a probe may not set.
func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer",
		"transfer-encoding", "upgrade", "content-length", "host":
		return true
	}
	return false
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
