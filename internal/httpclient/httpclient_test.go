package httpclient_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

// testTarget wraps an httptest server into an authorized origin bound to
// loopback, which is what the policy needs to validate.
func testTarget(srv *httptest.Server, cidr string) contracts.Origin {
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		panic(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return contracts.Origin{
		Scheme:       "http",
		Host:         host,
		Port:         port,
		PathPrefixes: []string{"/api/"},
		AllowedIPs:   []string{host},
		AllowedCIDRs: []string{cidr},
	}
}

func scopeFor(origin contracts.Origin) *httpclient.Scope {
	auth := contracts.ValidProfilingAuthorization()
	auth.Origins = []contracts.Origin{origin}
	auth.Methods = []string{"GET", "POST", "PUT"}
	auth.Retention = contracts.RetainDigestOnly
	auth.Limits.MaxBodyRetainBytes = 1 << 20
	scope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		panic(err)
	}
	scope.MaxRedirects = 3
	scope.Timeout = 3 * time.Second
	return pinClock(scope)
}

// pinClock freezes the scope inside its own authorization window. The contract
// fixtures carry fixed timestamps, so without this the suite would start failing
// the moment the real clock passes the fixture's expiry -- a test that expires is
// a test that silently stops proving anything.
func pinClock(s *httpclient.Scope) *httpclient.Scope {
	at := s.ExpiresAt.Add(-time.Hour)
	if !s.NotBefore.IsZero() && at.Before(s.NotBefore) {
		at = s.NotBefore.Add(time.Minute)
	}
	s.Now = func() time.Time { return at }
	return s
}

type countingDialer struct {
	mu      sync.Mutex
	attempt []string
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.attempt = append(d.attempt, addr)
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

func (d *countingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.attempt)
}

// TestUnauthorizedHostNeverReceivesRequest is JAVI-020 case 1.
func TestUnauthorizedHostNeverReceivesRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "should never be reached")
	}))
	defer srv.Close()

	// Authorize a different host name than the server actually serves.
	origin := testTarget(srv, "127.0.0.0/8")
	origin.Host = "not-the-real-host"
	c := httpclient.New(scopeFor(origin), 10)

	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("request to an unauthorized host succeeded")
	}
	if !errors.Is(err, httpclient.ErrHostNotAllowed) &&
		!strings.Contains(err.Error(), httpclient.ErrHostNotAllowed.Error()) {
		t.Fatalf("expected host refusal, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target received %d requests despite the refusal", got)
	}
	if len(c.Refusals()) == 0 {
		t.Fatal("refusal was not recorded for audit")
	}
}

// TestUnauthorizedPathNeverReceivesRequest is JAVI-020 case 2.
func TestUnauthorizedPathNeverReceivesRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 10)
	for _, path := range []string{"/admin/users", "/api/../secrets", "/"} {
		_, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + path, ProbeRef: "P-1",
		})
		if err == nil {
			t.Fatalf("path %q escaped the prefix allowlist", path)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("%d requests reached the target through unauthorized paths", got)
	}
}

// TestPathEscapeIsRefused covers the encoding trick against prefix allowlists.
func TestPathEscapeIsRefused(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	origin := testTarget(srv, "127.0.0.0/8")
	origin.PathPrefixes = []string{"/api/public"}
	c := httpclient.New(scopeFor(origin), 10)

	for _, path := range []string{
		"/api/public/../private",
		"/api/%2e%2e/private",
		"/api/public/../../etc/passwd",
	} {
		_, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + path, ProbeRef: "P-1",
		})
		if err == nil {
			t.Fatalf("dot-segment path %q was allowed", path)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("escapes reached the target: %d", got)
	}
}

// TestResolvedAddressOutsideAuthorizedRangeIsRefused is JAVI-020 case 3, the DNS
// rebinding gate: the host name is authorized, the answer it resolves to is not.
func TestResolvedAddressOutsideAuthorizedRangeIsRefused(t *testing.T) {
	d := &countingDialer{}
	origin := contracts.Origin{
		Scheme: "http", Host: "lab.local", Port: 80,
		PathPrefixes: []string{"/api/"},
		AllowedCIDRs: []string{"127.0.0.0/8"},
	}
	scope := scopeFor(origin)
	scope.Lookup = func(ctx context.Context, host string) ([]string, error) {
		return []string{"93.184.216.34"}, nil
	}
	c := httpclient.New(scope, 10)
	c.SetDialer(d)

	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: "http://lab.local/api/search", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("a host resolving outside the authorized CIDR was dialed")
	}
	if !strings.Contains(err.Error(), httpclient.ErrResolvedAddrBlocked.Error()) {
		t.Fatalf("expected resolved-address refusal, got %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("%d sockets were opened to a refused address", d.count())
	}
	var dialStage bool
	for _, r := range c.Refusals() {
		if r.Stage == "dial" {
			dialStage = true
		}
	}
	if !dialStage {
		t.Fatal("refusal was not attributed to the dial stage")
	}
}

// TestAllowedAddressIsDialedNotTheHostName proves the socket goes to the checked
// answer: the recorded resolution must be the IP the policy approved.
func TestAllowedAddressIsDialedNotTheHostName(t *testing.T) {
	var got int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&got, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	origin := testTarget(srv, "127.0.0.0/8")
	scope := scopeFor(origin)
	scope.Lookup = func(ctx context.Context, host string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}
	c := httpclient.New(scope, 10)
	resp, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err != nil {
		t.Fatalf("authorized request failed: %v", err)
	}
	if atomic.LoadInt32(&got) != 1 {
		t.Fatal("expected exactly one delivery")
	}
	if !strings.HasPrefix(resp.ResolvedAddr, "127.0.0.1:") {
		t.Fatalf("socket was not bound to the validated address: %q", resp.ResolvedAddr)
	}
}

// TestRedirectToUnauthorizedHostIsNotFetched is JAVI-020 case 4.
func TestRedirectToUnauthorizedHostIsNotFetched(t *testing.T) {
	var followHits int32
	escape := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&followHits, 1)
		fmt.Fprint(w, "you followed the redirect")
	}))
	defer escape.Close()

	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redir" {
			http.Redirect(w, r, escape.URL+"/api/outside", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer entry.Close()

	c := httpclient.New(scopeFor(testTarget(entry, "127.0.0.0/8")), 20)
	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: entry.URL + "/api/redir", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("a redirect to an unauthorized host was followed")
	}
	if got := atomic.LoadInt32(&followHits); got != 0 {
		t.Fatalf("the escape target received %d requests", got)
	}
	var redirectStage bool
	for _, r := range c.Refusals() {
		if r.Stage == "redirect" {
			redirectStage = true
		}
	}
	if !redirectStage {
		t.Fatal("redirect refusal was not recorded at the redirect stage")
	}
}

// TestRedirectLimitStopsWithinBudget proves the redirect ceiling is enforced
// rather than counted after the fact.
func TestRedirectLimitStopsWithinBudget(t *testing.T) {
	var hops int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		if r.URL.Path == "/api/loop" {
			http.Redirect(w, r, srvSelf+"/api/loop", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	srvSelf = srv.URL

	origin := testTarget(srv, "127.0.0.0/8")
	scope := scopeFor(origin)
	scope.MaxRedirects = 2
	c := httpclient.New(scope, 30)
	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/loop", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("redirect loop was not stopped")
	}
	if got := atomic.LoadInt32(&hops); got > 3 {
		t.Fatalf("limit of 2 redirects produced %d server hits", got)
	}
}

var srvSelf string

// TestUnauthorizedMethodIsRefused is JAVI-020 case 5.
func TestUnauthorizedMethodIsRefused(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	auth := contracts.ValidProfilingAuthorization()
	origin := testTarget(srv, "127.0.0.0/8")
	auth.Origins = []contracts.Origin{origin}
	auth.Methods = []string{"GET"}
	scope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		t.Fatal(err)
	}
	scope.Timeout = 2 * time.Second
	pinClock(scope)
	c := httpclient.New(scope, 10)

	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "POST", URL: srv.URL + "/api/search", Body: []byte(`{"q":"x"}`), ProbeRef: "P-1",
	}); err == nil {
		t.Fatal("POST was allowed through a GET-only authorization")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("refused method still reached the target %d times", got)
	}
}

// TestSchemeMismatchIsRefused covers http when only https is authorized.
func TestSchemeMismatchIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("https-only authorization must not deliver over http")
	}))
	defer srv.Close()

	origin := testTarget(srv, "127.0.0.0/8")
	origin.Scheme = "https"
	c := httpclient.New(scopeFor(origin), 10)
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	}); err == nil {
		t.Fatal("scheme downgrade was accepted")
	}
}

// TestExpiredAuthorizationIsRefused covers the time bound. The clock is injected
// rather than waited out, so the assertion is about the policy and not about how
// long the machine takes to notice.
func TestExpiredAuthorizationIsRefused(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "should never be reached")
	}))
	defer srv.Close()

	base := time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC)
	auth := contracts.ValidProfilingAuthorization()
	auth.Origins = []contracts.Origin{testTarget(srv, "127.0.0.0/8")}
	auth.IssuedAt = base.Add(-48 * time.Hour)
	auth.ExpiresAt = base
	scope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		t.Fatal(err)
	}
	scope.Timeout = 2 * time.Second
	c := httpclient.New(scope, 10)

	// One hour past the window: refused, and refused for the stated reason.
	c.Scope().Now = func() time.Time { return base.Add(time.Hour) }
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	}); !errors.Is(err, httpclient.ErrAuthorizationExpired) {
		t.Fatalf("expired authorization returned %v, want %v", err,
			httpclient.ErrAuthorizationExpired)
	}
	// Inside the window the same scope must work, otherwise the refusal above is
	// just an always-failing client.
	c.Scope().Now = func() time.Time { return base.Add(-time.Minute) }
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	}); err != nil {
		t.Fatalf("request inside the window failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly one delivery, inside the window only, got %d", got)
	}
	var preDialStage bool
	for _, r := range c.Refusals() {
		if r.Stage == "pre_dial" {
			preDialStage = true
		}
	}
	if !preDialStage {
		t.Fatal("expiry refusal was not attributed to the pre-dial stage")
	}
}

// TestBudgetExhaustionStopsAndDoesNotSend is criterion 25 at the budget layer.
func TestBudgetExhaustionStopsAndDoesNotSend(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(paced(scopeFor(testTarget(srv, "127.0.0.0/8"))), 3)
	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
		}); err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}
	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if !errors.Is(err, httpclient.ErrBudgetExhausted) {
		t.Fatalf("expected budget exhaustion, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("budget of 3 delivered %d requests", got)
	}
	if c.Ledger().Used() != 3 {
		t.Fatalf("ledger used=%d", c.Ledger().Used())
	}
	if c.Ledger().Remaining() != 0 {
		t.Fatal("remaining budget is not zero")
	}
}

// TestRateLimitedResponseHaltsTheClient is criterion 24 at the transport layer:
// a 429 stops execution and is not charged as an ordinary response.
func TestRateLimitedResponseHaltsTheClient(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "slow down")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(paced(scopeFor(testTarget(srv, "127.0.0.0/8"))), 20)
	resp, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.RateLimited {
		t.Fatal("429 did not set the rate-limited flag")
	}
	if _, reason := c.Ledger().Halted(); reason != string(contracts.TriggerRateLimited) {
		t.Fatalf("client did not halt on 429, reason=%q", reason)
	}
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-2",
	}); err == nil {
		t.Fatal("a request left the client after a 429 halt")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected the halt to prevent further traffic, got %d hits", got)
	}
	// The halted request must not consume budget.
	if c.Ledger().Used() != 1 {
		t.Fatalf("post-halt attempts consumed budget: used=%d", c.Ledger().Used())
	}
}

// TestValidationAuthorizationLimitsProbes proves the C-10 probe allowlist binds
// the client, not just the paperwork.
func TestValidationAuthorizationLimitsProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a probe outside the validation authorization must not be sent")
	}))
	defer srv.Close()

	v := contracts.ValidValidationAuthorization()
	origin := testTarget(srv, "127.0.0.0/8")
	origin.PathPrefixes = []string{"/api/search"}
	v.Origin = origin
	v.AllowedProbes = []string{"P-ALLOWED"}
	scope, err := httpclient.ScopeFromValidation(v)
	if err != nil {
		t.Fatal(err)
	}
	scope.Timeout = 2 * time.Second
	pinClock(scope)
	c := httpclient.New(scope, 10)
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-FORBIDDEN",
	}); err == nil {
		t.Fatal("unlisted probe was sent")
	} else if !strings.Contains(err.Error(), httpclient.ErrProbeNotAllowed.Error()) {
		t.Fatalf("expected probe refusal, got %v", err)
	}
}

// TestEnvironmentProxyIsIgnored proves the destination check cannot be bypassed
// by pointing HTTP_PROXY at an observer.
func TestEnvironmentProxyIsIgnored(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")

	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 5)
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&proxyHits); got != 0 {
		t.Fatalf("traffic went through an unvalidated proxy %d times", got)
	}
}

// TestHopByHopHeadersAreWithheld proves a probe cannot turn the request into a
// framing test, which is out of scope for a behavioural profiler.
func TestHopByHopHeadersAreWithheld(t *testing.T) {
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 5)
	resp, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
		Headers: []contracts.HeaderEntry{
			{Name: "X-Lab-Probe-Payload", Value: "xammu-probe"},
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Content-Length", Value: "0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Get("X-Lab-Probe-Payload") != "xammu-probe" {
		t.Fatal("diagnostic header was not delivered")
	}
	if len(c.Refusals()) == 0 {
		t.Fatal("framing headers were not recorded as withheld")
	}
	if resp.Status != 200 {
		t.Fatalf("unexpected status %d", resp.Status)
	}
}

// TestPacingRespectsRateLimit checks the limiter keeps the interval.
func TestPacingRespectsRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	scope := scopeFor(testTarget(srv, "127.0.0.0/8"))
	scope.RatePerSecond = 20
	c := httpclient.New(scope, 5)
	started := time.Now()
	for i := 0; i < 4; i++ {
		if _, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(started)
	// Four requests at 20/s span at least three intervals of 50 ms.
	if elapsed < 120*time.Millisecond {
		t.Fatalf("limiter let %d requests through in %v at 20 req/s", 4, elapsed)
	}
}

// TestRefusedRequestsDoNotConsumeBudget is the accounting half of criterion 26:
// a refusal is not a request, so the truncated/completed decision stays honest.
func TestRefusedRequestsDoNotConsumeBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 2)
	if _, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/forbidden", ProbeRef: "P-1",
	}); err == nil {
		t.Fatal("expected refusal")
	}
	if c.Ledger().Used() != 0 {
		t.Fatalf("refused attempt consumed budget: used=%d", c.Ledger().Used())
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
		}); err != nil {
			t.Fatalf("authorized budget was shortened by a refusal: %v", err)
		}
	}
}

func paced(s *httpclient.Scope) *httpclient.Scope {
	s.RatePerSecond = 50
	return s
}
