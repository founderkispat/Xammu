package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// Refusal reasons are stable strings so the acceptance tests can assert which
// gate stopped a request, instead of only that something stopped it.
var (
	ErrAuthorizationExpired = errors.New("authorization window closed")
	ErrSchemeNotAllowed     = errors.New("scheme not authorized")
	ErrHostNotAllowed       = errors.New("host not authorized")
	ErrPortNotAllowed       = errors.New("port not authorized")
	ErrPathNotAllowed       = errors.New("path outside authorized prefixes")
	ErrPathExcluded         = errors.New("path explicitly excluded by authorization")
	ErrPathEscape           = errors.New("path does not survive normalisation")
	ErrMethodNotAllowed     = errors.New("method not authorized")
	ErrProbeNotAllowed      = errors.New("probe not listed in the validation authorization")
	ErrResolvedAddrBlocked  = errors.New("resolved address outside authorized ranges")
	ErrNoAuthorizedAddress  = errors.New("host resolved to no authorized address")
	ErrRedirectLimit        = errors.New("redirect limit reached")
	ErrBudgetExhausted      = errors.New("request budget exhausted")
	ErrHalted               = errors.New("client halted")
	ErrHostUnparsable       = errors.New("destination is not a valid URL")
	ErrResponseTooLarge     = errors.New("response exceeds the authorized size cap")
)

// Scope is the immutable destination policy the client enforces. It is derived
// from an authorization contract, never hand-written, so what the operator
// approved is what the socket checks.
type Scope struct {
	AuthRef       string
	Hypothesis    string
	Origins       []contracts.Origin
	Excluded      []string
	Methods       map[string]bool
	AllowedProbes map[string]bool
	MaxRedirects  int
	Timeout       time.Duration
	RatePerSecond int
	MaxBodyBytes  int
	Retention     contracts.RetentionPolicy
	NotBefore     time.Time
	ExpiresAt     time.Time
	UserAgent     string
	// Now supplies the clock used for the authorization window test. It is
	// injectable so expiry is checked deterministically instead of by sleeping,
	// and so a fixture authorization frozen at a past timestamp stays usable in
	// a test that pins the clock inside its window.
	Now func() time.Time
	// Lookup resolves a host name. It is injectable so the resolved-address
	// gate is testable without depending on public DNS.
	Lookup func(ctx context.Context, host string) ([]string, error)
}

func (s *Scope) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ScopeFromProfiling derives the policy of a C-09 profiling authorization.
func ScopeFromProfiling(a *contracts.ProfilingAuthorization) (*Scope, error) {
	if a == nil {
		return nil, errors.New("nil profiling authorization")
	}
	if err := contracts.Validate(contracts.IDProfilingAuthorization, a); err != nil {
		return nil, fmt.Errorf("unusable authorization: %w", err)
	}
	methods := map[string]bool{}
	for _, m := range a.Methods {
		methods[strings.ToUpper(m)] = true
	}
	s := &Scope{
		AuthRef:       a.Ref,
		Origins:       append([]contracts.Origin(nil), a.Origins...),
		Excluded:      append([]string(nil), a.ExcludedPaths...),
		Methods:       methods,
		MaxRedirects:  a.Limits.MaxRedirects,
		Timeout:       time.Duration(a.Limits.TimeoutMS) * time.Millisecond,
		RatePerSecond: a.Limits.RatePerSecond,
		MaxBodyBytes:  positiveOr(a.Limits.MaxBodyRetainBytes, 1<<20),
		Retention:     a.Retention,
		NotBefore:     a.IssuedAt,
		ExpiresAt:     a.ExpiresAt,
		UserAgent:     "xammu/1.0.0 (waf-behaviour-profiling)",
	}
	// TLS is not a flag on this scope. CheckRequest matches the scheme against an
	// authorized origin, so an https origin cannot be reached over http, and the
	// transport has no path that disables certificate verification. The former
	// RequireTLS field was computed here and never read; removing it avoids a
	// global flag that would have rejected a permitted http origin in a mixed
	// authorization.
	return s, nil
}

// ScopeFromValidation derives the policy of a C-10 validation authorization:
// one hypothesis, one bound origin, an explicit probe list.
func ScopeFromValidation(v *contracts.ValidationAuthorization) (*Scope, error) {
	if v == nil {
		return nil, errors.New("nil validation authorization")
	}
	if err := contracts.Validate(contracts.IDValidationAuthorization, v); err != nil {
		return nil, fmt.Errorf("unusable validation authorization: %w", err)
	}
	s := &Scope{
		AuthRef:       v.ParentAuthRef,
		Hypothesis:    v.HypothesisRef,
		Origins:       []contracts.Origin{v.Origin},
		Methods:       map[string]bool{"GET": true, "POST": true},
		MaxRedirects:  3,
		Timeout:       5 * time.Second,
		RatePerSecond: v.RatePerSecond,
		MaxBodyBytes:  1 << 20,
		Retention:     contracts.RetainDigestOnly,
		NotBefore:     v.NotBefore,
		ExpiresAt:     v.ExpiresAt,
		UserAgent:     "xammu/1.0.0 (hypothesis-validation)",
	}
	probes := map[string]bool{}
	for _, p := range v.AllowedProbes {
		probes[p] = true
	}
	s.AllowedProbes = probes
	return s, nil
}

// CheckRequest validates the destination a caller intends to reach, before any
// socket exists. It checks the raw path and the normalised path against the
// same prefix list: a prefix allowlist tested only against the raw string is
// bypassable by encoding or by dot segments.
func (s *Scope) CheckRequest(method, rawURL, probeRef string) error {
	now := s.now()
	if !s.NotBefore.IsZero() && now.Add(-time.Minute).After(s.ExpiresAt) {
		return ErrAuthorizationExpired
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ErrHostUnparsable
	}
	if probeRef != "" && s.AllowedProbes != nil && !s.AllowedProbes[probeRef] {
		return ErrProbeNotAllowed
	}
	m := strings.ToUpper(method)
	if m == "" {
		m = "GET"
	}
	if !s.Methods[m] {
		return fmt.Errorf("%w: %s", ErrMethodNotAllowed, m)
	}
	scheme := strings.ToLower(u.Scheme)
	host := normalizeHost(u.Hostname())
	port := u.Port()
	var matched *contracts.Origin
	for i := range s.Origins {
		o := &s.Origins[i]
		originPort := fmt.Sprint(o.Port)
		if port == "" {
			port = defaultPort(o.Scheme)
		}
		if !strings.EqualFold(o.Scheme, scheme) {
			continue
		}
		if !strings.EqualFold(normalizeHost(o.Host), host) {
			continue
		}
		if originPort != port {
			continue
		}
		matched = o
		if perr := s.pathAllowed(o, u); perr != nil {
			return perr
		}
		break
	}
	if matched == nil {
		return fmt.Errorf("%w: %s://%s%s", ErrHostNotAllowed, scheme, u.Host, u.Path)
	}
	return nil
}

func (s *Scope) pathAllowed(o *contracts.Origin, u *url.URL) error {
	for _, ex := range s.Excluded {
		if strings.HasPrefix(u.Path, ex) {
			return fmt.Errorf("%w: %s", ErrPathExcluded, u.Path)
		}
	}
	raw := u.Path
	if raw == "" {
		raw = "/"
	}
	cleaned := path.Clean(raw)
	unescaped := raw
	if dec, err := url.PathUnescape(raw); err == nil {
		unescaped = path.Clean(dec)
	}
	for _, prefix := range o.PathPrefixes {
		if strings.HasPrefix(raw, prefix) && strings.HasPrefix(cleaned, prefix) &&
			strings.HasPrefix(unescaped, prefix) {
			return nil
		}
	}
	if cleaned != raw && strings.Contains(raw, "..") {
		return fmt.Errorf("%w: %s", ErrPathEscape, raw)
	}
	return fmt.Errorf("%w: %s", ErrPathNotAllowed, raw)
}

// CheckRedirect validates one hop of a redirect chain. The chain is re-validated
// per hop rather than trusted because it was entered legitimately.
func (s *Scope) CheckRedirect(hop *url.URL, depth int) error {
	if depth > s.MaxRedirects {
		return fmt.Errorf("%w: %d", ErrRedirectLimit, depth)
	}
	return s.CheckRequest("GET", hop.String(), "")
}

// CheckResolvedAddress validates the address the socket is about to use. This is
// the gate that survives DNS rebinding: the authorized host name having passed,
// the answer it resolves to must still be inside the agreed ranges.
func (s *Scope) CheckResolvedAddress(host string, ips []string) error {
	var origin *contracts.Origin
	h := normalizeHost(host)
	for i := range s.Origins {
		if normalizeHost(s.Origins[i].Host) == h ||
			containsAddr(s.Origins[i].AllowedIPs, h) {
			origin = &s.Origins[i]
			break
		}
	}
	if origin == nil {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: %s", ErrNoAuthorizedAddress, host)
	}
	allowed := len(origin.AllowedIPs) > 0 || len(origin.AllowedCIDRs) > 0
	if !allowed {
		return fmt.Errorf("%w: origin %s declares no address ranges", ErrResolvedAddrBlocked, host)
	}
	var firstErr error
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: unparseable answer %q", ErrResolvedAddrBlocked, ip)
			}
			continue
		}
		if addrAllowed(origin, parsed) {
			return nil
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%w: %s is outside the authorized ranges for %s",
				ErrResolvedAddrBlocked, ip, host)
		}
	}
	return firstErr
}

// ChooseAddress returns the first resolved address the policy allows, so the
// dial goes to a checked answer instead of letting the resolver pick one.
func (s *Scope) ChooseAddress(host string, ips []string) (string, error) {
	var origin *contracts.Origin
	h := normalizeHost(host)
	for i := range s.Origins {
		if normalizeHost(s.Origins[i].Host) == h {
			origin = &s.Origins[i]
			break
		}
	}
	if origin == nil {
		return "", fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && addrAllowed(origin, parsed) {
			return ip, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoAuthorizedAddress, host)
}

func addrAllowed(o *contracts.Origin, ip net.IP) bool {
	for _, literal := range o.AllowedIPs {
		if a := net.ParseIP(literal); a != nil && a.Equal(ip) {
			return true
		}
	}
	for _, cidr := range o.AllowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func containsAddr(list []string, needle string) bool {
	for _, v := range list {
		if normalizeHost(v) == needle {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(h, ".")
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// AllowedSchemes lists the schemes a scope may ever dial, for documentation and
// for the acceptance checklist.
func (s *Scope) AllowedSchemes() []string {
	set := map[string]bool{}
	for _, o := range s.Origins {
		set[strings.ToLower(o.Scheme)] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
