package httpclient

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

// fuzzScope is the smallest scope that can accept a request: one https origin,
// one path prefix and an open window. The fuzzer perturbs everything a caller
// supplies, not the authorization, because the authorization is what the check
// exists to enforce.
func fuzzScope() *Scope {
	return &Scope{
		AuthRef:      "XAMMU-FUZZ",
		Origins:      []contracts.Origin{{Scheme: "https", Host: "127.0.0.1", Port: 8443, PathPrefixes: []string{"/api/"}}},
		Methods:      map[string]bool{"GET": true, "POST": true},
		Timeout:      5 * time.Second,
		NotBefore:    time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(time.Hour),
		MaxBodyBytes: 1 << 20,
	}
}

// FuzzCheckRequest drives the destination gate with arbitrary method, URL and
// probe reference. The invariant is the one the single-egress promise rests on:
// whatever CheckRequest accepts, it accepted because scheme, host and port belong
// to an authorized origin and the path stays inside the authorized prefix. A
// panic is a bypass in waiting; an acceptance outside the scope is a bypass now.
func FuzzCheckRequest(f *testing.F) {
	f.Add("GET", "https://127.0.0.1:8443/api/search", "")
	f.Add("POST", "https://127.0.0.1:8443/api/search?q=1", "VAL-1")
	f.Add("get", "http://127.0.0.1:8443/api/search", "")
	f.Add("GET", "https://127.0.0.1:8444/api/search", "")
	f.Add("GET", "https://127.0.0.1:8443/../api/search", "")
	f.Add("GET", "https://evil.example/api/search", "")
	f.Add("PATCH", "https://127.0.0.1:8443/api/search", "VAL-1")
	f.Add("", "", "")
	f.Add("GET", "https://[::1]:8443/api/x", "")

	scope := fuzzScope()
	f.Fuzz(func(t *testing.T, method, rawURL, probeRef string) {
		if err := scope.CheckRequest(method, rawURL, probeRef); err != nil {
			return
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			t.Fatalf("accepted an unparsable destination: %q", rawURL)
		}
		o := scope.Origins[0]
		port := u.Port()
		if port == "" {
			port = defaultPort(o.Scheme)
		}
		if !strings.EqualFold(u.Scheme, o.Scheme) ||
			!strings.EqualFold(normalizeHost(u.Hostname()), normalizeHost(o.Host)) ||
			port != fmt.Sprint(o.Port) {
			t.Fatalf("accepted %q, outside origin %s://%s:%d", rawURL, o.Scheme, o.Host, o.Port)
		}
		if !strings.HasPrefix(u.Path, "/api/") {
			t.Fatalf("accepted %q, outside the authorized path prefix", rawURL)
		}
	})
}
