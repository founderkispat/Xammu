package httpclient_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

// TestHTTPSOriginCannotBeReachedOverPlainHTTP proves the scheme is part of the
// destination the authorization names. TLS is not a declarative flag: an https
// origin has no http match, so the request is refused before a socket exists.
func TestHTTPSOriginCannotBeReachedOverPlainHTTP(t *testing.T) {
	origin := contracts.Origin{
		Scheme: "https", Host: "127.0.0.1", Port: 443,
		PathPrefixes: []string{"/api/"},
		AllowedIPs:   []string{"127.0.0.1"},
		AllowedCIDRs: []string{"127.0.0.0/8"},
	}
	scope := scopeFor(origin)
	err := scope.CheckRequest("GET", "http://127.0.0.1:443/api/search", "")
	if !errors.Is(err, httpclient.ErrHostNotAllowed) {
		t.Fatalf("plain http reached an https-only origin: %v", err)
	}
	if err := scope.CheckRequest("GET", "https://127.0.0.1:443/api/search", ""); err != nil {
		t.Fatalf("the authorized https destination was refused: %v", err)
	}
}

// TestSelfSignedCertificateIsNotAccepted walks the whole client against a TLS
// server with an unknown authority. There is no option to accept it.
func TestSelfSignedCertificateIsNotAccepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a request must not be completed over an unverified certificate")
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(tlsTarget(t, srv)), 1)
	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("a self-signed certificate was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("the failure is not a certificate rejection: %v", err)
	}
}

// TestResponseHeaderFloodIsCapped makes the explicit 1 MiB cap observable: the
// response is refused instead of being buffered without bound.
func TestResponseHeaderFloodIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Flood", strings.Repeat("a", (1<<20)+1024))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 1)
	_, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err == nil {
		t.Fatal("a header set above the cap was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "header") {
		t.Fatalf("the failure does not name the header cap: %v", err)
	}
}

func tlsTarget(t *testing.T, srv *httptest.Server) contracts.Origin {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("cannot read the TLS test server address: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("cannot read the TLS test server port: %v", err)
	}
	return contracts.Origin{
		Scheme: "https", Host: host, Port: port,
		PathPrefixes: []string{"/api/"},
		AllowedIPs:   []string{host},
		AllowedCIDRs: []string{"127.0.0.0/8"},
	}
}
