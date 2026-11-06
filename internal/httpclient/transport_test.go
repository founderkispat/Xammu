package httpclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"xammu/internal/contracts"
)

// TestTransportRefusesToRelaxTLSAndHeaderCaps pins the properties that make the
// removed RequireTLS flag unnecessary: there is no proxy, no insecure skip, no
// TLS version below 1.2 and an explicit response-header cap.
func TestTransportRefusesToRelaxTLSAndHeaderCaps(t *testing.T) {
	scope := &Scope{
		AuthRef:      "AUTH-TEST",
		Origins:      []contracts.Origin{{Scheme: "https", Host: "example.test", Port: 443, PathPrefixes: []string{"/"}}},
		Methods:      map[string]bool{"GET": true},
		ExpiresAt:    time.Now().Add(time.Hour),
		MaxBodyBytes: 1 << 20,
	}
	c := New(scope, 1)
	tr, ok := c.agent.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the client does not use an *http.Transport: %T", c.agent.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("the transport honours a proxy, which would bypass destination checks")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("the transport has no TLS configuration")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the transport can skip certificate verification")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("the transport allows TLS below 1.2: %x", tr.TLSClientConfig.MinVersion)
	}
	if tr.MaxResponseHeaderBytes != 1<<20 {
		t.Fatalf("response header cap is %d, want %d", tr.MaxResponseHeaderBytes, 1<<20)
	}
}
