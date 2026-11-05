package httpclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/httpclient"
)

func secretOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "session=secreto")
		h.Add("Set-Cookie", "session=secreto")
		h.Set("X-Custom-Secret", "otrosecreto")
		h.Set("Server", "lab-edge")
		h.Set("Content-Type", "application/json")
		h.Set("Retry-After", "2")
		fmt.Fprint(w, `{"result":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func entriesNamed(entries []contracts.HeaderEntry, name string) []contracts.HeaderEntry {
	var out []contracts.HeaderEntry
	for _, h := range entries {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}

// TestSensitiveHeadersAreRedactedAtCapture is the 0.2 property at the socket
// boundary: the value never becomes an entry XAMMU could journal.
func TestSensitiveHeadersAreRedactedAtCapture(t *testing.T) {
	srv := secretOrigin(t)
	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 5)
	redactor, err := contracts.NewHeaderRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetHeaderRedactor(redactor)

	resp, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookies := entriesNamed(resp.Headers, "Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("expected two Set-Cookie entries, got %d: %+v", len(cookies), resp.Headers)
	}
	for _, h := range cookies {
		if !h.Redacted || h.Value != contracts.RedactedValueMarker {
			t.Fatalf("Set-Cookie kept a readable value: %+v", h)
		}
		if h.Digest == "" || h.Digest == contracts.NewDigest([]byte("session=secreto")) {
			t.Fatalf("Set-Cookie digest must be salted, got %q", h.Digest)
		}
	}
	if cookies[0].Digest != cookies[1].Digest {
		t.Fatalf("equal values in one run must share a digest: %q vs %q",
			cookies[0].Digest, cookies[1].Digest)
	}
	if entriesNamed(resp.Headers, "X-Custom-Secret")[0].Redacted {
		t.Fatal("an unlisted header must keep its value")
	}
	for _, name := range []string{"Server", "Content-Type", "Retry-After"} {
		h := entriesNamed(resp.Headers, name)[0]
		if h.Redacted {
			t.Fatalf("%s must stay readable for the detectors: %+v", name, h)
		}
	}
	if server := entriesNamed(resp.Headers, "Server")[0].Value; server != "lab-edge" {
		t.Fatalf("Server value changed to %q", server)
	}
	for _, h := range resp.Headers {
		if h.Redacted && strings.Contains(strings.ToLower(h.Value), "secreto") {
			t.Fatalf("a sensitive value survived capture in %s: %q", h.Name, h.Value)
		}
	}
}

// TestExtraSensitiveHeaderIsRedacted checks the operator extension.
func TestExtraSensitiveHeaderIsRedacted(t *testing.T) {
	srv := secretOrigin(t)
	c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 5)
	redactor, err := contracts.NewHeaderRedactor([]string{"x-custom-secret"})
	if err != nil {
		t.Fatal(err)
	}
	c.SetHeaderRedactor(redactor)

	resp, err := c.Do(context.Background(), httpclient.Request{
		Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := entriesNamed(resp.Headers, "X-Custom-Secret")[0]
	if !h.Redacted || h.Value != contracts.RedactedValueMarker {
		t.Fatalf("--sensitive-header was not applied: %+v", h)
	}
}

// TestDifferentRunsProduceDifferentDigests proves the salt is per run: the same
// cookie seen twice cannot be correlated across evidence sets.
func TestDifferentRunsProduceDifferentDigests(t *testing.T) {
	srv := secretOrigin(t)
	digestFromRun := func() string {
		c := httpclient.New(scopeFor(testTarget(srv, "127.0.0.0/8")), 5)
		redactor, err := contracts.NewHeaderRedactor(nil)
		if err != nil {
			t.Fatal(err)
		}
		c.SetHeaderRedactor(redactor)
		resp, err := c.Do(context.Background(), httpclient.Request{
			Method: "GET", URL: srv.URL + "/api/search", ProbeRef: "P-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return entriesNamed(resp.Headers, "Set-Cookie")[0].Digest
	}
	if first, second := digestFromRun(), digestFromRun(); first == second {
		t.Fatalf("two runs produced the same digest %q for one value", first)
	}
}
