package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// TestSensitiveResponseHeadersNeverReachTheBundle is the 0.2 acceptance test: a
// perimeter sends a cookie and a credential, the run seals its evidence, and no
// file in the bundle contains either literal value.
func TestSensitiveResponseHeadersNeverReachTheBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "session=secreto")
		h.Set("X-Custom-Secret", "otrosecreto")
		h.Set("Server", "lab-edge")
		h.Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":"ok"}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	auth := testAuth(t, perimeterPort(t, srv))
	auth.Limits.MaxRequests = 24
	authPath := writeAuthFile(t, dir, auth, "auth.json")
	runsDir := filepath.Join(dir, "runs")
	keyPath := filepath.Join(dir, "outside-the-bundle.ed25519")

	code, out, errs := run(t, "run", "--authorization", authPath, "--authorize", auth.Ref,
		"--issuer-keyring", testKeyring(dir),
		"--run", "cli-redaction", "--corpus", testCorpusRoot, "--runs-dir", runsDir,
		"--class", "sqli", "--vector", "query", "--budget", "24", "--signing-key", keyPath,
		"--sensitive-header", "X-Custom-Secret")
	if code != 0 {
		t.Fatalf("the run must complete: exit %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	// The policy is published before the first request and carried into the
	// reproducibility command, so a reader can see what the evidence omits.
	for _, want := range []string{"response header redaction:", "--sensitive-header x-custom-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("the run must state %q:\n%s", want, out)
		}
	}

	bundle := filepath.Join(runsDir, "cli-redaction")
	assertNoLiteralInBundle(t, bundle, "secreto")

	store, _, err := readBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := store.Records(integrity.StreamObservations)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("the run journalled no observation")
	}
	var sawCookie, sawExtra, sawServer bool
	for _, rec := range recs {
		var o contracts.RawObservation
		if err := json.Unmarshal(rec.Payload, &o); err != nil {
			t.Fatalf("observation %d is unreadable: %v", rec.Seq, err)
		}
		for _, h := range o.ResponseHeaders {
			switch strings.ToLower(h.Name) {
			case "set-cookie":
				if !h.Redacted || h.Value != contracts.RedactedValueMarker {
					t.Fatalf("Set-Cookie was not withheld: %+v", h)
				}
				sawCookie = true
			case "x-custom-secret":
				if !h.Redacted || h.Value != contracts.RedactedValueMarker {
					t.Fatalf("--sensitive-header did not withhold the value: %+v", h)
				}
				sawExtra = true
			case "server":
				if h.Redacted || h.Value != "lab-edge" {
					t.Fatalf("Server must stay readable for the detectors: %+v", h)
				}
				sawServer = true
			}
		}
	}
	if !sawCookie || !sawExtra || !sawServer {
		t.Fatalf("observations did not carry the expected headers: cookie=%v extra=%v server=%v",
			sawCookie, sawExtra, sawServer)
	}

	rep, err := readPublishedReport(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.Evidence.VerifyCommand, "--sensitive-header x-custom-secret") {
		t.Fatalf("the report must publish the redaction policy in its reproduction command: %s",
			rep.Evidence.VerifyCommand)
	}
}

// assertNoLiteralInBundle walks every file the run wrote and fails if the literal
// survives anywhere, so a future field that copies a header value is caught even
// if it is not the observations journal.
func assertNoLiteralInBundle(t *testing.T, dir, literal string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(literal)) {
			t.Errorf("%s contains the withheld value %q", path, literal)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cannot walk the bundle: %v", err)
	}
}
