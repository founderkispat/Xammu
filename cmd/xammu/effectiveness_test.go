package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

// TestEffectivenessCheckIsGateSurface locks the promise `effectiveness check`
// makes: it loads the whole corpus through the inertness gate, reports the
// minimums and sends nothing. If this command needed a target, a reviewer could
// not audit the corpus in an environment with no lab.
func TestEffectivenessCheckIsGateSurface(t *testing.T) {
	canary := newCanary(t)
	code, out, errs := run(t, "effectiveness", "check",
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"))
	if code != 0 {
		t.Fatalf("effectiveness check exited %d: %s", code, errs)
	}
	for _, want := range []string{
		"600 case(s): 300 attack, 300 benign",
		"every payload passed the inertness gate; nothing was sent.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("effectiveness check output is missing %q:\n%s", want, out)
		}
	}
	canary.idle(t, "effectiveness check")
}

// TestEffectivenessCheckRefusesAShortCorpus proves the floor is enforced rather
// than reported: a tree that does not meet the Phase 1 minimum is an error the
// operator sees before a run, not a smaller denominator afterwards.
func TestEffectivenessCheckRefusesAShortCorpus(t *testing.T) {
	dir := t.TempDir()
	writeAttackCase(t, filepath.Join(dir, "attack.yaml"), "attack-short-001")
	code, _, errs := run(t, "effectiveness", "check", "--corpus", dir)
	if code != 1 {
		t.Fatalf("a short corpus exited %d, want 1:\n%s", code, errs)
	}
	if !strings.Contains(errs, "below the Phase 1 floor") {
		t.Fatalf("the refusal does not name the floor:\n%s", errs)
	}
}

// TestEffectivenessEndToEndRunVerifyReport walks the whole Phase 1 surface
// against a loopback origin that blocks every marker-bearing request. It checks
// the three reader commands the acceptance depends on: run seals and publishes,
// verify --rederive reproduces E-03, and report renders it. It then edits the
// published document to prove --rederive treats a changed number as a failure.
func TestEffectivenessEndToEndRunVerifyReport(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if markerPresent(r, body.String()) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	u := strings.TrimPrefix(origin.URL, "http://")
	host, portText, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("cannot read the test origin %s: %v", origin.URL, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("cannot read the test origin port %s: %v", portText, err)
	}

	dir := t.TempDir()
	auth := effectivenessTestAuthorization(t, host, port)
	authPath := writeAuthFile(t, dir, auth, "effectiveness.json")
	bundle := filepath.Join(dir, "runs", "cli-effectiveness")
	signingKey := filepath.Join(dir, "signing.ed25519")

	code, out, errs := run(t, "effectiveness", "run",
		"--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", auth.Ref,
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"),
		"--runs-dir", filepath.Join(dir, "runs"),
		"--run", "cli-effectiveness",
		"--signing-key", signingKey,
		"--budget", "600",
	)
	if code != 0 {
		t.Fatalf("effectiveness run exited %d:\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"executed 600 case(s), 600 request(s) spent, 0 refusal(s), 0 failure(s)",
		"TP 300 FN 0 FP 0 TN 300 excluded 0",
		"sealed and signed:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("effectiveness run output is missing %q:\n%s", want, out)
		}
	}

	code, out, errs = run(t, "verify", "--store", bundle, "--rederive")
	if code != 0 {
		t.Fatalf("verify exited %d:\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"metrics_rederive",
		"metrics_document",
		"TP 300 FN 0 FP 0 TN 300 excluded 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("verify output is missing %q:\n%s", want, out)
		}
	}

	code, out, errs = run(t, "effectiveness", "report", "--store", bundle,
		"--format", "json", "--rederive")
	if code != 0 {
		t.Fatalf("effectiveness report exited %d:\n%s\n%s", code, out, errs)
	}
	var rendered struct {
		Cases  int `json:"cases"`
		Counts struct {
			TP int `json:"tp"`
			TN int `json:"tn"`
		} `json:"counts"`
	}
	if err := json.Unmarshal([]byte(out), &rendered); err != nil {
		t.Fatalf("report did not emit a JSON document: %v\n%s", err, out)
	}
	if rendered.Cases != 600 || rendered.Counts.TP != 300 || rendered.Counts.TN != 300 {
		t.Fatalf("report numbers do not match the run: %+v", rendered)
	}

	published := filepath.Join(dir, "published")
	code, out, errs = run(t, "effectiveness", "report", "--store", bundle,
		"--format", "both", "--out", published)
	if code != 0 {
		t.Fatalf("effectiveness report --out exited %d:\n%s\n%s", code, out, errs)
	}
	for _, name := range []string{effectivenessMetricsFile, effectivenessReportFile} {
		if _, err := os.Stat(filepath.Join(published, name)); err != nil {
			t.Fatalf("report --out did not write %s: %v", name, err)
		}
	}

	metricsPath := filepath.Join(bundle, effectivenessMetricsFile)
	original, err := os.ReadFile(metricsPath)
	if err != nil {
		t.Fatalf("cannot read the published metrics: %v", err)
	}
	edited := bytes.Replace(original, []byte(`"tp": 300`), []byte(`"tp": 299`), 1)
	if bytes.Equal(edited, original) {
		t.Fatalf("the published metrics do not contain the expected tp field:\n%s", original)
	}
	if err := os.WriteFile(metricsPath, edited, 0o640); err != nil {
		t.Fatalf("cannot edit the published metrics: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(metricsPath, original, 0o640) })

	if code, _, errs = run(t, "effectiveness", "report", "--store", bundle, "--rederive"); code != 1 {
		t.Fatalf("report --rederive accepted an edited document (exit %d):\n%s", code, errs)
	}
	if code, _, errs = run(t, "verify", "--store", bundle, "--rederive"); code != 1 {
		t.Fatalf("verify --rederive accepted an edited document (exit %d):\n%s", code, errs)
	}
	if code, _, errs = run(t, "effectiveness", "report", "--store", bundle, "--out", bundle); code != 1 {
		t.Fatalf("report --out wrote into the bundle (exit %d):\n%s", code, errs)
	}
}

// effectivenessTestAuthorization is a C-09 wide enough for the whole corpus on
// the loopback test origin. The rate is high on purpose: this test measures the
// command surface, not the pacer, which unit tests already cover.
func effectivenessTestAuthorization(t *testing.T, host string, port int) *contracts.ProfilingAuthorization {
	t.Helper()
	a := contracts.ValidProfilingAuthorization()
	a.Ref = "AUTH-CLI-EFFECTIVENESS-001"
	a.Origins = []contracts.Origin{{
		Scheme: "http", Host: host, Port: port,
		PathPrefixes: []string{"/api/", "/search"},
		AllowedCIDRs: []string{"127.0.0.0/8"},
	}}
	a.Limits.MaxRequests = 600
	a.Limits.RatePerSecond = 10000
	a.Limits.TimeoutMS = 5000
	a.AllowedClasses = contracts.AllAttackClasses()
	a.AllowedVectors = contracts.AllVectors()
	a.AllowedEncodings = contracts.AllEncodings()
	a.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	if err := contracts.Validate(contracts.IDProfilingAuthorization, a); err != nil {
		t.Fatalf("the effectiveness test authorization is not a valid C-09: %v", err)
	}
	return a
}

func markerPresent(r *http.Request, body string) bool {
	needle := "xammu-probe"
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	if has(r.URL.RawQuery) || has(r.URL.Path) {
		return true
	}
	for _, values := range r.Header {
		for _, value := range values {
			if has(value) {
				return true
			}
		}
	}
	return has(body)
}

// writeAttackCase writes one minimal attack case for the floor refusal. It is
// authored here rather than generated because the test is about the loader's
// arithmetic, and a one-case tree keeps the failure mode obvious.
func writeAttackCase(t *testing.T, path, id string) {
	t.Helper()
	body := fmt.Sprintf(`id: %s
kind: attack
class: sqli
payload: "' OR '1'='1 xammu-probe"
vector: query
encoding: canonical
parameter: q
method: GET
path: ""
expect: blocked
owasp: A03:2021-Injection
rationale: unit-test case
`, id)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("cannot write the test case: %v", err)
	}
}
