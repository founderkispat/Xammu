package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"xammu/internal/contracts"
)

func TestEffectivenessTampersListsTheVocabularyAndSendsNothing(t *testing.T) {
	canary := newCanary(t)
	code, out, errs := run(t, "effectiveness", "tampers")
	if code != 0 {
		t.Fatalf("effectiveness tampers exited %d:\n%s", code, errs)
	}
	for _, want := range []string{
		"at most 3 primitives",
		"url_encode_double",
		"base64               erases the inline marker",
		"chunked is absent on purpose",
		"xammu-lab-waf",
		"url_encode_double -> sql_comment",
		"Nothing here was sent",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("effectiveness tampers output is missing %q:\n%s", want, out)
		}
	}
	canary.idle(t, "effectiveness tampers")

	if code, _, errs := run(t, "effectiveness", "tampers", "extra"); code != 2 {
		t.Fatalf("tampers with a stray argument exited %d, want 2:\n%s", code, errs)
	}
}

func TestEffectivenessRunSelectsTheLabStackAndPublishesTheComparison(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		w.Header().Set("Server", "xammu-lab-waf/1.0")
		w.Header().Set("X-Lab-Waf-Action", "reject")
		if markerPresent(r, body.String()) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("XAMMU-LAB-WAF-BLOCK"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	host, port := testOriginAddress(t, origin.URL)
	dir := t.TempDir()
	auth := effectivenessTestAuthorization(t, host, port)
	auth.Ref = "AUTH-CLI-EFFECTIVENESS-002"
	auth.Limits.MaxRequests = 1300
	auth.AllowedTampers = contracts.AllTampers()
	authPath := writeAuthFile(t, dir, auth, "effectiveness.json")
	bundle := filepath.Join(dir, "runs", "cli-two-arm")

	code, out, errs := run(t, "effectiveness", "run",
		"--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", auth.Ref,
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"),
		"--runs-dir", filepath.Join(dir, "runs"),
		"--run", "cli-two-arm",
		"--signing-key", filepath.Join(dir, "signing.ed25519"),
		"--budget", "1200",
	)
	if code != 0 {
		t.Fatalf("two-arm run exited %d:\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"baseline: executed 600 case(s)",
		"fingerprint: xammu-lab-waf — confidence high",
		"tamper arm: url_encode_double -> sql_comment on 600 case(s)",
		"tamper: executed 600 case(s)",
		"comparison: baseline TPR 100.00%",
		"sealed and signed:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("two-arm run output is missing %q:\n%s", want, out)
		}
	}

	code, out, errs = run(t, "effectiveness", "report", "--store", bundle, "--format", "json")
	if code != 0 {
		t.Fatalf("report exited %d:\n%s\n%s", code, out, errs)
	}
	var rendered struct {
		Arms []struct {
			Arm         string   `json:"arm"`
			TamperStack []string `json:"tamper_stack"`
		} `json:"arms"`
		Comparison []struct {
			Class       string   `json:"class"`
			BaselineTPR *float64 `json:"baseline_tpr"`
			TamperTPR   *float64 `json:"tamper_tpr"`
		} `json:"comparison"`
		Fingerprint *struct {
			Vendors []struct {
				Vendor   string `json:"vendor"`
				Support  string `json:"support"`
				Evidence []struct {
					Kind     string `json:"kind"`
					Strength string `json:"strength"`
				} `json:"evidence"`
			} `json:"vendors"`
		} `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(out), &rendered); err != nil {
		t.Fatalf("report did not emit a JSON document: %v\n%s", err, out)
	}
	if len(rendered.Arms) != 2 || rendered.Arms[0].Arm != "baseline" || rendered.Arms[1].Arm != "tamper" {
		t.Fatalf("report arms = %+v", rendered.Arms)
	}
	if got := strings.Join(rendered.Arms[1].TamperStack, ","); got != "url_encode_double,sql_comment" {
		t.Fatalf("tamper stack = %q", got)
	}
	if len(rendered.Comparison) != 11 {
		t.Fatalf("comparison rows = %d, want 10 classes plus the global row", len(rendered.Comparison))
	}
	if rendered.Fingerprint == nil || len(rendered.Fingerprint.Vendors) == 0 {
		t.Fatalf("report has no fingerprint: %+v", rendered.Fingerprint)
	}
	lab := rendered.Fingerprint.Vendors[0]
	if lab.Vendor != "xammu-lab-waf" || lab.Support != "high" {
		t.Fatalf("fingerprint = %+v", lab)
	}
	kinds := map[string]bool{}
	for _, e := range lab.Evidence {
		kinds[e.Kind] = true
	}
	if !kinds["header"] || !kinds["error_page"] {
		t.Fatalf("fingerprint evidence does not cite both kinds: %+v", lab.Evidence)
	}

	if code, out, errs := run(t, "verify", "--store", bundle, "--rederive"); code != 0 {
		t.Fatalf("verify --rederive exited %d:\n%s\n%s", code, out, errs)
	}

	code, out, errs = run(t, "effectiveness", "report", "--store", bundle)
	if code != 0 {
		t.Fatalf("human report exited %d:\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"## WAF fingerprint",
		"### `xammu-lab-waf` — confidence `high`",
		"## Baseline vs tamper",
		"False-positive cost: baseline FPR",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the human report is missing %q:\n%s", want, out)
		}
	}
}

// A forced primitive the C-09 does not name is refused before the first socket,
// even when the budget would pay for it.
func TestEffectivenessRunRefusesAnUnauthorizedTamper(t *testing.T) {
	canary := newCanary(t)
	dir := t.TempDir()
	auth := effectivenessTestAuthorization(t, "127.0.0.1", canary.port())
	auth.AllowedTampers = nil
	authPath := writeAuthFile(t, dir, auth, "effectiveness.json")

	code, _, errs := run(t, "effectiveness", "run",
		"--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", auth.Ref,
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"),
		"--runs-dir", filepath.Join(dir, "runs"),
		"--run", "cli-unauthorized",
		"--signing-key", filepath.Join(dir, "signing.ed25519"),
		"--tampers", "case_switch",
	)
	if code != 1 {
		t.Fatalf("an unauthorized forced stack exited %d, want 1", code)
	}
	if !strings.Contains(errs, "does not name tamper primitive(s) case_switch") {
		t.Fatalf("the refusal does not name the primitive:\n%s", errs)
	}
	canary.idle(t, "effectiveness run with an unauthorized stack")
}

// The budget is checked against the largest arm before the baseline starts: a
// run that could only publish half a comparison is refused, not truncated.
func TestEffectivenessRunRefusesABudgetThatCannotPayBothArms(t *testing.T) {
	canary := newCanary(t)
	dir := t.TempDir()
	auth := effectivenessTestAuthorization(t, "127.0.0.1", canary.port())
	auth.AllowedTampers = contracts.AllTampers()
	authPath := writeAuthFile(t, dir, auth, "effectiveness.json")

	code, _, errs := run(t, "effectiveness", "run",
		"--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", auth.Ref,
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"),
		"--runs-dir", filepath.Join(dir, "runs"),
		"--run", "cli-short-budget",
		"--signing-key", filepath.Join(dir, "signing.ed25519"),
		"--tampers", "case_switch",
	)
	if code != 1 {
		t.Fatalf("a short budget exited %d, want 1", code)
	}
	if !strings.Contains(errs, "plans 1200 request(s)") || !strings.Contains(errs, "nothing was sent") {
		t.Fatalf("the budget refusal does not explain the plan:\n%s", errs)
	}
	canary.idle(t, "effectiveness run with a short budget")
}

// none is the documented way to say "baseline only": it stays within the Phase 1
// budget and publishes no comparison.
func TestEffectivenessRunWithTampersNoneStaysBaselineOnly(t *testing.T) {
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

	host, port := testOriginAddress(t, origin.URL)
	dir := t.TempDir()
	auth := effectivenessTestAuthorization(t, host, port)
	auth.AllowedTampers = contracts.AllTampers()
	authPath := writeAuthFile(t, dir, auth, "effectiveness.json")
	bundle := filepath.Join(dir, "runs", "cli-baseline-only")

	code, out, errs := run(t, "effectiveness", "run",
		"--authorization", authPath,
		"--issuer-keyring", testKeyring(dir),
		"--authorize", auth.Ref,
		"--corpus", filepath.Join("..", "..", "corpus", "effectiveness"),
		"--runs-dir", filepath.Join(dir, "runs"),
		"--run", "cli-baseline-only",
		"--signing-key", filepath.Join(dir, "signing.ed25519"),
		"--tampers", "none",
	)
	if code != 0 {
		t.Fatalf("--tampers none exited %d:\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "tamper: executed") {
		t.Fatalf("--tampers none still ran a tamper arm:\n%s", out)
	}
	if !strings.Contains(out, "comparison: no tamper arm measured") {
		t.Fatalf("--tampers none did not declare the absent arm:\n%s", out)
	}
	code, out, errs = run(t, "effectiveness", "report", "--store", bundle, "--format", "json")
	if code != 0 {
		t.Fatalf("report exited %d:\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, `"arms"`) || strings.Contains(out, `"comparison"`) {
		t.Fatalf("a baseline-only run published comparison fields:\n%s", out)
	}
}

// A Phase 1 bundle has no arm and no fingerprint evidence. The report says so
// rather than implying that no defensive layer was present.
func TestEffectivenessReportDeclaresAPhase1BundleLegacy(t *testing.T) {
	dir := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r3")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("the Phase 1 bundle is not present: %v", err)
	}
	code, out, errs := run(t, "effectiveness", "report", "--store", dir, "--rederive")
	if code != 0 {
		t.Fatalf("report exited %d:\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"This bundle predates Phase 2",
		"No tamper arm was measured in this run.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the Phase 1 report is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errs, "metrics_rederive") {
		t.Fatalf("the Phase 1 report did not rederive:\n%s", errs)
	}
}

func testOriginAddress(t *testing.T, raw string) (string, int) {
	t.Helper()
	u := strings.TrimPrefix(raw, "http://")
	host, portText, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("cannot read the test origin %s: %v", raw, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("cannot read the test origin port %s: %v", portText, err)
	}
	return host, port
}
