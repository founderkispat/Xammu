package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"xammu/internal/integrity"
)

// The gate is the command a pipeline types, so the exit code is the product: a
// failed policy and an unusable measurement have to be distinguishable without
// parsing prose. These tests drive the real dispatch over the shipped bundles.

func gatePolicy(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestGateExitCodesSeparateTheVerdictFromAnUnusableMeasurement(t *testing.T) {
	effectivenessStore := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r6")
	profilingStore := filepath.Join("..", "..", "runs", "demo-lab")
	for _, dir := range []string{effectivenessStore, profilingStore} {
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
			t.Skipf("the shipped bundle %s is absent: %v", dir, err)
		}
	}
	trustKey := filepath.Join("..", "..", "trust", "waf-effectiveness.pub")
	dir := t.TempDir()

	failing := gatePolicy(t, dir, "failing.yaml", `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`)
	passing := gatePolicy(t, dir, "passing.yaml", `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.05"
  max_fpr: "0.10"
`)
	medium := gatePolicy(t, dir, "medium.yaml", `schema_version: xammu.policy/v1
findings:
  fail_on_priority: medium
`)
	high := gatePolicy(t, dir, "high.yaml", `schema_version: xammu.policy/v1
findings:
  fail_on_priority: high
`)
	critical := gatePolicy(t, dir, "critical.yaml", `schema_version: xammu.policy/v1
findings:
  fail_on_priority: critical
`)

	cases := []struct {
		name   string
		argv   []string
		want   int
		stdout []string
		stderr []string
	}{
		{
			name: "no bundle", want: 2,
			argv:   []string{"gate", "--policy", passing},
			stderr: []string{"command line"},
		},
		{
			name: "no policy", want: 2,
			argv:   []string{"gate", "--store", effectivenessStore},
			stderr: []string{"command line", "--policy"},
		},
		{
			name: "unknown format", want: 2,
			argv:   []string{"gate", "--store", effectivenessStore, "--policy", passing, "--format", "xml"},
			stderr: []string{"command line"},
		},
		{
			name: "report-only flags", want: 2,
			argv: []string{"gate", "--store", effectivenessStore, "--policy", passing,
				"--signing-key", trustKey},
			stderr: []string{"command line", "only applies to --format all"},
		},
		{
			name: "critical is not a priority", want: 2,
			argv:   []string{"gate", "--store", profilingStore, "--policy", critical},
			stderr: []string{"does not add a level"},
		},
		{
			name: "unreadable trust key", want: 2,
			argv: []string{"gate", "--store", effectivenessStore, "--policy", passing,
				"--trust-key", filepath.Join(dir, "absent.hex")},
			stderr: []string{"cannot read the trusted key"},
		},
		{
			name: "TPR below the minimum is a failed policy, not an error", want: 1,
			argv: []string{"gate", "--store", effectivenessStore, "--policy", failing},
			stdout: []string{`"schema_version": "xammu.gate/v1"`, `"verdict": "fail"`,
				`"status": "fail"`},
			stderr: []string{"gate FAIL", "effectiveness.tpr"},
		},
		{
			name: "the same bundle meets a documented policy", want: 0,
			argv:   []string{"gate", "--store", effectivenessStore, "--policy", passing},
			stdout: []string{`"verdict": "pass"`, `"run_id": "waf-effectiveness-2026-11-05-r6"`},
			stderr: []string{"gate PASS"},
		},
		{
			name: "an anchored signature is a real check", want: 0,
			argv: []string{"gate", "--store", effectivenessStore, "--policy", passing,
				"--trust-key", trustKey},
			stdout: []string{"signer identity anchored"},
		},
		{
			name: "SARIF keeps the failing check and the exit code", want: 1,
			argv:   []string{"gate", "--store", effectivenessStore, "--policy", failing, "--format", "sarif"},
			stdout: []string{`"version": "2.1.0"`, `"ruleId": "XAMMU-EFF-TPR"`, `"exitCode": 1`},
			stderr: []string{"gate FAIL"},
		},
		{
			name: "YAML is accepted for the same verdict", want: 0,
			argv:   []string{"gate", "--store", effectivenessStore, "--policy", passing, "--format", "yaml"},
			stdout: []string{"schema_version: xammu.gate/v1", "verdict: pass"},
		},
		{
			name: "a medium finding fails a medium floor", want: 1,
			argv:   []string{"gate", "--store", profilingStore, "--policy", medium},
			stdout: []string{`"run_id": "demo-lab"`},
			stderr: []string{"gate FAIL", "findings.priority"},
		},
		{
			name: "a high floor passes the same findings", want: 0,
			argv:   []string{"gate", "--store", profilingStore, "--policy", high},
			stdout: []string{`"0 of 14 sealed finding(s) at or above high"`},
			stderr: []string{"gate PASS"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := run(t, tc.argv...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.want, out, errs)
			}
			for _, want := range tc.stdout {
				if !bytes.Contains([]byte(out), []byte(want)) {
					t.Errorf("stdout must state %q:\n%s", want, out)
				}
			}
			for _, want := range tc.stderr {
				if !bytes.Contains([]byte(errs), []byte(want)) {
					t.Errorf("stderr must state %q:\n%s", want, errs)
				}
			}
			if code == 2 && !bytes.Contains([]byte(errs), []byte("xammu:")) {
				t.Fatalf("an unusable input must be reported on stderr: %s", errs)
			}
		})
	}
}

func TestGateOutIsRefusedInsideTheSealedBundle(t *testing.T) {
	store := filepath.Join("..", "..", "runs", "demo-lab")
	if _, err := os.Stat(filepath.Join(store, "manifest.json")); err != nil {
		t.Skipf("the demonstration bundle is absent: %v", err)
	}
	dir := t.TempDir()
	policy := gatePolicy(t, dir, "high.yaml", `schema_version: xammu.policy/v1
findings:
  fail_on_priority: high
`)

	code, _, errs := run(t, "gate", "--store", store, "--policy", policy, "--out", store)
	if code == 0 || !bytes.Contains([]byte(errs), []byte("sealed evidence")) {
		t.Fatalf("writing a derived document into evidence must be refused: exit %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(store, "gate.json")); err == nil {
		t.Fatal("the refused command wrote gate.json into the bundle")
	}

	code, out, errs := run(t, "gate", "--store", store, "--policy", policy, "--out", dir)
	if code != 0 {
		t.Fatalf("a delivery outside the bundle must be written: exit %d\n%s\n%s", code, out, errs)
	}
	if !bytes.Contains([]byte(out), []byte("gate.json written to")) {
		t.Fatalf("the command must name the file it wrote: %s", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "gate.json"))
	if err != nil {
		t.Fatalf("reading the delivery: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"schema_version": "xammu.gate/v1"`)) {
		t.Fatalf("the written document is not the gate document:\n%s", raw)
	}
}

func TestGateMarkdownAndAnnexAreEphemeralRenderings(t *testing.T) {
	store := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r6")
	if _, err := os.Stat(filepath.Join(store, "manifest.json")); err != nil {
		t.Skipf("the effectiveness bundle is absent: %v", err)
	}
	dir := t.TempDir()
	failing := gatePolicy(t, dir, "failing.yaml", `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`)

	code, out, errs := run(t, "gate", "--store", store, "--policy", failing,
		"--format", "markdown", "--prepared-by", "Test")
	if code != 1 {
		t.Fatalf("markdown must keep the verdict exit code, got %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"## 1. Executive summary", "Verdict: **FAIL**",
		"## 4. Controls with evidence", "## 6. Explicit limits", "## 7. Reproduction and seal"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("the report does not state %q:\n%s", want, out)
		}
	}
	if bytes.Contains([]byte(errs), []byte("does not yet render")) {
		t.Fatalf("markdown is a supported rendering: %s", errs)
	}

	code, out, _ = run(t, "gate", "--store", store, "--policy", failing,
		"--format", "annex", "--lang", "es")
	if code != 1 || !bytes.Contains([]byte(out), []byte("Anexo técnico")) {
		t.Fatalf("the Spanish annex must render: exit %d\n%s", code, out)
	}
	code, out, _ = run(t, "gate", "--store", store, "--policy", failing, "--format", "annex")
	if code != 1 || !bytes.Contains([]byte(out), []byte("Technical annex")) {
		t.Fatalf("the default annex language is English: exit %d\n%s", code, out)
	}

	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"--lang with all", []string{"--format", "all", "--out", dir, "--signing-key", "k",
			"--lang", "es"}, "writes both annex languages"},
		{"--lang with markdown", []string{"--format", "markdown", "--lang", "es"},
			"only applies to --format annex"},
		{"--format all without --out", []string{"--format", "all", "--signing-key", "k"},
			"needs --out"},
		{"--format all without --signing-key", []string{"--format", "all", "--out", dir},
			"needs --signing-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append([]string{"gate", "--store", store, "--policy", failing}, tc.argv...)
			code, out, errs := run(t, argv...)
			if code != 2 || !bytes.Contains([]byte(errs), []byte(tc.want)) {
				t.Fatalf("exit %d, want 2 with %q\nstdout: %s\nstderr: %s", code, tc.want, out, errs)
			}
		})
	}
}

func TestGateAllWritesAVerifiableSealedDelivery(t *testing.T) {
	store := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r6")
	if _, err := os.Stat(filepath.Join(store, "manifest.json")); err != nil {
		t.Skipf("the effectiveness bundle is absent: %v", err)
	}
	trustKey := filepath.Join("..", "..", "trust", "waf-effectiveness.pub")
	if _, err := os.Stat(trustKey); err != nil {
		t.Skipf("the repository trust anchor is absent: %v", err)
	}
	root := t.TempDir()
	policy := gatePolicy(t, root, "failing.yaml", `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`)
	key, err := integrity.LoadOrCreateKey(filepath.Join(root, "publication.ed25519"))
	if err != nil {
		t.Fatalf("creating the publication key: %v", err)
	}
	keyPub := filepath.Join(root, "publication.pub")
	if err := os.WriteFile(keyPub, []byte(hex.EncodeToString(key.Public)+"\n"), 0o600); err != nil {
		t.Fatalf("writing the publication public key: %v", err)
	}
	out := filepath.Join(root, "publication")

	code, stdout, stderr := run(t, "gate", "--store", store, "--policy", policy,
		"--format", "all", "--out", out, "--signing-key", key.Path, "--trust-key", trustKey,
		"--prepared-by", "Test")
	if code != 1 {
		t.Fatalf("a failing policy must still exit 1 after sealing, got %d\n%s\n%s",
			code, stdout, stderr)
	}
	for _, want := range []string{"delivery written to", "publication.json", "signed by ed25519 key"} {
		if !bytes.Contains([]byte(stdout), []byte(want)) {
			t.Errorf("the command must state %q:\n%s", want, stdout)
		}
	}
	for _, name := range []string{"gate.json", "gate.yaml", "results.sarif", "report.md",
		"annex-es.md", "annex-en.md", "publication.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("the delivery is missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(store, "publication.json")); err == nil {
		t.Fatal("the delivery wrote into the sealed bundle")
	}

	code, stdout, stderr = run(t, "verify", "--publication", out, "--trust-key", keyPub)
	if code != 0 {
		t.Fatalf("the sealed delivery must verify: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"delivery_files_unchanged", "checks_reproduce_from_gate_json",
		"source_bundle_verifies", "envelope sha256:", "verdict fail"} {
		if !bytes.Contains([]byte(stdout), []byte(want)) {
			t.Errorf("verify must report %q:\n%s", want, stdout)
		}
	}

	// Without a trust anchor the delivery is consistent and says the identity is not.
	code, stdout, _ = run(t, "verify", "--publication", out)
	if code != 0 || !bytes.Contains([]byte(stdout), []byte("not anchored")) {
		t.Fatalf("an unanchored verification must report it: exit %d\n%s", code, stdout)
	}

	// A different key is a failed check, not a note.
	other, err := integrity.LoadOrCreateKey(filepath.Join(root, "other.ed25519"))
	if err != nil {
		t.Fatalf("creating the second key: %v", err)
	}
	otherPub := filepath.Join(root, "other.pub")
	if err := os.WriteFile(otherPub, []byte(hex.EncodeToString(other.Public)+"\n"), 0o600); err != nil {
		t.Fatalf("writing the second public key: %v", err)
	}
	code, stdout, _ = run(t, "verify", "--publication", out, "--trust-key", otherPub)
	if code != 1 || !bytes.Contains([]byte(stdout), []byte("signer_is_trusted")) {
		t.Fatalf("a different trusted key must fail: exit %d\n%s", code, stdout)
	}

	// One byte added to a delivered document is a failed delivery.
	reportPath := filepath.Join(out, "report.md")
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("reading report.md: %v", err)
	}
	if err := os.WriteFile(reportPath, append(raw, []byte("tampered\n")...), 0o640); err != nil {
		t.Fatalf("tampering: %v", err)
	}
	code, stdout, stderr = run(t, "verify", "--publication", out, "--trust-key", keyPub)
	if code != 1 || !bytes.Contains([]byte(stdout), []byte("delivery_files_unchanged")) {
		t.Fatalf("a changed report must fail verification: exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestVerifyPublicationRefusesBundleOnlyFlags(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run(t, "verify", "--publication", dir, "--corpus", "corpus")
	if code != 2 || !bytes.Contains([]byte(errs), []byte("do not apply to --publication")) {
		t.Fatalf("bundle flags must be refused for a delivery: exit %d\n%s", code, errs)
	}
	code, _, errs = run(t, "verify", "--publication", dir, "--rederive")
	if code != 2 || !bytes.Contains([]byte(errs), []byte("--rederive")) {
		t.Fatalf("--rederive must be refused for a delivery: exit %d\n%s", code, errs)
	}
}
