package gate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/yamlish"
)

var (
	effectivenessBundle = filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r6")
	profilingBundle     = filepath.Join("..", "..", "runs", "demo-lab")
)

func policyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	return path
}

func loadPolicy(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := LoadPolicy(policyFile(t, body))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

func loadEvidence(t *testing.T, dir string, trusted []byte) *Evidence {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Skipf("bundle %s is absent: %v", dir, err)
	}
	ev, err := Load(dir, trusted)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	return ev
}

func evaluate(t *testing.T, ev *Evidence, body string) *Evaluation {
	t.Helper()
	e, err := Evaluate(ev, loadPolicy(t, body), "bundle", false)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return e
}

const (
	effectivenessPolicyFailTPR = `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`
	effectivenessPolicyPass = `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.05"
  max_fpr: "0.10"
`
	findingsPolicyMedium = `schema_version: xammu.policy/v1
findings:
  fail_on_priority: medium
`
	findingsPolicyHigh = `schema_version: xammu.policy/v1
findings:
  fail_on_priority: high
`
)

func TestPolicyParsesTheDeclaredThresholds(t *testing.T) {
	p := loadPolicy(t, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.05"
  min_precision: "0.75"
  max_excluded_ratio: "0.10"
findings:
  fail_on_priority: low
`)
	if p.Effectiveness == nil || p.Findings == nil {
		t.Fatalf("both sections must be present: %+v", p)
	}
	if p.Effectiveness.MinTPR != 0.80 || p.Effectiveness.MaxFPR != 0.05 ||
		p.Effectiveness.MinPrecision == nil || *p.Effectiveness.MinPrecision != 0.75 ||
		p.Effectiveness.MaxExcludedRatio != 0.10 {
		t.Fatalf("thresholds decoded as %+v", p.Effectiveness)
	}
	if p.Findings.FailOnPriority != contracts.PriorityLow {
		t.Fatalf("fail_on_priority = %q", p.Findings.FailOnPriority)
	}
	if !strings.HasPrefix(p.SHA256, "sha256:") || len(p.SHA256) != len("sha256:")+64 {
		t.Fatalf("the policy digest is %q", p.SHA256)
	}
}

// The reference thresholds are part of the demonstration contract: they are
// written before the r7 run and must not be lowered after seeing its result. A
// test that pins the file is what makes that rule enforceable rather than a
// promise in a paragraph.
func TestReferencePoliciesArePinned(t *testing.T) {
	reference, err := LoadPolicy(filepath.Join("..", "..", "policies", "effectiveness-reference.yaml"))
	if err != nil {
		t.Fatalf("the shipped reference policy must load: %v", err)
	}
	if reference.Effectiveness == nil || reference.Effectiveness.MinTPR != 0.80 ||
		reference.Effectiveness.MaxFPR != 0.05 ||
		reference.Effectiveness.MinPrecision == nil || *reference.Effectiveness.MinPrecision != 0.70 ||
		reference.Effectiveness.MaxExcludedRatio != 0.0 {
		t.Fatalf("the reference thresholds moved: %+v", reference.Effectiveness)
	}
	ev := loadEvidence(t, effectivenessBundle, nil)
	e, err := Evaluate(ev, reference, "bundle", false)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if e.ExitCode != 1 || e.Document.Checks["effectiveness.tpr"].Status != StatusFail {
		t.Fatalf("r6 must fail the reference policy; that is the failing side of the demo: %+v", e.Failed)
	}

	profiling, err := LoadPolicy(filepath.Join("..", "..", "policies", "profiling-demo.yaml"))
	if err != nil {
		t.Fatalf("the shipped profiling policy must load: %v", err)
	}
	if profiling.Findings == nil || profiling.Findings.FailOnPriority != contracts.PriorityMedium {
		t.Fatalf("the profiling policy moved: %+v", profiling.Findings)
	}
}

func TestPolicyRefusesWhatItCannotApply(t *testing.T) {
	cases := map[string]string{
		"no sections": `schema_version: xammu.policy/v1
`,
		"wrong schema version": `schema_version: xammu.policy/v2
findings:
  fail_on_priority: low
`,
		"unknown top-level key": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.8"
  max_fpr: "0.1"
tresholds:
  min_tpr: "0.1"
`,
		"unknown effectiveness key": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.8"
  max_fpr: "0.1"
  max_tpr: "0.9"
`,
		"missing min_tpr": `schema_version: xammu.policy/v1
effectiveness:
  max_fpr: "0.1"
`,
		"missing max_fpr": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.8"
`,
		"ratio above one": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "1.20"
  max_fpr: "0.1"
`,
		"negative ratio": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "-0.10"
  max_fpr: "0.1"
`,
		"not a number": `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "eighty"
  max_fpr: "0.1"
`,
		"empty section": `schema_version: xammu.policy/v1
findings:
`,
		"critical priority": `schema_version: xammu.policy/v1
findings:
  fail_on_priority: critical
`,
		"unknown priority": `schema_version: xammu.policy/v1
findings:
  fail_on_priority: severe
`,
		"two documents": `schema_version: xammu.policy/v1
findings:
  fail_on_priority: low
---
schema_version: xammu.policy/v1
findings:
  fail_on_priority: high
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPolicy(policyFile(t, body))
			if err == nil {
				t.Fatal("the policy was accepted; a threshold that cannot be applied must be refused")
			}
			if !errors.Is(err, ErrUnusable) {
				t.Fatalf("the refusal must be ErrUnusable so the CLI exits 2: %v", err)
			}
		})
	}
}

func TestCriticalIsRefusedAsALevelTheEvidenceDoesNotHave(t *testing.T) {
	_, err := LoadPolicy(policyFile(t, `schema_version: xammu.policy/v1
findings:
  fail_on_priority: critical
`))
	if err == nil {
		t.Fatal("critical was accepted")
	}
	for _, want := range []string{"does not add a level", "high, medium or low"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must state %q: %v", want, err)
		}
	}
}

func TestEffectivenessGateFailsBelowTheTPRThreshold(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)

	if e.ExitCode != 1 || e.Document.Verdict != VerdictFail {
		t.Fatalf("exit %d verdict %q, want 1/fail", e.ExitCode, e.Document.Verdict)
	}
	if len(e.Failed) != 1 || e.Failed[0] != "effectiveness.tpr" {
		t.Fatalf("failed checks = %v", e.Failed)
	}
	c := e.Document.Checks["effectiveness.tpr"]
	if c.Status != StatusFail || c.Threshold != ">= 0.8" || !strings.Contains(c.Reason, "below") {
		t.Fatalf("TPR check = %+v", c)
	}
	if c.Observed != "0.08333333333333333 (8.33%)" {
		t.Fatalf("observed = %q; the document must publish the sealed rate, not a recomputation", c.Observed)
	}
	if e.Document.Checks["effectiveness.fpr"].Status != StatusPass {
		t.Fatalf("FPR 2.67%% is below the 10%% maximum: %+v", e.Document.Checks["effectiveness.fpr"])
	}
}

func TestEffectivenessGatePassesAndSaysPrecisionWasNotDeclared(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyPass)

	if e.ExitCode != 0 || e.Document.Verdict != VerdictPass || len(e.Failed) != 0 {
		t.Fatalf("exit %d verdict %q failed %v", e.ExitCode, e.Document.Verdict, e.Failed)
	}
	precision := e.Document.Checks["effectiveness.precision"]
	if precision.Applies || precision.Status != StatusNotApplicable {
		t.Fatalf("an undeclared precision threshold is not a check: %+v", precision)
	}
	if _, ok := e.Document.NotApplicable["effectiveness.precision"]; !ok {
		t.Fatal("not_applicable must name every check the policy did not configure")
	}
	if e.Document.Metrics == nil || e.Document.Metrics.RunID != ev.RunID {
		t.Fatalf("the document must publish the sealed E-03 metrics: %+v", e.Document.Metrics)
	}
	if e.Document.Metrics.Cases != 600 || e.Document.Metrics.Counts.TP != 25 {
		t.Fatalf("metrics moved: %+v", e.Document.Metrics)
	}
}

func TestChangingOnlyTheTPRThresholdChangesTheVerdict(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	below := evaluate(t, ev, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`)
	above := evaluate(t, ev, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.05"
  max_fpr: "0.10"
`)
	if below.ExitCode != 1 || above.ExitCode != 0 {
		t.Fatalf("exit codes %d and %d; only min_tpr changed", below.ExitCode, above.ExitCode)
	}
	if below.Document.Checks["effectiveness.fpr"].Status !=
		above.Document.Checks["effectiveness.fpr"].Status {
		t.Fatal("the FPR check moved although its threshold did not")
	}
}

func TestDeclaredPrecisionIsEvaluated(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.05"
  max_fpr: "0.10"
  min_precision: "0.90"
`)
	c := e.Document.Checks["effectiveness.precision"]
	if c.Status != StatusFail || !strings.Contains(c.Reason, "below") {
		t.Fatalf("precision 0.758 must fail a 0.90 minimum: %+v", c)
	}
	if e.ExitCode != 1 {
		t.Fatalf("exit %d, want 1", e.ExitCode)
	}
}

func TestNullRateFailsWithNoDenominatorInsteadOfZero(t *testing.T) {
	// A rate whose denominator is zero is null. Reading it as 0.0 would report a
	// measured failure that never happened; reading it as 1.0 would report a pass
	// that never happened.
	cases := []struct {
		name    string
		counts  effectiveness.Counts
		checkID string
	}{
		// Ten benign outcomes and no attack outcome: the TPR denominator is zero.
		{"no attack outcome", effectiveness.Counts{TN: 10}, "effectiveness.tpr"},
		// Ten attack outcomes and no benign outcome: the FPR denominator is zero.
		{"no benign outcome", effectiveness.Counts{TP: 10}, "effectiveness.fpr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &Evidence{
				Kind: KindEffectiveness,
				Metrics: &effectiveness.Metrics{
					RunID: "synthetic-null", Cases: 10, Counts: tc.counts,
				},
			}
			e, err := Evaluate(ev, loadPolicy(t, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.80"
  max_fpr: "0.10"
`), "synthetic", false)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			c := e.Document.Checks[tc.checkID]
			if c.Status != StatusFail || c.Reason != reasonNoDenominator || c.Observed != "n/a" {
				t.Fatalf("a null rate must fail as %q, got %+v", reasonNoDenominator, c)
			}
			if e.ExitCode != 1 {
				t.Fatalf("exit %d, want 1", e.ExitCode)
			}
		})
	}
}

func TestExcludedRatioIsReadOverTheCaseList(t *testing.T) {
	ev := &Evidence{
		Kind: KindEffectiveness,
		Metrics: &effectiveness.Metrics{
			RunID:  "synthetic-excluded",
			Cases:  10,
			Counts: effectiveness.Counts{TP: 2, FN: 1, FP: 1, TN: 4, Excluded: 2},
		},
	}
	e, err := Evaluate(ev, loadPolicy(t, `schema_version: xammu.policy/v1
effectiveness:
  min_tpr: "0.10"
  max_fpr: "0.50"
  max_excluded_ratio: "0.10"
`), "synthetic", false)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	c := e.Document.Checks["effectiveness.excluded_ratio"]
	if c.Status != StatusFail || c.Observed != "2/10 = 0.2 (20.00%)" {
		t.Fatalf("excluded ratio = %+v", c)
	}
}

func TestProfilingGateFailsOnSealedFindingsAtTheConfiguredPriority(t *testing.T) {
	ev := loadEvidence(t, profilingBundle, nil)
	e := evaluate(t, ev, findingsPolicyMedium)

	if e.ExitCode != 1 || e.Document.Verdict != VerdictFail {
		t.Fatalf("exit %d verdict %q", e.ExitCode, e.Document.Verdict)
	}
	c := e.Document.Checks["findings.priority"]
	if c.Status != StatusFail || c.Observed != "2 of 14 sealed finding(s) at or above medium" {
		t.Fatalf("priority check = %+v", c)
	}
	if !strings.Contains(c.Reason, "BYP-G-DEV-SQLI-Q-TAUTO") ||
		!strings.Contains(c.Reason, "OVB-informative_either") {
		t.Fatalf("the refusal must name the findings a reader has to act on: %q", c.Reason)
	}
	if len(e.Document.Findings) != 14 {
		t.Fatalf("findings published = %d, want every sealed record", len(e.Document.Findings))
	}
	if e.Document.Metrics != nil {
		t.Fatal("a profiling bundle carries no E-03 metrics; publishing a zero-value view would invent one")
	}
	inventory := e.Document.Controls["findings.inventory"]
	if inventory.Status != StatusInfo ||
		inventory.Observed != "14 sealed finding(s): 0 high, 2 medium, 12 low" {
		t.Fatalf("inventory control = %+v", inventory)
	}
}

func TestProfilingGatePassesWhenNothingReachesTheFloor(t *testing.T) {
	ev := loadEvidence(t, profilingBundle, nil)
	e := evaluate(t, ev, findingsPolicyHigh)
	if e.ExitCode != 0 || e.Document.Verdict != VerdictPass {
		t.Fatalf("exit %d verdict %q failed %v", e.ExitCode, e.Document.Verdict, e.Failed)
	}
	c := e.Document.Checks["findings.priority"]
	if c.Status != StatusPass || c.Observed != "0 of 14 sealed finding(s) at or above high" {
		t.Fatalf("priority check = %+v", c)
	}
}

func TestAGateRefusesAPolicyThatCannotJudgeTheBundle(t *testing.T) {
	effectivenessEvidence := loadEvidence(t, effectivenessBundle, nil)
	if _, err := Evaluate(effectivenessEvidence, loadPolicy(t, findingsPolicyHigh), "bundle", false); !errors.Is(err, ErrUnusable) {
		t.Fatalf("a findings-only policy cannot gate E-03: %v", err)
	}

	profilingEvidence := loadEvidence(t, profilingBundle, nil)
	if _, err := Evaluate(profilingEvidence, loadPolicy(t, effectivenessPolicyPass), "bundle", false); !errors.Is(err, ErrUnusable) {
		t.Fatalf("an effectiveness-only policy cannot gate C-16: %v", err)
	}
}

func TestLoadRefusesABundleThatNoLongerCommitsToItSelf(t *testing.T) {
	dir := t.TempDir()
	copyBundle(t, profilingBundle, dir)
	path := filepath.Join(dir, "findings.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading findings.jsonl: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o640); err != nil {
		t.Fatalf("damaging findings.jsonl: %v", err)
	}
	if _, err := Load(dir, nil); !errors.Is(err, ErrUnusable) {
		t.Fatalf("a bundle whose inventory no longer matches must be refused, got %v", err)
	}
}

func TestLoadRefusesADirectoryThatIsNotABundle(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir, nil); !errors.Is(err, ErrUnusable) {
		t.Fatalf("an empty directory is not evidence: %v", err)
	}
}

func copyBundle(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), raw, 0o640); err != nil {
			t.Fatalf("writing %s: %v", entry.Name(), err)
		}
	}
}

func TestJSONIsDeterministic(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	first, err := JSON(e.Document)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	second, err := JSON(e.Document)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("two renderings of one document must be byte-identical")
	}
}

func TestYAMLRoundTripsThroughTheRepositoryParser(t *testing.T) {
	ev := loadEvidence(t, profilingBundle, nil)
	e := evaluate(t, ev, findingsPolicyMedium)
	raw, err := YAML(e.Document)
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	docs, err := yamlish.Parse(raw)
	if err != nil {
		t.Fatalf("the YAML the gate writes must parse with internal/yamlish: %v\n%s", err, raw)
	}
	if len(docs) != 1 {
		t.Fatalf("documents = %d", len(docs))
	}
	root, ok := docs[0].Root.(map[string]any)
	if !ok {
		t.Fatalf("root = %T", docs[0].Root)
	}
	want := map[string]string{
		"schema_version": SchemaVersion,
		"tool_version":   toolVersion(),
		"verdict":        VerdictFail,
	}
	for key, value := range want {
		if root[key] != value {
			t.Errorf("%s = %v, want %q", key, root[key], value)
		}
	}
	source, _ := root["source"].(map[string]any)
	if source["run_id"] != "demo-lab" || source["kind"] != KindProfiling {
		t.Errorf("source = %+v", source)
	}
	checks, _ := root["checks"].(map[string]any)
	check, _ := checks["findings.priority"].(map[string]any)
	if check["status"] != StatusFail {
		t.Errorf("findings.priority = %+v", check)
	}
	findings, _ := root["findings"].(map[string]any)
	if len(findings) != len(e.Document.Findings) {
		t.Errorf("YAML findings = %d, want %d", len(findings), len(e.Document.Findings))
	}
}

func TestSARIFCarriesOneResultPerFailedCheck(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	raw, err := SARIF(e.Document, e.ExitCode)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name            string `json:"name"`
					SemanticVersion string `json:"semanticVersion"`
					Rules           []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				ExitCode            int  `json:"exitCode"`
			} `json:"invocations"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("the SARIF must be JSON: %v", err)
	}
	if log.Schema != sarifSchema || log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("log header = %q %q runs=%d", log.Schema, log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "XAMMU" || run.Tool.Driver.SemanticVersion != "1.0.0" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want only the failed check", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != "XAMMU-EFF-TPR" || result.Level != "error" {
		t.Fatalf("result = %+v", result)
	}
	if !strings.Contains(result.Message.Text, "TPR") {
		t.Fatalf("message = %q", result.Message.Text)
	}
	if len(result.Locations) != 1 {
		t.Fatalf("locations = %d", len(result.Locations))
	}
	loc := result.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "effectiveness_metrics.jsonl" || loc.Region.StartLine < 1 {
		t.Fatalf("location = %+v", loc)
	}
	if len(result.PartialFingerprints) == 0 {
		t.Fatal("a result without a partial fingerprint moves on every run")
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful ||
		run.Invocations[0].ExitCode != 1 {
		t.Fatalf("invocation = %+v; it must carry the real exit code", run.Invocations)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "XAMMU-EFF-TPR" {
		t.Fatalf("rules = %+v", run.Tool.Driver.Rules)
	}
}

func TestSARIFReportsOneResultPerFindingAtTheFloor(t *testing.T) {
	ev := loadEvidence(t, profilingBundle, nil)
	e := evaluate(t, ev, findingsPolicyMedium)
	raw, err := SARIF(e.Document, e.ExitCode)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want the two medium findings", len(results))
	}
	seen := map[string]bool{}
	for _, result := range results {
		seen[result.RuleID] = true
		if result.Level != "warning" {
			t.Errorf("%s level = %q, want warning for a medium priority", result.RuleID, result.Level)
		}
		loc := result.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "findings.jsonl" || loc.Region.StartLine < 1 {
			t.Errorf("%s location = %+v", result.RuleID, loc)
		}
	}
	for _, want := range []string{"XAMMU-FINDING-ENCODING_BYPASS_PATTERN", "XAMMU-FINDING-OVER_BLOCKING"} {
		if !seen[want] {
			t.Errorf("SARIF does not report %s; results = %+v", want, results)
		}
	}
}

func TestSARIFIsEmptyWhenEveryCheckPasses(t *testing.T) {
	ev := loadEvidence(t, profilingBundle, nil)
	e := evaluate(t, ev, findingsPolicyHigh)
	raw, err := SARIF(e.Document, e.ExitCode)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("a passing gate must enumerate no problem: %s", raw)
	}
}

// The measured target is named in the limits when the fingerprint says it is the
// repository's own fixture: a reader must not take r7's numbers for a product's
// efficacy. The lab bundle identifies as another vendor, so the sentence is
// absent there.
func TestLimitsNameTheReferenceFixtureWhenTheTargetIsIt(t *testing.T) {
	referenceBundle := filepath.Join("..", "..", "runs", "waf-effectiveness-2026-11-05-r7")
	reference := loadEvidence(t, referenceBundle, nil)
	e := evaluate(t, reference, effectivenessPolicyPass)
	named := false
	for _, limit := range e.Document.Limits {
		if strings.Contains(limit, "reference fixture") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the limits do not say the target is the reference fixture: %+v", e.Document.Limits)
	}

	lab := evaluate(t, loadEvidence(t, effectivenessBundle, nil), effectivenessPolicyPass)
	for _, limit := range lab.Document.Limits {
		if strings.Contains(limit, "reference fixture") {
			t.Fatalf("the lab bundle must not be described as the reference fixture: %q", limit)
		}
	}
}
