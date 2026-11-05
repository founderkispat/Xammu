package gate

import (
	"strings"
	"testing"

	"xammu/internal/effectiveness"
)

func TestReportCarriesEverySectionAndPrintsNullRatesAsNA(t *testing.T) {
	doc := &Document{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion(),
		Source: Source{Kind: KindEffectiveness, RunID: "run-1", Bundle: "runs/run-1",
			ManifestSHA256: "sha256:aa", ManifestSignerKeyID: "kk",
			Artifacts: map[string]string{"effectiveness_metrics.jsonl": "sha256:bb"}},
		Policy:  PolicyView{SHA256: "sha256:cc", SchemaVersion: PolicySchemaVersion},
		Verdict: VerdictPass,
		Checks: map[string]Check{
			"evidence.manifest": {ID: "evidence.manifest", Applies: true, Status: StatusPass},
		},
		Metrics:       &MetricsView{Rates: effectiveness.Rates{}, Latency: effectiveness.LatencySummary{}},
		Findings:      map[string]FindingView{},
		Controls:      map[string]Control{},
		Limits:        []string{"this is an explicit limit"},
		NotApplicable: map[string]string{},
	}
	md := ReportMarkdown(doc, ReportOptions{PublicationDir: "publications/run-1"})
	for _, want := range []string{
		"## 1. Executive summary", "## 2. Scope and evidence", "## 3. Metrics",
		"## 4. Controls with evidence", "## 5. Sealed C-16 findings", "## 6. Explicit limits",
		"## 7. Reproduction and seal", "Verdict: **PASS**", "not a general security assertion",
		"this is an explicit limit", "xammu verify --publication publications/run-1 --trust-key FILE",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report does not contain %q", want)
		}
	}
	if !strings.Contains(md, "| TPR | n/a |") {
		t.Fatalf("a null rate must print n/a, never zero:\n%s", md)
	}
	if strings.Contains(strings.ToLower(md), "cvss") {
		t.Fatal("the report must not carry an invented score")
	}
}

func TestReportOverTheReferenceBundleStatesTheObservedTPR(t *testing.T) {
	ev := loadEvidence(t, effectivenessBundle, nil)
	e := evaluate(t, ev, effectivenessPolicyFailTPR)
	md := ReportMarkdown(e.Document, ReportOptions{})
	for _, want := range []string{
		"Verdict: **FAIL**", "effectiveness.tpr", "0.08333333333333333 (8.33%)",
		"Failed checks: effectiveness.tpr", "run waf-effectiveness-2026-11-05-r6",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report does not state %q:\n%s", want, md)
		}
	}
}
