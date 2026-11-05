package annex

import (
	"strings"
	"testing"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/gate"
)

func ptr(v float64) *float64 { return &v }

func effectivenessDoc() *gate.Document {
	return &gate.Document{
		SchemaVersion: gate.SchemaVersion,
		ToolVersion:   "xammu-1.0.0",
		Source: gate.Source{Kind: gate.KindEffectiveness, RunID: "run-annex", Bundle: "runs/run-annex",
			ManifestSHA256: "sha256:manifest", ManifestSignerKeyID: "key-1",
			Artifacts: map[string]string{}},
		Policy:  gate.PolicyView{SHA256: "sha256:policy", SchemaVersion: gate.PolicySchemaVersion},
		Verdict: gate.VerdictFail,
		Checks: map[string]gate.Check{
			"effectiveness.tpr": {ID: "effectiveness.tpr", Applies: true, Status: gate.StatusFail,
				Threshold: ">= 0.8", Observed: "0.08333333333333333 (8.33%)",
				Evidence: "effectiveness_metrics.jsonl", Line: 1},
		},
		Metrics: &gate.MetricsView{
			RunID: "run-annex", AuthorizationRef: "AUTH-1", CorpusDigest: "sha256:corpus",
			Cases:  3,
			Counts: effectiveness.Counts{TP: 1, FN: 1, FP: 1},
			Rates:  effectiveness.Rates{TPR: ptr(0.5), FPR: ptr(0.5), Precision: ptr(0.5)},
			Classes: map[string]gate.ClassView{
				"sqli": {Class: "sqli", Kind: effectiveness.KindAttack,
					Counts: effectiveness.Counts{TP: 1, FN: 1},
					Rates:  effectiveness.Rates{TPR: ptr(0.5)}},
			},
			Latency: effectiveness.LatencySummary{N: 4, P50: 1.5, P95: 2.5, P99: 3.5},
		},
		Findings: map[string]gate.FindingView{
			"F-1": {Ref: "F-1", FindingType: "over_blocking", Priority: "medium",
				WhatWasObserved: "the observed sentence is quoted", WhatIsInferred: "the inference",
				WhatEvidenceIsMissing: "the missing evidence",
				MeasuredImpact:        contracts.Ratio{Numerator: 1, Denominator: 2, Basis: "trials"},
				ReproductionCommand:   "xammu validate --finding F-1"},
		},
		Controls: map[string]gate.Control{
			"effectiveness.tpr": {Expectation: ">= 0.8", Observed: "0.08333333333333333 (8.33%)",
				Evidence: "effectiveness_metrics.jsonl", Status: gate.StatusFail},
		},
		Limits:        []string{"no traffic was sent"},
		NotApplicable: map[string]string{},
	}
}

func TestEffectivenessAnnexTranslatesProseAndKeepsTheData(t *testing.T) {
	doc := effectivenessDoc()
	meta := Meta{Client: "Client", PreparedBy: "Team"}
	es := EffectivenessMarkdown(doc, Spanish, meta, "publications/run-annex")
	en := EffectivenessMarkdown(doc, English, meta, "publications/run-annex")

	if !strings.Contains(es, "Anexo técnico") {
		t.Fatal("the Spanish annex does not use Spanish headings")
	}
	if !strings.Contains(en, "Technical annex") {
		t.Fatal("the English annex does not use English headings")
	}
	// Every figure and every evidence field appears in both languages unchanged.
	for _, want := range []string{
		"run-annex", "AUTH-1", "sha256:corpus", "sha256:manifest", "key-1", "sha256:policy",
		"0.08333333333333333 (8.33%)", "50.00%", "effectiveness_metrics.jsonl",
		"the observed sentence is quoted", "the inference", "the missing evidence",
		"xammu validate --finding F-1",
	} {
		if !strings.Contains(es, want) {
			t.Errorf("the Spanish annex omits %q", want)
		}
		if !strings.Contains(en, want) {
			t.Errorf("the English annex omits %q", want)
		}
	}
	if !strings.Contains(es, "no cumple") || !strings.Contains(en, "fail") {
		t.Fatal("the verdict must be stated in each language")
	}
	if !strings.Contains(es, "no traffic was sent") || !strings.Contains(en, "no traffic was sent") {
		t.Fatal("bundle limits are evidence and must be quoted verbatim in both languages")
	}
}
