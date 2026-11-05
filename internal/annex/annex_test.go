package annex

import (
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

func fixture() *contracts.Report {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return &contracts.Report{
		ReportID:                "11111111-1111-4111-8111-111111111111",
		RunID:                   "run-annex-test",
		GeneratedAt:             t0,
		SchemaVersion:           "1.0.0",
		AuthorizationRef:        "AUTH-ANNEX-001",
		AuthorizationValidUntil: t0.Add(72 * time.Hour),
		RunState:                contracts.StateCompleted,
		StateReason:             "the plan was exhausted",
		TargetOrigin:            "https://edge.example.test",
		Partition:               "smoke",
		DurationSeconds:         93,
		RequestsUsed:            40,
		RequestBudget:           48,
		LimitsSummary:           []string{"the plan stops at 48 requests"},
		Findings: []contracts.DiscoveryFinding{
			{
				FindingID:   "22222222-2222-4222-8222-222222222222",
				Ref:         "F-ENC-1",
				RunID:       "run-annex-test",
				DetectedAt:  t0,
				FindingType: contracts.FindingEncodingBypass,
				ClaimType:   contracts.ClaimAssociation,
				WhatWasObserved: "The canonical form was blocked in 3 of 3 valid trials; the " +
					"double-encoded form passed in 3 of 3 valid trials against the same endpoint.",
				WhatIsInferred: "The edge normalises URL encoding before evaluating the request, " +
					"so a double-encoded marker reaches the origin unclassified.",
				WhatEvidenceIsMissing: "WAF logs and a configuration export for the affected route.",
				Limitations: []string{
					"Only one route was probed.",
					"Only one encoding pair was compared.",
				},
				AttributionStatus:  contracts.AttributionCompatible,
				EvidenceBasis:      contracts.BasisHTTPControl,
				EvidenceLevel:      contracts.EvidenceReplicatedWithControls,
				EvidenceProfileRef: "C-08-ENC-1",
				ObservationRefs:    []string{"obs-1", "obs-2"},
				Alternatives: []contracts.AlternativeAssessment{
					{
						Kind:                 contracts.AltWAF,
						State:                contracts.AltSupported,
						Justification:        "The block appears before the origin answers.",
						TestThatWouldResolve: "Compare WAF logs for the same request id.",
					},
					{
						Kind:          contracts.AltOriginApplication,
						State:         contracts.AltRuledOut,
						Justification: "The origin returned the marker for the canonical form too.",
					},
				},
				ReproductionCommand:  "xammu report --run runs/demo --format json",
				Recommendation:       "Decode repeatedly before matching, or reject mixed encodings.",
				RegressionTest:       "xammu run --authorization AUTH-ANNEX-001 --authorize AUTH-ANNEX-001",
				Priority:             contracts.PriorityHigh,
				PriorityBasis:        "6 of 6 valid trials diverged by encoding",
				MeasuredImpact:       contracts.Ratio{Numerator: 6, Denominator: 6, Basis: "valid trials"},
				AffectedScope:        "POST /login, query string",
				AttackClass:          contracts.ClassSQLi,
				Vector:               contracts.VectorQuery,
				Encoding:             contracts.EncodingURLDouble,
				SecurityEngineerNote: "Ask for the WAF rule order before recommending a rewrite.",
			},
			{
				FindingID:             "33333333-3333-4333-8333-333333333333",
				Ref:                   "F-UND-1",
				RunID:                 "run-annex-test",
				DetectedAt:            t0,
				FindingType:           contracts.FindingUndeterminedArea,
				ClaimType:             contracts.ClaimDescriptive,
				WhatWasObserved:       "The xss/query cell returned 5xx for every trial.",
				WhatIsInferred:        "No reading was produced for that cell.",
				WhatEvidenceIsMissing: "A stable origin response for the cell.",
				Limitations:           []string{"Nothing about xss handling can be stated."},
				AttributionStatus:     contracts.AttributionUndetermined,
				EvidenceBasis:         contracts.BasisNone,
				EvidenceLevel:         contracts.EvidenceNone,
				ObservationRefs:       []string{"obs-9"},
				Alternatives: []contracts.AlternativeAssessment{
					{
						Kind:          contracts.AltOriginApplication,
						State:         contracts.AltNotRuledOut,
						Justification: "The 5xx came from the origin, not from the edge.",
					},
				},
				ReproductionCommand:  "xammu report --run runs/demo --cell xss/query",
				Recommendation:       "Re-run the cell once the origin is stable.",
				RegressionTest:       "xammu report --run runs/demo --cell xss/query",
				Priority:             contracts.PriorityLow,
				PriorityBasis:        "no coverage was produced",
				AffectedScope:        "GET /search, query string",
				AttackClass:          contracts.ClassXSS,
				Vector:               contracts.VectorQuery,
				SecurityEngineerNote: "This is a blind spot, not a weakness.",
				UnevaluatedReason:    contracts.ReasonOriginUnstable,
			},
		},
		Matrix: contracts.CoverageMatrix{
			Classes: []contracts.AttackClass{contracts.ClassSQLi, contracts.ClassXSS},
			Vectors: []contracts.Vector{contracts.VectorQuery},
			Cells: []contracts.CoverageCell{
				{
					Class:  contracts.ClassSQLi,
					Vector: contracts.VectorQuery,
					Encodings: []contracts.EncodingRow{
						{
							Encoding: contracts.EncodingCanonical, Blocked: 3, ValidTrials: 3,
							ControlValid: true, Verdict: "blocked",
							Evidence: contracts.EvidenceReplicatedWithControls,
						},
						{
							Encoding: contracts.EncodingURLDouble, Passed: 3, ValidTrials: 3,
							ControlValid: true, Verdict: "passed",
							Evidence: contracts.EvidenceReplicatedWithControls,
						},
					},
					Status:    "measured",
					Aggregate: contracts.Ratio{Numerator: 3, Denominator: 6, Basis: "valid trials"},
					ClaimType: contracts.ClaimAssociation,
					Evidence:  contracts.EvidenceReplicatedWithControls,
				},
				{
					Class:     contracts.ClassXSS,
					Vector:    contracts.VectorQuery,
					Status:    "not_measured",
					Aggregate: contracts.Ratio{Basis: "no valid trials"},
					ClaimType: contracts.ClaimDescriptive,
					Evidence:  contracts.EvidenceNone,
				},
			},
			Basis:       "6 valid trials over 1 measured cell",
			NotMeasured: []string{"xss/query was not measured: unstable origin"},
		},
		ResidualRisk: contracts.ResidualRisk{
			ConditionalRisk: contracts.Scenario{
				Statement:    "If the double-encoded form is not decoded, the marker reaches the origin.",
				Scope:        "POST /login",
				Verification: "xammu verify --run runs/demo",
				Untested:     []string{"WAF logs"},
			},
			ConditionNotDemonstrated: contracts.Scenario{
				Statement:    "That the origin executes the marker was not demonstrated.",
				Scope:        "POST /login",
				Verification: "xammu verify --run runs/demo",
				Untested:     []string{"application behaviour"},
			},
			Undeterminable: contracts.Scenario{
				Statement:    "Whether other routes share the decoding order is undeterminable from this run.",
				Scope:        "the whole origin",
				Verification: "xammu verify --run runs/demo",
				Untested:     []string{"routes outside the corpus"},
			},
		},
		Unevaluated: []contracts.UnevaluatedZone{
			{
				Scope:               "xss/query",
				Reason:              contracts.ReasonOriginUnstable,
				Detail:              "The origin answered 5xx on every trial.",
				Remediation:         "Stabilise the origin and re-run the cell.",
				ReproductionCommand: "xammu report --run runs/demo --cell xss/query",
				PlannedRequests:     6,
			},
		},
		Evidence: contracts.EvidenceSection{
			ManifestPath:     "runs/demo/manifest.json",
			ManifestDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			VerifyCommand:    "xammu verify --run runs/demo",
			ObservationCount: 23,
			RoundIDs:         []string{"round-1"},
			CorpusCommitRef:  "corpus@abc123",
			DetectorSetHash:  "detectors-hash",
			ToolVersion:      "1.0.0",
			GeneratedByUser:  "engineer",
		},
		ContractVersions: map[string]string{"C-15": "1.0.0"},
		OutOfScope:       append([]string(nil), contracts.RequiredOutOfScope...),
	}
}

func TestParseLang(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
		ok   bool
	}{
		{"", English, true},
		{"en", English, true},
		{"EN-US", English, true},
		{"english", English, true},
		{"es", Spanish, true},
		{"ES-CO", Spanish, true},
		{"español", Spanish, true},
		{" espanol ", Spanish, true},
		{"fr", "", false},
		{"de-DE", "", false},
	}
	for _, c := range cases {
		got, err := ParseLang(c.in)
		if c.ok && err != nil {
			t.Fatalf("ParseLang(%q): unexpected error %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("ParseLang(%q): expected a refusal", c.in)
		}
		if got != c.want {
			t.Fatalf("ParseLang(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAnnexSpanishTranslatesTheStructure(t *testing.T) {
	out := Markdown(fixture(), Spanish, Meta{Client: "Cliente Ejemplo"})
	for _, want := range []string{
		"# Anexo técnico",
		"## 1. Datos del engagement",
		"## 2. Qué mide este anexo y qué no",
		"## 5. Hallazgos",
		"## 6. Zonas no evaluadas",
		"## 8. Evidencia y reproducibilidad",
		"## 9. Límites y uso autorizado",
		"## 10. Declarado fuera de alcance",
		"patrón de evasión por codificación",
		"origen inestable (5xx)",
		"aplicación de origen (`origin_application`)",
		"No sustituye una prueba de penetración.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the Spanish annex is missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"Engagement data",
		"Unevaluated zones",
		"Declared out of scope",
		"Not a replacement for a penetration test.",
	} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("the Spanish annex leaked the English label %q", unwanted)
		}
	}
}

func TestAnnexEnglishUsesEnglishStructure(t *testing.T) {
	out := Markdown(fixture(), English, Meta{Client: "Example Client"})
	for _, want := range []string{
		"# Technical annex",
		"## 1. Engagement data",
		"## 2. What this annex measures and what it does not",
		"## 5. Findings",
		"## 6. Unevaluated zones",
		"## 8. Evidence and reproducibility",
		"## 10. Declared out of scope",
		"encoding bypass pattern",
		"unstable origin (5xx)",
		"Not a replacement for a penetration test.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the English annex is missing %q", want)
		}
	}
	if strings.Contains(out, "Datos del engagement") {
		t.Fatal("the English annex leaked a Spanish heading")
	}
}

// The four honesty fields are the part of a finding a client must be able to
// read without trusting the annex's author. They travel verbatim, in both
// languages, because a translation is a second claim.
func TestAnnexQuotesEvidenceVerbatim(t *testing.T) {
	rep := fixture()
	f := rep.Findings[0]
	for _, lang := range []Lang{Spanish, English} {
		out := Markdown(rep, lang, Meta{})
		for _, field := range []string{
			f.WhatWasObserved, f.WhatIsInferred, f.WhatEvidenceIsMissing,
			f.Limitations[0], f.Recommendation, f.SecurityEngineerNote,
			f.ReproductionCommand, f.RegressionTest,
		} {
			if !strings.Contains(out, field) {
				t.Fatalf("%s annex lost the verbatim field %q", lang, field)
			}
		}
	}
}

func TestAnnexNumbersComeFromTheReport(t *testing.T) {
	rep := fixture()
	out := Markdown(rep, English, Meta{})
	for _, want := range []string{
		"Published findings: 2",
		"Planned cells with a reading: 1 / 2",
		"Unevaluated zones: 1",
		"Requests used: 40 / 48",
		"40 / 48",
		"23",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("a number the report states is missing from the annex: %q", want)
		}
	}
	if strings.Contains(out, "confidence") {
		t.Fatal("the annex introduced a confidence vocabulary")
	}

	other := fixture()
	other.RequestsUsed = 7
	other.Findings = other.Findings[:1]
	out = Markdown(other, English, Meta{})
	if !strings.Contains(out, "Requests used: 7 / 48") {
		t.Fatal("the annex did not follow a changed request count")
	}
	if !strings.Contains(out, "Published findings: 1") {
		t.Fatal("the annex did not follow a changed finding count")
	}
}

func TestAnnexHTMLIsEscaped(t *testing.T) {
	rep := fixture()
	rep.Findings[0].WhatWasObserved = `<script>alert("x")</script> & more`
	out := HTML(rep, Spanish, Meta{Client: `<b>Cliente</b>`})
	if strings.Contains(out, "<script>alert") {
		t.Fatal("the HTML annex emitted an unescaped script tag")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; more") {
		t.Fatal("the HTML annex did not escape the evidence field as expected")
	}
	if !strings.Contains(out, "&lt;b&gt;Cliente&lt;/b&gt;") {
		t.Fatal("the HTML annex did not escape the client name")
	}
	if !strings.Contains(out, `lang="es"`) {
		t.Fatal("the HTML annex did not declare its language")
	}
}
