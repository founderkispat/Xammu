// Package gate turns one sealed XAMMU bundle into a consumable quality-gate
// document. It reads evidence, sends nothing, and never writes into the bundle
// it evaluates.
//
// The document is versioned (xammu.gate/v1) instead of extending E-03: adding
// fields to E-03 would change its canonical bytes and every Phase 1/2 bundle
// would stop re-deriving. Collections are maps keyed by id so the same structure
// has one stable JSON ordering and one YAML representation.
package gate

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/effectiveness"
	"xammu/internal/fingerprint"
	"xammu/internal/integrity"
)

const (
	// SchemaVersion names the consumable document, not the evidence.
	SchemaVersion = "xammu.gate/v1"

	KindEffectiveness = "effectiveness"
	KindProfiling     = "profiling"

	VerdictPass = "pass"
	VerdictFail = "fail"

	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusNotApplicable = "not_applicable"
	StatusInfo          = "info"
)

// ErrUnusable marks input the gate refuses to evaluate: a command, a policy, a
// bundle or the evidence itself. The CLI maps it to exit 2 so a pipeline can
// tell "the target failed the policy" (exit 1) from "the gate could not measure"
// (exit 2).
var ErrUnusable = errors.New("the gate cannot evaluate this input")

// ErrFailed marks a completed evaluation whose checks did not meet the policy.
// It is a result about the target, not a tool error.
var ErrFailed = errors.New("the gate evaluated the evidence and the policy was not met")

// Document is the xammu.gate/v1 consumable.
type Document struct {
	SchemaVersion string                 `json:"schema_version"`
	ToolVersion   string                 `json:"tool_version"`
	Source        Source                 `json:"source"`
	Policy        PolicyView             `json:"policy"`
	Verdict       string                 `json:"verdict"`
	Checks        map[string]Check       `json:"checks"`
	Metrics       *MetricsView           `json:"metrics"`
	Findings      map[string]FindingView `json:"findings"`
	Controls      map[string]Control     `json:"controls"`
	Limits        []string               `json:"limits"`
	NotApplicable map[string]string      `json:"not_applicable"`
}

// Source identifies the sealed evidence the document was derived from.
type Source struct {
	Kind                string            `json:"kind"`
	RunID               string            `json:"run_id"`
	Bundle              string            `json:"bundle"`
	ManifestSHA256      string            `json:"manifest_sha256"`
	ManifestSignerKeyID string            `json:"manifest_signer_key_id"`
	Artifacts           map[string]string `json:"artifacts"`
}

// PolicyView is the normalized policy that produced the verdict. The values are
// copied into the document so a reader can reproduce the decision without the
// policy file, and so changing the file changes the seal.
type PolicyView struct {
	SHA256        string                   `json:"sha256"`
	SchemaVersion string                   `json:"schema_version"`
	Effectiveness *EffectivenessPolicyView `json:"effectiveness,omitempty"`
	Findings      *FindingsPolicyView      `json:"findings,omitempty"`
}

type EffectivenessPolicyView struct {
	MinTPR           float64  `json:"min_tpr"`
	MaxFPR           float64  `json:"max_fpr"`
	MinPrecision     *float64 `json:"min_precision,omitempty"`
	MaxExcludedRatio float64  `json:"max_excluded_ratio"`
}

type FindingsPolicyView struct {
	FailOnPriority string `json:"fail_on_priority"`
}

// Check is one machine-evaluable gate condition. Observed and Threshold are text
// because a missing denominator has no numeric value: it is reported as "n/a"
// with reason "no denominator", never as zero.
type Check struct {
	ID        string `json:"id"`
	Applies   bool   `json:"applies"`
	Status    string `json:"status"`
	Threshold string `json:"threshold,omitempty"`
	Observed  string `json:"observed,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
	// Line locates the sealed record a SARIF result cites. It is the journal
	// sequence number, which integrity verification pins to the line.
	Line int `json:"line,omitempty"`
}

// Control is the professional-report row for one check. Informational controls
// carry status "info" and no invented verdict.
type Control struct {
	Expectation string `json:"expectation"`
	Observed    string `json:"observed"`
	Evidence    string `json:"evidence"`
	Status      string `json:"status"`
}

// MetricsView carries every E-03 field, with the collections that E-03 stores as
// lists re-indexed by id. No metric is added or recomputed here.
type MetricsView struct {
	RunID            string                       `json:"run_id"`
	AuthorizationRef string                       `json:"authorization_ref"`
	CorpusDigest     string                       `json:"corpus_digest"`
	Cases            int                          `json:"cases"`
	Counts           effectiveness.Counts         `json:"counts"`
	Rates            effectiveness.Rates          `json:"rates"`
	Classes          map[string]ClassView         `json:"classes"`
	Latency          effectiveness.LatencySummary `json:"latency"`
	ExcludedByReason map[string]int               `json:"excluded_by_reason"`
	Arms             map[string]ArmView           `json:"arms,omitempty"`
	Comparison       map[string]ComparisonView    `json:"comparison,omitempty"`
	Fingerprint      *FingerprintView             `json:"fingerprint,omitempty"`
	Notes            []string                     `json:"notes"`
	GeneratedAt      time.Time                    `json:"generated_at"`
}

// ClassView is ClassMetrics with the duplicated class name kept as a field so a
// reader of one entry does not have to look up its key.
type ClassView struct {
	Class   string                       `json:"class"`
	Kind    effectiveness.Kind           `json:"kind"`
	Counts  effectiveness.Counts         `json:"counts"`
	Rates   effectiveness.Rates          `json:"rates"`
	Latency effectiveness.LatencySummary `json:"latency"`
	OWASP   string                       `json:"owasp,omitempty"`
}

type ArmView struct {
	Arm              string                       `json:"arm"`
	TamperStack      []string                     `json:"tamper_stack,omitempty"`
	SelectionBasis   string                       `json:"selection_basis,omitempty"`
	Cases            int                          `json:"cases"`
	Counts           effectiveness.Counts         `json:"counts"`
	Rates            effectiveness.Rates          `json:"rates"`
	Classes          map[string]ClassView         `json:"classes,omitempty"`
	Latency          effectiveness.LatencySummary `json:"latency"`
	ExcludedByReason map[string]int               `json:"excluded_by_reason,omitempty"`
}

type ComparisonView struct {
	Class       string   `json:"class"`
	BaselineTPR *float64 `json:"baseline_tpr"`
	TamperTPR   *float64 `json:"tamper_tpr"`
	DeltaPP     *float64 `json:"delta_pp"`
	BaselineN   int      `json:"baseline_n"`
	TamperN     int      `json:"tamper_n"`
	Note        string   `json:"note,omitempty"`
}

// FingerprintView indexes vendors and their evidence by id. A list of objects
// cannot be represented by the repository's YAML subset, and the gate publishes
// the same document in YAML; the JSON keeps every field of E-03.
type FingerprintView struct {
	Policy       string                `json:"policy"`
	Observed     int                   `json:"observed_outcomes"`
	WithEvidence int                   `json:"outcomes_with_evidence"`
	Vendors      map[string]VendorView `json:"vendors"`
}

type VendorView struct {
	Vendor              string                        `json:"vendor"`
	Support             string                        `json:"support"`
	Evidence            map[string]EvidenceView       `json:"evidence"`
	Cases               int                           `json:"cases"`
	RecommendedStacks   map[string]RecommendationView `json:"recommended_stacks,omitempty"`
	RecommendationBasis string                        `json:"recommendation_basis,omitempty"`
}

type EvidenceView struct {
	Signature string `json:"signature"`
	Kind      string `json:"kind"`
	Strength  string `json:"strength"`
	Detail    string `json:"detail"`
}

type RecommendationView struct {
	Stack []string `json:"stack"`
	Basis string   `json:"basis"`
}

// FindingView is the reader-relevant part of one sealed C-16 record. It copies
// the four honesty fields verbatim; the gate never rewrites what was observed.
type FindingView struct {
	Ref                   string          `json:"ref"`
	FindingType           string          `json:"finding_type"`
	ClaimType             string          `json:"claim_type"`
	Priority              string          `json:"priority"`
	PriorityBasis         string          `json:"priority_basis"`
	AttributionStatus     string          `json:"attribution_status"`
	EvidenceBasis         string          `json:"evidence_basis"`
	EvidenceLevel         string          `json:"evidence_level"`
	WhatWasObserved       string          `json:"what_was_observed"`
	WhatIsInferred        string          `json:"what_is_inferred"`
	WhatEvidenceIsMissing string          `json:"what_evidence_is_missing"`
	Limitations           []string        `json:"limitations"`
	AffectedScope         string          `json:"affected_scope"`
	AttackClass           string          `json:"attack_class,omitempty"`
	Vector                string          `json:"vector,omitempty"`
	Encoding              string          `json:"encoding,omitempty"`
	ReproductionCommand   string          `json:"reproduction_command"`
	Recommendation        string          `json:"recommendation"`
	RegressionTest        string          `json:"regression_test_to_run"`
	MeasuredImpact        contracts.Ratio `json:"measured_impact"`
	Line                  int             `json:"line"`
}

// metricsView converts E-03 into the indexed view without computing anything.
func metricsView(m effectiveness.Metrics) *MetricsView {
	v := &MetricsView{
		RunID: m.RunID, AuthorizationRef: m.AuthorizationRef,
		CorpusDigest: m.CorpusDigest, Cases: m.Cases,
		Counts: m.Counts, Rates: m.Rates,
		Classes:          classMap(m.Classes),
		Latency:          m.Latency,
		ExcludedByReason: copyIntMap(m.ExcludedByReason),
		Notes:            append([]string(nil), m.Notes...),
		GeneratedAt:      m.GeneratedAt,
	}
	if len(m.Arms) > 0 {
		v.Arms = map[string]ArmView{}
		for _, a := range m.Arms {
			key := string(a.Arm)
			v.Arms[key] = ArmView{
				Arm: string(a.Arm), TamperStack: tamperStrings(a.TamperStack),
				SelectionBasis: a.SelectionBasis, Cases: a.Cases,
				Counts: a.Counts, Rates: a.Rates, Classes: classMap(a.Classes),
				Latency: a.Latency, ExcludedByReason: copyIntMap(a.ExcludedByReason),
			}
		}
	}
	if len(m.Comparison) > 0 {
		v.Comparison = map[string]ComparisonView{}
		for _, r := range m.Comparison {
			v.Comparison[r.Class] = ComparisonView{
				Class: r.Class, BaselineTPR: r.BaselineTPR, TamperTPR: r.TamperTPR,
				DeltaPP: r.DeltaPP, BaselineN: r.BaselineN, TamperN: r.TamperN, Note: r.Note,
			}
		}
	}
	if m.Fingerprint != nil {
		v.Fingerprint = fingerprintView(*m.Fingerprint)
	}
	return v
}

func classMap(classes []effectiveness.ClassMetrics) map[string]ClassView {
	out := make(map[string]ClassView, len(classes))
	for _, c := range classes {
		out[c.Class] = ClassView{
			Class: c.Class, Kind: c.Kind, Counts: c.Counts, Rates: c.Rates,
			Latency: c.Latency, OWASP: c.OWASP,
		}
	}
	return out
}

func fingerprintView(s fingerprint.Summary) *FingerprintView {
	v := &FingerprintView{Policy: s.Policy, Observed: s.Observed, WithEvidence: s.WithEvidence,
		Vendors: map[string]VendorView{}}
	for _, f := range s.Vendors {
		vv := VendorView{
			Vendor: f.Vendor, Support: string(f.Support), Cases: f.Cases,
			Evidence:            map[string]EvidenceView{},
			RecommendationBasis: f.RecommendationBasis,
		}
		for _, e := range f.Evidence {
			vv.Evidence[uniqueKey(vv.Evidence, e.Signature)] = EvidenceView{
				Signature: e.Signature, Kind: string(e.Kind), Strength: string(e.Strength), Detail: e.Detail,
			}
		}
		if len(f.RecommendedStacks) > 0 {
			vv.RecommendedStacks = map[string]RecommendationView{}
			for _, r := range f.RecommendedStacks {
				stack := tamperStrings(r.Stack)
				key := strings.Join(stack, "+")
				if key == "" {
					key = "identity"
				}
				vv.RecommendedStacks[uniqueKey(vv.RecommendedStacks, key)] =
					RecommendationView{Stack: stack, Basis: r.Basis}
			}
		}
		v.Vendors[uniqueKey(v.Vendors, f.Vendor)] = vv
	}
	return v
}

// uniqueKey keeps an indexed view lossless when two records carry the same id.
// A silent overwrite would remove evidence from the consumable document.
func uniqueKey[T any](m map[string]T, key string) string {
	if _, ok := m[key]; !ok {
		return key
	}
	for i := 2; ; i++ {
		candidate := key + "#" + strconv.Itoa(i)
		if _, ok := m[candidate]; !ok {
			return candidate
		}
	}
}

func tamperStrings(in []contracts.Tamper) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

func copyIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func findingView(f contracts.DiscoveryFinding, line int) FindingView {
	return FindingView{
		Ref: f.Ref, FindingType: string(f.FindingType), ClaimType: string(f.ClaimType),
		Priority: string(f.Priority), PriorityBasis: f.PriorityBasis,
		AttributionStatus: string(f.AttributionStatus), EvidenceBasis: string(f.EvidenceBasis),
		EvidenceLevel:         string(f.EvidenceLevel),
		WhatWasObserved:       f.WhatWasObserved,
		WhatIsInferred:        f.WhatIsInferred,
		WhatEvidenceIsMissing: f.WhatEvidenceIsMissing,
		Limitations:           append([]string(nil), f.Limitations...),
		AffectedScope:         f.AffectedScope, AttackClass: string(f.AttackClass),
		Vector: string(f.Vector), Encoding: string(f.Encoding),
		ReproductionCommand: f.ReproductionCommand, Recommendation: f.Recommendation,
		RegressionTest: f.RegressionTest, MeasuredImpact: f.MeasuredImpact, Line: line,
	}
}

func policyView(p *Policy) PolicyView {
	v := PolicyView{SHA256: p.SHA256, SchemaVersion: PolicySchemaVersion}
	if p.Effectiveness != nil {
		e := &EffectivenessPolicyView{
			MinTPR: p.Effectiveness.MinTPR, MaxFPR: p.Effectiveness.MaxFPR,
			MaxExcludedRatio: p.Effectiveness.MaxExcludedRatio,
			MinPrecision:     p.Effectiveness.MinPrecision,
		}
		v.Effectiveness = e
	}
	if p.Findings != nil {
		v.Findings = &FindingsPolicyView{FailOnPriority: string(p.Findings.FailOnPriority)}
	}
	return v
}

// toolVersion is the manifest version string; the document keeps the same
// literal so a release states one version everywhere.
func toolVersion() string { return integrity.ToolVersion }

// reasons are short and stable so a pipeline can grep them. "no denominator" is
// the literal the handoff specifies for a null rate.
const reasonNoDenominator = "no denominator"
