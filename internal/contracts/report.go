package contracts

import (
	"sort"
	"strings"
	"time"
)

func containsString(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

// DimensionKind is one of the five report dimensions.
type DimensionKind string

const (
	DimCoverage    DimensionKind = "coverage"
	DimBehavior    DimensionKind = "behavior"
	DimAttribution DimensionKind = "attribution"
	DimDiscovery   DimensionKind = "discovery"
	DimUncertainty DimensionKind = "uncertainty"
)

func AllDimensionKinds() []DimensionKind {
	return []DimensionKind{DimCoverage, DimBehavior, DimAttribution, DimDiscovery, DimUncertainty}
}

// dimensionQuestions is the machine-checkable form of acceptance criterion 8:
// each dimension declares which of the seven section-2 questions it answers,
// and the validator requires the union to be exactly 1..7.
var dimensionQuestions = map[DimensionKind][]int{
	DimCoverage:    {1, 3},
	DimBehavior:    {2},
	DimAttribution: {5},
	DimDiscovery:   {4, 6},
	DimUncertainty: {7},
}

// QuestionsAnsweredBy reports the question numbers a dimension is responsible for.
func QuestionsAnsweredBy(k DimensionKind) []int {
	return append([]int(nil), dimensionQuestions[k]...)
}

// AllReportQuestions lists 1..7.
func AllReportQuestions() []int { return []int{1, 2, 3, 4, 5, 6, 7} }

// Dimension is one section of the report with the statements it makes.
type Dimension struct {
	Kind       DimensionKind `json:"kind"`
	Title      string        `json:"title"`
	Questions  []int         `json:"answers_questions"`
	Statements []string      `json:"statements"`
	Refs       []string      `json:"data_refs"`
}

// Scenario is one of the three separated residual-risk statements. They stay
// separate on purpose: an aggregate would hide the difference between a
// conditional exposure, an untested condition, and an unanswerable question.
type Scenario struct {
	Statement    string   `json:"statement"`
	Scope        string   `json:"scope"`
	EvidenceRefs []string `json:"evidence_refs"`
	Verification string   `json:"verification_command"`
	Untested     []string `json:"what_was_not_tested"`
}

// ResidualRisk is the three-scenario block.
type ResidualRisk struct {
	ConditionalRisk          Scenario `json:"conditional_risk"`
	ConditionNotDemonstrated Scenario `json:"condition_not_demonstrated"`
	Undeterminable           Scenario `json:"undeterminable"`
}

// UnevaluatedZone is a declared blind spot with a typed reason.
type UnevaluatedZone struct {
	Scope               string     `json:"scope"`
	Reason              ReasonCode `json:"reason_code"`
	Detail              string     `json:"detail"`
	Remediation         string     `json:"remediation"`
	ReproductionCommand string     `json:"reproduction_command"`
	PlannedRequests     int        `json:"planned_requests_not_spent"`
}

// EncodingRow is one measured encoding inside a coverage cell.
type EncodingRow struct {
	Encoding     Encoding      `json:"encoding"`
	Blocked      int           `json:"blocked"`
	Passed       int           `json:"passed"`
	ValidTrials  int           `json:"valid_trials"`
	Inconclusive int           `json:"inconclusive"`
	ControlValid bool          `json:"control_valid"`
	Verdict      string        `json:"verdict"`
	Evidence     EvidenceLevel `json:"evidence_level"`
}

// CoverageCell is one class x vector intersection with its encoding breakdown.
type CoverageCell struct {
	Class           AttackClass   `json:"attack_class"`
	Vector          Vector        `json:"vector"`
	Encodings       []EncodingRow `json:"encodings"`
	Status          string        `json:"status"`
	Aggregate       Ratio         `json:"aggregate"`
	ClaimType       ClaimType     `json:"claim_type"`
	Evidence        EvidenceLevel `json:"evidence_level"`
	ObservationRefs []string      `json:"observation_refs"`
}

// CoverageMatrix is the class x vector view (acceptance criterion 12).
type CoverageMatrix struct {
	Classes     []AttackClass  `json:"classes"`
	Vectors     []Vector       `json:"vectors"`
	Cells       []CoverageCell `json:"cells"`
	Basis       string         `json:"basis"`
	NotMeasured []string       `json:"not_measured_cells"`
}

// Bucket is one counted category of a distribution.
type Bucket struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// DistributionKind fixes the bucket vocabulary of a distribution. Without it, a
// producer could drop the "inconclusive" declaration and quietly widen a
// denominator, which is exactly the failure criterion 23 forbids.
type DistributionKind string

const (
	DistBehavioralSignal  DistributionKind = "behavioral_signal"
	DistAttributionStatus DistributionKind = "attribution_status"
	DistEvidenceBasis     DistributionKind = "evidence_basis"
	DistHypothesisOutcome DistributionKind = "hypothesis_outcome"
	DistCoverageVerdict   DistributionKind = "coverage_verdict"
)

// distributionSpec pairs each kind with its allowed buckets and the one bucket
// that never enters the denominator.
var distributionSpec = map[DistributionKind]struct {
	buckets      []string
	nonScoring   string
	labelMessage string
}{
	DistBehavioralSignal: {
		buckets:    []string{"compatible_block", "compatible_normal", "indeterminate", "rate_limited", "transport_error", "not_measured"},
		nonScoring: "indeterminate",
	},
	DistAttributionStatus: {
		buckets: []string{"undetermined", "compatible", "probable_without_corroboration",
			"supported_by_logs", "confirmed_by_correlated_evidence", "not_attributable_to_waf"},
		nonScoring: "undetermined",
	},
	DistEvidenceBasis: {
		buckets: []string{"none", "http_only", "http_plus_valid_control",
			"http_plus_independent_rounds", "http_plus_correlated_logs",
			"http_plus_configuration_export", "not_applicable"},
		nonScoring: "none",
	},
	DistHypothesisOutcome: {
		buckets:    []string{"supported", "refuted", "inconclusive"},
		nonScoring: "inconclusive",
	},
	DistCoverageVerdict: {
		buckets:    []string{"blocked", "passed", "mixed", "indeterminate", "not_measured"},
		nonScoring: "indeterminate",
	},
}

func AllDistributionKinds() []DistributionKind {
	out := make([]DistributionKind, 0, len(distributionSpec))
	for k := range distributionSpec {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// NonScoringBucket reports which bucket of a kind is excluded from the
// denominator by definition.
func NonScoringBucket(k DistributionKind) string { return distributionSpec[k].nonScoring }

// AllDistributionBuckets returns the declared vocabulary of a kind, in its
// declared order. A report renders every bucket, including the ones a run left at
// zero, so a reader can see the vocabulary was not narrowed to what was convenient
// rather than inferring it from the absence of a row.
func AllDistributionBuckets(k DistributionKind) []string {
	spec, ok := distributionSpec[k]
	if !ok {
		return nil
	}
	return append([]string(nil), spec.buckets...)
}

// Distribution reports an observed frequency with its denominator stated and
// non-scoring work kept out of that denominator (criterion 23).
type Distribution struct {
	Name               string           `json:"name"`
	Kind               DistributionKind `json:"kind"`
	Buckets            []Bucket         `json:"buckets"`
	Denominator        int              `json:"denominator"`
	Basis              string           `json:"basis"`
	InconclusiveBucket string           `json:"non_scoring_bucket"`
	Excluded           []string         `json:"excluded_from_denominator"`
}

// EvidenceSection is the reproducibility block.
type EvidenceSection struct {
	ManifestPath     string   `json:"manifest_path"`
	ManifestDigest   string   `json:"manifest_digest"`
	VerifyCommand    string   `json:"verify_command"`
	ObservationCount int      `json:"observation_count"`
	RoundIDs         []string `json:"round_ids"`
	CorpusCommitRef  string   `json:"corpus_commit_ref"`
	DetectorSetHash  string   `json:"detector_set_hash"`
	ToolVersion      string   `json:"tool_version"`
	GeneratedByUser  string   `json:"generated_by"`
}

// Report is C-15.
type Report struct {
	ReportID                string    `json:"report_id"`
	RunID                   string    `json:"run_id"`
	GeneratedAt             time.Time `json:"generated_at"`
	SchemaVersion           string    `json:"schema_version"`
	AuthorizationRef        string    `json:"authorization_ref"`
	AuthorizationValidUntil time.Time `json:"authorization_valid_until"`
	RunState                RunState  `json:"run_state"`
	StateReason             string    `json:"state_reason"`
	TargetOrigin            string    `json:"target_origin"`
	Partition               string    `json:"corpus_partition"`
	DurationSeconds         int       `json:"duration_seconds"`
	RequestsUsed            int       `json:"requests_used"`
	RequestBudget           int       `json:"request_budget"`
	LimitsSummary           []string  `json:"limits_summary"`

	ExecutiveSummary []string           `json:"executive_summary"`
	Dimensions       []Dimension        `json:"dimensions"`
	Findings         []DiscoveryFinding `json:"findings"`
	Matrix           CoverageMatrix     `json:"coverage_matrix"`
	ResidualRisk     ResidualRisk       `json:"residual_risk"`
	Unevaluated      []UnevaluatedZone  `json:"unevaluated_zones"`
	UnevaluatedNone  bool               `json:"unevaluated_declared_none"`
	Distributions    []Distribution     `json:"distributions"`
	Evidence         EvidenceSection    `json:"evidence"`
	ContractVersions map[string]string  `json:"contract_versions"`
	OutOfScope       []string           `json:"declared_out_of_scope"`
}

func (Report) Contract() ID { return IDReport }

// RequiredOutOfScope are the claims a XAMMU report must always disclaim. The
// report cannot be submitted without them, which is what keeps section 3.2 of
// the handoff from depending on someone remembering to write it.
var RequiredOutOfScope = []string{
	"application_vulnerabilities_not_evaluated",
	"no_exploitation_performed",
	"routes_not_proved_are_not_covered",
	"origin_behaviour_beyond_observed_responses_not_evaluated",
	"no_attestation_that_the_waf_is_secure",
	"not_a_replacement_for_a_penetration_test",
}

func registerReportContract() {
	register(IDReport, func(payload any) error {
		r, err := cast[Report](IDReport, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDReport)
		uuidField(c, "report_id", r.ReportID)
		c.required("run_id", r.RunID)
		c.required("authorization_ref", r.AuthorizationRef)
		c.required("target_origin", r.TargetOrigin)
		c.required("schema_version", r.SchemaVersion)
		if r.GeneratedAt.IsZero() {
			c.add("generated_at", "required")
		}
		oneofT(c, "run_state", r.RunState, AllStates()...)
		if !IsTerminal(r.RunState) && r.RunState != StatePaused &&
			r.RunState != StateHaltedRateLimit && r.RunState != StateHaltedControl &&
			r.RunState != StateHaltedOperator {
			c.add("run_state", "a report is only issued from a stopped run")
		}
		c.required("state_reason", r.StateReason)
		c.nonNegative("requests_used", r.RequestsUsed)
		c.nonNegative("request_budget", r.RequestBudget)
		if r.RequestsUsed > r.RequestBudget {
			c.add("requests_used", "exceeds budget")
		}
		c.nonEmpty("limits_summary", len(r.LimitsSummary))
		c.nonEmpty("executive_summary", len(r.ExecutiveSummary))

		// Five dimensions, each once, covering the seven questions between them.
		seenDim := map[DimensionKind]int{}
		covered := map[int]int{}
		for _, d := range r.Dimensions {
			oneofT(c, "dimensions[].kind", d.Kind, AllDimensionKinds()...)
			c.required("dimensions[].title", d.Title)
			c.nonEmpty("dimensions[].statements", len(d.Statements))
			seenDim[d.Kind]++
			for _, q := range d.Questions {
				covered[q]++
			}
			want := dimensionQuestions[d.Kind]
			if !sameInts(d.Questions, want) {
				c.add("dimensions[].answers_questions",
					string(d.Kind)+" must declare exactly the questions "+intsToString(want)+", got "+intsToString(d.Questions))
			}
		}
		for _, k := range AllDimensionKinds() {
			if seenDim[k] == 0 {
				c.add("dimensions", "missing dimension "+string(k))
			}
			if seenDim[k] > 1 {
				c.add("dimensions", "duplicate dimension "+string(k))
			}
		}
		for _, q := range AllReportQuestions() {
			if covered[q] != 1 {
				c.add("dimensions", "question "+itoaSimple(q)+" must be answered by exactly "+
					"one dimension; found "+itoaSimple(covered[q]))
			}
		}

		// Findings: every one must stand on its own.
		c.nonEmpty("findings", len(r.Findings))
		refs := map[string]bool{}
		for _, f := range r.Findings {
			if vf := Validate(IDDiscoveryFinding, &f); vf != nil {
				var vErr ValidationError
				if ok := asValidation(vf, &vErr); ok {
					for _, fe := range vErr.Fields {
						c.fields = append(c.fields, FieldError{
							Field:  "findings." + f.Ref + "." + fe.Field,
							Reason: fe.Reason, Allowed: fe.Allowed,
						})
					}
				} else {
					c.add("findings."+f.Ref, vf.Error())
				}
			}
			if refs[f.Ref] {
				c.add("findings", "duplicate finding ref "+f.Ref)
			}
			refs[f.Ref] = true
		}

		// Matrix present in every report (criterion 12).
		c.nonEmpty("coverage_matrix.classes", len(r.Matrix.Classes))
		c.nonEmpty("coverage_matrix.vectors", len(r.Matrix.Vectors))
		c.nonEmpty("coverage_matrix.cells", len(r.Matrix.Cells))
		c.required("coverage_matrix.basis", r.Matrix.Basis)
		for _, cell := range r.Matrix.Cells {
			oneofT(c, "coverage_matrix.cells[].class", cell.Class, AllAttackClasses()...)
			oneofT(c, "coverage_matrix.cells[].vector", cell.Vector, AllVectors()...)
			c.oneof("coverage_matrix.cells[].status", cell.Status,
				"measured", "partial", "not_measured", "control_invalid")
			for _, e := range cell.Encodings {
				oneofT(c, "coverage_matrix.cells[].encodings[].encoding", e.Encoding, AllEncodings()...)
				oneofT(c, "coverage_matrix.cells[].encodings[].verdict", e.Verdict,
					"blocked", "passed", "mixed", "indeterminate", "not_measured")
				c.nonNegative("coverage_matrix.cells[].encodings[].blocked", e.Blocked)
				c.nonNegative("coverage_matrix.cells[].encodings[].passed", e.Passed)
				if e.Verdict != "not_measured" && e.ValidTrials == 0 {
					c.add("coverage_matrix.cells[].encodings[].valid_trials",
						"a verdict without valid trials is not a measurement")
				}
				if e.Blocked+e.Passed > e.ValidTrials {
					c.add("coverage_matrix.cells[].encodings[].blocked",
						"blocked+passed exceeds valid trials")
				}
			}
			if cell.Status == "measured" {
				cell.Aggregate.validate(c, "coverage_matrix.cells[].aggregate")
				if cell.Aggregate.Denominator == 0 {
					c.add("coverage_matrix.cells[].aggregate.denominator",
						"measured cells need a denominator")
				}
			}
		}
		if len(r.Matrix.NotMeasured) == 0 {
			c.add("coverage_matrix.not_measured_cells",
				"a matrix that measured everything is a matrix with a plan that was too small")
		}

		// Three separated scenarios, all non-empty, none merged.
		scenarios := []struct {
			name string
			s    Scenario
		}{
			{"residual_risk.conditional_risk", r.ResidualRisk.ConditionalRisk},
			{"residual_risk.condition_not_demonstrated", r.ResidualRisk.ConditionNotDemonstrated},
			{"residual_risk.undeterminable", r.ResidualRisk.Undeterminable},
		}
		for _, sc := range scenarios {
			c.required(sc.name+".statement", sc.s.Statement)
			c.required(sc.name+".scope", sc.s.Scope)
			c.nonEmpty(sc.name+".what_was_not_tested", len(sc.s.Untested))
			c.required(sc.name+".verification_command", sc.s.Verification)
		}
		if r.ResidualRisk.ConditionalRisk.Statement != "" &&
			r.ResidualRisk.ConditionalRisk.Statement == r.ResidualRisk.Undeterminable.Statement {
			c.add("residual_risk", "the three scenarios must be distinct statements")
		}

		// The fifth dimension is always present, even when it is empty
		// (criterion 14).
		if len(r.Unevaluated) == 0 && !r.UnevaluatedNone {
			c.add("unevaluated_zones",
				"the unevaluated section is mandatory: list the zones or declare the section empty")
		}
		for _, z := range r.Unevaluated {
			c.required("unevaluated_zones[].scope", z.Scope)
			oneofT(c, "unevaluated_zones[].reason_code", z.Reason, AllReasonCodes()...)
			c.required("unevaluated_zones[].detail", z.Detail)
			c.required("unevaluated_zones[].remediation", z.Remediation)
			c.required("unevaluated_zones[].reproduction_command", z.ReproductionCommand)
			c.nonNegative("unevaluated_zones[].planned_requests_not_spent", z.PlannedRequests)
		}

		// Distributions cannot silently absorb non-scoring work: the kind fixes
		// which bucket is non-scoring, so removing the declaration is an error
		// rather than a widening of the denominator.
		for _, d := range r.Distributions {
			c.required("distributions[].name", d.Name)
			c.required("distributions[].basis", d.Basis)
			oneofT(c, "distributions[].kind", d.Kind, AllDistributionKinds()...)
			spec, ok := distributionSpec[d.Kind]
			if !ok {
				continue
			}
			var sum int
			buckets := map[string]int{}
			for _, b := range d.Buckets {
				c.nonNegative("distributions[].buckets[].count", b.Count)
				if !containsString(spec.buckets, b.Name) {
					c.add("distributions[].buckets[].name",
						b.Name+" is not a bucket of kind "+string(d.Kind)+
							"; allowed: "+strings.Join(spec.buckets, "|"))
				}
				if _, dup := buckets[b.Name]; dup {
					c.add("distributions[].buckets[].name", "duplicate bucket "+b.Name)
				}
				sum += b.Count
				buckets[b.Name] = b.Count
			}
			nonScoringCount := buckets[spec.nonScoring]
			if d.InconclusiveBucket != spec.nonScoring {
				c.add("distributions[].non_scoring_bucket",
					"kind "+string(d.Kind)+" defines "+spec.nonScoring+
						" as the bucket that never enters the denominator")
			}
			declaredExcluded := containsString(d.Excluded, spec.nonScoring)
			if !declaredExcluded {
				c.add("distributions[].excluded_from_denominator",
					"must list "+spec.nonScoring+" (criterion 23)")
			}
			if sum-nonScoringCount != d.Denominator {
				c.add("distributions[].denominator",
					"must equal the counted buckets minus the excluded non-scoring work")
			}
		}

		c.required("evidence.manifest_path", r.Evidence.ManifestPath)
		c.required("evidence.verify_command", r.Evidence.VerifyCommand)
		digestField(c, "evidence.manifest_digest", r.Evidence.ManifestDigest)
		if r.Evidence.ObservationCount == 0 {
			c.add("evidence.observation_count", "a report with no observations is not a report")
		}
		c.required("evidence.tool_version", r.Evidence.ToolVersion)
		c.required("evidence.detector_set_hash", r.Evidence.DetectorSetHash)
		c.required("evidence.corpus_commit_ref", r.Evidence.CorpusCommitRef)
		c.nonEmpty("contract_versions", len(r.ContractVersions))
		if r.ContractVersions[string(IDDiscoveryFinding)] == "" {
			c.add("contract_versions", "must publish the C-16 version")
		}

		// Section 3.2 declared in code: the disclaimers are not optional prose.
		have := map[string]bool{}
		for _, s := range r.OutOfScope {
			have[s] = true
		}
		for _, need := range RequiredOutOfScope {
			if !have[need] {
				c.add("declared_out_of_scope", "must disclaim "+need)
			}
		}
		return c.err()
	})
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	countA := map[int]int{}
	for _, v := range a {
		countA[v]++
	}
	for _, v := range b {
		countA[v]--
		if countA[v] < 0 {
			return false
		}
	}
	for _, n := range countA {
		if n != 0 {
			return false
		}
	}
	return true
}

func intsToString(in []int) string {
	if len(in) == 0 {
		return "[]"
	}
	out := "["
	for i, v := range in {
		if i > 0 {
			out += ","
		}
		out += itoaSimple(v)
	}
	return out + "]"
}

func asValidation(err error, target *ValidationError) bool {
	v, ok := err.(ValidationError)
	if ok {
		*target = v
	}
	return ok
}

func init() { registerReportContract() }
