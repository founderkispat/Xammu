package contracts_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

func mustValid(t *testing.T, id contracts.ID, payload any) {
	t.Helper()
	if err := contracts.Validate(id, payload); err != nil {
		t.Fatalf("fixture for %s (%s) must be valid: %v", id, id.Label(), err)
	}
}

func expectInvalid(t *testing.T, id contracts.ID, payload any, mustMention string) {
	t.Helper()
	err := contracts.Validate(id, payload)
	if err == nil {
		t.Fatalf("%s: expected rejection mentioning %q, got acceptance", id, mustMention)
	}
	if !strings.Contains(err.Error(), mustMention) {
		t.Fatalf("%s: rejection should mention %q, got: %v", id, mustMention, err)
	}
}

// TestFixturesAreValid proves every catalogue entry has a real, passing instance.
func TestFixturesAreValid(t *testing.T) {
	mustValid(t, contracts.IDRawObservation, contracts.ValidRawObservation())
	mustValid(t, contracts.IDTransientCapture, contracts.ValidTransientCapture())
	mustValid(t, contracts.IDSignatureAnalysis, contracts.ValidSignatureAnalysis())
	mustValid(t, contracts.IDBehavioralClassification, contracts.ValidClassification())
	mustValid(t, contracts.IDAttribution, contracts.ValidAttribution())
	mustValid(t, contracts.IDAttributionStatus, contracts.ValidAttributionStatus())
	mustValid(t, contracts.IDEvidenceProfile, contracts.ValidEvidenceProfile())
	mustValid(t, contracts.IDHypothesis, contracts.ValidHypothesis())
	mustValid(t, contracts.IDProfilingAuthorization, contracts.ValidProfilingAuthorization())
	mustValid(t, contracts.IDValidationAuthorization, contracts.ValidValidationAuthorization())
	mustValid(t, contracts.IDRunProfile, contracts.ValidRunProfile())
	mustValid(t, contracts.IDRunProfile, contracts.ValidCompletedRun())
	mustValid(t, contracts.IDCorpusItem, contracts.ValidCorpusItem())
	mustValid(t, contracts.IDCorpusPartition, contracts.ValidCorpusPartition())
	mustValid(t, contracts.IDDiscoveryFinding, contracts.ValidFinding())
	mustValid(t, contracts.IDReport, contracts.ValidReport())
}

// TestEveryContractHasAValidator is checklist item 1: C-01..C-16 implemented.
func TestEveryContractHasAValidator(t *testing.T) {
	ids := contracts.IDs()
	if len(ids) != 16 {
		t.Fatalf("expected 16 contracts, got %d", len(ids))
	}
	for _, id := range ids {
		if id.Label() == "unknown" {
			t.Fatalf("contract %q is not labelled", id)
		}
		err := contracts.Validate(id, &struct{}{})
		if err == nil || !strings.Contains(err.Error(), "expected") {
			t.Fatalf("contract %q has no type-checked validator: %v", id, err)
		}
	}
}

// Criterion 17: a raw observation carries no interpretation.
func TestRawObservationRejectsInterpretiveFields(t *testing.T) {
	o := contracts.ValidRawObservation()
	for _, key := range []string{"blocked", "classification", "confidence", "severity", "attributed_to"} {
		mutated := map[string]any{}
		blob, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(blob, &mutated); err != nil {
			t.Fatal(err)
		}
		mutated[key] = true
		hits := contracts.InterpretiveKeysInJSON(mutated)
		if len(hits) == 0 {
			t.Fatalf("ingest scan accepted interpretive key %q", key)
		}
	}
}

func TestRawObservationRejectsOutOfRangeStatus(t *testing.T) {
	o := contracts.ValidRawObservation()
	o.ResponseStatus = 999
	expectInvalid(t, contracts.IDRawObservation, o, "response_status")
}

func TestRawObservationRequiresResolvedDestination(t *testing.T) {
	o := contracts.ValidRawObservation()
	o.Target.ResolvedAddr = ""
	expectInvalid(t, contracts.IDRawObservation, o, "resolved_addr")
}

// Criterion C-02: a body cannot be retained while claiming it was dropped.
func TestTransientCaptureRejectsBodyLeak(t *testing.T) {
	c := contracts.ValidTransientCapture()
	c.Body = []byte("<html>interstitial</html>")
	expectInvalid(t, contracts.IDTransientCapture, c, "body retained although policy")

	c2 := contracts.ValidTransientCapture()
	c2.Retention = "not_a_policy"
	expectInvalid(t, contracts.IDTransientCapture, c2, "retention")
}

// Criterion 24 / C-03: 429 is a pacing fact, never a block signal.
func TestSignatureAnalysisTiesRateLimitToStatus(t *testing.T) {
	s := contracts.ValidSignatureAnalysis()
	s.RateLimited = true
	expectInvalid(t, contracts.IDSignatureAnalysis, s, "rate_limited")
}

func TestClassificationRejectsCauseVocabulary(t *testing.T) {
	blob, err := json.Marshal(contracts.ValidClassification())
	if err != nil {
		t.Fatal(err)
	}
	mutated := map[string]any{}
	if err := json.Unmarshal(blob, &mutated); err != nil {
		t.Fatal(err)
	}
	mutated["cause"] = "waf"
	if hits := scanCauseKeys(mutated); len(hits) == 0 {
		t.Fatal("classification accepted a cause key")
	}
}

func scanCauseKeys(node any) []string {
	var out []string
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if k == "cause" || k == "root_cause" || k == "because" {
				out = append(out, k)
			}
			out = append(out, scanCauseKeys(child)...)
		}
	case []any:
		for _, child := range v {
			out = append(out, scanCauseKeys(child)...)
		}
	}
	return out
}

// Criterion 19 / JAVI-016: confirmed attribution needs all three conditions.
func TestConfirmedAttributionNeedsThreeConditions(t *testing.T) {
	cases := []struct {
		name   string
		rounds bool
		ctrls  bool
		logs   bool
	}{
		{"missing rounds", false, true, true},
		{"missing controls", true, false, true},
		{"missing corroboration", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := contracts.ValidAttributionStatus()
			s.Status = contracts.AttributionConfirmed
			s.Conditions = contracts.ConfirmedConditions{
				ReproducibleAcrossRounds:     tc.rounds,
				ValidControlsInScope:         tc.ctrls,
				CorroboratedByIndependentSrc: tc.logs,
				IndependentSourceKind:        "waf_logs",
				IndependentSourceRef:         "log-export-99",
			}
			s.EvidenceBasis = contracts.BasisHTTPLogs
			s.MissingEvidence = []string{}
			expectInvalid(t, contracts.IDAttributionStatus, s, "all three conditions")
		})
	}

	all := contracts.ValidAttributionStatus()
	all.Status = contracts.AttributionConfirmed
	all.EvidenceBasis = contracts.BasisHTTPLogs
	all.Conditions = contracts.ConfirmedConditions{
		ReproducibleAcrossRounds: true, ValidControlsInScope: true,
		CorroboratedByIndependentSrc: true,
		IndependentSourceKind:        "waf_logs", IndependentSourceRef: "log-export-99",
	}
	all.Justification = "three conditions met"
	all.MissingEvidence = []string{}
	mustValid(t, contracts.IDAttributionStatus, all)
}

func TestAttributionStatusCannotExceedItsConditions(t *testing.T) {
	s := contracts.ValidAttributionStatus()
	s.Status = contracts.AttributionProbable
	expectInvalid(t, contracts.IDAttributionStatus, s, "exceeds the ceiling")
}

func TestDeriveStatusIsTheSingleGate(t *testing.T) {
	got := contracts.DeriveStatus(contracts.ConfirmedConditions{
		ReproducibleAcrossRounds: true, ValidControlsInScope: true,
		CorroboratedByIndependentSrc: true,
	}, contracts.BasisHTTPOnly)
	if got == contracts.AttributionConfirmed {
		t.Fatal("http-only evidence cannot confirm attribution")
	}
	if got != contracts.AttributionProbable {
		t.Fatalf("expected probable without corroboration, got %s", got)
	}
}

// Criterion 21: no numeric scale, so the claim ceiling must be derived.
func TestEvidenceProfileCeilingIsDerived(t *testing.T) {
	p := contracts.ValidEvidenceProfile()
	p.Level = contracts.EvidenceSingleObservation
	expectInvalid(t, contracts.IDEvidenceProfile, p, "caps claims at descriptive")

	p2 := contracts.ValidEvidenceProfile()
	p2.ClaimCeiling = contracts.ClaimAttribution
	p2.CeilingJustification = "ambitious"
	expectInvalid(t, contracts.IDEvidenceProfile, p2, "caps claims at association")
}

func TestEvidenceProfileDenominatorExcludesInconclusive(t *testing.T) {
	p := contracts.ValidEvidenceProfile()
	p.Measured.Denominator = p.Population
	expectInvalid(t, contracts.IDEvidenceProfile, p, "inconclusive and invalid trials are excluded")
}

// Criterion C-07: no confirmed outcome exists in the vocabulary.
func TestHypothesisHasNoConfirmedOutcome(t *testing.T) {
	for _, o := range contracts.AllHypothesisOutcomes() {
		if string(o) == "confirmed" {
			t.Fatal("hypothesis vocabulary contains a confirmed outcome")
		}
	}
	h := contracts.ValidHypothesis()
	h.Outcome = "confirmed"
	expectInvalid(t, contracts.IDHypothesis, h, "outcome")
}

func TestHypothesisCannotSelfCertify(t *testing.T) {
	h := contracts.ValidHypothesis()
	h.ClaimType = contracts.ClaimConfirmed
	expectInvalid(t, contracts.IDHypothesis, h, "self-certify")
}

func TestInconclusiveNeedsATypedReason(t *testing.T) {
	h := contracts.ValidHypothesis()
	h.Outcome = contracts.HypothesisInconclusive
	h.InconclusiveReason = ""
	expectInvalid(t, contracts.IDHypothesis, h, "inconclusive_reason_code")
}

// Criterion 25 partial: an authorization with no address bounds is unusable.
func TestAuthorizationNeedsResolvedBounds(t *testing.T) {
	a := contracts.ValidProfilingAuthorization()
	a.Origins[0].AllowedCIDRs = nil
	expectInvalid(t, contracts.IDProfilingAuthorization, a, "JAVI-020")

	a2 := contracts.ValidProfilingAuthorization()
	a2.ExpiresAt = a2.IssuedAt.Add(-time.Hour)
	expectInvalid(t, contracts.IDProfilingAuthorization, a2, "after issued_at")
}

// An address bound the egress check cannot parse authorises nothing, so a C-09 holding
// one is a permission that cannot be exercised. It has to fail when it is loaded, not
// one refused request at a time after the run was allowed to spend its budget.
func TestAuthorizationAddressBoundsMustParse(t *testing.T) {
	a := contracts.ValidProfilingAuthorization()
	a.Origins[0].AllowedCIDRs = []string{"127.0.0.1"}
	expectInvalid(t, contracts.IDProfilingAuthorization, a, "not a network in CIDR notation")

	a2 := contracts.ValidProfilingAuthorization()
	a2.Origins[0].AllowedCIDRs = []string{"127.0.0.0/8"}
	a2.Origins[0].AllowedIPs = []string{"loopback"}
	expectInvalid(t, contracts.IDProfilingAuthorization, a2, "neither an IPv4 nor an IPv6 address")

	a3 := contracts.ValidProfilingAuthorization()
	a3.Origins[0].AllowedCIDRs = []string{" 127.0.0.0/8 "}
	a3.Origins[0].AllowedIPs = []string{"::1"}
	if err := contracts.Validate(contracts.IDProfilingAuthorization, a3); err != nil {
		t.Fatalf("a padded network and an IPv6 literal are both honourable: %v", err)
	}
}

func TestProductionAuthorizationCannotRetainBodies(t *testing.T) {
	a := contracts.ValidProfilingAuthorization()
	a.Environment = contracts.EnvProduction
	a.Retention = contracts.RetainFullAllowed
	expectInvalid(t, contracts.IDProfilingAuthorization, a, "may not retain response bodies")
}

func TestValidationAuthorizationIsImmutableAndScoped(t *testing.T) {
	v := contracts.ValidValidationAuthorization()
	v.ImmutabilityDigest = "sha256:zz"
	expectInvalid(t, contracts.IDValidationAuthorization, v, "immutability_digest")

	v2 := contracts.ValidValidationAuthorization()
	v2.AllowedProbes = nil
	expectInvalid(t, contracts.IDValidationAuthorization, v2, "allowed_probe_refs")
}

// Criterion 26: a spent budget can never read as completed.
func TestBudgetExhaustionCannotBeCompleted(t *testing.T) {
	r := contracts.ValidCompletedRun()
	r.RequestsUsed = r.RequestBudget
	expectInvalid(t, contracts.IDRunProfile, r, "criterion 26")
}

// Criterion 27: no transition out of a terminal state.
func TestTerminalStateHasNoExit(t *testing.T) {
	for _, s := range contracts.TerminalStates() {
		if !contracts.IsTerminal(s) {
			t.Fatalf("%s claims to be terminal but has exits", s)
		}
		if len(contracts.Outcomes(s)) != 0 {
			t.Fatalf("%s has legal successors", s)
		}
	}
}

func TestIllegalTransitionRejected(t *testing.T) {
	r := contracts.ValidRunProfile()
	r.Transitions[0].To = contracts.StateCompleted
	r.Transitions[1].From = contracts.StateCompleted
	r.Transitions[1].To = contracts.StateExecuting
	r.Transitions[2].Cause = "replay"
	r.Transitions[3].Cause = "replay"
	r.Transitions[4].Cause = "replay"
	expectInvalid(t, contracts.IDRunProfile, r, "illegal transition")
}

func TestHistoryMustEndInTheRecordedState(t *testing.T) {
	r := contracts.ValidRunProfile()
	r.State = contracts.StatePaused
	expectInvalid(t, contracts.IDRunProfile, r, "does not match replayed history")
}

func TestTransitionTableIsExhaustive(t *testing.T) {
	states := contracts.AllStates()
	if len(states) < 12 {
		t.Fatalf("state machine looks too small: %d states", len(states))
	}
	for _, from := range states {
		for _, to := range contracts.Outcomes(from) {
			if !contracts.LegalTransition(from, to) {
				t.Fatalf("%s lists %s as an outcome but rejects it", from, to)
			}
		}
	}
}

func TestNonTerminalRunNeedsResumeToken(t *testing.T) {
	r := contracts.ValidRunProfile()
	r.ResumeToken = ""
	expectInvalid(t, contracts.IDRunProfile, r, "resume_token")
}

// Criterion: the corpus inertness gate is a precondition of loading.
func TestCorpusItemRequiresVerifiedInertness(t *testing.T) {
	i := contracts.ValidCorpusItem()
	i.Inertness.Verdict = contracts.InertUnchecked
	expectInvalid(t, contracts.IDCorpusItem, i, "verified_inert")

	i2 := contracts.ValidCorpusItem()
	i2.Inertness.GateVersion = ""
	expectInvalid(t, contracts.IDCorpusItem, i2, "gate_version")
}

func TestCorpusItemValidationEvidenceRequired(t *testing.T) {
	i := contracts.ValidCorpusItem()
	i.Validation = nil
	expectInvalid(t, contracts.IDCorpusItem, i, "validation_evidence")
}

func TestEncodingReplicaMustDifferFromCanonical(t *testing.T) {
	i := contracts.ValidCorpusItem()
	i.Encoding = contracts.EncodingURLDouble
	expectInvalid(t, contracts.IDCorpusItem, i, "identical to canonical form")
}

// Checklist: partition leakage fails validation.
func TestPartitionRequiresChecksAgainstEveryOther(t *testing.T) {
	p := contracts.ValidCorpusPartition()
	p.OverlapChecks = p.OverlapChecks[:1]
	expectInvalid(t, contracts.IDCorpusPartition, p, "never checked against")
}

func TestPartitionLeakDetectedCannotClaimClean(t *testing.T) {
	p := contracts.ValidCorpusPartition()
	p.OverlapChecks[0].Verdict = "leak_detected"
	p.OverlapChecks[0].SharedGroups = []string{"g-sqli-canonical"}
	expectInvalid(t, contracts.IDCorpusPartition, p, "claims clean")
}

func TestIndependentPartitionCannotBeUsedForTuning(t *testing.T) {
	p := contracts.ValidCorpusPartition()
	p.Name = contracts.PartitionIndependent
	p.Sealed = true
	p.AllowedUses = []string{"independent_validation", "threshold_setting"}
	against := make([]contracts.OverlapCheck, 0, 2)
	for _, o := range p.OverlapChecks {
		if o.Against == contracts.PartitionIndependent {
			continue
		}
		against = append(against, o)
	}
	p.OverlapChecks = against
	if err := contracts.Validate(contracts.IDCorpusPartition, p); err == nil {
		t.Fatal("tuning use on the independent partition was accepted")
	} else if !strings.Contains(err.Error(), "may not be used for") {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestIndependentPartitionMustBeSealed(t *testing.T) {
	p := contracts.ValidCorpusPartition()
	p.Name = contracts.PartitionIndependent
	p.Sealed = false
	p.AllowedUses = []string{"independent_validation"}
	err := contracts.Validate(contracts.IDCorpusPartition, p)
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("unsealed independent partition accepted: %v", err)
	}
}

// Criterion 9: the four honesty fields are not optional.
func TestFindingRequiresAllFourHonestyFields(t *testing.T) {
	fields := []func(f *contracts.DiscoveryFinding){
		func(f *contracts.DiscoveryFinding) { f.WhatWasObserved = "" },
		func(f *contracts.DiscoveryFinding) { f.WhatIsInferred = "" },
		func(f *contracts.DiscoveryFinding) { f.WhatEvidenceIsMissing = "   " },
		func(f *contracts.DiscoveryFinding) { f.Limitations = nil },
	}
	names := []string{"what_was_observed", "what_is_inferred", "what_evidence_is_missing", "limitations"}
	for i, mut := range fields {
		f := contracts.ValidFinding()
		mut(f)
		expectInvalid(t, contracts.IDDiscoveryFinding, f, names[i])
	}
}

// Criterion 10: every finding carries a runnable reproduction command.
func TestFindingReproductionCommandIsScoped(t *testing.T) {
	f := contracts.ValidFinding()
	f.ReproductionCommand = "curl -s https://lab.local/api"
	expectInvalid(t, contracts.IDDiscoveryFinding, f, "must be a xammu command")

	f2 := contracts.ValidFinding()
	f2.ReproductionCommand = "xammu validate --hypothesis GAP-001"
	expectInvalid(t, contracts.IDDiscoveryFinding, f2, "authorized scope")
}

// Criterion 11: the engineer-facing note is mandatory.
func TestFindingRequiresEngineerNote(t *testing.T) {
	f := contracts.ValidFinding()
	f.SecurityEngineerNote = ""
	expectInvalid(t, contracts.IDDiscoveryFinding, f, "security_engineer_note")
}

func TestPriorityMustBeDerivedFromMeasurement(t *testing.T) {
	f := contracts.ValidFinding()
	f.MeasuredImpact = contracts.Ratio{Basis: "nothing counted"}
	expectInvalid(t, contracts.IDDiscoveryFinding, f, "requires the coverage quantity")

	f2 := contracts.ValidFinding()
	f2.PriorityBasis = ""
	expectInvalid(t, contracts.IDDiscoveryFinding, f2, "priority_basis")
}

func TestUndeterminedAreaCarriesNoInference(t *testing.T) {
	f := contracts.ValidFinding()
	f.FindingType = contracts.FindingUndeterminedArea
	f.UnevaluatedReason = contracts.ReasonControlInvalid
	f.ClaimType = contracts.ClaimAssociation
	f.AttributionStatus = contracts.AttributionCompatible
	f.EvidenceLevel = contracts.EvidenceNone
	expectInvalid(t, contracts.IDDiscoveryFinding, f, "must be descriptive")

	f2 := contracts.ValidFinding()
	f2.FindingType = contracts.FindingUndeterminedArea
	f2.UnevaluatedReason = contracts.ReasonControlInvalid
	f2.ClaimType = contracts.ClaimDescriptive
	f2.AttributionStatus = contracts.AttributionUndetermined
	f2.EvidenceLevel = contracts.EvidenceNone
	f2.Priority = contracts.PriorityLow
	f2.MeasuredImpact = contracts.Ratio{}
	f2.WhatIsInferred = "this route is probably vulnerable"
	expectInvalid(t, contracts.IDDiscoveryFinding, f2, "may not infer a vulnerability")
}

func TestClaimTypeCannotOutrunEvidence(t *testing.T) {
	f := contracts.ValidFinding()
	f.ClaimType = contracts.ClaimAttribution
	expectInvalid(t, contracts.IDDiscoveryFinding, f, "independent rounds")

	f2 := contracts.ValidFinding()
	f2.ClaimType = contracts.ClaimConfirmed
	f2.AttributionStatus = contracts.AttributionProbable
	expectInvalid(t, contracts.IDDiscoveryFinding, f2, "confirmed_by_correlated_evidence")
}

// Criterion 8: the seven questions are covered, structurally.
func TestReportCoversAllSevenQuestions(t *testing.T) {
	r := contracts.ValidReport()
	r.Dimensions[0].Questions = []int{1}
	expectInvalid(t, contracts.IDReport, r, "must be answered by exactly one dimension")

	r2 := contracts.ValidReport()
	r2.Dimensions = r2.Dimensions[:4]
	expectInvalid(t, contracts.IDReport, r2, "missing dimension uncertainty")
}

// Criterion 12: the coverage matrix is in every report.
func TestReportRequiresCoverageMatrix(t *testing.T) {
	r := contracts.ValidReport()
	r.Matrix.Cells = nil
	expectInvalid(t, contracts.IDReport, r, "coverage_matrix.cells")

	r2 := contracts.ValidReport()
	r2.Matrix.NotMeasured = nil
	expectInvalid(t, contracts.IDReport, r2, "not_measured_cells")
}

func TestMatrixVerdictNeedsValidTrials(t *testing.T) {
	r := contracts.ValidReport()
	r.Matrix.Cells[0].Encodings[0].ValidTrials = 0
	expectInvalid(t, contracts.IDReport, r, "not a measurement")
}

// Criterion 15: the three residual-risk scenarios stay separate.
func TestReportRequiresThreeSeparateScenarios(t *testing.T) {
	r := contracts.ValidReport()
	r.ResidualRisk.Undeterminable.Statement = r.ResidualRisk.ConditionalRisk.Statement
	expectInvalid(t, contracts.IDReport, r, "must be distinct statements")

	r2 := contracts.ValidReport()
	r2.ResidualRisk.ConditionNotDemonstrated.Statement = ""
	expectInvalid(t, contracts.IDReport, r2, "condition_not_demonstrated")
}

// Criterion 14: the unevaluated section never disappears.
func TestReportAlwaysDeclaresUnevaluated(t *testing.T) {
	r := contracts.ValidReport()
	r.Unevaluated = nil
	expectInvalid(t, contracts.IDReport, r, "mandatory")

	r2 := contracts.ValidReport()
	r2.Unevaluated = nil
	r2.UnevaluatedNone = true
	mustValid(t, contracts.IDReport, r2)
}

// Criterion 23: distributions cannot fold inconclusive work into a rate.
func TestDistributionCannotMixInconclusiveIntoDenominator(t *testing.T) {
	r := contracts.ValidReport()
	r.Distributions[0].Denominator = 118
	expectInvalid(t, contracts.IDReport, r, "minus the excluded non-scoring work")

	r2 := contracts.ValidReport()
	r2.Distributions[0].InconclusiveBucket = ""
	r2.Distributions[0].Excluded = nil
	r2.Distributions[0].Denominator = 118
	expectInvalid(t, contracts.IDReport, r2, "non_scoring_bucket")

	r3 := contracts.ValidReport()
	r3.Distributions[0].Buckets = append(r3.Distributions[0].Buckets,
		contracts.Bucket{Name: "self_serving", Count: 0})
	expectInvalid(t, contracts.IDReport, r3, "is not a bucket of kind")
}

// Section 3.2 declared in code.
func TestReportMustDisclaimOutOfScopeClaims(t *testing.T) {
	for _, need := range contracts.RequiredOutOfScope {
		r := contracts.ValidReport()
		filtered := r.OutOfScope[:0]
		for _, s := range r.OutOfScope {
			if s != need {
				filtered = append(filtered, s)
			}
		}
		r.OutOfScope = filtered
		expectInvalid(t, contracts.IDReport, r, "must disclaim "+need)
	}
}

func TestReportCannotBeIssuedFromRunningState(t *testing.T) {
	r := contracts.ValidReport()
	r.RunState = contracts.StateExecuting
	expectInvalid(t, contracts.IDReport, r, "stopped run")
}

func TestManifestPinsEveryContractVersion(t *testing.T) {
	m := contracts.ValidManifestSkeleton()
	delete(m.ContractVersions, string(contracts.IDDiscoveryFinding))
	expectInvalid(t, contracts.IDIntegrityManifest, m, "pin the version of discovery_finding")
}

func TestManifestFilesMustBeSortedAndCounted(t *testing.T) {
	m := contracts.ValidManifestSkeleton()
	m.Files = append(m.Files, contracts.ManifestFileEntry{
		Path: "a-first.jsonl", Digest: contracts.NewDigest([]byte("x")),
		Bytes: 1, Lines: 1, Contract: contracts.IDRunProfile,
	})
	m.FileCount = len(m.Files)
	expectInvalid(t, contracts.IDIntegrityManifest, m, "sorted by path")
}

// Criterion 20 / 21: the forbidden vocabulary really is absent.
func TestForbiddenVocabularyAbsentFromContractKeys(t *testing.T) {
	forbidden := map[string]bool{}
	for _, f := range contracts.ForbiddenJSONKeyNames() {
		forbidden[f] = true
	}
	samples := []any{
		contracts.ValidRawObservation(), contracts.ValidClassification(),
		contracts.ValidAttribution(), contracts.ValidAttributionStatus(),
		contracts.ValidEvidenceProfile(), contracts.ValidHypothesis(),
		contracts.ValidFinding(), contracts.ValidReport(),
		contracts.ValidRunProfile(), contracts.ValidCorpusItem(),
	}
	for _, s := range samples {
		blob, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var node any
		if err := json.Unmarshal(blob, &node); err != nil {
			t.Fatal(err)
		}
		var hits []string
		for _, k := range contracts.InterpretiveKeysInJSON(node) {
			base := k
			if i := strings.LastIndex(k, "."); i >= 0 {
				base = k[i+1:]
			}
			if forbidden[base] {
				hits = append(hits, k)
			}
		}
		if len(hits) > 0 && !isRawObservation(s) {
			t.Fatalf("forbidden key in %T: %v", s, hits)
		}
		if len(hits) > 0 && isRawObservation(s) {
			t.Fatalf("interpretive key in raw observation: %v", hits)
		}
	}
}

func isRawObservation(v any) bool {
	_, ok := v.(*contracts.RawObservation)
	return ok
}

func TestUnknownContractIsRejected(t *testing.T) {
	if err := contracts.Validate("made_up_contract", &struct{}{}); err == nil {
		t.Fatal("unknown contract validated")
	}
}
