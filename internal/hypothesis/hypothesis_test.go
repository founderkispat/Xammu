package hypothesis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

var clock = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const basis = "valid sqli probes with a blocked canonical form in the query vector"

// trials builds a subject's counts. The defaults are the strongest rung, so each
// test lowers one condition to see the ladder stop where it should.
func trials() Trials {
	return Trials{
		Population: 18, Valid: 8, Inconclusive: 2, Invalid: 0, Replicas: 8,
		Rounds:               []string{"round-1", "round-2"},
		PositiveControlValid: true,
		NegativeControlValid: true,
		CorroborationSource:  "waf_log_entry:log-2026-10-28-0001",
		Hits:                 8,
		HitBasis:             basis,
		Refs:                 []string{"obs-1", "obs-2", "cls-1"},
	}
}

func subjectFor(t Trials) Subject {
	return Subject{
		RunID: "run-2026-10-28-lab", Ref: "cell:sqli|query|canonical|/api/search",
		Kind: "probe_cell", Trials: t, CompiledAt: clock,
	}
}

func profileAt(t *testing.T, t2 Trials) contracts.EvidenceProfile {
	t.Helper()
	p, err := Profile(subjectFor(t2))
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	return p
}

// associationTrials is the strongest subject HTTP evidence alone can build: the
// reading repeated, both controls valid, one authorized round and nothing outside the
// exchange. Its ceiling is association, which is what most of these tests check the
// derived claim type against.
func associationTrials() Trials {
	tr := trials()
	tr.Rounds = []string{"round-1"}
	tr.CorroborationSource = ""
	return tr
}

func claimFor(p contracts.EvidenceProfile) Claim {
	return Claim{
		RunID: p.RunID, Ref: "hyp.cell:sqli|query|canonical|/api/search",
		Statement:   "a layer inspects the query vector for SQLi-shaped payloads",
		AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical,
		Scope:    "https://lab.local:8443/api/search over sqli/query/canonical",
		Predictions: []string{
			"a canonical SQLi-shaped probe in query is rejected",
			"a benign reference on the same path is handled ordinarily",
		},
		Falsifier:           "a valid control pair where the probe and the reference produce the same signal",
		ReproductionCommand: "xammu report --run " + p.RunID + " --cell 'sqli|query|canonical|/api/search'",
		Profile:             p, AttributionRefs: []string{"att-1"},
	}
}

func TestLadderRungsCapTheClaim(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(Trials) Trials
		want    contracts.EvidenceLevel
		ceiling contracts.ClaimType
	}{
		{"no valid trial", func(t Trials) Trials {
			t.Valid, t.Hits, t.Replicas, t.Inconclusive, t.Invalid = 0, 0, 0, 9, 9
			t.Population = 18
			t.HitBasis = ""
			return t
		}, contracts.EvidenceNone, ""},
		{"one valid trial", func(t Trials) Trials {
			t.Valid, t.Hits, t.Replicas = 1, 1, 1
			return t
		}, contracts.EvidenceSingleObservation, contracts.ClaimDescriptive},
		{"repeated inside the run", func(t Trials) Trials {
			t.Valid, t.Hits, t.Replicas = 2, 2, 2
			t.PositiveControlValid, t.NegativeControlValid = false, false
			t.Rounds = nil
			t.CorroborationSource = ""
			return t
		}, contracts.EvidenceReplicated, contracts.ClaimAssociation},
		{"with a calibration pair", func(t Trials) Trials {
			t.CorroborationSource = ""
			t.Rounds = []string{"round-1"}
			return t
		}, contracts.EvidenceReplicatedWithControls, contracts.ClaimAssociation},
		{"across independent rounds", func(t Trials) Trials {
			t.CorroborationSource = ""
			return t
		}, contracts.EvidenceIndependentRounds, contracts.ClaimAttribution},
		{"corroborated outside HTTP", func(t Trials) Trials { return t },
			contracts.EvidenceCorrelatedIndependent, contracts.ClaimConfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := profileAt(t, tc.mutate(trials()))
			if p.Level != tc.want {
				t.Fatalf("want level %s, got %s", tc.want, p.Level)
			}
			if p.ClaimCeiling != tc.ceiling {
				t.Fatalf("want ceiling %q, got %q", tc.ceiling, p.ClaimCeiling)
			}
			if expected := contracts.MaxClaimType(p.Level); expected != p.ClaimCeiling {
				t.Fatalf("the ceiling is read off the ladder: expected %q, got %q", expected, p.ClaimCeiling)
			}
			if err := contracts.Validate(contracts.IDEvidenceProfile, &p); err != nil {
				t.Fatalf("C-08: %v", err)
			}
		})
	}
}

func TestLadderStopsAtTheFirstUnearnedRung(t *testing.T) {
	// Repetition is present, calibration is not: the level cannot name controls it
	// never saw, even though every lower rung holds.
	p := profileAt(t, func(t Trials) Trials {
		t.PositiveControlValid = false
		t.Rounds = nil
		t.CorroborationSource = ""
		return t
	}(trials()))
	if p.Level != contracts.EvidenceReplicated {
		t.Fatalf("want replicated_within_run, got %s", p.Level)
	}
	var named bool
	for _, m := range p.MissingEvidence {
		if strings.Contains(m, "positive control") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the profile must name the rung it stopped on: %v", p.MissingEvidence)
	}
}

func TestRoundsMustBeTwoDistinctRounds(t *testing.T) {
	// Repetition inside one authorized round is replication, not an independent round.
	p := profileAt(t, func(t Trials) Trials {
		t.Rounds = []string{"round-1", "round-1"}
		t.CorroborationSource = ""
		return t
	}(trials()))
	if p.Level == contracts.EvidenceIndependentRounds {
		t.Fatal("one round listed twice must not reach the rounds level")
	}
	if len(p.Rounds) != 1 {
		t.Fatalf("round ids are deduplicated, got %v", p.Rounds)
	}
	if p.Level != contracts.EvidenceReplicatedWithControls {
		t.Fatalf("want the controls level, got %s", p.Level)
	}
}

func TestDenominatorIsValidTrialsOnly(t *testing.T) {
	p := profileAt(t, trials())
	if p.Measured.Denominator != p.ValidTrials {
		t.Fatalf("criterion 23: denominator %d must equal valid_trials %d",
			p.Measured.Denominator, p.ValidTrials)
	}
	if p.Measured.ExcludedInconclusive != 2 || p.Measured.Numerator != 8 {
		t.Fatalf("the exclusions must be stated next to the rate: %+v", p.Measured)
	}
	if p.Measured.Basis != basis {
		t.Fatalf("basis %q", p.Measured.Basis)
	}
	// A rate that measured nothing says so instead of reading as zero.
	empty := profileAt(t, func(t Trials) Trials {
		t.Valid, t.Hits, t.Replicas, t.HitBasis = 0, 0, 0, ""
		return t
	}(trials()))
	if !empty.Measured.IsEmpty() {
		t.Fatal("an empty denominator must stay empty, not become 0/0 = 0%")
	}
	if !strings.Contains(empty.Measured.Basis, "not zero") {
		t.Fatalf("the basis must warn against reading it as zero: %q", empty.Measured.Basis)
	}
}

func TestLevelNoneProfileIsValidAndSaysSo(t *testing.T) {
	tr := trials()
	tr.Valid, tr.Hits, tr.Replicas, tr.Inconclusive, tr.Invalid, tr.Population = 0, 0, 0, 6, 6, 12
	tr.HitBasis = ""
	p := profileAt(t, tr)
	if p.ClaimCeiling != "" {
		t.Fatalf("a subject with no valid trial caps no claim, it has none: %q", p.ClaimCeiling)
	}
	if len(p.MissingEvidence) == 0 {
		t.Fatal("C-08 requires an empty profile to say what is missing")
	}
	if !strings.Contains(p.CeilingJustification, "supports no claim") {
		t.Fatalf("justification %q", p.CeilingJustification)
	}
	// Its refs still resolve, because the finding that reports this zone cites them.
	if len(p.Refs) == 0 {
		t.Fatal("the coverage record still needs its evidence references")
	}
}

func TestImpossibleCountsAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Trials) Trials
	}{
		{"trials beyond the population", func(t Trials) Trials { t.Valid = 20; t.Hits = 20; return t }},
		{"more hits than valid trials", func(t Trials) Trials { t.Hits = 9; return t }},
		{"more replicas than valid trials", func(t Trials) Trials { t.Replicas = 9; return t }},
		{"a negative count", func(t Trials) Trials { t.Invalid = -1; return t }},
		{"a rate with no definition", func(t Trials) Trials { t.HitBasis = ""; return t }},
	}
	for _, tc := range cases {
		tr := tc.mutate(trials())
		if _, err := Profile(subjectFor(tr)); err == nil {
			t.Errorf("%s: Profile accepted counts that cannot describe one population", tc.name)
			continue
		}
		// The same counts, if they reached a report, are caught by the contract too.
		if tr.Valid+tr.Inconclusive+tr.Invalid > tr.Population || tr.Hits > tr.Valid {
			p := contracts.ValidEvidenceProfile()
			p.Population, p.ValidTrials = tr.Population, tr.Valid
			p.Inconclusive, p.InvalidTrials = tr.Inconclusive, tr.Invalid
			p.Replicas, p.Measured.Numerator = tr.Replicas, tr.Hits
			if err := contracts.Validate(contracts.IDEvidenceProfile, p); err == nil {
				t.Errorf("%s: C-08 accepted it as well", tc.name)
			}
		}
	}
}

func TestProfileNeedsItsOwnMetadata(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Subject)
	}{
		{"run id", func(s *Subject) { s.RunID = "" }},
		{"subject ref", func(s *Subject) { s.Ref = "" }},
		{"subject kind", func(s *Subject) { s.Kind = "  " }},
		{"compiled_at", func(s *Subject) { s.CompiledAt = time.Time{} }},
	}
	for _, tc := range cases {
		s := subjectFor(trials())
		tc.mutate(&s)
		if _, err := Profile(s); err == nil {
			t.Errorf("a profile without %s cannot be cited or graded", tc.name)
		}
	}
}

func TestChosenCeilingIsRejected(t *testing.T) {
	// A producer that hand-writes a ceiling above its level is refused by the
	// contract, which is what makes the ceiling derived rather than requested.
	tr := trials()
	tr.Rounds, tr.CorroborationSource = []string{"round-1"}, ""
	tr.PositiveControlValid, tr.NegativeControlValid = false, false
	tr.Valid, tr.Hits, tr.Replicas = 1, 1, 1
	p := profileAt(t, tr)
	if p.Level != contracts.EvidenceSingleObservation {
		t.Fatalf("setup: level %s", p.Level)
	}
	for _, over := range []contracts.ClaimType{contracts.ClaimAssociation, contracts.ClaimAttribution,
		contracts.ClaimConfirmed} {
		mutated := p
		mutated.ClaimCeiling = over
		if err := contracts.Validate(contracts.IDEvidenceProfile, &mutated); err == nil {
			t.Errorf("level single_observation accepted the %q ceiling", over)
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), string(contracts.MaxClaimType(p.Level))) {
		t.Fatal("the journalled profile must carry the ceiling its level implies")
	}
}

func TestSupportedOutcomeNeedsEveryPredictionTested(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = []Check{
		{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[1], Result: MetResult, EvidenceRef: "obs-2"},
	}
	h, err := Derive(c)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if h.Outcome != contracts.HypothesisSupported {
		t.Fatalf("want supported, got %s", h.Outcome)
	}
	if h.ClaimType != contracts.ClaimAssociation {
		t.Fatalf("the controls level caps the claim at association, got %s", h.ClaimType)
	}
	if h.InconclusiveReason != "" {
		t.Fatal("a supported hypothesis carries no inconclusive reason")
	}
	if len(h.Checks) != 2 || h.Checks[0].CheckID != "chk.1" {
		t.Fatalf("checks %v", h.Checks)
	}
	if h.EvidenceProfileRef != p.ProfileID {
		t.Fatal("the hypothesis must cite the profile that caps it")
	}
	if !h.FormedAt.Equal(p.CompiledAt) {
		t.Fatal("a hypothesis is dated by the evidence it was formed from")
	}
}

func TestUnmetPredictionRefutes(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = []Check{
		{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[1], Result: UnmetResult, EvidenceRef: "cls-1"},
	}
	h, err := Derive(c)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if h.Outcome != contracts.HypothesisRefuted {
		t.Fatalf("want refuted, got %s", h.Outcome)
	}
	if !strings.Contains(h.OutcomeReason, c.Predictions[1]) ||
		!strings.Contains(h.OutcomeReason, c.Ref) {
		t.Fatalf("the refutation must name the prediction and the stated falsifier: %q", h.OutcomeReason)
	}
}

func TestUnevaluablePredictionIsInconclusiveWithATypedReason(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = []Check{
		{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[1], Result: UnevaluableResult, EvidenceRef: p.ProfileID},
	}
	c.Obstacles = []Obstacle{{
		Reason: contracts.ReasonRateLimited,
		Detail: "the run halted on a 429 before the reference probes",
	}}
	h, err := Derive(c)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if h.Outcome != contracts.HypothesisInconclusive {
		t.Fatalf("want inconclusive, got %s", h.Outcome)
	}
	if h.InconclusiveReason != contracts.ReasonRateLimited {
		t.Fatalf("reason %s", h.InconclusiveReason)
	}
	if !strings.Contains(h.OutcomeReason, "429") {
		t.Fatalf("the reason must carry the operator's obstacle detail: %q", h.OutcomeReason)
	}
}

func TestInconclusiveWithoutAnObstacleIsRefused(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = []Check{{Prediction: c.Predictions[0], Result: UnevaluableResult, EvidenceRef: "obs-1"}}
	_, err := Derive(c)
	if err == nil {
		t.Fatal("an inconclusive outcome with no reason is the shape of an excuse")
	}
	if !strings.Contains(err.Error(), "without a reason") {
		t.Fatalf("error %q should ask for the obstacle", err)
	}

	c.Obstacles = []Obstacle{{Reason: contracts.ReasonCode("we_did_not_get_to_it")}}
	if _, err := Derive(c); err == nil {
		t.Fatal("a reason code outside the contract's vocabulary must be refused")
	}
}

func TestNoHypothesisOverAnEmptySubject(t *testing.T) {
	tr := trials()
	tr.Valid, tr.Hits, tr.Replicas, tr.Inconclusive, tr.Invalid, tr.Population = 0, 0, 0, 4, 4, 8
	tr.HitBasis = ""
	p := profileAt(t, tr)
	c := claimFor(p)
	c.Checks = []Check{{Prediction: c.Predictions[0], Result: UnevaluableResult, EvidenceRef: p.ProfileID}}
	c.Obstacles = []Obstacle{{Reason: contracts.ReasonInconclusiveSignal, Detail: "no valid trial"}}
	_, err := Derive(c)
	if err == nil {
		t.Fatal("there is nothing to hypothesize over a subject with no valid trial")
	}
	if !strings.Contains(err.Error(), "undetermined-area") {
		t.Fatalf("the error must point at the record that does carry an unevaluated zone: %v", err)
	}
}

func TestHypothesisCannotCertifyItsOwnConfirmation(t *testing.T) {
	p := profileAt(t, trials()) // correlated independent evidence
	if p.ClaimCeiling != contracts.ClaimConfirmed {
		t.Fatalf("setup: ceiling %q", p.ClaimCeiling)
	}
	c := claimFor(p)
	c.Checks = []Check{
		{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[1], Result: MetResult, EvidenceRef: "obs-2"},
	}
	h, err := Derive(c)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if h.ClaimType != contracts.ClaimAttribution {
		t.Fatalf("the strongest claim a hypothesis may carry is attribution, got %s", h.ClaimType)
	}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), string(contracts.ClaimConfirmed)) {
		t.Fatalf("C-07 bytes carry a confirmation: %s", raw)
	}
	for _, o := range contracts.AllHypothesisOutcomes() {
		if o == contracts.HypothesisOutcome("confirmed") {
			t.Fatal("the outcome vocabulary must not offer a confirmation state")
		}
	}
}

func TestCheckMustCiteEvidenceTheProfileHolds(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = []Check{{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "obs-not-in-this-run"}}
	_, err := Derive(c)
	if err == nil {
		t.Fatal("a check against invented evidence is how a conclusion is laundered")
	}
	if !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("error %q must say the citation does not resolve", err)
	}
}

func TestCheckWithoutAResultOrPredictionIsRefused(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	for _, chk := range []Check{
		{Prediction: "", Result: MetResult, EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[0], Result: "probably", EvidenceRef: "obs-1"},
		{Prediction: c.Predictions[0], Result: MetResult, EvidenceRef: "  "},
	} {
		single := c
		single.Checks = []Check{chk}
		if _, err := Derive(single); err == nil {
			t.Errorf("check %+v accepted", chk)
		}
	}
}

func TestClaimGuards(t *testing.T) {
	p := profileAt(t, associationTrials())
	base := claimFor(p)
	base.Checks = []Check{{Prediction: base.Predictions[0], Result: MetResult, EvidenceRef: "obs-1"}}
	cases := []struct {
		name   string
		mutate func(*Claim)
	}{
		{"no run", func(c *Claim) { c.RunID = "" }},
		{"no reference", func(c *Claim) { c.Ref = "" }},
		{"no statement", func(c *Claim) { c.Statement = " " }},
		{"no prediction", func(c *Claim) { c.Predictions = nil }},
		{"no falsifier", func(c *Claim) { c.Falsifier = "" }},
		{"no scope", func(c *Claim) { c.Scope = "" }},
		{"unreproducible", func(c *Claim) { c.ReproductionCommand = "" }},
		{"profile from another run", func(c *Claim) { c.Profile.RunID = "run-somebody-elses" }},
	}
	for _, tc := range cases {
		c := base
		c.Profile = p
		tc.mutate(&c)
		if _, err := Derive(c); err == nil {
			t.Errorf("%s: Derive accepted a claim nobody could test or trace", tc.name)
		}
	}
}

func TestSupportedWithoutAnyCheckIsRefused(t *testing.T) {
	p := profileAt(t, associationTrials())
	c := claimFor(p)
	c.Checks = nil
	h, err := Derive(c)
	if err != nil {
		// No checks means nothing was tested; that is inconclusive, and an
		// unexplained inconclusive is refused. Either outcome is honest, but a
		// supported verdict with no checks is not an option.
		if h.Outcome == contracts.HypothesisSupported {
			t.Fatal("a supported hypothesis with no checks")
		}
		return
	}
	if h.Outcome == contracts.HypothesisSupported {
		t.Fatal("an untested statement is not supported")
	}
	if err := contracts.Validate(contracts.IDHypothesis, &h); err != nil {
		t.Fatalf("C-07: %v", err)
	}
}
