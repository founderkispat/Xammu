package discover_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/discover"
	"xammu/internal/hypothesis"
	"xammu/internal/inference"
)

var stamp = time.Date(2026, time.October, 28, 12, 0, 0, 0, time.UTC)

const (
	testRun   = "run-2026-10-28-lab"
	testRound = "round-1"
	// testAuth is the reference of the C-09 the run was executed under. A finding's
	// reproduction command has to name it, because a reader holds the permission by its
	// reference and not by whatever file the operator pointed at.
	testAuth = "auth-2026-1028-lab"
	testPath = "/api/search"
	origin   = "http://waf:8080"
)

// ---------------------------------------------------------------- fixtures

type spec struct {
	ref       string
	group     string
	class     contracts.AttackClass
	vector    contracts.Vector
	encoding  contracts.Encoding
	canonical string
	probe     string
	purpose   contracts.Purpose
	expect    contracts.ExpectedBehavior
	anchors   []string
	partition contracts.PartitionName
}

func (s spec) item() contracts.CorpusItem {
	if s.canonical == "" {
		s.canonical = "' or 1=1 xammu-probe"
	}
	if s.probe == "" {
		s.probe = s.canonical
	}
	if s.purpose == "" {
		s.purpose = contracts.PurposeDiagnosis
	}
	if s.encoding == "" {
		s.encoding = contracts.EncodingCanonical
	}
	if s.expect == "" {
		s.expect = contracts.ExpectBlock
	}
	if s.partition == "" {
		s.partition = contracts.PartitionDevelopment
	}
	if len(s.anchors) == 0 {
		s.anchors = []string{"lab-rule-table:GENERIC-001"}
	}
	var ev []contracts.CorpusValidationEvidence
	for _, a := range s.anchors {
		ev = append(ev, contracts.CorpusValidationEvidence{
			RunRef: a, ObservedAt: stamp, Result: "declared_by_fixture_rule_table",
			LabImageDigest: "sha256:aa", MatchesExpectation: true,
		})
	}
	return contracts.CorpusItem{
		ItemID: contracts.NewUUID(), Ref: s.ref, GroupID: s.group, Partition: s.partition,
		AttackClass: s.class, Vector: s.vector, Encoding: s.encoding,
		Canonical: s.canonical, Probe: s.probe, ProbeDigest: contracts.NewDigest([]byte(s.probe)),
		Purpose: s.purpose, ExpectedBehavior: s.expect,
		Provenance:    contracts.Provenance{Source: "test", Author: "test", ReviewRef: "T-1", RetrievedAt: stamp},
		Inertness:     contracts.InertnessRecord{Verdict: contracts.InertVerified, CheckedAt: stamp, Notes: "test"},
		Validation:    ev,
		AuthoringNote: "written for the discovery tests",
	}
}

func corpusSet(t *testing.T, items ...contracts.CorpusItem) *corpus.Set {
	t.Helper()
	byName := map[contracts.PartitionName][]contracts.CorpusItem{}
	for _, i := range items {
		byName[i.Partition] = append(byName[i.Partition], i)
	}
	out := &corpus.Set{Root: "fixture", Partitions: map[contracts.PartitionName]*corpus.Partition{},
		Gate: corpus.DefaultPolicy()}
	for _, name := range contracts.AllPartitionNames() {
		set := byName[name]
		if len(set) == 0 {
			continue
		}
		out.Partitions[name] = &corpus.Partition{Name: name, Dir: corpus.PartitionDir[name], Items: set,
			Groups: map[string][]string{}, SourceOf: map[string]string{}}
		for _, i := range set {
			out.Partitions[name].Groups[i.GroupID] = append(out.Partitions[name].Groups[i.GroupID], i.Ref)
			out.Partitions[name].SourceOf[i.ItemID] = "fixture:0"
		}
	}
	return out
}

type trial struct {
	ref    string
	signal contracts.Signal
	valid  bool
	id     string
}

func obs(n int) string { return "obs-" + strconv.Itoa(n) }

// cellSpec is one verdict's worth of measured facts. The evidence level is never
// part of it: hypothesis.Profile derives it from the counts, so a fixture cannot
// hand the discover layer a level its own trials did not earn.
type cellSpec struct {
	key    inference.CellKey
	trials []trial

	// positiveValid and negativeValid restate the run's calibration outcome for the
	// cell: the rung above replication is earned by controls, and a fixture that
	// claims them must also send them in result().
	positiveValid bool
	negativeValid bool
	rounds        []string

	attribution contracts.AttributionStatus
	skip        string
	obstacles   []hypothesis.Obstacle

	// hypothesisRef is the C-07 record the pass formed over this cell. A finding that
	// has one must cite it rather than state the mechanism itself.
	hypothesisRef string
}

func cell(t *testing.T, cs cellSpec) inference.Verdict {
	t.Helper()
	if len(cs.trials) == 0 {
		t.Fatal("a cell fixture with no trial measures nothing; give it at least one")
	}
	var trials []inference.Trial
	signals := map[contracts.Signal]int{}
	refused := 0
	for i, tr := range cs.trials {
		id := tr.id
		if id == "" {
			id = obs(i + 1)
		}
		signals[tr.signal]++
		if tr.valid && tr.signal == contracts.SignalBlock {
			refused++
		}
		trials = append(trials, inference.Trial{
			RunID: testRun, RoundID: testRound, ProbeRef: "probe-" + tr.ref, CorpusRef: tr.ref,
			ControlRole: contracts.RoleProbe, ObservationID: id, AnalysisID: "analysis-" + id,
			ClassificationID: "class-" + id, Signal: tr.signal, StatusCode: statusOf(tr.signal),
			Valid: tr.valid, At: stamp,
		})
	}
	c := inference.Cell{
		CellKey: cs.key, Origin: origin, Trials: trials, RunIDs: []string{testRun},
		RoundIDs: cs.rounds, Signals: signals,
	}
	for _, tr := range trials {
		switch {
		case tr.Valid:
			c.Valid++
		case tr.Signal == contracts.SignalIndeterminate:
			c.Inconclusive++
		default:
			c.Invalid++
		}
	}
	rounds := cs.rounds
	if len(rounds) == 0 {
		rounds = []string{testRound}
	}
	prof, err := hypothesis.Profile(hypothesis.Subject{
		RunID: testRun, Ref: cs.key.Ref(), Kind: "cell", CompiledAt: stamp,
		Trials: hypothesis.Trials{
			Population: len(trials), Valid: c.Valid, Inconclusive: c.Inconclusive, Invalid: c.Invalid,
			Replicas:             c.Replicas(),
			Rounds:               rounds,
			PositiveControlValid: cs.positiveValid,
			NegativeControlValid: cs.negativeValid,
			Hits:                 refused,
			HitBasis:             "valid trials of this cell the classifier recorded as a refusal",
			Refs:                 observationIDs(trials),
		},
	})
	if err != nil {
		t.Fatalf("fixture cell %s is not a gradeable subject: %v", cs.key, err)
	}
	v := inference.Verdict{Cell: c, Profile: prof, Skip: cs.skip, Obstacles: cs.obstacles}
	if cs.hypothesisRef != "" {
		v.Hypothesis = &contracts.Hypothesis{HypothesisID: contracts.NewUUID(), Ref: cs.hypothesisRef,
			RunID: testRun, FormedAt: stamp}
	}
	if cs.attribution != "" {
		v.Attribution = &contracts.Attribution{
			AttributionID: contracts.NewUUID(), RunID: testRun, SubjectID: cs.key.Ref(),
			SubjectContract: contracts.IDBehavioralClassification, AttributedAt: stamp,
			Primary: contracts.AltWAF, Status: cs.attribution,
			EvidenceBasis: contracts.BasisHTTPControl,
		}
	}
	return v
}

func observationIDs(trials []inference.Trial) []string {
	out := make([]string, 0, len(trials))
	for _, tr := range trials {
		out = append(out, tr.ObservationID)
	}
	return out
}

func statusOf(s contracts.Signal) int {
	switch s {
	case contracts.SignalBlock:
		return 403
	case contracts.SignalRateLimited:
		return 429
	case contracts.SignalTransportError:
		return 0
	default:
		return 200
	}
}

func input(pass *inference.Result, set *corpus.Set) discover.Input {
	return discover.Input{
		RunID: testRun, RoundID: testRound, Pass: pass, Corpus: set,
		Partition:         contracts.PartitionDevelopment,
		AuthorizationRef:  testAuth,
		AuthorizedClasses: contracts.AllAttackClasses(),
		AuthorizedVectors: contracts.AllVectors(),
		GeneratedAt:       stamp,
	}
}

// result builds the pass with the calibration pair the fixtures claim: a valid
// positive control refused and a valid benign exchange handled ordinarily. A test
// that needs different controls replaces them before calling Analyze.
func result(verdicts ...inference.Verdict) *inference.Result {
	return &inference.Result{RunID: testRun, RoundID: testRound, Verdicts: verdicts,
		Controls: inference.Controls{
			Positive: []inference.Trial{{RunID: testRun, RoundID: testRound, ProbeRef: "probe-pos",
				CorpusRef: "CAL-POS", ControlRole: contracts.RolePositiveControl,
				ObservationID: "obs-positive", AnalysisID: "a-pos", ClassificationID: "c-pos",
				Signal: contracts.SignalBlock, StatusCode: 403, Valid: true, At: stamp}},
			Negative: []inference.Trial{{RunID: testRun, RoundID: testRound, ProbeRef: "probe-neg",
				CorpusRef: "CAL-NEG", ControlRole: contracts.RoleBenignReference,
				ObservationID: "obs-negative", AnalysisID: "a-neg", ClassificationID: "c-neg",
				Signal: contracts.SignalPass, StatusCode: 200, Valid: true, At: stamp}},
		}}
}

func calibItem(ref string, purpose contracts.Purpose, expect contracts.ExpectedBehavior) contracts.CorpusItem {
	return spec{ref: ref, group: "G-CAL", class: contracts.ClassSQLi, vector: contracts.VectorQuery,
		purpose: purpose, expect: expect, anchors: []string{"lab-rule-table:SQLI-001"},
		partition: contracts.PartitionCalibration}.item()
}

func requireFinding(t *testing.T, rep *discover.Report, ty contracts.FindingType, want string) contracts.DiscoveryFinding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.FindingType == ty && strings.Contains(f.Ref, want) {
			return f
		}
	}
	var got []string
	for _, f := range rep.Findings {
		got = append(got, string(f.FindingType)+" "+f.Ref)
	}
	t.Fatalf("no %s finding matching %q; published: %s", ty, want, strings.Join(got, ", "))
	return contracts.DiscoveryFinding{}
}

// everyFindingIsValid is the assertion this package exists for: nothing that reaches
// a Report may be unpublishable, and nothing may reproduce outside the authorization.
func everyFindingIsValid(t *testing.T, rep *discover.Report) {
	t.Helper()
	if len(rep.Findings) == 0 {
		t.Fatal("the pass published nothing, so this test proves only that no finding was checked")
	}
	for _, f := range rep.Findings {
		if err := contracts.Validate(contracts.IDDiscoveryFinding, f); err != nil {
			t.Errorf("finding %s was published although C-16 refuses it: %v", f.Ref, err)
		}
		if !strings.HasPrefix(f.ReproductionCommand, "xammu ") {
			t.Errorf("finding %s reproduces with %q: not a xammu command", f.Ref, f.ReproductionCommand)
		}
		if !strings.Contains(f.ReproductionCommand, "--authorization") ||
			!strings.Contains(f.ReproductionCommand, testAuth) {
			t.Errorf("finding %s reproduces unbound: %s", f.Ref, f.ReproductionCommand)
		}
		if strings.TrimSpace(f.RegressionTest) == "" {
			t.Errorf("finding %s has no regression test, so nobody can re-check it after a change", f.Ref)
		}
		if strings.TrimSpace(f.PriorityBasis) == "" {
			t.Errorf("finding %s states priority %q without the measurement it came from", f.Ref, f.Priority)
		}
	}
}

func hasAlternative(f contracts.DiscoveryFinding, kind contracts.AlternativeKind,
	state contracts.AlternativeState) bool {
	for _, a := range f.Alternatives {
		if a.Kind == kind && a.State == state {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------- guards

func TestAnalyzeRefusesInputsThatCannotGroundAFinding(t *testing.T) {
	set := corpusSet(t, calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		spec{ref: "DEV-SQLI-Q-01", group: "G-T", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())

	// An empty pass cannot produce a finding set: there is no reading to compare.
	_, err := discover.Analyze(input(&inference.Result{RunID: testRun, RoundID: testRound}, set))
	if err == nil || !strings.Contains(err.Error(), "no probe trial") {
		t.Errorf("an empty pass must be refused rather than reported, got %v", err)
	}

	in := input(result(), set)
	in.AuthorizationRef = ""
	if _, err := discover.Analyze(in); err == nil ||
		!strings.Contains(err.Error(), "bound to an authorization") {
		t.Errorf("a missing authorization must be refused: %v", err)
	}

	// A trial citing a corpus ref the tree does not contain has no expectation, so it
	// cannot enter a measurement: the alternative is a finding whose expectation is
	// invented from the probe's name.
	orphan := cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials: []trial{{ref: "NOT-IN-CORPUS", signal: contracts.SignalPass, valid: true}},
	})
	_, err = discover.Analyze(input(result(orphan), set))
	if err == nil || !strings.Contains(err.Error(), "which is not in") {
		t.Fatalf("a probe with no corpus expectation must refuse the analysis, got %v", err)
	}
	if !strings.Contains(err.Error(), "cannot be reported against that corpus") {
		t.Errorf("the refusal must say why: %v", err)
	}

	// One ref resolving in two partitions is the leak the overlap detector exists to
	// find. The reading is not ambiguous in prose only: a probe refused in one
	// partition and expected to pass in another has no single expectation to compare.
	leaked := corpusSet(t,
		calibItem("DEV-SQLI-Q-01", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-Q-01", group: "G-T", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())
	both := cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials:        []trial{{ref: "DEV-SQLI-Q-01", signal: contracts.SignalPass, valid: true}},
		positiveValid: true, negativeValid: true,
	})
	if _, err := discover.Analyze(input(result(both), leaked)); err == nil ||
		!strings.Contains(err.Error(), "the expectation is ambiguous") {
		t.Errorf("a ref that resolves in two partitions must refuse the analysis, got %v", err)
	}
}

// -------------------------------------------------------------- coverage gaps

func TestCoverageGapIsPublishedWithItsDenominator(t *testing.T) {
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorBodyJSON,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-J-01", group: "G-SQLI-J", class: contracts.ClassSQLi,
			vector: contracts.VectorBodyJSON, anchors: []string{"lab-rule-table:coverage:json_body_uninspected"}}.item())

	// Six valid trials that were all handled ordinarily, plus one inconclusive that
	// has to be named outside the denominator rather than dropped from it.
	passes := make([]trial, 0, 7)
	for i := 0; i < 6; i++ {
		passes = append(passes, trial{ref: "DEV-SQLI-J-01", signal: contracts.SignalPass, valid: true})
	}
	passes = append(passes, trial{ref: "DEV-SQLI-J-01", signal: contracts.SignalIndeterminate})
	v := cell(t, cellSpec{key: key, trials: passes, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible, hypothesisRef: key.Ref()})

	rep, err := discover.Analyze(input(result(v), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingCoverageGap, "GAP-sqli-body_json")

	if f.MeasuredImpact.Denominator != 6 || f.MeasuredImpact.Numerator != 0 {
		t.Errorf("measured impact must be 0 of 6 refused over the valid trials, got %d of %d",
			f.MeasuredImpact.Numerator, f.MeasuredImpact.Denominator)
	}
	if f.MeasuredImpact.ExcludedInconclusive != 1 {
		t.Errorf("the inconclusive trial must be named, not dropped: %+v", f.MeasuredImpact)
	}
	if f.MeasuredImpact.Basis == "" {
		t.Error("a coverage finding must state what its denominator counts")
	}
	if !strings.Contains(f.WhatWasObserved, "coverage:json_body_uninspected") {
		t.Errorf("the finding must cite the declared evidence it contradicts: %s", f.WhatWasObserved)
	}
	if f.Priority != contracts.PriorityHigh {
		t.Errorf("0 of 6 valid probes refused where refusal is expected is the whole difference; got %s "+
			"because the trial count gates it: %s", f.Priority, f.PriorityBasis)
	}
	if f.ClaimType != contracts.ClaimAssociation || f.EvidenceLevel != contracts.EvidenceReplicatedWithControls {
		t.Errorf("claim %s at level %s: association is the ceiling for this layer, and only with a "+
			"graded control pair", f.ClaimType, f.EvidenceLevel)
	}
	if len(f.Alternatives) < 4 {
		t.Errorf("only %d alternatives evaluated", len(f.Alternatives))
	}
	if !hasAlternative(f, contracts.AltInputNormalization, contracts.AltNotRuledOut) {
		t.Errorf("a coverage gap has to keep origin-side normalisation open: %+v", f.Alternatives)
	}
	if f.HypothesisRef != key.Ref() {
		t.Errorf("the finding must cite the C-07 record formed over its own cell (%q), got %q: naming the "+
			"mechanism is that record's job, so a finding points at it instead of outranking it",
			key.Ref(), f.HypothesisRef)
	}
}

func TestCoverageGapNeedsTheControlsItClaims(t *testing.T) {
	// Without a graded control pair the same measurement cannot say "association":
	// the reading has nothing to be contrasted against, and C-16 caps the claim.
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorBodyJSON,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-J-01", group: "G-SQLI-J", class: contracts.ClassSQLi,
			vector: contracts.VectorBodyJSON}.item())
	v := cell(t, cellSpec{key: key, positiveValid: true, negativeValid: false,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SQLI-J-01", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-SQLI-J-01", signal: contracts.SignalPass, valid: true},
		}})

	// The pass has to agree with the profile it carries: the negative control was
	// sent, but it arrived rate limited, so the cell is graded without one.
	pass := result(v)
	pass.Controls.Negative = []inference.Trial{{RunID: testRun, RoundID: testRound,
		ProbeRef: "probe-neg", CorpusRef: "CAL-NEG", ControlRole: contracts.RoleNegativeControl,
		ObservationID: "obs-negative", AnalysisID: "a-neg", ClassificationID: "c-neg",
		Signal: contracts.SignalRateLimited, StatusCode: 429, Valid: false, At: stamp}}

	rep, err := discover.Analyze(input(pass, set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingCoverageGap, "GAP-sqli-body_json")
	if f.ClaimType != contracts.ClaimDescriptive {
		t.Errorf("an uncalibrated cell claimed %s: the ladder says %s caps at %q", f.ClaimType,
			f.EvidenceLevel, contracts.MaxClaimType(f.EvidenceLevel))
	}
	if f.Priority != contracts.PriorityLow {
		t.Errorf("two valid trials cannot rank above low, got %s: %s", f.Priority, f.PriorityBasis)
	}
}

func TestCoverageGapIsNotPublishedFromAPartialContradiction(t *testing.T) {
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-Q-01", group: "G-T", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())
	v := cell(t, cellSpec{key: key, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalPass, valid: true},
		}})

	rep, err := discover.Analyze(input(result(v), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	for _, f := range rep.Findings {
		if f.FindingType == contracts.FindingCoverageGap {
			t.Errorf("a cell whose majority reading matches the expectation was published as a gap: %+v", f)
		}
	}
}

// ---------------------------------------------------------------- asymmetries

func TestVectorAsymmetryComparesOnePayloadAcrossTransports(t *testing.T) {
	queryKey := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	bodyKey := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorBodyJSON,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SENTINEL-Q", group: "G-SENTINEL", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery, expect: contracts.ExpectBlock,
			anchors: []string{"lab-rule-table:GENERIC-001"}, probe: "xammu-probe-token",
			canonical: "xammu-probe-token"}.item(),
		spec{ref: "DEV-SENTINEL-J", group: "G-SENTINEL", class: contracts.ClassSQLi,
			vector: contracts.VectorBodyJSON, expect: contracts.ExpectPass,
			anchors: []string{"lab-rule-table:coverage:json_body_uninspected"}, probe: "xammu-probe-token",
			canonical: "xammu-probe-token"}.item())

	q := cell(t, cellSpec{key: queryKey, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SENTINEL-Q", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SENTINEL-Q", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SENTINEL-Q", signal: contracts.SignalBlock, valid: true},
		}})
	b := cell(t, cellSpec{key: bodyKey, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SENTINEL-J", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-SENTINEL-J", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-SENTINEL-J", signal: contracts.SignalPass, valid: true},
		}})

	rep, err := discover.Analyze(input(result(q, b), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingVectorAsymmetry, "G-SENTINEL")

	if f.Vector != contracts.VectorBodyJSON {
		t.Errorf("an asymmetry finding is scoped to the transport that was not refused, got %s", f.Vector)
	}
	for _, want := range []string{"query", "body_json", "3/3", "0/3", "xammu-probe-token"} {
		if !strings.Contains(f.WhatWasObserved, want) {
			t.Errorf("the comparison must state %q; got %s", want, f.WhatWasObserved)
		}
	}
	if f.MeasuredImpact.Denominator != 6 {
		t.Errorf("the denominator must be both transports in the comparison, got %d",
			f.MeasuredImpact.Denominator)
	}
	// The payload is identical, so the difference cannot be about content: the routing
	// alternative has to stay open, and the explanation that rests on the payload does
	// not apply at all.
	if !hasAlternative(f, contracts.AltRoutingDivergence, contracts.AltNotRuledOut) {
		t.Errorf("a transport comparison must leave routing divergence open: %+v", f.Alternatives)
	}
	if hasAlternative(f, contracts.AltInputNormalization, contracts.AltNotRuledOut) {
		t.Error("normalisation of the payload is not a competing explanation when the payload never " +
			"changed: it must not be listed as open")
	}
	if !hasAlternative(f, contracts.AltOriginApplication, contracts.AltRuledOut) {
		t.Errorf("the calibration pair on the same route rules the origin out and must say so: %+v",
			f.Alternatives)
	}
	if f.ClaimType != contracts.ClaimAssociation {
		t.Errorf("a measured comparison across transports is an association, got %s", f.ClaimType)
	}
}

func TestEncodingBypassRequiresARefusedCanonicalForm(t *testing.T) {
	canonKey := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	dblKey := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingURLDouble, Path: testPath}
	tautology := "' or 1=1 xammu-probe"
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-TAUTO-01", group: "G-TAUTO", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery, canonical: tautology,
			anchors: []string{"lab-rule-table:SQLI-003"}}.item(),
		spec{ref: "DEV-TAUTO-03", group: "G-TAUTO", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery, encoding: contracts.EncodingURLDouble,
			probe: "%2527%2520or%25201%253d1%2520xammu-probe", canonical: tautology,
			purpose: contracts.PurposeEncodingReplica, expect: contracts.ExpectPass,
			anchors: []string{"lab-rule-table:SQLI-003"}}.item())

	c := cell(t, cellSpec{key: canonKey, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-TAUTO-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-TAUTO-01", signal: contracts.SignalBlock, valid: true},
		}})
	d := cell(t, cellSpec{key: dblKey, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-03", signal: contracts.SignalPass, valid: true},
		}})

	rep, err := discover.Analyze(input(result(c, d), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingEncodingBypass, "G-TAUTO")
	if !strings.Contains(f.WhatWasObserved, "url_double") {
		t.Errorf("the finding must name the encoding that walked past: %s", f.WhatWasObserved)
	}
	if !hasAlternative(f, contracts.AltInputNormalization, contracts.AltNotRuledOut) {
		t.Errorf("a decoding-depth difference must keep framework normalisation open: %+v", f.Alternatives)
	}
	if f.Priority != contracts.PriorityHigh {
		t.Errorf("a 100-point difference measured over 8 valid trials is the highest rank this layer "+
			"gives, got %s: %s", f.Priority, f.PriorityBasis)
	}
	if f.Encoding != contracts.EncodingURLDouble {
		t.Errorf("the finding is scoped to the encoding that walked past, got %s", f.Encoding)
	}

	// Without a refused canonical form there is nothing to walk past: the same
	// replicas become a coverage gap instead, because the family was never blocked.
	cNo := cell(t, cellSpec{key: canonKey, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-TAUTO-01", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-TAUTO-01", signal: contracts.SignalPass, valid: true},
		}})
	rep2, err := discover.Analyze(input(result(cNo, d), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep2)
	for _, f := range rep2.Findings {
		if f.FindingType == contracts.FindingEncodingBypass {
			t.Error("a bypass was published from a family that was never refused: the difference would " +
				"have no baseline")
		}
	}
	if len(rep2.Findings) == 0 {
		t.Error("a family handled ordinarily everywhere published nothing at all")
	}
}

// -------------------------------------------------------------- over-blocking

func TestOverBlockingIsMeasuredOverTheLegitimatePopulation(t *testing.T) {
	benign := spec{ref: "CAL-BEN-1", group: "G-CAL", class: contracts.ClassSQLi,
		vector: contracts.VectorQuery, purpose: contracts.PurposeBenignReference,
		expect: contracts.ExpectPass, canonical: "widget list page 2",
		probe:   "widget list page 2",
		anchors: []string{"lab-rule-table:coverage:benign_baseline"}, partition: contracts.PartitionCalibration}.item()
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		benign,
		spec{ref: "DEV-SQLI-Q-01", group: "G-T", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	v := cell(t, cellSpec{key: key, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalBlock, valid: true},
		}})

	pass := result(v)
	// The legitimate population is the corpus's own: negative controls and benign
	// references. One of the four is refused, one is rate limited and therefore out
	// of the denominator, and the remaining two show ordinary handling.
	pass.Controls.Negative = []inference.Trial{
		{RunID: testRun, RoundID: testRound, ProbeRef: "p1", CorpusRef: "CAL-BEN-1",
			ControlRole: contracts.RoleBenignReference, ObservationID: "obs-b1", AnalysisID: "a1",
			ClassificationID: "c1", Signal: contracts.SignalBlock, StatusCode: 403, Valid: true, At: stamp},
		{RunID: testRun, RoundID: testRound, ProbeRef: "p2", CorpusRef: "CAL-BEN-1",
			ControlRole: contracts.RoleBenignReference, ObservationID: "obs-b2", AnalysisID: "a2",
			ClassificationID: "c2", Signal: contracts.SignalPass, StatusCode: 200, Valid: true, At: stamp},
		{RunID: testRun, RoundID: testRound, ProbeRef: "p3", CorpusRef: "CAL-BEN-1",
			ControlRole: contracts.RoleNegativeControl, ObservationID: "obs-b3", AnalysisID: "a3",
			ClassificationID: "c3", Signal: contracts.SignalPass, StatusCode: 200, Valid: true, At: stamp},
		{RunID: testRun, RoundID: testRound, ProbeRef: "p4", CorpusRef: "CAL-BEN-1",
			ControlRole: contracts.RoleBenignReference, ObservationID: "obs-b4", AnalysisID: "a4",
			ClassificationID: "c4", Signal: contracts.SignalRateLimited, StatusCode: 429, Valid: false,
			At: stamp},
	}
	rep, err := discover.Analyze(input(pass, set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingOverBlocking, "OVB-")
	if f.MeasuredImpact.Numerator != 1 || f.MeasuredImpact.Denominator != 3 {
		t.Errorf("one refused legitimate exchange out of three valid ones, got %d of %d",
			f.MeasuredImpact.Numerator, f.MeasuredImpact.Denominator)
	}
	if f.MeasuredImpact.ExcludedInvalid != 1 {
		t.Errorf("the 429 must be excluded and named, not counted as a refusal: %+v", f.MeasuredImpact)
	}
	if !strings.Contains(f.WhatWasObserved, "widget list page 2") {
		t.Errorf("an over-block finding must name the legitimate shape refused: %s", f.WhatWasObserved)
	}
	if !strings.Contains(f.Limitations[0], "corpus's legitimate set") {
		t.Errorf("the finding must state that the population is the corpus's, not the target's traffic: %v",
			f.Limitations)
	}
	if !hasAlternative(f, contracts.AltRateLimiting, contracts.AltNotRuledOut) {
		t.Errorf("a 429 inside the measured population makes pacing and rejection inseparable, so rate "+
			"limiting has to stay open: %+v", f.Alternatives)
	}
	// The over-block rate is measured over the calibration exchanges, so its evidence
	// profile must be the one that grades them -- not a probe cell's.
	if f.EvidenceProfileRef == v.Profile.ProfileID {
		t.Errorf("the over-block finding cites probe cell %s's profile for a rate measured over the "+
			"controls", v.Cell.CellKey)
	}
	if f.EvidenceProfileRef == "" {
		t.Error("the over-block finding cites no evidence profile for its own population")
	}
}

// ------------------------------------------------------------- undetermined

func TestUndeterminedAreasCoverEveryUnreadZone(t *testing.T) {
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-CMD-Q-01", group: "G-CMD", class: contracts.ClassCommandInjection,
			vector: contracts.VectorQuery}.item(),
		spec{ref: "DEV-XSS-Q-01", group: "G-XSS", class: contracts.ClassXSS,
			vector: contracts.VectorQuery, anchors: []string{"lab-rule-table:XSS-001"}}.item(),
		// Nothing was sent for these two, and the probe partition carries them: the
		// reason code has to distinguish "this build cannot send it" from "this run
		// did not send it".
		spec{ref: "DEV-SSRF-Q-01", group: "G-SSRF", class: contracts.ClassSSRF,
			vector: contracts.VectorQuery}.item(),
		spec{ref: "DEV-SQLI-M-01", group: "G-SQLI-M", class: contracts.ClassSQLi,
			vector: contracts.VectorMultipart}.item())

	dead := cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassCommandInjection, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials: []trial{
			{ref: "DEV-CMD-Q-01", signal: contracts.SignalTransportError},
			{ref: "DEV-CMD-Q-01", signal: contracts.SignalIndeterminate},
		},
		skip: "no valid trial in this cell, so no hypothesis can be formed over it",
		obstacles: []hypothesis.Obstacle{{
			Reason: contracts.ReasonTransportFailure,
			Detail: "2 of 2 trial(s) produced no reading",
		}},
	})
	healthy := cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassXSS, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials:        []trial{{ref: "DEV-XSS-Q-01", signal: contracts.SignalBlock, valid: true}},
		positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
	})

	pass := result(dead, healthy)
	pass.Missing = []string{"observation 5f0c was never classified"}
	pass.Divergences = []inference.Divergence{{
		ProbeRef: "p-1", ObservationID: "obs-1", Field: "signal", Journaled: "signal_block",
		Derived: "signal_pass",
	}}
	in := input(pass, set)
	in.Unplanned = []discover.Unplanned{{
		Ref: "DEV-SSRF-Q-02", Reason: contracts.ReasonBudgetExhausted,
		Detail: "the authorized budget ended before this cell's next pass",
	}}
	rep, err := discover.Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)

	areas := map[contracts.ReasonCode]int{}
	for _, f := range rep.Findings {
		if f.FindingType != contracts.FindingUndeterminedArea {
			continue
		}
		areas[f.UnevaluatedReason]++
		if f.ClaimType != contracts.ClaimDescriptive ||
			f.AttributionStatus != contracts.AttributionUndetermined {
			t.Errorf("%s: an undetermined area claims %s with %s attribution", f.Ref,
				f.ClaimType, f.AttributionStatus)
		}
		if strings.Contains(strings.ToLower(f.WhatIsInferred), "vulnerab") {
			t.Errorf("%s infers a vulnerability from an absence: %s", f.Ref, f.WhatIsInferred)
		}
		if f.Priority != contracts.PriorityLow {
			t.Errorf("%s ranks an unmeasured zone at %s", f.Ref, f.Priority)
		}
		if len(f.ObservationRefs) == 0 || !strings.HasPrefix(f.ObservationRefs[0], "absence:") {
			t.Errorf("%s cites %v: a zone with no reading must cite the absence, never an "+
				"observation it did not make", f.Ref, f.ObservationRefs)
		}
	}
	for _, want := range []struct {
		code  contracts.ReasonCode
		what  string
		count int
	}{
		{contracts.ReasonTransportFailure, "the cell that produced no reading", 1},
		{contracts.ReasonBudgetExhausted, "the item the selection could not plan", 1},
		{contracts.ReasonCorpusGap, "classes and transports this build cannot send", 2},
		{contracts.ReasonInconclusiveSignal, "the divergence and the unread exchange", 2},
		{contracts.ReasonNotYetAttempted, "the ssrf class and the multipart transport, carried by " +
			"the partition and never placed", 2},
	} {
		if areas[want.code] < want.count {
			t.Errorf("expected at least %d undetermined area(s) with reason %q for %s, got %d",
				want.count, want.code, want.what, areas[want.code])
		}
	}
	if rep.Counts[contracts.FindingUndeterminedArea] == 0 {
		t.Errorf("the summary counts no undetermined area although five sources were present: %v", areas)
	}
	// An undetermined area must stay in the report even when the run measured
	// everything else successfully: it is the reader's map of what is not known.
	if len(rep.Findings) < rep.Counts[contracts.FindingUndeterminedArea] {
		t.Error("Counts names findings the Report does not carry")
	}
}

// A published step is only a route out of a finding if it asks the question the finding
// says is open. Appending the run's own scope to a step that widens the scope would
// override it - the last flag wins - and the reader would pay for a plan of the scope
// that was already measured. The reverse half matters too: a reproduction command that
// names the permission twice, or not at all, resolves to something the run never was.
func TestPublishedCommandsCarryTheirOwnScope(t *testing.T) {
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-XSS-Q-01", group: "G-XSS", class: contracts.ClassXSS,
			vector: contracts.VectorQuery}.item(),
		spec{ref: "DEV-SQLI-Q-01", group: "G-SQLI", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())
	healthy := cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassXSS, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials:        []trial{{ref: "DEV-XSS-Q-01", signal: contracts.SignalBlock, valid: true}},
		positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
	})
	in := input(result(healthy), set)
	in.Unplanned = []discover.Unplanned{{
		Ref: "DEV-SQLI-Q-01", Reason: contracts.ReasonNotYetAttempted,
		Detail: "the run planned no probe of this class",
	}}
	in.CommandFlags = "--authorization " + testAuth +
		" --authorizations authorization --corpus corpus --class xss --vector query --budget 9"
	in.EngagementFlags = "--authorization " + testAuth + " --authorizations authorization --corpus corpus"
	rep, err := discover.Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)

	var steps, repros int
	for _, f := range rep.Findings {
		if n := countToken(f.ReproductionCommand, "--authorization"); n != 1 {
			t.Errorf("finding %s names the permission %d time(s) in %q: a reader cannot tell which "+
				"one the measurement was made under", f.Ref, n, f.ReproductionCommand)
		}
		if !strings.Contains(f.ReproductionCommand, testAuth) {
			t.Errorf("finding %s reproduces under a permission the run did not use: %q",
				f.Ref, f.ReproductionCommand)
		}
		if !strings.Contains(f.ReproductionCommand, "--budget 9") {
			t.Errorf("finding %s reproduces without the budget that chose its probes, so the pasted "+
				"command plans a different run: %q", f.Ref, f.ReproductionCommand)
		}
		repros++
		step := f.RegressionTest
		if !strings.HasPrefix(step, "xammu playbook") {
			continue
		}
		steps++
		// The step exists to measure a zone this run left unmeasured. Inheriting the
		// run's own scope - its budget, the class it planned, the transport it used -
		// would spend requests to re-learn nothing, and a flag named twice is a flag
		// whose value the reader has to guess.
		for _, forbidden := range []string{"--budget 9", "--class xss", "--vector query"} {
			if strings.Contains(step, forbidden) {
				t.Errorf("the widening step %q carries this run's scope %q", step, forbidden)
			}
		}
		for _, flagName := range []string{"--class", "--vector", "--budget"} {
			if n := countToken(step, flagName); n > 1 {
				t.Errorf("the step %q names %s %d time(s): the reader cannot tell which value counts",
					step, flagName, n)
			}
		}
		if !strings.Contains(step, testAuth) || countToken(step, "--authorization") != 1 {
			t.Errorf("the widening step %q must name the permission once, so a step that asks for a "+
				"class the run skipped is still inside the authorized scope", step)
		}
	}
	if steps == 0 || repros == 0 {
		t.Fatalf("the fixtures were meant to publish both a measured finding and a playbook step: "+
			"%d step(s), %d reproduction command(s)", steps, repros)
	}
}

// countToken counts whole arguments rather than substrings. "--authorizations DIR"
// travels with "--authorization REF" in every command the CLI publishes, and a
// substring count reads that pair as the permission named twice - which would make the
// test fail on a correct command and pass on a wrong one. Quoted values with spaces are
// not present in these fixtures; this is a check of flag discipline, not a shell.
func countToken(cmd, token string) int {
	var n int
	for _, field := range strings.Fields(cmd) {
		if field == token {
			n++
		}
	}
	return n
}

func TestEveryAbsenceCarriesATypedReason(t *testing.T) {
	// The obstacle's typed reason is the only thing that separates "we could not read
	// this" from "nothing is there". A cell the pass skipped without recording an
	// obstacle still has to be published with a reason -- the default one, which names
	// the missing reading instead of inventing a cause for it.
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-CMD-Q-01", group: "G-CMD", class: contracts.ClassCommandInjection,
			vector: contracts.VectorQuery}.item())
	key := inference.CellKey{AttackClass: contracts.ClassCommandInjection, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	v := cell(t, cellSpec{key: key,
		trials: []trial{{ref: "DEV-CMD-Q-01", signal: contracts.SignalTransportError}},
		skip:   "no valid trial in this cell"})
	rep, err := discover.Analyze(input(result(v), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	var found bool
	for _, f := range rep.Findings {
		if f.FindingType != contracts.FindingUndeterminedArea ||
			!strings.Contains(f.AffectedScope, string(contracts.ClassCommandInjection)) {
			continue
		}
		found = true
		var typed bool
		for _, code := range contracts.AllReasonCodes() {
			if f.UnevaluatedReason == code {
				typed = true
			}
		}
		if !typed {
			t.Errorf("%s: the absence is typed %q, which is not a reason code the contracts define",
				f.Ref, f.UnevaluatedReason)
		}
		if f.UnevaluatedReason != contracts.ReasonInconclusiveSignal {
			t.Errorf("%s: with no obstacle recorded the reason has to stay the default %q, got %q",
				f.Ref, contracts.ReasonInconclusiveSignal, f.UnevaluatedReason)
		}
	}
	if !found {
		t.Error("a cell the pass skipped appeared nowhere in the finding set: the reader would see a run " +
			"that never planned it rather than a run that could not read it")
	}
}

func TestNoMeasuredFindingIsPublishedFromLevelNoneEvidence(t *testing.T) {
	// A cell with no valid trial grades at level none by construction, and level none
	// supports no claim about the target: the only honest output is the undetermined
	// area that names why the run learned nothing there.
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-Q-01", group: "G-T", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item())
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	v := cell(t, cellSpec{key: key,
		trials: []trial{
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalTransportError},
			{ref: "DEV-SQLI-Q-01", signal: contracts.SignalIndeterminate},
		},
		skip: "no valid trial in this cell, so no hypothesis can be formed over it",
		obstacles: []hypothesis.Obstacle{{
			Reason: contracts.ReasonTransportFailure, Detail: "both trials failed at the transport",
		}}})
	if v.Profile.Level != contracts.EvidenceNone {
		t.Fatalf("the fixture does not grade at level none after all: %s", v.Profile.Level)
	}
	rep, err := discover.Analyze(input(result(v), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	for _, f := range rep.Findings {
		if f.FindingType != contracts.FindingUndeterminedArea {
			t.Errorf("%s published a measured finding (%s) from a cell with evidence level none",
				f.Ref, f.FindingType)
		}
	}
}

// --------------------------------------------------------- configuration load

func TestConfigurationConcernIsDistinctFromASignatureRefusal(t *testing.T) {
	// A refusal grounded on a named policy is the one behaviour a rule-table review
	// cannot predict, which is why it is its own finding type and not a coverage gap:
	// the probes were refused, exactly as declared, and the reason has nothing to do
	// with the payload.
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorHeader,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-H-01", group: "G-HEADER", class: contracts.ClassSQLi,
			vector: contracts.VectorHeader, canonical: "xammu-probe-header-marker",
			probe:   "xammu-probe-header-marker",
			anchors: []string{"lab-rule-table:policy:x-lab-probe-transfer-encoding"}}.item())
	v := cell(t, cellSpec{key: key, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SQLI-H-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-H-01", signal: contracts.SignalBlock, valid: true},
			{ref: "DEV-SQLI-H-01", signal: contracts.SignalBlock, valid: true},
		}})

	rep, err := discover.Analyze(input(result(v), set))
	if err != nil {
		t.Fatal(err)
	}
	everyFindingIsValid(t, rep)
	f := requireFinding(t, rep, contracts.FindingConfigurationConcern, "CFG-x-lab-probe-transfer-encoding")

	if !strings.Contains(f.WhatWasObserved, "x-lab-probe-transfer-encoding") {
		t.Errorf("the finding must name the policy it measured, not just a refusal: %s", f.WhatWasObserved)
	}
	if !strings.Contains(f.SecurityEngineerNote, "signature review") {
		t.Errorf("the note must tell the reviewer why rule review will never predict this: %s",
			f.SecurityEngineerNote)
	}
	for _, other := range rep.Findings {
		if other.FindingType == contracts.FindingCoverageGap {
			t.Errorf("%s was published as a coverage gap beside %s: these probes were refused, which is "+
				"what the corpus declares, so there is no contradiction to report", other.Ref, f.Ref)
		}
	}
	// A policy id is not a signature. The sentences that name what the engine matches
	// must not quote it as one.
	if strings.Contains(f.WhatIsInferred, "policy:x-lab-probe") {
		t.Errorf("the inference quotes the raw run_ref instead of naming the policy: %s", f.WhatIsInferred)
	}
	if f.Priority != contracts.PriorityLow {
		t.Errorf("100%% refusal over 3 valid trials stays low because the count gates it: got %s (%s)",
			f.Priority, f.PriorityBasis)
	}
}

func TestSummaryCountsEveryPublishedFinding(t *testing.T) {
	key := inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorBodyJSON,
		Encoding: contracts.EncodingCanonical, Path: testPath}
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-J-01", group: "G-SQLI-J", class: contracts.ClassSQLi,
			vector: contracts.VectorBodyJSON}.item())
	v := cell(t, cellSpec{key: key, positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
		trials: []trial{
			{ref: "DEV-SQLI-J-01", signal: contracts.SignalPass, valid: true},
			{ref: "DEV-SQLI-J-01", signal: contracts.SignalPass, valid: true},
		}})
	pass := result(v)
	pass.Controls.Positive = append(pass.Controls.Positive, inference.Trial{RunID: testRun,
		RoundID: testRound, ProbeRef: "probe-pos2", CorpusRef: "CAL-POS",
		ControlRole: contracts.RolePositiveControl, ObservationID: "obs-positive-2",
		AnalysisID: "a-pos2", ClassificationID: "c-pos2", Signal: contracts.SignalIndeterminate,
		Valid: false, At: stamp})

	rep, err := discover.Analyze(input(pass, set))
	if err != nil {
		t.Fatal(err)
	}

	// Counts must describe Findings exactly: a report whose summary counts a finding
	// it does not carry would overstate the run.
	total := 0
	for _, n := range rep.Counts {
		total += n
	}
	if total != len(rep.Findings) {
		t.Errorf("Counts sums to %d but the report carries %d findings", total, len(rep.Findings))
	}
	summary := rep.Summary()
	for _, want := range []string{testRun, testRound, "coverage_gap=1", "1/2 positive control(s) refused",
		"0/1 legitimate exchange(s) refused"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary line omits %q: %s", want, summary)
		}
	}
	if strings.Contains(summary, "=0") {
		t.Errorf("the summary lists a type with no findings, which reads as a measured absence: %s",
			summary)
	}
	if rep.Baseline.ExcludedInconclusive != 1 {
		t.Errorf("the control that produced no reading must be named in the baseline, not dropped: %+v",
			rep.Baseline)
	}
}
