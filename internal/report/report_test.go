package report_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/discover"
	"xammu/internal/hypothesis"
	"xammu/internal/inference"
	"xammu/internal/report"
)

var stamp = time.Date(2026, time.October, 28, 12, 0, 0, 0, time.UTC)

const (
	testRun   = "run-2026-10-28-lab"
	testRound = "round-1"
	testAuth  = "auth-2026-042"
	testPath  = "/api/search"
	origin    = "https://lab.local:8443"
)

// ------------------------------------------------------------- pass fixtures

type spec struct {
	ref       string
	group     string
	class     contracts.AttackClass
	vector    contracts.Vector
	encoding  contracts.Encoding
	purpose   contracts.Purpose
	expect    contracts.ExpectedBehavior
	partition contracts.PartitionName
	anchors   []string
}

func (s spec) item() contracts.CorpusItem {
	if s.canonicalDefaultsNeeded() {
		s.encoding = contracts.EncodingCanonical
	}
	if s.purpose == "" {
		s.purpose = contracts.PurposeDiagnosis
	}
	if s.expect == "" {
		s.expect = contracts.ExpectBlock
	}
	if s.partition == "" {
		s.partition = contracts.PartitionDevelopment
	}
	if len(s.anchors) == 0 {
		s.anchors = []string{"lab-rule-table:SQLI-001"}
	}
	var ev []contracts.CorpusValidationEvidence
	for _, a := range s.anchors {
		ev = append(ev, contracts.CorpusValidationEvidence{
			RunRef: a, ObservedAt: stamp, Result: "declared_by_fixture_rule_table",
			LabImageDigest: "sha256:aa", MatchesExpectation: true,
		})
	}
	probe := "' or 1=1 xammu-probe"
	return contracts.CorpusItem{
		ItemID: contracts.NewUUID(), Ref: s.ref, GroupID: s.group, Partition: s.partition,
		AttackClass: s.class, Vector: s.vector, Encoding: s.encoding,
		Canonical: probe, Probe: probe, ProbeDigest: contracts.NewDigest([]byte(probe)),
		Purpose: s.purpose, ExpectedBehavior: s.expect,
		Provenance:    contracts.Provenance{Source: "test", Author: "test", ReviewRef: "T-1", RetrievedAt: stamp},
		Inertness:     contracts.InertnessRecord{Verdict: contracts.InertVerified, CheckedAt: stamp, Notes: "test"},
		Validation:    ev,
		AuthoringNote: "written for the report tests",
	}
}

func (s spec) canonicalDefaultsNeeded() bool { return s.encoding == "" }

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
}

func cell(t *testing.T, cs cellSpec) inference.Verdict {
	t.Helper()
	var trials []inference.Trial
	signals := map[contracts.Signal]int{}
	refused := 0
	for i, tr := range cs.trials {
		id := "obs-" + strconv.Itoa(i+1)
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
	ids := make([]string, 0, len(trials))
	for _, tr := range trials {
		ids = append(ids, tr.ObservationID)
	}
	prof, err := hypothesis.Profile(hypothesis.Subject{
		RunID: testRun, Ref: cs.key.Ref(), Kind: "cell", CompiledAt: stamp,
		Trials: hypothesis.Trials{
			Population: len(trials), Valid: c.Valid, Inconclusive: c.Inconclusive, Invalid: c.Invalid,
			Replicas: c.Replicas(), Rounds: rounds,
			PositiveControlValid: cs.positiveValid, NegativeControlValid: cs.negativeValid,
			Hits: refused, HitBasis: "valid trials of this cell the classifier recorded as a refusal",
			Refs: ids,
		},
	})
	if err != nil {
		t.Fatalf("fixture cell %s is not gradeable: %v", cs.key, err)
	}
	v := inference.Verdict{Cell: c, Profile: prof, Skip: cs.skip}
	if cs.attribution != "" {
		v.Attribution = &contracts.Attribution{
			AttributionID: contracts.NewUUID(), RunID: testRun, SubjectID: cs.key.Ref(),
			SubjectContract: contracts.IDBehavioralClassification, AttributedAt: stamp,
			Primary: contracts.AltWAF, Status: cs.attribution, EvidenceBasis: contracts.BasisHTTPControl,
		}
	}
	return v
}

type cellSpec struct {
	key           inference.CellKey
	trials        []trial
	positiveValid bool
	negativeValid bool
	rounds        []string
	attribution   contracts.AttributionStatus
	skip          string
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

func result(verdicts ...inference.Verdict) *inference.Result {
	return &inference.Result{
		RunID: testRun, RoundID: testRound, Verdicts: verdicts, ReferenceCount: 6,
		Controls: inference.Controls{
			Positive: []inference.Trial{{RunID: testRun, RoundID: testRound, ProbeRef: "probe-pos",
				CorpusRef: "CAL-POS", ControlRole: contracts.RolePositiveControl,
				ObservationID: "obs-positive", AnalysisID: "a-pos", ClassificationID: "c-pos",
				Signal: contracts.SignalBlock, StatusCode: 403, Valid: true, At: stamp}},
			Negative: []inference.Trial{{RunID: testRun, RoundID: testRound, ProbeRef: "probe-neg",
				CorpusRef: "CAL-NEG", ControlRole: contracts.RoleBenignReference,
				ObservationID: "obs-negative", AnalysisID: "a-neg", ClassificationID: "c-neg",
				Signal: contracts.SignalPass, StatusCode: 200, Valid: true, At: stamp}},
		},
	}
}

func calibItem(ref string, purpose contracts.Purpose, expect contracts.ExpectedBehavior) contracts.CorpusItem {
	return spec{ref: ref, group: "G-CAL", class: contracts.ClassSQLi, vector: contracts.VectorQuery,
		purpose: purpose, expect: expect, partition: contracts.PartitionCalibration}.item()
}

// ------------------------------------------------------------ input fixture

// mixedPass is the shape a report is usually written from: one cell that behaved as
// the corpus declared, one that did not, one encoding replica that walked past, and one
// cell that produced no reading at all.
func mixedPass(t *testing.T) (*inference.Result, *corpus.Set) {
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-Q", group: "G-SQLI-Q", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item(),
		spec{ref: "DEV-SQLI-Q-E1", group: "G-SQLI-Q", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery, encoding: contracts.EncodingURLSingle,
			purpose: contracts.PurposeEncodingReplica}.item(),
		spec{ref: "DEV-SQLI-J", group: "G-SQLI-J", class: contracts.ClassSQLi,
			vector:  contracts.VectorBodyJSON,
			anchors: []string{"lab-rule-table:coverage:json_body_uninspected"}}.item(),
		spec{ref: "DEV-XSS-Q", group: "G-XSS-Q", class: contracts.ClassXSS,
			vector: contracts.VectorQuery}.item(),
	)
	key := func(c contracts.AttackClass, v contracts.Vector, e contracts.Encoding) inference.CellKey {
		return inference.CellKey{AttackClass: c, Vector: v, Encoding: e, Path: testPath}
	}
	passes := func(n int, ref string) []trial {
		out := make([]trial, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, trial{ref: ref, signal: contracts.SignalPass, valid: true})
		}
		return out
	}
	blocks := func(n int, ref string) []trial {
		out := make([]trial, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, trial{ref: ref, signal: contracts.SignalBlock, valid: true})
		}
		return out
	}
	indeterminate := func(n int, ref string) []trial {
		out := make([]trial, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, trial{ref: ref, signal: contracts.SignalIndeterminate})
		}
		return out
	}
	queried := append(blocks(4, "DEV-SQLI-Q"), indeterminate(1, "DEV-SQLI-Q")...)
	return result(
		cell(t, cellSpec{key: key(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingCanonical),
			trials: queried, positiveValid: true, negativeValid: true,
			attribution: contracts.AttributionCompatible}),
		cell(t, cellSpec{key: key(contracts.ClassSQLi, contracts.VectorQuery, contracts.EncodingURLSingle),
			trials: append(passes(4, "DEV-SQLI-Q-E1"), trial{ref: "DEV-SQLI-Q-E1",
				signal: contracts.SignalRateLimited}),
			positiveValid: true, negativeValid: true,
			attribution: contracts.AttributionCompatible}),
		cell(t, cellSpec{key: key(contracts.ClassSQLi, contracts.VectorBodyJSON, contracts.EncodingCanonical),
			trials: passes(3, "DEV-SQLI-J"), positiveValid: true, negativeValid: true,
			attribution: contracts.AttributionCompatible}),
		cell(t, cellSpec{key: key(contracts.ClassXSS, contracts.VectorQuery, contracts.EncodingCanonical),
			trials:        indeterminate(2, "DEV-XSS-Q"),
			skip:          "no valid trial: every exchange the cell sent came back indeterminate",
			positiveValid: true, negativeValid: true}),
	), set
}

func inputFor(t *testing.T, pass *inference.Result, set *corpus.Set) report.Input {
	t.Helper()
	auth := contracts.ValidProfilingAuthorization()
	disc, err := discover.Analyze(discover.Input{
		RunID: testRun, RoundID: testRound, Pass: pass, Corpus: set,
		Partition: contracts.PartitionDevelopment, AuthorizationRef: auth.Ref,
		AuthorizedClasses: auth.AllowedClasses, AuthorizedVectors: auth.AllowedVectors,
		Unplanned: []discover.Unplanned{
			{Ref: "DEV-SSRF-Q", Reason: contracts.ReasonBudgetExhausted, Detail: "budget ended at request 480"},
			{Ref: "DEV-SSRF-H", Reason: contracts.ReasonBudgetExhausted, Detail: "budget ended at request 480"},
		},
		GeneratedAt: stamp,
	})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	run := contracts.ValidCompletedRun()
	run.RunID = testRun
	run.RoundID = testRound
	run.TargetOrigin = origin
	return report.Input{
		Run: *run, Auth: auth, Pass: pass, Findings: disc,
		Unplanned: []discover.Unplanned{
			{Ref: "DEV-SSRF-Q", Reason: contracts.ReasonBudgetExhausted, Detail: "budget ended at request 480"},
			{Ref: "DEV-SSRF-H", Reason: contracts.ReasonBudgetExhausted, Detail: "budget ended at request 480"},
		},
		Evidence: report.EvidenceFacts{
			ManifestPath:    "runs/" + testRun + "/manifest.json",
			ManifestDigest:  contracts.NewDigest([]byte("manifest bytes")),
			VerifyCommand:   "xammu verify --run " + testRun,
			CorpusCommitRef: "corpus-digest:" + strings.Repeat("a", 8),
			DetectorSetHash: contracts.NewDigest([]byte("detector set")),
			ToolVersion:     "xammu-1.0.0",
		},
		GeneratedBy: "operator",
		GeneratedAt: stamp,
	}
}

func build(t *testing.T, in report.Input) *contracts.Report {
	t.Helper()
	rep, err := report.Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := contracts.Validate(contracts.IDReport, rep); err != nil {
		t.Fatalf("the assembled report does not satisfy C-15: %v", err)
	}
	return rep
}

// ------------------------------------------------------------------- tests

func TestBuildIssuesAValidC15(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))

	if rep.RunID != testRun || rep.AuthorizationRef != testAuth {
		t.Errorf("report identifies run %s / authorization %s", rep.RunID, rep.AuthorizationRef)
	}
	if len(rep.Dimensions) != 5 {
		t.Fatalf("five dimensions are required, got %d", len(rep.Dimensions))
	}
	covered := map[int]int{}
	for _, d := range rep.Dimensions {
		if len(d.Statements) == 0 {
			t.Errorf("dimension %s answers its questions with no statement", d.Kind)
		}
		if len(d.Refs) == 0 {
			t.Errorf("dimension %s cites no data", d.Kind)
		}
		for _, q := range d.Questions {
			covered[q]++
		}
	}
	for _, q := range contracts.AllReportQuestions() {
		if covered[q] != 1 {
			t.Errorf("question %d answered by %d dimension(s); the contract wants exactly one", q, covered[q])
		}
	}
	if len(rep.Findings) != len(inputFor(t, pass, set).Findings.Findings) {
		t.Error("the report dropped or invented a finding")
	}
}

func TestReportRefusesARunThatIsStillSending(t *testing.T) {
	pass, set := mixedPass(t)
	in := inputFor(t, pass, set)
	in.Run.State = contracts.StateExecuting
	if _, err := report.Build(in); err == nil {
		t.Fatal("a report was issued from a run that had not stopped")
	} else if !strings.Contains(err.Error(), "stopped run") {
		t.Errorf("error does not name the reason: %v", err)
	}
}

func TestReportRefusesAnEvidenceSectionItCannotCheck(t *testing.T) {
	pass, set := mixedPass(t)
	for _, field := range []func(in *report.Input){
		func(i *report.Input) { i.Evidence.ManifestPath = "" },
		func(i *report.Input) { i.Evidence.ManifestDigest = "" },
		func(i *report.Input) { i.Evidence.VerifyCommand = "" },
		func(i *report.Input) { i.Evidence.CorpusCommitRef = "" },
		func(i *report.Input) { i.Evidence.DetectorSetHash = "" },
		func(i *report.Input) { i.Evidence.ToolVersion = "" },
		func(i *report.Input) { i.GeneratedBy = "" },
	} {
		in := inputFor(t, pass, set)
		field(&in)
		if _, err := report.Build(in); err == nil {
			t.Fatal("a report with an empty reproducibility field was issued")
		}
	}
}

func TestMatrixHolesAreNamedAndMeasuredCellsHaveDenominators(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))

	if len(rep.Matrix.NotMeasured) == 0 {
		t.Fatal("the matrix claims every authorized cell was measured")
	}
	if len(rep.Matrix.Classes) != 5 || len(rep.Matrix.Vectors) != 6 {
		t.Errorf("the grid must be the authorization's own scope: got %d x %d",
			len(rep.Matrix.Classes), len(rep.Matrix.Vectors))
	}
	var withReading int
	for _, cell := range rep.Matrix.Cells {
		if cell.Status == "measured" || cell.Status == "partial" {
			withReading++
		}
		if cell.Status == "measured" && cell.Aggregate.Denominator == 0 {
			t.Errorf("cell %s|%s is measured with an empty denominator", cell.Class, cell.Vector)
		}
		var blocked, passed, valid int
		for _, e := range cell.Encodings {
			blocked += e.Blocked
			passed += e.Passed
			valid += e.ValidTrials
			if e.Verdict != "not_measured" && e.ValidTrials == 0 {
				t.Errorf("encoding %s of %s|%s has a verdict with no valid trial", e.Encoding,
					cell.Class, cell.Vector)
			}
		}
		if blocked != cell.Aggregate.Numerator || valid != cell.Aggregate.Denominator {
			t.Errorf("cell %s|%s: its encoding rows sum to %d/%d but the aggregate says %d/%d",
				cell.Class, cell.Vector, blocked, valid, cell.Aggregate.Numerator,
				cell.Aggregate.Denominator)
		}
		if passed+blocked > valid {
			t.Errorf("cell %s|%s counts trials that are neither refused nor handled ordinarily",
				cell.Class, cell.Vector)
		}
	}
	if withReading == 0 {
		t.Error("no cell holds a reading, so the run measured nothing and reported a grid")
	}
	for _, s := range rep.ExecutiveSummary {
		if strings.Contains(s, "Coverage of the authorized grid") &&
			!strings.Contains(s, strconv.Itoa(withReading)+" of 30") {
			t.Errorf("the summary's coverage sentence (%q) disagrees with the matrix (%d cells)", s, withReading)
		}
	}
}

func TestDistributionArithmeticCannotAbsorbTheIndeterminateBucket(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))
	if len(rep.Distributions) != 5 {
		t.Fatalf("five distributions are required, got %d", len(rep.Distributions))
	}
	for _, d := range rep.Distributions {
		vocab := contracts.AllDistributionBuckets(d.Kind)
		if len(d.Buckets) != len(vocab) {
			t.Errorf("%s: %d bucket(s) rendered of a %d-bucket vocabulary: a missing row is a narrowed "+
				"vocabulary, not an absence of work", d.Kind, len(d.Buckets), len(vocab))
		}
		seen := map[string]bool{}
		var sum, nonScoring int
		for _, b := range d.Buckets {
			if !contains(vocab, b.Name) {
				t.Errorf("%s: bucket %q is not in the declared vocabulary", d.Kind, b.Name)
			}
			if seen[b.Name] {
				t.Errorf("%s: duplicate bucket %q", d.Kind, b.Name)
			}
			seen[b.Name] = true
			sum += b.Count
			if b.Name == contracts.NonScoringBucket(d.Kind) {
				nonScoring = b.Count
			}
		}
		if d.Denominator != sum-nonScoring {
			t.Errorf("%s: denominator %d but the counted buckets sum to %d minus %d non-scoring",
				d.Kind, d.Denominator, sum, nonScoring)
		}
		if d.InconclusiveBucket != contracts.NonScoringBucket(d.Kind) {
			t.Errorf("%s: declares %q as its non-scoring bucket", d.Kind, d.InconclusiveBucket)
		}
		if !contains(d.Excluded, contracts.NonScoringBucket(d.Kind)) {
			t.Errorf("%s: the non-scoring bucket is not declared in excluded_from_denominator", d.Kind)
		}
	}
}

// TestAnUnmeasuredCellCarriesNoCeiling locks the one place where a placeholder could
// have spoken for a result: an aggregate starts at the top rung of the ladder so the
// walk can only ever climb down, and a cell that received no reading would otherwise
// report the strongest ceiling in the vocabulary as though it had earned it.
func TestAnUnmeasuredCellCarriesNoCeiling(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))
	var empty int
	for _, c := range rep.Matrix.Cells {
		if c.Aggregate.Denominator != 0 {
			continue
		}
		empty++
		if c.Evidence != contracts.EvidenceNone {
			t.Errorf("%s|%s: no valid trial but evidence level %q", c.Class, c.Vector, c.Evidence)
		}
		if c.ClaimType != "" {
			t.Errorf("%s|%s: no valid trial but claim ceiling %q", c.Class, c.Vector, c.ClaimType)
		}
		for _, e := range c.Encodings {
			if e.ValidTrials == 0 && e.Evidence != contracts.EvidenceNone {
				t.Errorf("%s|%s|%s: no valid trial but row evidence %q",
					c.Class, c.Vector, e.Encoding, e.Evidence)
			}
		}
	}
	if empty == 0 {
		t.Fatal("the fixture left no cell without a reading, so the guard was never exercised")
	}
	if md := report.Markdown(rep); !strings.Contains(md, "no claim") {
		t.Error("the rendered matrix leaves the ceiling of an unmeasured cell blank instead of stating it")
	}
}

// TestTheReportStatesOneSetOfCountsAcrossEverySection is the reason the arithmetic lives
// in one walk: the inconclusive and invalid exchanges are quoted by the matrix basis and
// by the coverage dimension, and a report that states two different numbers for them
// contains two measurements of one run rather than one measurement described twice. It
// also locks the indeterminate bucket against the trials themselves, because an
// indeterminate exchange is frequently also an invalid one and the reading it states is
// the classifier's inability, not the flag.
func TestTheReportStatesOneSetOfCountsAcrossEverySection(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))
	var inconclusive, invalid, indeterminate int
	for _, v := range pass.Verdicts {
		inconclusive += v.Cell.Inconclusive
		invalid += v.Cell.Invalid
		for _, tr := range v.Cell.Trials {
			if tr.Signal == contracts.SignalIndeterminate {
				indeterminate++
			}
		}
	}
	want := fmt.Sprintf("%d inconclusive and %d invalid", inconclusive, invalid)
	if !strings.Contains(rep.Matrix.Basis, want) {
		t.Errorf("the matrix basis does not quote the walk's counts (%s): %q", want, rep.Matrix.Basis)
	}
	var stated bool
	for _, d := range rep.Dimensions {
		if d.Kind != contracts.DimCoverage {
			continue
		}
		for _, s := range d.Statements {
			if strings.Contains(s, want) {
				stated = true
			}
		}
	}
	if !stated {
		t.Errorf("no coverage statement repeats (%s), so the sections state different arithmetic", want)
	}
	for _, d := range rep.Distributions {
		if d.Kind != contracts.DistBehavioralSignal {
			continue
		}
		for _, b := range d.Buckets {
			if b.Name == "indeterminate" && b.Count != indeterminate {
				t.Errorf("the behavioural distribution counts %d indeterminate exchange(s); the trials "+
					"carry %d", b.Count, indeterminate)
			}
		}
	}
}

// TestALateReportSaysItsPermissionHasLapsed: a report written after its authorization
// expired is normal -- analysis comes after the run -- but it must not claim the expiry
// stopped anything, and it must tell the reader that the commands it prints are no
// longer executable under the reference they cite.
func TestALateReportSaysItsPermissionHasLapsed(t *testing.T) {
	pass, set := mixedPass(t)
	in := inputFor(t, pass, set)
	rep := build(t, in)
	var lapsed string
	for _, l := range rep.LimitsSummary {
		if strings.Contains(l, "expired") {
			lapsed = l
		}
		if strings.Contains(l, "may not outlive") {
			t.Errorf("the limits attribute the run's stop to the expiry: %q", l)
		}
	}
	if lapsed == "" {
		t.Fatal("a report generated after its authorization lapsed does not say so")
	}
	if !strings.Contains(lapsed, testAuth) {
		t.Errorf("the lapse note does not name the authorization it lapsed: %q", lapsed)
	}

	in.GeneratedAt = in.Auth.ExpiresAt.Add(-time.Hour)
	early := build(t, in)
	for _, l := range early.LimitsSummary {
		if strings.Contains(l, "expired") {
			t.Errorf("a report written inside the window still warns about a lapse: %q", l)
		}
	}
}

func TestResidualRiskStaysThreeSeparateStatements(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))
	all := []contracts.Scenario{rep.ResidualRisk.ConditionalRisk,
		rep.ResidualRisk.ConditionNotDemonstrated, rep.ResidualRisk.Undeterminable}
	seen := map[string]bool{}
	for i, s := range all {
		if s.Statement == "" || s.Scope == "" || s.Verification == "" {
			t.Errorf("scenario %d is missing a field", i)
		}
		if len(s.Untested) == 0 {
			t.Errorf("scenario %d states nothing it did not test", i)
		}
		if !strings.HasPrefix(s.Verification, "xammu ") {
			t.Errorf("scenario %d verification is not a xammu command: %q", i, s.Verification)
		}
		if seen[s.Statement] {
			t.Error("two scenarios carry the same sentence, which is the merge the contract forbids")
		}
		seen[s.Statement] = true
	}
	if !strings.Contains(all[0].Statement, "valid trial") {
		t.Errorf("the conditional statement does not quote its own rate: %q", all[0].Statement)
	}
}

func TestEveryUnmeasuredCellIsADeclaredZone(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))
	if len(rep.Unevaluated) == 0 && !rep.UnevaluatedNone {
		t.Fatal("neither zones nor an explicit empty declaration")
	}
	var planned int
	for _, z := range rep.Unevaluated {
		if z.Reason == "" || z.Scope == "" || z.Detail == "" || z.Remediation == "" {
			t.Errorf("zone %q is missing a field", z.Scope)
		}
		if !strings.HasPrefix(z.ReproductionCommand, "xammu ") {
			t.Errorf("zone %q cannot be reproduced: %q", z.Scope, z.ReproductionCommand)
		}
		planned += z.PlannedRequests
	}
	if planned == 0 {
		t.Error("no zone carries the requests this run never spent")
	}
}

func TestAReportOfOnlyAbsencesStillAnswersEveryQuestion(t *testing.T) {
	// One cell, refused exactly as declared: nothing was bypassed, nothing was
	// over-blocked, so the only findings the pass can publish are the absences.
	set := corpusSet(t,
		calibItem("CAL-POS", contracts.PurposePositiveControl, contracts.ExpectBlock),
		calibItem("CAL-NEG", contracts.PurposeNegativeControl, contracts.ExpectPass),
		spec{ref: "DEV-SQLI-Q", group: "G-SQLI-Q", class: contracts.ClassSQLi,
			vector: contracts.VectorQuery}.item(),
	)
	pass := result(cell(t, cellSpec{
		key: inference.CellKey{AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
			Encoding: contracts.EncodingCanonical, Path: testPath},
		trials:        []trial{{ref: "DEV-SQLI-Q", signal: contracts.SignalBlock, valid: true}},
		positiveValid: true, negativeValid: true,
		attribution: contracts.AttributionCompatible,
	}))
	rep := build(t, inputFor(t, pass, set))

	var measured int
	for _, f := range rep.Findings {
		if f.FindingType != contracts.FindingUndeterminedArea {
			measured++
		}
	}
	if measured != 0 {
		t.Fatalf("expected a pass with no measured difference, got %d measured finding(s)", measured)
	}
	if !strings.Contains(rep.ResidualRisk.ConditionalRisk.Statement, "coverage") {
		t.Errorf("with no measured finding the conditional risk must be about coverage, got %q",
			rep.ResidualRisk.ConditionalRisk.Statement)
	}
	if len(rep.Matrix.NotMeasured) == 0 {
		t.Error("a run that placed one probe cannot leave the unmeasured list empty")
	}
}

func TestJSONRoundTripsAndMarkdownCarriesEverySection(t *testing.T) {
	pass, set := mixedPass(t)
	rep := build(t, inputFor(t, pass, set))

	raw, err := report.JSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back contracts.Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("the published JSON does not parse: %v", err)
	}
	if err := contracts.Validate(contracts.IDReport, &back); err != nil {
		t.Fatalf("the published JSON does not satisfy C-15: %v", err)
	}
	if back.ReportID != rep.ReportID {
		t.Error("the round-tripped report is a different document")
	}

	md := report.Markdown(rep)
	for _, want := range append([]string{
		"Executive summary", "The five dimensions", "Coverage matrix", "Residual risk",
		"Unevaluated zones", "Evidence and reproducibility", rep.Evidence.VerifyCommand,
		rep.Matrix.Basis,
	}, dimensionTitles(rep)...) {
		if !strings.Contains(md, want) {
			t.Errorf("the markdown is missing %q", want)
		}
	}
	for _, f := range rep.Findings {
		if !strings.Contains(md, f.Ref) || !strings.Contains(md, f.WhatWasObserved) {
			t.Errorf("finding %s is not rendered in full", f.Ref)
		}
	}
	for _, s := range contracts.RequiredOutOfScope {
		if !strings.Contains(md, s) {
			t.Errorf("the rendered report omits the required disclaimer %q", s)
		}
	}
	// A sentence built by string concatenation rather than Sprintf keeps its verbs, and
	// a reader then sees the template instead of the measurement. Percentages are legal
	// prose; a verb is not.
	for _, verb := range []string{"%q", "%d", "%s", "%v"} {
		if strings.Contains(md, verb) {
			t.Errorf("the rendered report leaks the format verb %q into a sentence", verb)
		}
	}
	// A reference the run does not have must be stated as an absence, not rendered as an
	// empty slot that makes the trail look broken rather than incomplete.
	for _, hole := range []string{"- Evidence: ;", "Evidence profile: ``", "; ;"} {
		if strings.Contains(md, hole) {
			t.Errorf("the rendered report has an unfilled reference at %q", hole)
		}
	}
}

// dimensionTitles is what the rendered document must contain for each of the five
// sections: its title and the question numbers the contract assigns it.
func dimensionTitles(rep *contracts.Report) []string {
	out := make([]string, 0, 10)
	for _, d := range rep.Dimensions {
		out = append(out, d.Title)
		for _, q := range d.Questions {
			out = append(out, "Q"+strconv.Itoa(q))
		}
	}
	return out
}

func TestCorpusCommitRefNamesTheTreeItCameFrom(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.MkdirAll(filepath.Join(dir, "development"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "development", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.jsonl", `{"ref":"DEV-A"}`+"\n")
	write("b.jsonl", `{"ref":"DEV-B"}`+"\n")
	first, err := report.CorpusCommitRef(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "corpus-digest:") && !strings.HasPrefix(first, "git:") {
		t.Errorf("the commit ref does not name a source: %q", first)
	}
	again, err := report.CorpusCommitRef(dir)
	if err != nil || again != first {
		t.Errorf("the same tree produced two refs: %q vs %q (%v)", again, first, err)
	}
	write("b.jsonl", `{"ref":"DEV-B-EDITED"}`+"\n")
	changed, err := report.CorpusCommitRef(dir)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Error("an edited corpus still reports the old identity")
	}

	empty := t.TempDir()
	if _, err := report.CorpusCommitRef(empty); err == nil {
		t.Error("a corpus with no files has an identity in the report")
	}
}

func TestReportRefusesAnEmptyPass(t *testing.T) {
	pass, set := mixedPass(t)
	in := inputFor(t, pass, set)
	in.Pass = &inference.Result{RunID: testRun, RoundID: testRound}
	if _, err := report.Build(in); err == nil {
		t.Fatal("a report was issued from a pass that graded nothing")
	}
}

func contains(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}
