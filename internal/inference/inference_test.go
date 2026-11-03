package inference_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"xammu/internal/attributor"
	"xammu/internal/contracts"
	"xammu/internal/inference"
	"xammu/internal/integrity"
	"xammu/internal/observer"
	"xammu/internal/orchestrator"
)

// ---------------------------------------------------------------------------
// The lab
//
// The pipeline is exercised over a real socket: the plan is built, the requests
// leave through the single egress, the responses arrive, and everything asserted
// below is read back from the journal files rather than handed to an assertion by
// the code that wrote it. A unit test can check that a rule is implemented; only a
// run like this one checks that the rules still fit together once bytes are
// involved.
// ---------------------------------------------------------------------------

// blockBody is what a rejection page looks like from the outside: an HTML document
// announcing a problem, served with a refusal status.
const blockBody = `<html><body><h1>Request blocked</h1><p>You violated the security policy. ` +
	`Access denied. Contact your network administrator. Incident ID: 1234</p></body></html>`

// ordinaryBody is an ordinary answer to an ordinary request. It carries no heading
// and no rejection wording, so the only reading available to the ensemble is the
// one it earns from the reference cluster.
const ordinaryBody = `{"results":[{"id":1,"name":"widget"},{"id":2,"name":"gadget"},` +
	`{"id":3,"name":"sprocket"}],"count":3,"page":1,"total":3}`

type script struct {
	status int
	body   string
	// drop closes the connection without answering, the only honest way to produce a
	// transport failure against a live target.
	drop bool
}

type lab struct {
	mu      sync.Mutex
	hits    map[string]int
	scripts map[string]script
	srv     *httptest.Server
}

func newLab(t *testing.T, scripts map[string]script) *lab {
	t.Helper()
	l := &lab{hits: map[string]int{}, scripts: scripts}
	l.srv = httptest.NewServer(l)
	t.Cleanup(l.srv.Close)
	return l
}

func (l *lab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("q")
	l.mu.Lock()
	l.hits[key]++
	sc, known := l.scripts[key]
	l.mu.Unlock()
	if !known {
		sc = script{status: http.StatusOK, body: ordinaryBody}
	}
	if sc.drop {
		hj, canHijack := w.(http.Hijacker)
		if !canHijack {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(sc.status)
	_, _ = w.Write([]byte(sc.body))
}

func (l *lab) hitsFor(ref string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits[ref]
}

func (l *lab) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.hits {
		n += c
	}
	return n
}

func (l *lab) origin() string {
	u, _ := url.Parse(l.srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return fmt.Sprintf("http://%s:%d", u.Hostname(), port)
}

// ---------------------------------------------------------------------------
// Authorization and plan
// ---------------------------------------------------------------------------

func authorization(l *lab, at time.Time) *contracts.ProfilingAuthorization {
	u, err := url.Parse(l.srv.URL)
	if err != nil {
		panic(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return &contracts.ProfilingAuthorization{
		AuthorizationID: contracts.NewUUID(),
		Ref:             "auth-inference-e2e",
		IssuedAt:        at.Add(-time.Hour),
		ExpiresAt:       at.Add(time.Hour),
		Issuer:          "security-owner@example.internal",
		ApprovedBy:      "CISO delegate",
		Environment:     contracts.EnvLab,
		Origins: []contracts.Origin{{
			Scheme: "http", Host: u.Hostname(), Port: port,
			PathPrefixes: []string{"/api/"},
			AllowedCIDRs: []string{"127.0.0.0/8"},
		}},
		Methods: []string{"GET", "POST"},
		Limits: contracts.OperationalLimits{
			MaxRequests: 500, RatePerSecond: 1000, MaxRedirects: 0,
			TimeoutMS: 2000, MaxConcurrent: 1, MaxBodyRetainBytes: 4096,
		},
		Retention:        contracts.RetainDigestOnly,
		AllowedClasses:   []contracts.AttackClass{contracts.ClassSQLi},
		AllowedVectors:   []contracts.Vector{contracts.VectorQuery, contracts.VectorBodyJSON},
		AllowedEncodings: []contracts.Encoding{contracts.EncodingCanonical},
		CorpusPartitions: []string{"development"},
		StatementOfScope: "Behavioural profiling of the lab filter only.",
		RulesOfEngagement: []string{
			"no exploitation attempts",
			"stop on any 429 and report",
		},
		ContactForHalt:       "oncall@example.internal",
		IssuerKeyFingerprint: "ed25519:test",
	}
}

type probeSpec struct {
	ref    string
	method string
	vector contracts.Vector
	role   contracts.ControlRole
	body   string
}

func (s probeSpec) item(origin string) orchestrator.PlanItem {
	return orchestrator.PlanItem{
		Ref: s.ref, CorpusRef: "item-" + s.ref, Group: "development",
		Method: s.method, URL: origin + "/api/search?q=" + s.ref,
		Body: []byte(s.body), AttackClass: contracts.ClassSQLi,
		Vector: s.vector, Encoding: contracts.EncodingCanonical,
		ControlRole: s.role,
		Rationale:   "measure how this shape is handled at the authorized path",
	}
}

// fullScript is one round of a normal profile: four canonical SQLi probes in the
// query, which the filter answers with a block page; the same class in the JSON body
// at the same path, which the origin answers ordinarily; one positive control that
// has to be caught; and four exchanges that calibrate what ordinary handling is.
var fullScript = []probeSpec{
	{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	{ref: "P-Q2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	{ref: "P-Q3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	{ref: "P-Q4", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	{ref: "P-B1", method: "POST", vector: contracts.VectorBodyJSON, role: contracts.RoleProbe,
		body: `{"q":"' OR 1=1 --","limit":10,"fields":["id","name"]}`},
	{ref: "P-B2", method: "POST", vector: contracts.VectorBodyJSON, role: contracts.RoleProbe,
		body: `{"q":"UNION SELECT NULL,NULL","limit":10,"fields":["id","name"]}`},
	{ref: "PC-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RolePositiveControl},
	{ref: "NC-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleNegativeControl},
	{ref: "BR-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
	{ref: "BR-2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
	{ref: "BR-3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
}

func fullLab() map[string]script {
	s := map[string]script{}
	for _, ref := range []string{"P-Q1", "P-Q2", "P-Q3", "P-Q4", "PC-1"} {
		s[ref] = script{status: http.StatusForbidden, body: blockBody}
	}
	for _, ref := range []string{"P-B1", "P-B2", "NC-1", "BR-1", "BR-2", "BR-3"} {
		s[ref] = script{status: http.StatusOK, body: ordinaryBody}
	}
	return s
}

// round is one completed pass: the run, the batch result and everything a test needs
// to check them against the files on disk.
type round struct {
	run     *orchestrator.Run
	p       *inference.Pipeline
	res     *inference.Result
	journal *inference.Journal
	ex      *orchestrator.Execution
	lab     *lab
	dir     string
}

func (rd *round) store() *integrity.Store { return rd.run.Store() }

// runPipeline authorizes, plans, executes and infers. It does not assert that
// nothing failed, because two of the scripts below are about runs that failed.
func runPipeline(t *testing.T, scripts map[string]script, specs []probeSpec,
	budget int) *round {
	t.Helper()
	l := newLab(t, scripts)
	base := time.Now().UTC()
	now := func() time.Time { return base }
	dir := t.TempDir()

	r, err := orchestrator.Begin(authorization(l, base), nil, orchestrator.Config{
		RunID: "run-e2e", StoreDir: dir, Partition: "development",
		TargetOrigin: l.origin(), Budget: budget, RoundID: "round-1", Now: now,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := r.Authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	items := make([]orchestrator.PlanItem, 0, len(specs))
	for _, s := range specs {
		items = append(items, s.item(l.origin()))
	}
	if err := r.Plan(items); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		if !r.Store().Sealed() {
			_, _ = r.Finalize("test teardown")
		}
	})

	p, err := inference.New(observer.DefaultSet())
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	ex, err := r.Execute(context.Background(), p.Step)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	j, err := inference.Read(r.Store())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	res, err := p.Infer(j, inference.Options{Sink: r})
	if err != nil {
		t.Fatalf("infer: %v", err)
	}
	return &round{run: r, p: p, res: res, journal: j, ex: ex, lab: l, dir: dir}
}

func verdictFor(res *inference.Result, vector contracts.Vector) *inference.Verdict {
	for i := range res.Verdicts {
		if res.Verdicts[i].Cell.Vector == vector {
			return &res.Verdicts[i]
		}
	}
	return nil
}

func journalText(t *testing.T, dir string, st integrity.Stream) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, string(st)+".jsonl"))
	if err != nil {
		t.Fatalf("read %s journal: %v", st, err)
	}
	return string(raw)
}

func observationOf(t *testing.T, j *inference.Journal, probeRef string) contracts.RawObservation {
	t.Helper()
	for _, o := range j.Observations {
		if o.Sent.ProbeRef == probeRef {
			return o
		}
	}
	t.Fatalf("no observation for probe %s", probeRef)
	return contracts.RawObservation{}
}

func cellRef(j *inference.Journal, vector contracts.Vector) string {
	for _, o := range j.Observations {
		if contracts.Vector(o.Sent.Vector) == vector &&
			contracts.ControlRole(o.Sent.ControlRole) == contracts.RoleProbe {
			return "cell:" + strings.Join([]string{o.Sent.AttackClass, o.Sent.Vector,
				o.Sent.Encoding, o.Target.Path}, "|")
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// The round
// ---------------------------------------------------------------------------

func TestEndToEndRoundProducesCheckableRecords(t *testing.T) {
	rd := runPipeline(t, fullLab(), fullScript, 20)
	res, j, st := rd.res, rd.journal, rd.store()

	if len(rd.ex.Failures) > 0 {
		t.Fatalf("execution reported a failure: %v", rd.ex.Failures[0])
	}
	if len(rd.ex.Executed) != len(fullScript) {
		t.Errorf("%d probes have evidence for %d planned", len(rd.ex.Executed), len(fullScript))
	}
	if rd.lab.total() != len(fullScript) {
		t.Fatalf("the target received %d requests for %d planned probes", rd.lab.total(), len(fullScript))
	}
	if got := rd.lab.hitsFor("P-Q1"); got != 1 {
		t.Fatalf("P-Q1 was sent %d times; a probe is not retried inside one authorization", got)
	}
	if res.ReferenceCount != 4 {
		t.Errorf("reference cluster holds %d exchanges, expected the negative control and the "+
			"three benign references", res.ReferenceCount)
	}
	if len(res.Missing) != 0 {
		t.Fatalf("the trail has gaps: %v", res.Missing)
	}
	if len(res.Divergences) != 0 {
		t.Fatalf("the first pass disagrees with itself: %v", res.Divergences)
	}

	counts := map[integrity.Stream]int{
		integrity.StreamObservations:    len(fullScript),
		integrity.StreamCaptures:        len(fullScript),
		integrity.StreamAnalyses:        len(fullScript),
		integrity.StreamClassifications: len(fullScript),
		integrity.StreamAttributions:    2,
		integrity.StreamStatuses:        2,
		integrity.StreamEvidence:        2,
		integrity.StreamHypotheses:      2,
		integrity.StreamFindings:        0,
	}
	for stream, want := range counts {
		if got := st.Count(stream); got != want {
			t.Errorf("%s holds %d records, expected %d", stream, got, want)
		}
	}

	summary := res.Summary()
	for _, want := range []string{"2 cell(s)", "2 evidence profile(s)", "2 attribution(s)",
		"2 hypothesis(s) (supported 2, refuted 0, inconclusive 0)", "0 undetermined",
		"0 divergence(s)", "0 journal gap(s)", "4 reference exchange(s)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary omits %q:\n%s", want, summary)
		}
	}

	// ---- the cell that was rejected ----------------------------------------
	blocked := verdictFor(res, contracts.VectorQuery)
	if blocked == nil {
		t.Fatal("no verdict for the query cell")
	}
	if len(blocked.Cell.Trials) != 4 {
		t.Fatalf("the query cell holds %d trials; calibration traffic belongs to Controls, "+
			"not inside the denominator it exists to validate", len(blocked.Cell.Trials))
	}
	for _, tr := range blocked.Cell.Trials {
		if tr.ControlRole != contracts.RoleProbe {
			t.Errorf("trial %s has role %s inside a payload cell", tr.ProbeRef, tr.ControlRole)
		}
		if tr.ClassificationID == "" || tr.ObservationID == "" {
			t.Errorf("trial %s cites nothing: a rate nobody can trace is not a measurement", tr.ProbeRef)
		}
	}
	if blocked.Cell.Valid != 4 || blocked.Cell.Invalid != 0 || blocked.Cell.Inconclusive != 0 {
		t.Errorf("query cell arithmetic: valid=%d invalid=%d inconclusive=%d",
			blocked.Cell.Valid, blocked.Cell.Invalid, blocked.Cell.Inconclusive)
	}
	if blocked.Profile.Measured.Numerator != 4 || blocked.Profile.Measured.Denominator != 4 {
		t.Errorf("measured rate %d/%d, expected 4/4",
			blocked.Profile.Measured.Numerator, blocked.Profile.Measured.Denominator)
	}
	if blocked.Profile.Level != contracts.EvidenceReplicatedWithControls {
		t.Errorf("evidence level %s: one round was authorized, so the run stops at controls",
			blocked.Profile.Level)
	}
	if blocked.Profile.ClaimCeiling != contracts.ClaimAssociation {
		t.Errorf("claim ceiling %q is not what %s earns",
			blocked.Profile.ClaimCeiling, blocked.Profile.Level)
	}
	if !blocked.Profile.PositiveControlValid || !blocked.Profile.NegativeControlValid {
		t.Error("this round calibrated and the profile says it did not")
	}
	if len(blocked.Profile.MissingEvidence) == 0 {
		t.Error("a capped profile must name the rung that would raise it")
	}
	if blocked.Hypothesis == nil {
		t.Fatal("a repeated, calibrated rejection produced no hypothesis")
	}
	if blocked.Hypothesis.Outcome != contracts.HypothesisSupported {
		t.Errorf("outcome %q: every prediction of the block claim is testable from this journal",
			blocked.Hypothesis.Outcome)
	}
	if blocked.Hypothesis.ClaimType != contracts.ClaimAssociation {
		t.Errorf("claim type %q exceeds the ceiling the ladder granted", blocked.Hypothesis.ClaimType)
	}
	if blocked.Hypothesis.EvidenceProfileRef != blocked.Profile.ProfileID {
		t.Error("the hypothesis cites a profile other than its cell's")
	}
	if !strings.Contains(blocked.Hypothesis.Statement, "inspects the request payload") {
		t.Errorf("statement does not say what it claims: %s", blocked.Hypothesis.Statement)
	}
	if !strings.Contains(blocked.Hypothesis.Falsifier, "negative control") {
		t.Error("a block claim with no control-shaped falsifier cannot be refuted by anything")
	}
	if !strings.Contains(blocked.Hypothesis.ReproductionCommand, blocked.Cell.Ref()) {
		t.Errorf("reproduction command does not name the cell: %s", blocked.Hypothesis.ReproductionCommand)
	}
	for _, chk := range blocked.Hypothesis.Checks {
		if chk.Result != "met" {
			t.Errorf("prediction %q came out %s in a round that tested it", chk.Prediction, chk.Result)
		}
	}

	// The grade is derived and capped: JAVI-016 lives in these two records.
	if blocked.Attribution == nil || blocked.Status == nil {
		t.Fatal("the query cell has no attribution")
	}
	if blocked.Attribution.Status == contracts.AttributionConfirmed {
		t.Error("C-05 carried confirmation, which only the C-06 conditions gate grants")
	}
	if blocked.Status.Status != contracts.AttributionCompatible {
		t.Errorf("grade %q from one round with valid controls and no independent source; "+
			"expected %q", blocked.Status.Status, contracts.AttributionCompatible)
	}
	if blocked.Status.Conditions.CorroboratedByIndependentSrc {
		t.Error("nothing outside HTTP was supplied, yet the conditions claim corroboration")
	}
	if blocked.Attribution.EvidenceBasis != contracts.BasisHTTPControl {
		t.Errorf("basis %q: the controls are the only thing beyond HTTP here",
			blocked.Attribution.EvidenceBasis)
	}
	if blocked.Attribution.Primary != contracts.AltWAF {
		t.Errorf("primary candidate %q: a payload-shaped rejection points at the filter first",
			blocked.Attribution.Primary)
	}
	if len(blocked.Attribution.Alternatives) != len(contracts.AllAlternativeKinds()) {
		t.Errorf("%d alternatives rated of %d: an unrated alternative is an escape hatch",
			len(blocked.Attribution.Alternatives), len(contracts.AllAlternativeKinds()))
	}

	// ---- the cell that was not ---------------------------------------------
	passed := verdictFor(res, contracts.VectorBodyJSON)
	if passed == nil {
		t.Fatal("no verdict for the body_json cell")
	}
	if passed.Cell.MajorityReading() != contracts.SignalPass {
		t.Errorf("the body cell read %s; two probes answered in the reference shape",
			passed.Cell.MajorityReading())
	}
	if passed.Profile.Measured.Numerator != 0 || passed.Profile.Measured.Denominator != 2 {
		t.Errorf("body cell rate %d/%d, expected 0/2",
			passed.Profile.Measured.Numerator, passed.Profile.Measured.Denominator)
	}
	if passed.Hypothesis == nil || passed.Hypothesis.Outcome != contracts.HypothesisSupported {
		t.Fatal("the pass reading is repeatable and calibrated, so it has to be stated")
	}
	if !strings.Contains(passed.Hypothesis.Statement, "no layer on this path inspects this payload") {
		t.Errorf("pass statement reads: %s", passed.Hypothesis.Statement)
	}
	if passed.Skip != "" {
		t.Errorf("a cell that produced a hypothesis reports no skip reason, got %q", passed.Skip)
	}

	// ---- retention: the body was read, then released -----------------------
	if bodies := journalText(t, rd.dir, integrity.StreamCaptures); strings.Contains(bodies, "Request blocked") ||
		strings.Contains(bodies, "security policy") {
		t.Fatal("a digest-only run journalled response body text")
	}
	for _, o := range j.Observations {
		capture, ok := j.Captures[o.ObservationID]
		if !ok {
			t.Fatalf("observation %s has no capture", o.ObservationID)
		}
		if capture.RetainedBytes != 0 {
			t.Errorf("capture for %s retained %d bytes under digest-only retention",
				o.Sent.ProbeRef, capture.RetainedBytes)
		}
		if capture.BodyDigest != o.ResponseBodyDigest {
			t.Errorf("capture for %s digested a different body than the observation recorded",
				o.Sent.ProbeRef)
		}
	}

	// ---- the reading carries no cause --------------------------------------
	classified := strings.ToLower(journalText(t, rd.dir, integrity.StreamClassifications))
	for _, banned := range []string{"because", "attributed", "waf", "confidence", "malicious", "score"} {
		if strings.Contains(classified, banned) {
			t.Errorf("C-04 contains %q: a classification states a shape, never a cause", banned)
		}
	}

	// ---- every citation resolves -------------------------------------------
	ids := map[string]bool{}
	for _, cls := range j.Classified {
		ids[cls.ClassificationID] = true
	}
	for _, v := range res.Verdicts {
		for _, ref := range v.Profile.Refs {
			if !ids[ref] {
				t.Errorf("profile %s cites %s, which is not a classification in this journal",
					v.Profile.ProfileID, ref)
			}
		}
		known := map[string]bool{v.Profile.ProfileID: true}
		for _, ref := range v.Profile.Refs {
			known[ref] = true
		}
		if v.Hypothesis == nil {
			continue
		}
		for _, chk := range v.Hypothesis.Checks {
			if !known[chk.EvidenceRef] {
				t.Errorf("hypothesis %s check %s cites %s, which its profile does not hold",
					v.Hypothesis.Ref, chk.CheckID, chk.EvidenceRef)
			}
		}
	}
	if got := strings.Join(res.Verdicts[0].Cell.RunIDs, ","); got != "run-e2e" {
		t.Errorf("cell names run %q", got)
	}
}

// TestRereadOfSealedBundleReproducesTheSameRecords is the reviewer's guarantee: a
// second process holding only the files re-derives the same conclusions, reports no
// divergence, and writes nothing.
func TestRereadOfSealedBundleReproducesTheSameRecords(t *testing.T) {
	rd := runPipeline(t, fullLab(), fullScript, 20)

	profile, err := rd.run.Finalize("plan complete")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if profile.State != contracts.StateCompleted {
		t.Fatalf("state %s after every probe was executed inside the budget", profile.State)
	}
	if profile.StopTrigger != contracts.TriggerNone {
		t.Errorf("a completed run reports stop trigger %q", profile.StopTrigger)
	}
	if profile.Counters.PlannedProbes != len(fullScript) {
		t.Errorf("profile planned %d probes for a %d-probe plan",
			profile.Counters.PlannedProbes, len(fullScript))
	}
	if !rd.store().Sealed() {
		t.Error("the evidence trail stayed open after the terminal state")
	}

	heads := map[integrity.Stream]string{}
	for _, st := range integrity.AllStreams() {
		heads[st] = rd.store().Head(st)
	}

	reopened, err := integrity.Open(rd.dir)
	if err != nil {
		t.Fatalf("reopen sealed bundle: %v", err)
	}
	if breaks := reopened.Verify(); len(breaks) != 0 {
		t.Fatalf("the bundle this run just wrote does not verify: %v", breaks[0])
	}
	reread, err := inference.Read(reopened)
	if err != nil {
		t.Fatalf("read sealed bundle: %v", err)
	}
	second, err := rd.p.Infer(reread, inference.Options{})
	if err != nil {
		t.Fatalf("re-read infer: %v", err)
	}

	if len(second.Divergences) != 0 {
		t.Fatalf("the re-read disagrees with the journal: %v", second.Divergences)
	}
	if len(second.Missing) != 0 {
		t.Fatalf("the re-read found gaps that were not there: %v", second.Missing)
	}
	if len(second.Verdicts) != len(rd.res.Verdicts) {
		t.Fatalf("re-read produced %d verdicts, the run produced %d",
			len(second.Verdicts), len(rd.res.Verdicts))
	}
	for i := range rd.res.Verdicts {
		a, b := rd.res.Verdicts[i], second.Verdicts[i]
		if a.Profile.ProfileID != b.Profile.ProfileID {
			t.Errorf("cell %s was graded by a different profile on re-read", a.Cell.Ref())
		}
		if a.Attribution.AttributionID != b.Attribution.AttributionID {
			t.Errorf("cell %s was re-attributed instead of read back", a.Cell.Ref())
		}
		if (a.Hypothesis == nil) != (b.Hypothesis == nil) {
			t.Errorf("cell %s: a hypothesis appeared or vanished on re-read", a.Cell.Ref())
			continue
		}
		if a.Hypothesis == nil {
			continue
		}
		if a.Hypothesis.HypothesisID != b.Hypothesis.HypothesisID {
			t.Errorf("cell %s: the re-read rewrote the hypothesis identifier", a.Cell.Ref())
		}
		if a.Hypothesis.OutcomeReason != b.Hypothesis.OutcomeReason {
			t.Errorf("cell %s: the outcome reason changed between passes", a.Cell.Ref())
		}
	}
	if got := reopened.Count(integrity.StreamClassifications); got != len(fullScript) {
		t.Errorf("the bundle holds %d classifications after a read-only pass", got)
	}
	for _, st := range integrity.AllStreams() {
		if got := reopened.Head(st); got != heads[st] {
			t.Errorf("%s grew during a read-only re-derivation", st)
		}
	}
}

// TestRateLimitedExchangeIsPacingNotProtection pins criterion 24 at the end of the
// pipe: a 429 whose body is a block page is still a limit, the patterns it carried
// never reach C-04, and its cell produces no claim about a filter.
func TestRateLimitedExchangeIsPacingNotProtection(t *testing.T) {
	scripts := map[string]script{
		"P-Q1": {status: http.StatusTooManyRequests, body: blockBody},
	}
	specs := []probeSpec{
		{ref: "BR-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)

	if state := rd.run.Profile().State; state != contracts.StateHaltedRateLimit {
		t.Fatalf("state after a 429 is %s, expected the rate-limit halt", state)
	}
	if rd.lab.total() != 4 {
		t.Errorf("the target received %d requests; a limit stops the run, not slows it", rd.lab.total())
	}

	obs := observationOf(t, rd.journal, "P-Q1")
	cls := rd.journal.Classified[obs.ObservationID]
	if cls.Signal != contracts.SignalRateLimited {
		t.Fatalf("signal %q for a 429 that carried an interstitial page", cls.Signal)
	}
	if len(cls.MatchedPatterns) != 0 {
		t.Errorf("C-04 kept %v as block evidence; pacing is not protection", cls.MatchedPatterns)
	}
	if cls.DetectorAgreement != "no_firing" {
		t.Errorf("agreement %q for a rate limit; nothing was read", cls.DetectorAgreement)
	}
	// The block page really was there: dropping the patterns is a decision taken at
	// C-04, not a detector that failed to fire.
	if len(rd.journal.Analyses[obs.ObservationID].Matches) == 0 {
		t.Fatal("the observer found nothing in a body that says Request blocked")
	}

	if len(rd.res.Verdicts) != 1 {
		t.Fatalf("%d verdicts for the one probe cell this run attempted", len(rd.res.Verdicts))
	}
	v := rd.res.Verdicts[0]
	if v.Cell.MajorityReading() != contracts.SignalRateLimited {
		t.Fatalf("cell reads %s", v.Cell.MajorityReading())
	}
	if v.Hypothesis != nil {
		t.Error("a paced exchange produced a hypothesis about a filter")
	}
	if !strings.Contains(v.Skip, "limit response") {
		t.Errorf("skip reason does not name the pacing: %q", v.Skip)
	}
	if got := rd.store().Count(integrity.StreamHypotheses); got != 0 {
		t.Errorf("%d hypotheses journalled over a paced cell", got)
	}

	profile, err := rd.run.Finalize("halted by the target")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if profile.State != contracts.StateTruncated {
		t.Errorf("state %s: a run cut short by pacing is truncated, never completed", profile.State)
	}
	if profile.StopTrigger != contracts.TriggerRateLimited ||
		profile.TerminalCode != contracts.ReasonRateLimited {
		t.Errorf("terminal report %s/%s, expected the rate limit",
			profile.StopTrigger, profile.TerminalCode)
	}
}

// TestUnansweredExchangesLeaveAnUndeterminedArea is the honest shape of a bad run: a
// target that never answers produces a typed obstacle and no claim. The zone is
// undetermined, not quiet.
func TestUnansweredExchangesLeaveAnUndeterminedArea(t *testing.T) {
	scripts := map[string]script{"P-Q1": {drop: true}, "P-Q2": {drop: true}}
	specs := []probeSpec{
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
		{ref: "P-Q2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)

	if len(rd.ex.Failures) != 2 {
		t.Errorf("%d probe failures for two exchanges that never completed", len(rd.ex.Failures))
	}
	if len(rd.res.Verdicts) != 1 {
		t.Fatalf("%d verdicts for one cell", len(rd.res.Verdicts))
	}
	v := rd.res.Verdicts[0]
	if v.Cell.Valid != 0 || v.Cell.Invalid != 2 {
		t.Errorf("valid=%d invalid=%d", v.Cell.Valid, v.Cell.Invalid)
	}
	if v.Profile.Level != contracts.EvidenceNone {
		t.Errorf("evidence level %s over 0 valid trials", v.Profile.Level)
	}
	if v.Profile.ClaimCeiling != "" {
		t.Errorf("claim ceiling %q with no valid trial", v.Profile.ClaimCeiling)
	}
	if v.Hypothesis != nil {
		t.Error("a subject with no valid trial produced a hypothesis")
	}
	if len(v.Obstacles) == 0 || v.Obstacles[0].Reason != contracts.ReasonTransportFailure {
		t.Errorf("obstacles %v: the zone must be undetermined for a typed reason", v.Obstacles)
	}
	if !strings.Contains(v.Skip, "undetermined") {
		t.Errorf("skip reason %q does not call this what it is", v.Skip)
	}
	if len(v.Profile.MissingEvidence) == 0 {
		t.Error("a level-none profile must say what would earn a claim")
	}
	if rd.res.ReferenceCount != 0 {
		t.Errorf("reference cluster of %d with no calibration traffic", rd.res.ReferenceCount)
	}
	if got := rd.store().Count(integrity.StreamHypotheses); got != 0 {
		t.Errorf("%d hypotheses journalled over nothing", got)
	}
	if got := rd.store().Count(integrity.StreamEvidence); got != 1 {
		t.Errorf("%d evidence profiles: the coverage gap is itself a record", got)
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

func TestInferRefusesAJournalItWasNotBuiltFor(t *testing.T) {
	p, err := inference.New(observer.DefaultSet())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Infer(nil, inference.Options{}); err == nil {
		t.Fatal("Infer accepted no journal")
	}
	if _, err := p.Infer(&inference.Journal{RunID: "run-empty"}, inference.Options{}); err == nil ||
		!strings.Contains(err.Error(), "nothing to infer") {
		t.Fatalf("an empty journal was answered with %v", err)
	}
	// A journal whose analyses came from a different ensemble cannot be classified by
	// this one: the records would claim a measurement they never performed.
	j := &inference.Journal{
		RunID: "run-x", SetHash: "sha256:not-this-set",
		Observations: []contracts.RawObservation{{
			ObservationID: contracts.NewUUID(), RunID: "run-x",
			Sequence: 1, ResponseStatus: http.StatusForbidden,
		}},
	}
	if _, err := p.Infer(j, inference.Options{}); err == nil ||
		!strings.Contains(err.Error(), "did not make them") {
		t.Fatalf("a foreign detector set was answered with %v", err)
	}
	if _, err := inference.New(nil); err == nil {
		t.Fatal("a pipeline with no ensemble was built")
	}
	if _, err := inference.Read(nil); err == nil {
		t.Fatal("Read accepted no store")
	}
}

func TestReadRefusesATamperedJournal(t *testing.T) {
	scripts := map[string]script{
		"P-Q1": {status: http.StatusForbidden, body: blockBody},
	}
	specs := []probeSpec{
		{ref: "BR-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)
	if _, err := rd.run.Finalize("done"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if breaks := integrity.VerifyDir(rd.dir); len(breaks) != 0 {
		t.Fatalf("a clean bundle reported breaks: %v", breaks)
	}

	path := filepath.Join(rd.dir, string(integrity.StreamClassifications)+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("the classifications journal holds %d lines", len(lines))
	}
	// Remove one exchange's classification and leave every remaining byte untouched:
	// the chain still ends in an honest record, so only a full walk notices the hole.
	middle := len(lines) / 2
	remaining := append(append([]string{}, lines[:middle]...), lines[middle+1:]...)
	if err := os.WriteFile(path, []byte(strings.Join(remaining, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	store, err := integrity.Open(rd.dir)
	if err != nil {
		// Caught at open time, which is the same refusal arriving one step earlier.
		return
	}
	if _, err := inference.Read(store); err == nil {
		t.Fatal("inference read a journal with a classification missing from it")
	} else if !strings.Contains(err.Error(), "chain is broken") {
		t.Fatalf("the refusal did not name the damage: %v", err)
	}
}

// TestCorroborationRaisesTheGradeWithoutInventingEvidence states the boundary of
// C-06: an independent source is supplied by an operator, never fetched, and it is
// the only thing that lifts a grade above the HTTP ceiling. It moves no count.
func TestCorroborationRaisesTheGradeWithoutInventingEvidence(t *testing.T) {
	scripts := map[string]script{
		"P-Q1": {status: http.StatusForbidden, body: blockBody},
	}
	specs := []probeSpec{
		{ref: "BR-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)
	ref := cellRef(rd.journal, contracts.VectorQuery)
	if ref == "" {
		t.Fatal("the probe cell produced no subject reference")
	}

	// A re-read of the same journal with a filter log handed over by the operator. No
	// sink: the evidence that is already written is not rewritten by the newcomer.
	res, err := rd.p.Infer(rd.journal, inference.Options{
		Corroboration: map[string]*attributor.Corroboration{ref: {
			Kind: "filter_log", Ref: "waf-log-2026-10-28-0007", Agrees: true,
			Detail: "rule 402 dropped the request at the edge",
		}},
	})
	if err != nil {
		t.Fatalf("infer with corroboration: %v", err)
	}
	v := verdictFor(res, contracts.VectorQuery)
	if v == nil || v.Attribution == nil {
		t.Fatal("no attribution came back for the corroborated cell")
	}
	if v.Attribution.Status != contracts.AttributionSupportedByLogs {
		t.Errorf("C-05 grade %q with an independent source that agrees", v.Attribution.Status)
	}
	if v.Status.Status != contracts.AttributionSupportedByLogs {
		t.Errorf("C-06 grade %q: corroboration alone does not grant confirmation, which also "+
			"needs reproduction across two rounds", v.Status.Status)
	}
	if v.Status.Conditions.ReproducibleAcrossRounds {
		t.Error("one round was run and the conditions say otherwise")
	}
	if v.Profile.Level != contracts.EvidenceSingleObservation {
		t.Errorf("level %s over one valid trial", v.Profile.Level)
	}
	if v.Profile.ClaimCeiling != contracts.ClaimDescriptive {
		t.Errorf("ceiling %q: corroboration is not a replica", v.Profile.ClaimCeiling)
	}
	if v.Hypothesis == nil {
		t.Fatal("a corroborated single observation is still a testable statement")
	}
	if v.Hypothesis.Outcome != contracts.HypothesisInconclusive {
		t.Errorf("outcome %q: one trial cannot test the repetition prediction",
			v.Hypothesis.Outcome)
	}
	if v.Hypothesis.InconclusiveReason == "" {
		t.Error("an inconclusive hypothesis must carry the typed obstacle that left it so")
	}
	if len(v.Hypothesis.Checks) == 0 {
		t.Fatal("the cell that could not repeat its reading must say so in its checks")
	}
	// Corroboration moves the grade and nothing else: the counts the report reads are
	// the ones the journal produced.
	if v.Profile.ValidTrials != 1 || v.Profile.Replicas != 1 {
		t.Errorf("profile counts moved by corroboration: valid=%d replicas=%d",
			v.Profile.ValidTrials, v.Profile.Replicas)
	}
	if v.Profile.CorroborationSource != "" {
		t.Errorf("the profile of the first pass said %q before any log existed",
			v.Profile.CorroborationSource)
	}
}

// TestAnIndeterminateReadingIsReportedAndNotForced: two probes whose shape matches
// neither the reference cluster nor a rejection page produce mixed cells and no
// claim, while the run itself still reports what it did.
func TestAnIndeterminateReadingIsNotForcedIntoAClaim(t *testing.T) {
	// A 404 for a payload: routing says nothing, and a rejection reading would be
	// invented rather than observed.
	notFound := `<html><body><h1>Not found</h1>` +
		`<p>The requested route does not exist on this origin.</p></body></html>`
	scripts := map[string]script{
		"P-Q1": {status: http.StatusNotFound, body: notFound},
		"P-Q2": {status: http.StatusNotFound, body: notFound},
	}
	specs := []probeSpec{
		{ref: "BR-1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "BR-3", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleBenignReference},
		{ref: "P-Q1", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
		{ref: "P-Q2", method: "GET", vector: contracts.VectorQuery, role: contracts.RoleProbe},
	}
	rd := runPipeline(t, scripts, specs, 10)

	v := verdictFor(rd.res, contracts.VectorQuery)
	if v == nil {
		t.Fatal("no verdict for the 404 cell")
	}
	if v.Cell.MajorityReading() != "" {
		t.Errorf("majority reading %q: both trials are indeterminate, so no valid trial exists",
			v.Cell.MajorityReading())
	}
	if v.Cell.Inconclusive != 2 || v.Cell.Valid != 0 {
		t.Errorf("inconclusive=%d valid=%d over two indeterminate exchanges",
			v.Cell.Inconclusive, v.Cell.Valid)
	}
	if v.Hypothesis != nil {
		t.Error("an unreadable response produced a hypothesis")
	}
	if v.Skip == "" {
		t.Error("the cell vanished silently instead of becoming an undetermined area")
	}
	for _, cls := range rd.journal.Classified {
		if cls.ProbeRef == "P-Q1" || cls.ProbeRef == "P-Q2" {
			if cls.Signal != contracts.SignalIndeterminate {
				t.Errorf("probe %s read %s; a 404 is neither a rejection nor ordinary handling",
					cls.ProbeRef, cls.Signal)
			}
		}
	}
	profile, err := rd.run.Finalize("plan complete")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	// The exchanges happened and were recorded honestly; the gap is in the reading,
	// and C-11 counts it so a summary cannot present the run as two clean trials.
	if profile.State != contracts.StateCompleted {
		t.Errorf("state %s", profile.State)
	}
	if profile.Counters.Indeterminate != 2 {
		t.Errorf("indeterminate counter is %d after two unreadable responses",
			profile.Counters.Indeterminate)
	}
	if profile.Counters.ValidTrials != 3 || profile.Counters.InvalidTrials != 2 {
		t.Errorf("valid=%d invalid=%d: the three benign references calibrated, the two probes did not",
			profile.Counters.ValidTrials, profile.Counters.InvalidTrials)
	}
	if profile.Counters.Hypotheses != 0 {
		t.Errorf("%d hypotheses over a run whose payload cells were unreadable",
			profile.Counters.Hypotheses)
	}
}
