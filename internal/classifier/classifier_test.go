package classifier

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/observer"
)

var clock = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const blockBody = `<html><body><h1>Request blocked</h1>` +
	`<p>You violated the security policy. Access denied. ` +
	`Contact your network administrator. Incident ID: 1234</p></body></html>`

const benignBody = `<html><body><h1>Search results</h1><p>here are your results</p></body></html>`

// ordinaryText carries no interstitial wording, no error heading and enough bytes
// to clear the length detector, so only the status line can say anything about it.
const ordinaryText = "the quick brown fox jumps over the lazy dog and keeps on jumping for a while"

type run struct {
	t    *testing.T
	set  *observer.DetectorSet
	c    *Classifier
	obs  contracts.RawObservation
	an   contracts.SignatureAnalysis
	refs []observer.Shape
}

func newRun(t *testing.T, status int, body string) *run {
	t.Helper()
	set := observer.DefaultSet()
	c, err := New(set)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bytes := []byte(body)
	obs := contracts.ValidRawObservation()
	obs.ResponseStatus = status
	obs.ResponseBodyBytes = len(bytes)
	obs.ResponseBodyDigest = contracts.NewDigest(bytes)
	rec, err := observer.Analyse(observer.Exchange{
		Observation: *obs, Body: bytes,
		Retention: contracts.RetainDigestOnly, Now: clock,
	}, set)
	if err != nil {
		t.Fatalf("observer.Analyse: %v", err)
	}
	return &run{t: t, set: set, c: c, obs: *obs, an: rec.Analysis}
}

func (r *run) classify() contracts.BehavioralClassification {
	r.t.Helper()
	b, err := r.c.Classify(Input{
		Observation: r.obs, Analysis: r.an, References: r.refs, Now: clock,
	})
	if err != nil {
		r.t.Fatalf("Classify: %v", err)
	}
	return b
}

func shapesFor(body string, status int, n int) []observer.Shape {
	out := make([]observer.Shape, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, observer.ShapeOf(status, []byte(body)))
	}
	return out
}

func TestRateLimitedIsNeverABlock(t *testing.T) {
	// Criterion 24: the lab answers a probe with a full interstitial and a 429.
	r := newRun(t, 429, blockBody)
	if len(r.an.Matches) == 0 {
		t.Fatal("the observer must still journal what the bytes said")
	}
	b := r.classify()
	if b.Signal != contracts.SignalRateLimited {
		t.Fatalf("want signal_rate_limited, got %s", b.Signal)
	}
	// The patterns are dropped, not kept-and-ignored, so no later stage can re-read
	// pacing as protection.
	if len(b.MatchedPatterns) != 0 {
		t.Fatalf("a rate-limited exchange carries no scored patterns, got %v", b.MatchedPatterns)
	}
	if b.DetectorAgreement != "no_firing" {
		t.Fatalf("agreement %q", b.DetectorAgreement)
	}
	if len(b.NonFiredDetectors) != len(r.set.IDs()) {
		t.Fatalf("every consulted detector is listed as non-firing, got %v", b.NonFiredDetectors)
	}
	if err := contracts.Validate(contracts.IDBehavioralClassification, &b); err != nil {
		t.Fatalf("C-04: %v", err)
	}
}

func TestTransportFailureShortCircuits(t *testing.T) {
	set := observer.DefaultSet()
	c, _ := New(set)
	obs := contracts.ValidRawObservation()
	obs.ResponseStatus = 0
	obs.Transport.ErrorClass = "connection_reset"
	obs.ResponseBodyBytes = 0
	obs.ResponseBodyDigest = contracts.NewDigest(nil)
	an := contracts.ValidSignatureAnalysis()
	an.ObservationID = obs.ObservationID
	an.RunID = obs.RunID
	an.StatusCode = 0
	an.StatusCategory = "none"
	an.BodyDigest = obs.ResponseBodyDigest
	an.DetectorSetHash = set.Hash()
	an.Matches = nil
	b, err := c.Classify(Input{Observation: *obs, Analysis: *an, Now: clock})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if b.Signal != contracts.SignalTransportError {
		t.Fatalf("want transport_error, got %s", b.Signal)
	}
	if len(b.NonFiredDetectors) != len(set.IDs()) {
		t.Fatal("a socket failure fired nothing; the reviewer needs that recorded")
	}
}

func TestRedirectChainIsItsOwnSignal(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		r := newRun(t, status, blockBody)
		b := r.classify()
		if b.Signal != contracts.SignalRedirect {
			t.Errorf("status %d: want signal_redirect, got %s", status, b.Signal)
		}
		if len(b.MatchedPatterns) != 0 {
			t.Errorf("status %d: a chain that never reached an answer is not scored: %v",
				status, b.MatchedPatterns)
		}
	}
	// A 304 is a terminal answer about freshness, not a chain.
	r := newRun(t, 304, blockBody)
	if b := r.classify(); b.Signal == contracts.SignalRedirect {
		t.Fatal("304 must be read as a response, not hidden as a redirect")
	}
}

func TestBlockShapeWithoutReferences(t *testing.T) {
	r := newRun(t, 403, blockBody)
	b := r.classify()
	if b.Signal != contracts.SignalBlock {
		t.Fatalf("want signal_block, got %s", b.Signal)
	}
	if b.DetectorAgreement != "all_agree" {
		t.Fatalf("agreement %q", b.DetectorAgreement)
	}
	for _, want := range []string{"p.shape.403", "p.int.request_blocked", "p.env.html_document"} {
		if !contains(b.MatchedPatterns, want) {
			t.Errorf("matched patterns %v missing %s", b.MatchedPatterns, want)
		}
	}
	if contains(b.MatchedPatterns, "p.con.matches_reference") {
		t.Error("a pass reading needs a cluster; none was supplied")
	}
	if !contains(b.NonFiredDetectors, "det.length_collapse") {
		t.Errorf("the length detector abstained and must be listed: %v", b.NonFiredDetectors)
	}
}

func TestPassRequiresAnAgreeingCluster(t *testing.T) {
	r := newRun(t, 200, benignBody)
	// No cluster: nothing in a response alone proves it was the ordinary answer.
	if b := r.classify(); b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("want indeterminate with no references, got %s", b.Signal)
	}
	// One reference is one observation, not a baseline.
	r.refs = shapesFor(benignBody, 200, 1)
	if b := r.classify(); b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("want indeterminate against a lone reference, got %s", b.Signal)
	}
	// Two agreeing references calibrate the run.
	r.refs = shapesFor(benignBody, 200, 2)
	b := r.classify()
	if b.Signal != contracts.SignalPass {
		t.Fatalf("want signal_pass against an agreeing cluster, got %s", b.Signal)
	}
	if !contains(b.MatchedPatterns, "p.con.matches_reference") {
		t.Errorf("the pass reading must cite its pattern: %v", b.MatchedPatterns)
	}
	// A cluster that disagrees measures nothing.
	r.refs = append(shapesFor(benignBody, 200, 1), observer.ShapeOf(500, []byte("x")))
	if b := r.classify(); b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("an uncalibrated run must not report a pass, got %s", b.Signal)
	}
}

func TestDisagreementIsIndeterminateNotMajority(t *testing.T) {
	// One rejection reading (the status line) against one ordinary-handling reading
	// (the cluster). Three detectors against one is also a response the ensemble has
	// no name for.
	split := newRun(t, 403, ordinaryText)
	split.refs = shapesFor(ordinaryText, 403, 2)
	b := split.classify()
	if b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("1 block vs 1 pass: want indeterminate, got %s", b.Signal)
	}
	if b.DetectorAgreement != "split" {
		t.Fatalf("agreement %q, want split", b.DetectorAgreement)
	}

	outvoted := newRun(t, 403, blockBody)
	outvoted.refs = shapesFor(blockBody, 403, 2)
	o := outvoted.classify()
	if o.Signal != contracts.SignalIndeterminate {
		t.Fatalf("3 block vs 1 pass: want indeterminate, got %s", o.Signal)
	}
	if o.DetectorAgreement != "majority" {
		t.Fatalf("agreement %q, want majority", o.DetectorAgreement)
	}
	// Awarding the majority would turn one ambiguous page into a claim about a
	// filter, so the pattern list stays honest about which detectors spoke.
	if len(o.MatchedPatterns) == 0 {
		t.Error("the readings that fired are still journalled as evidence of the conflict")
	}
}

func TestNothingFiredIsReportedAsSuch(t *testing.T) {
	r := newRun(t, 200, ordinaryText)
	b := r.classify()
	if b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("want indeterminate, got %s", b.Signal)
	}
	if b.DetectorAgreement != "no_firing" {
		t.Fatalf("agreement %q", b.DetectorAgreement)
	}
	if len(b.MatchedPatterns) != 0 {
		t.Fatalf("no detector fired, so no pattern may be listed: %v", b.MatchedPatterns)
	}
	if len(b.NonFiredDetectors) != len(r.set.IDs()) {
		t.Fatalf("non-fired list must name all consulted detectors: %v", b.NonFiredDetectors)
	}
}

func TestProvenanceNamesTheWholeEnsemble(t *testing.T) {
	r := newRun(t, 403, blockBody)
	b := r.classify()
	// C-04 records the ensemble consulted, not only the members that fired, so a
	// reviewer can re-run exactly this measurement.
	if len(b.DetectorRefs) != len(r.set.IDs()) {
		t.Fatalf("detector_refs %v does not name the full set %v", b.DetectorRefs, r.set.IDs())
	}
	if b.DetectorSetHash != r.set.Hash() {
		t.Fatal("the classification must commit to the set that produced it")
	}
	if b.ClassifierVer != Version {
		t.Fatalf("classifier_version %q", b.ClassifierVer)
	}
	if b.ObservationID != r.obs.ObservationID || b.AnalysisID != r.an.AnalysisID {
		t.Fatal("the chain of citations is how a reviewer walks back to the bytes")
	}
	if b.RunID != r.obs.RunID || b.ProbeRef != r.obs.Sent.ProbeRef ||
		b.ControlRole != r.obs.Sent.ControlRole {
		t.Fatal("run, probe and control role come from the observation, not from defaults")
	}
	if b.StatusCategory != contracts.StatusCategory(r.obs.ResponseStatus) {
		t.Fatal("status category disagrees with the status")
	}
}

func TestRefusesAMismatchedAnalysis(t *testing.T) {
	set := observer.DefaultSet()
	c, _ := New(set)
	r := newRun(t, 403, blockBody)
	cases := []struct {
		name   string
		mutate func(*contracts.SignatureAnalysis, *contracts.RawObservation)
		want   string
	}{
		{"observation id", func(a *contracts.SignatureAnalysis, _ *contracts.RawObservation) {
			a.ObservationID = contracts.NewUUID()
		}, "belongs to observation"},
		{"run id", func(a *contracts.SignatureAnalysis, _ *contracts.RawObservation) {
			a.RunID = "run-somebody-elses"
		}, "from run"},
		{"status", func(a *contracts.SignatureAnalysis, _ *contracts.RawObservation) {
			a.StatusCode = 200
		}, "against an observation of"},
		{"body digest", func(a *contracts.SignatureAnalysis, _ *contracts.RawObservation) {
			a.BodyDigest = contracts.NewDigest([]byte("another body"))
		}, "not the body that arrived"},
	}
	for _, tc := range cases {
		obs := r.obs
		an := r.an
		tc.mutate(&an, &obs)
		_, err := c.Classify(Input{Observation: obs, Analysis: an, Now: clock})
		if err == nil {
			t.Errorf("%s: a joined-up wrong pair must be refused", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not say what drifted", tc.name, err)
		}
	}
}

func TestRefusesAnAnalysisFromAnotherDetectorSet(t *testing.T) {
	r := newRun(t, 403, blockBody)
	other := &r.an
	other.DetectorSetHash = contracts.NewDigest([]byte("a different ensemble"))
	_, err := r.c.Classify(Input{Observation: r.obs, Analysis: *other, Now: clock})
	if err == nil {
		t.Fatal("signals from a different set are not the same measurement")
	}
	if !strings.Contains(err.Error(), "same measurement") {
		t.Fatalf("error %q must explain comparability", err)
	}
}

func TestRefusesUndatedOrUnidentifiedInput(t *testing.T) {
	r := newRun(t, 403, blockBody)
	if _, err := r.c.Classify(Input{Observation: r.obs, Analysis: r.an}); err == nil {
		t.Fatal("an undated classification cannot be ordered")
	}
	obs := r.obs
	obs.ObservationID = ""
	if _, err := r.c.Classify(Input{Observation: obs, Analysis: r.an, Now: clock}); err == nil {
		t.Fatal("without an id nothing downstream can cite the exchange")
	}
}

func TestNilSetIsRefusedNotDefaulted(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("a silent default is how a run comes back classified by a set nobody approved")
	}
}

// A set carrying two cluster detectors is refused rather than half-consulted: the
// first would answer for both and the classification would claim a provenance it did
// not use.
func TestSetWithTwoReferenceDetectorsIsRefused(t *testing.T) {
	base := observer.DefaultSet()
	dets := base.Detectors()
	second := dets[len(dets)-1]
	second.ID = "det.second_contrast"
	set, err := observer.NewSet(append(dets, second)...)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	c, err := New(set)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := newRun(t, 200, benignBody)
	an := r.an
	an.DetectorSetHash = set.Hash()
	if _, err := c.Classify(Input{Observation: r.obs, Analysis: an,
		References: shapesFor(benignBody, 200, 2), Now: clock}); err == nil {
		t.Fatal("a detector that produced no reading must stop the classification")
	}
}

func TestClassificationCarriesNoCause(t *testing.T) {
	// The contract refuses interpretive keys; the classifier must not invent a field
	// that names a cause either.
	r := newRun(t, 403, blockBody)
	b := r.classify()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, banned := range []string{"because", "attributed", "waf", "confidence", "score", "malicious"} {
		if strings.Contains(strings.ToLower(string(raw)), banned) {
			t.Errorf("C-04 bytes carry %q, which is the attributor's job: %s", banned, raw)
		}
	}
}

// TestFailingOriginIsNotOrdinaryHandling pins the 5xx rule at C-04. A destination
// that fails answers with a shape the cluster would otherwise read as ordinary
// handling: the body is a normal answer and the status matches the references. What
// the front end would have done with the payload was never measured, so the exchange
// is indeterminate and the pass patterns are dropped rather than carried forward.
func TestFailingOriginIsNotOrdinaryHandling(t *testing.T) {
	r := newRun(t, 502, benignBody)
	// Without the status rule this cluster reading would be a pass: same shape, same
	// status, two agreeing references.
	r.refs = shapesFor(benignBody, 502, 3)
	b := r.classify()
	if b.Signal != contracts.SignalIndeterminate {
		t.Fatalf("a 502 read as %s: the origin failed, so the payload was never handled", b.Signal)
	}
	if b.DetectorAgreement != "no_firing" {
		t.Fatalf("agreement %q: nothing about the payload was measured", b.DetectorAgreement)
	}
	if len(b.MatchedPatterns) != 0 {
		t.Fatalf("a failing origin carries no scored patterns, got %v", b.MatchedPatterns)
	}
	if len(b.NonFiredDetectors) != len(r.set.IDs()) {
		t.Fatalf("every consulted detector is listed as non-firing, got %v", b.NonFiredDetectors)
	}
	if err := contracts.Validate(contracts.IDBehavioralClassification, &b); err != nil {
		t.Fatalf("C-04: %v", err)
	}
}

// TestAFailingOriginThatServesAnInterstitialIsStillABlock is the other side of the
// same rule: a rejection reading is a decision, so a WAF page served with a 503 stays
// a block. The status alone must not erase what the body and the ensemble read.
func TestAFailingOriginThatServesAnInterstitialIsStillABlock(t *testing.T) {
	r := newRun(t, 503, blockBody)
	b := r.classify()
	if b.Signal != contracts.SignalBlock {
		t.Fatalf("a 503 carrying a rejection page read as %s", b.Signal)
	}
	if !contains(b.MatchedPatterns, "p.int.request_blocked") {
		t.Errorf("the interstitial reading must survive the status: %v", b.MatchedPatterns)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
