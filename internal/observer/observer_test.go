package observer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

// The observer is the only stage that ever holds a response body, so its tests are
// about two things: that retention limits what is *kept* and not what is *read*,
// and that each detector fires for the shape it claims and for nothing else.

var clock = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// blockBody is one interstitial page: a 200-or-403 HTML document that announces a
// rejection in the words filter products actually use.
const blockBody = `<html><body><h1>Request blocked</h1>` +
	`<p>You violated the security policy. Access denied. ` +
	`Contact your network administrator. Incident ID: 1234</p></body></html>`

// benignBody is ordinary product copy. It carries an HTML heading, so the envelope
// detector must not fire on the wording alone.
const benignBody = `<html><body><h1>Search results</h1><p>here are your results</p></body></html>`

func exchangeFor(t *testing.T, status int, body []byte, retention contracts.RetentionPolicy,
	maxRetain int) Exchange {
	t.Helper()
	obs := contracts.ValidRawObservation()
	obs.ResponseStatus = status
	obs.ResponseBodyBytes = len(body)
	obs.ResponseBodyDigest = contracts.NewDigest(body)
	if status == 0 {
		obs.Transport.ErrorClass = "dns_failure"
	}
	return Exchange{
		Observation:    *obs,
		Body:           body,
		Retention:      retention,
		MaxRetainBytes: maxRetain,
		Now:            clock,
		ContentType:    "text/html",
		ServerHeader:   "cloudfront-waf",
	}
}

func patternIDsFor(t *testing.T, rec Records, detectorID string) []string {
	t.Helper()
	r, ok := rec.Readings[detectorID]
	if !ok {
		t.Fatalf("detector %s produced no reading", detectorID)
	}
	var out []string
	for _, m := range r.Matches {
		out = append(out, m.PatternID)
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestDigestOnlyKeepsNothingButStillAnalyses(t *testing.T) {
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 403, []byte(blockBody), contracts.RetainDigestOnly, 4096), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.RetainedBytes != 0 || len(rec.Capture.Body) != 0 {
		t.Fatalf("digest-only retention kept %d bytes", rec.Capture.RetainedBytes)
	}
	if rec.Capture.DroppedReason == "" {
		t.Fatal("a capture that dropped the body must say why")
	}
	if rec.Capture.BodyDigest != contracts.NewDigest([]byte(blockBody)) {
		t.Fatal("the digest must commit to the whole body the client read")
	}
	// The measurement still happened: retention limits storage, not reading.
	if got := patternIDsFor(t, rec, "det.interstitial_phrase"); !has(got, "p.int.request_blocked") {
		t.Fatalf("digest-only run lost the interstitial reading: %v", got)
	}
	if rec.Analysis.BodyDigest != rec.Capture.BodyDigest {
		t.Fatal("C-03 must cite the digest the capture produced")
	}
	// The body must not survive into the journal bytes.
	raw, err := json.Marshal(rec.Capture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "Request blocked") {
		t.Fatalf("journalled capture leaked the body: %s", raw)
	}
}

func TestTruncatedRetentionCapsPrefix(t *testing.T) {
	set := DefaultSet()
	body := []byte(strings.Repeat("a", contracts.MaxTruncatedBodyBytes+1000))
	rec, err := Analyse(exchangeFor(t, 200, body, contracts.RetainTruncated, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.RetainedBytes != contracts.MaxTruncatedBodyBytes {
		t.Fatalf("retained %d bytes, want the prefix cap %d",
			rec.Capture.RetainedBytes, contracts.MaxTruncatedBodyBytes)
	}
	if len(rec.Capture.Body) != contracts.MaxTruncatedBodyBytes {
		t.Fatalf("body field holds %d bytes", len(rec.Capture.Body))
	}
	if rec.Capture.PrefixDigest != contracts.NewDigest(body[:contracts.MaxTruncatedBodyBytes]) {
		t.Fatal("prefix digest does not commit to the retained bytes")
	}
	// The digest covers the whole read body, so the truncated prefix is provably a
	// prefix of it rather than a substitution.
	if rec.Capture.BodyDigest != contracts.NewDigest(body) {
		t.Fatal("body digest must commit to the whole body")
	}
}

func TestTruncatedRetentionHonoursAuthorisedCap(t *testing.T) {
	set := DefaultSet()
	body := []byte(blockBody)
	rec, err := Analyse(exchangeFor(t, 200, body, contracts.RetainTruncated, 16), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.RetainedBytes != 16 {
		t.Fatalf("the authorization said 16 bytes, capture kept %d", rec.Capture.RetainedBytes)
	}
}

func TestTruncatedRetentionRecordsWhyWhenClientStoppedReading(t *testing.T) {
	set := DefaultSet()
	ex := exchangeFor(t, 200, []byte(benignBody), contracts.RetainTruncated, 0)
	ex.BodyTruncated = true
	rec, err := Analyse(ex, set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.DroppedReason == "" {
		t.Fatal("a detector pass over a partially read body must say so")
	}
	if !strings.Contains(rec.Capture.DroppedReason, "in memory") {
		t.Fatalf("reason should explain what was scanned: %q", rec.Capture.DroppedReason)
	}
}

func TestFullAllowedRetentionCapsAtAuthorisedMaximum(t *testing.T) {
	set := DefaultSet()
	body := []byte(strings.Repeat("b", 200))
	rec, err := Analyse(exchangeFor(t, 200, body, contracts.RetainFullAllowed, 50), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.RetainedBytes != 50 {
		t.Fatalf("kept %d of a 50-byte cap", rec.Capture.RetainedBytes)
	}
	if rec.Capture.DroppedReason == "" {
		t.Fatal("retaining less than the body needs an explanation of the remainder")
	}
	if rec.Analysis.BodyDigest != contracts.NewDigest(body) {
		t.Fatal("the analysis digest is of the whole body, not of the retained slice")
	}
}

func TestUnknownRetentionIsRefused(t *testing.T) {
	set := DefaultSet()
	ex := exchangeFor(t, 200, []byte(benignBody), contracts.RetentionPolicy("retain_everything"), 0)
	if _, err := Analyse(ex, set); err == nil {
		t.Fatal("an retention policy this build does not know must not produce records")
	}
}

func TestNoneRetentionKeepsNothing(t *testing.T) {
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 200, []byte(benignBody), contracts.RetainNone, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Capture.RetainedBytes != 0 || rec.Capture.DroppedReason == "" {
		t.Fatalf("retention none must keep zero bytes and state why: %+v", rec.Capture)
	}
}

func TestFourTwentyNineMarksRateLimitedNotBlocked(t *testing.T) {
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 429, []byte(blockBody), contracts.RetainDigestOnly, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if !rec.Analysis.RateLimited {
		t.Fatal("a 429 must set rate_limited so the orchestrator halts")
	}
	// The match is a fact about the bytes; the classifier is what refuses to read it
	// as a block. Dropping it here would hide evidence from the reviewer.
	if rec.Analysis.StatusCode != 429 {
		t.Fatalf("status %d", rec.Analysis.StatusCode)
	}
}

func TestRetryAfterRecordedWithoutChangingReadings(t *testing.T) {
	set := DefaultSet()
	ex := exchangeFor(t, 429, []byte(benignBody), contracts.RetainDigestOnly, 0)
	ex.RetryAfterSeconds = 30
	rec, err := Analyse(ex, set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if !rec.Analysis.HasRetryAfter || rec.Analysis.RetryAfterSeconds != 30 {
		t.Fatalf("Retry-After was not journalled: %+v", rec.Analysis)
	}
}

func TestInterstitialIsDetectedUnderASuccessStatus(t *testing.T) {
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 200, []byte(blockBody), contracts.RetainDigestOnly, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Readings["det.status_shape"].Reading != ReadsNothing {
		t.Fatal("a 200 is not a refusal to handle; the status detector must abstain")
	}
	if rec.Readings["det.interstitial_phrase"].Reading != ReadsBlock {
		t.Fatal("the wording detector must read the block it carries")
	}
	if rec.Readings["det.html_error_envelope"].Reading != ReadsBlock {
		t.Fatal("an error document served with 200 is the envelope detector's case")
	}
	want := []string{"p.int.request_blocked", "p.int.security_policy", "p.int.access_denied",
		"p.int.netadmin", "p.int.incident_id"}
	got := patternIDsFor(t, rec, "det.interstitial_phrase")
	for _, w := range want {
		if !has(got, w) {
			t.Errorf("missing interstitial pattern %s in %v", w, got)
		}
	}
}

func TestStatusShapeFiresOnlyForRefusalCodes(t *testing.T) {
	set := DefaultSet()
	cases := map[int]bool{
		403: true, 405: true, 406: true, 451: true,
		404: false, 401: false, 429: false, 500: false, 200: false,
	}
	for status, wantBlock := range cases {
		rec, err := Analyse(exchangeFor(t, status, []byte(benignBody), contracts.RetainDigestOnly, 0), set)
		if err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		got := rec.Readings["det.status_shape"].Reading
		if wantBlock && got != ReadsBlock {
			t.Errorf("status %d: want block_shape, got %q", status, got)
		}
		if !wantBlock && got != ReadsNothing {
			t.Errorf("status %d: want abstain, got %q -- a routing or origin fact is not a filter claim",
				status, got)
		}
	}
}

func TestEnvelopeNeedsHeadingAndErrorWord(t *testing.T) {
	set := DefaultSet()
	cases := []struct {
		name string
		body string
		want Reading
	}{
		{"html heading, ordinary copy", benignBody, ReadsNothing},
		{"html heading, error wording", blockBody, ReadsBlock},
		{"error wording, no document", "error: blocked", ReadsNothing},
		{"document, no heading", "<html><body>the error is described here</body></html>", ReadsNothing},
	}
	for _, tc := range cases {
		rec, err := Analyse(exchangeFor(t, 200, []byte(tc.body), contracts.RetainDigestOnly, 0), set)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := rec.Readings["det.html_error_envelope"].Reading; got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestLengthCollapseReadsSilentSuccess(t *testing.T) {
	set := DefaultSet()
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{200, "", "p.len.empty_2xx"},
		{200, "ok", "p.len.trivial_2xx"},
		{204, "", ""},
		{200, benignBody, ""},
		{403, "", ""},
	}
	for _, tc := range cases {
		rec, err := Analyse(exchangeFor(t, tc.status, []byte(tc.body), contracts.RetainDigestOnly, 0), set)
		if err != nil {
			t.Fatalf("status %d body %q: %v", tc.status, tc.body, err)
		}
		got := patternIDsFor(t, rec, "det.length_collapse")
		if tc.want == "" {
			if len(got) != 0 {
				t.Errorf("status %d body %q: want abstain, got %v", tc.status, tc.body, got)
			}
			continue
		}
		if !has(got, tc.want) {
			t.Errorf("status %d body %q: want %s, got %v", tc.status, tc.body, tc.want, got)
		}
	}
}

func TestReferenceContrastNeedsACluster(t *testing.T) {
	set := DefaultSet()
	ref, ok := set.ReferenceDetector()
	if !ok {
		t.Fatal("the v1 set must carry a contrast detector")
	}
	ordinary := []Shape{ShapeOf(200, []byte(benignBody)), ShapeOf(200, []byte(benignBody+"!"))}

	// One reference is one observation, not a baseline.
	if r := ref.Contrast(ShapeOf(200, []byte(benignBody)), ordinary[:1]); r.Reading != ReadsNothing {
		t.Fatal("a lone reference must not calibrate the run")
	}
	// A cluster that disagrees measures nothing.
	if r := ref.Contrast(ShapeOf(200, []byte(benignBody)),
		[]Shape{ShapeOf(200, []byte(benignBody)), ShapeOf(403, []byte(blockBody))}); r.Reading != ReadsNothing {
		t.Fatal("two equally supported reference shapes cannot yield a pass reading")
	}
	// Agreement is what earns the reading.
	r := ref.Contrast(ShapeOf(200, []byte(benignBody)), ordinary)
	if r.Reading != ReadsPass {
		t.Fatalf("want pass_shape against an agreeing cluster, got %q", r.Reading)
	}
	if !has(patternIDs(r), "p.con.matches_reference") {
		t.Fatalf("the pass reading needs its pattern: %v", r.Matches)
	}
	// A probe outside the cluster gets no reading at all -- absence of the baseline
	// is not evidence of a block.
	blocked := ref.Contrast(ShapeOf(403, []byte(blockBody)), ordinary)
	if blocked.Reading != ReadsNothing {
		t.Fatal("a probe outside the reference cluster must abstain, not claim a pass")
	}
}

func patternIDs(r Result) []string {
	out := make([]string, 0, len(r.Matches))
	for _, m := range r.Matches {
		out = append(out, m.PatternID)
	}
	return out
}

func TestDetectorSetHashIsTheSetItsOwnMeasurement(t *testing.T) {
	a, b := DefaultSet(), DefaultSet()
	if a.Hash() != b.Hash() {
		t.Fatal("two v1 ensembles must hash identically or signals are not comparable")
	}
	if a.Hash() == "" {
		t.Fatal("the hash is required by C-03")
	}
	mutated := &DetectorSet{detectors: append([]Detector(nil), a.detectors...)}
	mutated.detectors[0].Patterns = append([]Pattern(nil), mutated.detectors[0].Patterns...)
	mutated.detectors[0].Patterns[0].Literal = "changed wording"
	if mutated.Hash() == a.Hash() {
		t.Fatal("changing a pattern must change the hash: the run would claim a set it did not run")
	}
}

func TestReadingsFromSeedsEveryResponseDetector(t *testing.T) {
	set := DefaultSet()
	ids := set.ResponseDetectorIDs()
	if len(ids) != 4 {
		t.Fatalf("v1 has four single-exchange detectors, got %v", ids)
	}
	matches := []contracts.MarkerMatch{
		{DetectorID: "det.status_shape", PatternID: "p.shape.403", Location: "status_line",
			Evidence: contracts.NewDigest([]byte("403"))},
		// A match attributed to a detector outside this ensemble.
		{DetectorID: "det.from_another_build", PatternID: "p.other", Location: "body",
			Evidence: contracts.NewDigest([]byte("x"))},
		// A cluster reading smuggled into a single exchange's analysis.
		{DetectorID: "det.reference_contrast", PatternID: "p.con.matches_reference",
			Location: "reference_cluster", Evidence: contracts.NewDigest([]byte("2xx|b65_512"))},
	}
	readings := set.ReadingsFrom(matches)
	for _, id := range ids {
		if _, ok := readings[id]; !ok {
			t.Errorf("detector %s got no reading; C-04 requires one per consulted detector", id)
		}
	}
	if readings["det.status_shape"].Reading != ReadsBlock {
		t.Errorf("status_shape: want block_shape, got %q", readings["det.status_shape"].Reading)
	}
	for _, id := range []string{"det.interstitial_phrase", "det.html_error_envelope", "det.length_collapse"} {
		if readings[id].Reading != ReadsNothing {
			t.Errorf("detector %s with no match must abstain, got %q", id, readings[id].Reading)
		}
	}
	if _, ok := readings["det.from_another_build"]; ok {
		t.Error("ReadingsFrom must not invent a reading for a detector outside the ensemble")
	}
	if _, ok := readings["det.reference_contrast"]; ok {
		t.Error("a cluster reading is not a single exchange's match: it must be recomputed")
	}
}

func TestAnalyseRefusesUnattributableExchanges(t *testing.T) {
	set := DefaultSet()
	if _, err := Analyse(exchangeFor(t, 403, []byte(blockBody), contracts.RetainDigestOnly, 0), nil); err == nil {
		t.Fatal("an empty ensemble may not classify an exchange")
	}

	noTime := exchangeFor(t, 403, []byte(blockBody), contracts.RetainDigestOnly, 0)
	noTime.Now = time.Time{}
	if _, err := Analyse(noTime, set); err == nil {
		t.Fatal("an undated record cannot be ordered in a journal")
	}

	noID := exchangeFor(t, 403, []byte(blockBody), contracts.RetainDigestOnly, 0)
	noID.Observation.ObservationID = ""
	if _, err := Analyse(noID, set); err == nil {
		t.Fatal("an observation with no id leaves nothing downstream citable")
	}

	silent := exchangeFor(t, 0, nil, contracts.RetainDigestOnly, 0)
	silent.Observation.Transport.ErrorClass = ""
	if _, err := Analyse(silent, set); err == nil {
		t.Fatal("neither a status nor a transport error is not an exchange")
	}
}

func TestTransportFailedExchangeStillProducesAValidAnalysis(t *testing.T) {
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 0, nil, contracts.RetainDigestOnly, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Analysis.StatusCategory != "none" {
		t.Fatalf("a no-response exchange has category %q", rec.Analysis.StatusCategory)
	}
	if len(rec.Analysis.DetectorRefs) == 0 {
		t.Fatal("provenance is required even when nothing matched")
	}
	for _, r := range rec.Readings {
		if r.Reading != ReadsNothing {
			t.Fatal("no detector may read a block out of an exchange that got no response")
		}
	}
}

func TestAnalyseRejectsADetectorThatAbstainsWithMatches(t *testing.T) {
	set := &DetectorSet{detectors: []Detector{{
		ID: "det.bad", Family: "bad", Emits: []Reading{ReadsBlock},
		Patterns: []Pattern{{ID: "p.bad", Literal: "x", Reason: "test"}},
		Evaluate: func(s Shape) Result {
			return Result{Reading: ReadsNothing, Matches: []contracts.MarkerMatch{{
				DetectorID: "det.bad", PatternID: "p.bad", Location: "body",
				Evidence: contracts.NewDigest([]byte("x")),
			}}}
		},
	}}}
	_, err := Analyse(exchangeFor(t, 200, []byte(benignBody), contracts.RetainDigestOnly, 0), set)
	if err == nil {
		t.Fatal("a detector that reports evidence it says it did not see must stop the run")
	}
}

func TestNoHeaderIsReachableFromADetector(t *testing.T) {
	// The lab answers with a filtering product's own header name. Nothing may score
	// it: the type a detector receives carries no headers at all.
	set := DefaultSet()
	rec, err := Analyse(exchangeFor(t, 200, []byte(benignBody), contracts.RetainDigestOnly, 0), set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.Analysis.ServerHeader == "" {
		t.Fatal("the header is journalled as a fact for the reviewer")
	}
	for _, r := range rec.Readings {
		if r.Reading != ReadsNothing {
			t.Fatalf("a Server header named %q produced a reading; the shape type must not carry headers",
				rec.Analysis.ServerHeader)
		}
	}
}

func TestScanWindowBoundsTheBody(t *testing.T) {
	set := DefaultSet()
	body := append([]byte(strings.Repeat("z", ScanWindow)), []byte(blockBody)...)
	ex := exchangeFor(t, 200, body, contracts.RetainDigestOnly, 0)
	rec, err := Analyse(ex, set)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// A marker past the window is missed, which under-reports a block rather than
	// inventing one.
	if got := rec.Readings["det.interstitial_phrase"].Reading; got != ReadsNothing {
		t.Fatalf("want the window to hide the past-window marker, got %q", got)
	}
}
