package attributor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
)

var clock = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// newSubject is one probe cell answered with a rejection, plus the control pair that
// makes the reading mean something.
func newSubject(signal contracts.Signal, status int) Subject {
	return Subject{
		RunID: "run-2026-10-28-lab", Ref: "cell:sqli|query|canonical|/api/search",
		AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding:     contracts.EncodingCanonical,
		TargetOrigin: "https://lab.local:8443", Path: "/api/search",
		Evidence: []Datum{{
			RoundID: "round-1", Classification: contracts.NewUUID(),
			Observation: contracts.NewUUID(), ProbeRef: "P-SQLI-001",
			Signal: signal, StatusCode: status,
		}},
		Controls: Controls{
			PositiveRefs:    []string{"cls-pos"},
			PositiveSignals: []contracts.Signal{contracts.SignalBlock},
			NegativeRefs:    []string{"cls-neg"},
			NegativeSignals: []contracts.Signal{contracts.SignalPass},
		},
		Now: clock,
	}
}

func (s Subject) withRounds(names ...string) Subject {
	for _, name := range names {
		s.Evidence = append(s.Evidence, Datum{
			RoundID: name, Classification: contracts.NewUUID(), Observation: contracts.NewUUID(),
			ProbeRef: "P-SQLI-001", Signal: s.Evidence[0].Signal, StatusCode: s.Evidence[0].StatusCode,
		})
	}
	return s
}

func stateOf(rep Report, kind contracts.AlternativeKind) contracts.AlternativeState {
	for _, alt := range rep.Attribution.Alternatives {
		if alt.Kind == kind {
			return alt.State
		}
	}
	return contracts.AlternativeState("missing")
}

func TestGradeIsDerivedFromConditions(t *testing.T) {
	rep, err := Attribute(newSubject(contracts.SignalBlock, 403))
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	// One round, valid controls, no source outside the exchange: the HTTP ceiling.
	if rep.Status.Status != contracts.AttributionCompatible {
		t.Fatalf("want compatible, got %s", rep.Status.Status)
	}
	if rep.Attribution.Status != contracts.AttributionCompatible {
		t.Fatalf("C-05 says %s", rep.Attribution.Status)
	}
	if rep.Status.EvidenceBasis != contracts.BasisHTTPControl {
		t.Fatalf("basis %s", rep.Status.EvidenceBasis)
	}
	if rep.Attribution.Primary != contracts.AltWAF {
		t.Fatalf("primary %s", rep.Attribution.Primary)
	}
	if stateOf(rep, contracts.AltWAF) != contracts.AltSupported {
		t.Fatalf("WAF candidate: %s", stateOf(rep, contracts.AltWAF))
	}
	// The grade is stated next to the test that would raise it.
	var raised bool
	for _, m := range rep.Status.MissingEvidence {
		if strings.Contains(m, "round") {
			raised = true
		}
	}
	if !raised {
		t.Fatalf("missing evidence must name the second round: %v", rep.Status.MissingEvidence)
	}
}

func TestC05NeverEmitsConfirmation(t *testing.T) {
	sub := newSubject(contracts.SignalBlock, 403).withRounds("round-2")
	sub.Corroboration = &Corroboration{
		Kind: "waf_log_entry", Ref: "log-2026-10-28-0001", Agrees: true,
		Detail: "rule 41 blocked the query string",
	}
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Status.Status != contracts.AttributionConfirmed {
		t.Fatalf("all three JAVI-016 conditions hold, so C-06 must confirm: got %s", rep.Status.Status)
	}
	cc := rep.Status.Conditions
	if !(cc.ReproducibleAcrossRounds && cc.ValidControlsInScope && cc.CorroboratedByIndependentSrc) {
		t.Fatalf("all three JAVI-016 conditions must be recorded, got %+v", cc)
	}
	if rep.Attribution.Status != contracts.AttributionSupportedByLogs {
		t.Fatalf("C-05 must carry the grade below confirmation, got %s", rep.Attribution.Status)
	}
	raw, err := json.Marshal(rep.Attribution)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), string(contracts.AttributionConfirmed)) {
		t.Fatalf("C-05 bytes carry a confirmation nobody but the conditions gate granted: %s", raw)
	}
	if rep.Status.EvidenceBasis != contracts.BasisHTTPLogs {
		t.Fatalf("basis %s", rep.Status.EvidenceBasis)
	}
	// The corroborating source is identified, not merely asserted.
	if rep.Status.Conditions.IndependentSourceRef != "log-2026-10-28-0001" {
		t.Fatalf("source ref %q", rep.Status.Conditions.IndependentSourceRef)
	}
}

func TestConfirmationNeedsTwoRoundsNotReplicas(t *testing.T) {
	// Repetition inside one round is replication, not independent reproduction.
	sub := newSubject(contracts.SignalBlock, 403).withRounds("round-1", "round-1")
	sub.Corroboration = &Corroboration{Kind: "waf_log_entry", Ref: "log-1", Agrees: true}
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Status.Status == contracts.AttributionConfirmed {
		t.Fatal("three exchanges from one round cannot satisfy reproducible_across_independent_rounds")
	}
	if rep.Status.Conditions.ReproducibleAcrossRounds {
		t.Fatal("the condition itself must be false, not merely unused")
	}
	// A log source plus controls still earns the logs grade, which is the honest
	// answer when only one round exists.
	if rep.Status.Status != contracts.AttributionSupportedByLogs {
		t.Fatalf("want supported_by_logs, got %s", rep.Status.Status)
	}
}

func TestProbableIsRoundsAndControlsWithoutLogs(t *testing.T) {
	sub := newSubject(contracts.SignalBlock, 403).withRounds("round-2")
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Status.Status != contracts.AttributionProbable {
		t.Fatalf("want probable, got %s", rep.Status.Status)
	}
	if rep.Status.EvidenceBasis != contracts.BasisHTTPRound {
		t.Fatalf("basis %s: two rounds of HTTP are their own basis", rep.Status.EvidenceBasis)
	}
	// The name says what is missing.
	if stateOf(rep, contracts.AltWAF) != contracts.AltSupported {
		t.Fatal("the filter candidate stays the supported explanation")
	}
	if ruledOut(rep) < 2 {
		t.Fatalf("probable requires two competing explanations excluded, got %d", ruledOut(rep))
	}
}

func ruledOut(rep Report) int {
	n := 0
	for _, alt := range rep.Attribution.Alternatives {
		if alt.Kind != contracts.AltWAF && alt.State == contracts.AltRuledOut {
			n++
		}
	}
	return n
}

func TestEveryAlternativeIsRatedEveryTime(t *testing.T) {
	subjects := []Subject{
		newSubject(contracts.SignalBlock, 403),
		newSubject(contracts.SignalPass, 200),
		newSubject(contracts.SignalIndeterminate, 500),
		newSubject(contracts.SignalTransportError, 0),
	}
	for _, sub := range subjects {
		rep, err := Attribute(sub)
		if err != nil {
			t.Fatalf("Attribute(%s): %v", sub.Evidence[0].Signal, err)
		}
		if len(rep.Attribution.Alternatives) != len(contracts.AllAlternativeKinds()) {
			t.Fatalf("signal %s rated %d of %d explanations", sub.Evidence[0].Signal,
				len(rep.Attribution.Alternatives), len(contracts.AllAlternativeKinds()))
		}
		for _, alt := range rep.Attribution.Alternatives {
			if alt.State == contracts.AlternativeState("missing") {
				t.Fatalf("signal %s left %s unrated", sub.Evidence[0].Signal, alt.Kind)
			}
			if alt.State != contracts.AltNotInScope {
				if alt.Justification == "" || alt.TestThatWouldResolve == "" {
					t.Fatalf("%s is rated %s with no reason or no resolving test", alt.Kind, alt.State)
				}
			}
		}
		var found bool
		for _, alt := range rep.Attribution.Alternatives {
			if alt.Kind == rep.Attribution.Primary {
				found = true
			}
		}
		if !found {
			t.Fatalf("primary %s is not among the evaluated alternatives", rep.Attribution.Primary)
		}
	}
}

func TestContradictedSourceRejectsBothRecords(t *testing.T) {
	sub := newSubject(contracts.SignalBlock, 403).withRounds("round-2")
	sub.Corroboration = &Corroboration{
		Kind: "config_export", Ref: "export-9", Agrees: false, IsConfig: true,
		Detail: "the rule group for this path has no SQL inspection enabled",
	}
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Attribution.Status != contracts.AttributionRejected {
		t.Fatalf("C-05: %s", rep.Attribution.Status)
	}
	if rep.Status.Status != contracts.AttributionRejected {
		t.Fatalf("C-06: %s", rep.Status.Status)
	}
	if !strings.Contains(rep.Status.Justification, "disagrees") {
		t.Fatalf("the rejection must say which source disagreed: %q", rep.Status.Justification)
	}
	if !strings.Contains(rep.Status.Justification, sub.Corroboration.Detail) {
		t.Fatal("and it must carry the operator's own words, not a paraphrase")
	}
	if rep.Status.EvidenceBasis != contracts.BasisConfigExport {
		t.Fatalf("basis %s", rep.Status.EvidenceBasis)
	}
}

func TestBenignReferenceRejectedPointsAtTheOrigin(t *testing.T) {
	sub := newSubject(contracts.SignalBlock, 403)
	sub.Controls.NegativeSignals = []contracts.Signal{contracts.SignalBlock}
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	// Whatever answered is not reading the payload.
	if rep.Attribution.Primary != contracts.AltOriginApplication {
		t.Fatalf("primary %s", rep.Attribution.Primary)
	}
	if stateOf(rep, contracts.AltOriginApplication) != contracts.AltSupported {
		t.Fatal("the origin candidate is supported when benign traffic is rejected too")
	}
	if stateOf(rep, contracts.AltWAF) == contracts.AltSupported {
		t.Fatal("a blanket rejection cannot support a payload-inspection claim")
	}
	if stateOf(rep, contracts.AltAuthZLayer) != contracts.AltSupported {
		t.Fatal("a session or route rule answers benign and attack traffic alike")
	}
	if rep.Status.Status == contracts.AttributionConfirmed ||
		rep.Status.Status == contracts.AttributionProbable {
		t.Fatalf("controls that reject benign traffic are not valid controls: %s", rep.Status.Status)
	}
}

func TestRateLimitedEvidenceIsNeverBlockEvidence(t *testing.T) {
	sub := newSubject(contracts.SignalRateLimited, 429)
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Attribution.Primary != contracts.AltRateLimiting {
		t.Fatalf("primary %s", rep.Attribution.Primary)
	}
	if stateOf(rep, contracts.AltRateLimiting) != contracts.AltSupported {
		t.Fatal("a 429 is the pacing explanation, and it is the leading one")
	}
	if stateOf(rep, contracts.AltWAF) == contracts.AltSupported {
		t.Fatal("pacing may not be reported as protection (criterion 24)")
	}
}

func TestTransportFailureKeepsPacingUnexcluded(t *testing.T) {
	sub := newSubject(contracts.SignalTransportError, 0)
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Attribution.Primary != contracts.AltNetworkOrClient {
		t.Fatalf("primary %s", rep.Attribution.Primary)
	}
	if stateOf(rep, contracts.AltNetworkOrClient) != contracts.AltSupported {
		t.Fatal("the socket failure is the explanation the evidence gives")
	}
	// An exchange that never completed cannot exclude anything that would have been
	// visible only in a completed one.
	for _, kind := range []contracts.AlternativeKind{contracts.AltRateLimiting, contracts.AltHarnessArtifact} {
		if stateOf(rep, kind) == contracts.AltRuledOut {
			t.Errorf("%s ruled out from an exchange that got no response", kind)
		}
	}
	if rep.Status.Status != contracts.AttributionUndetermined &&
		rep.Status.Status != contracts.AttributionCompatible {
		t.Fatalf("grade %s", rep.Status.Status)
	}
}

func TestUncalibratedRunIsUndetermined(t *testing.T) {
	sub := newSubject(contracts.SignalBlock, 403)
	sub.Controls = Controls{}
	rep, err := Attribute(sub)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if rep.Status.Status != contracts.AttributionUndetermined {
		t.Fatalf("without controls and rounds the grade is undetermined, got %s", rep.Status.Status)
	}
	if rep.Status.EvidenceBasis != contracts.BasisHTTPOnly {
		t.Fatalf("basis %s", rep.Status.EvidenceBasis)
	}
	// A rejection reading with no calibration cannot even call itself compatible:
	// nothing says the origin would not have answered that way anyway.
	if stateOf(rep, contracts.AltWAF) != contracts.AltNotRuledOut {
		t.Fatalf("WAF candidate: %s", stateOf(rep, contracts.AltWAF))
	}
	if stateOf(rep, contracts.AltHarnessArtifact) == contracts.AltRuledOut {
		t.Fatal("an uncalibrated run cannot exclude its own harness")
	}
	if len(rep.Status.MissingEvidence) == 0 {
		t.Fatal("undetermined still has to say what would raise it")
	}
}

func TestControlsValidityIsDerivedFromSignals(t *testing.T) {
	c := Controls{PositiveSignals: []contracts.Signal{contracts.SignalPass}}
	if c.PositiveValid() {
		t.Fatal("a positive control that was not rejected calibrates nothing")
	}
	c = Controls{NegativeSignals: []contracts.Signal{contracts.SignalPass, contracts.SignalIndeterminate}}
	if c.NegativeValid() {
		t.Fatal("one undecided benign reference makes the baseline unreliable")
	}
	c = Controls{NegativeSignals: nil}
	if c.NegativeValid() {
		t.Fatal("no benign reference is not the same as a clean one")
	}
}

func TestRefusesASubjectWithNothingToAttribute(t *testing.T) {
	if _, err := Attribute(Subject{}); err == nil {
		t.Fatal("a subject needs a run and a reference")
	}
	sub := newSubject(contracts.SignalBlock, 403)
	sub.Evidence = nil
	if _, err := Attribute(sub); err == nil {
		t.Fatal("an attribution with no evidence is an opinion")
	}
	sub = newSubject(contracts.SignalBlock, 403)
	sub.Now = time.Time{}
	if _, err := Attribute(sub); err == nil {
		t.Fatal("an undated grade cannot be ordered against the run that produced it")
	}
}

func TestRecordsPassTheirOwnValidators(t *testing.T) {
	rep, err := Attribute(newSubject(contracts.SignalBlock, 403))
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if err := contracts.Validate(contracts.IDAttribution, &rep.Attribution); err != nil {
		t.Fatalf("C-05: %v", err)
	}
	if err := contracts.Validate(contracts.IDAttributionStatus, &rep.Status); err != nil {
		t.Fatalf("C-06: %v", err)
	}
	if rep.Status.RunID != rep.Attribution.RunID {
		t.Fatal("the two records must describe the same run")
	}
	if rep.Status.AttributionID != rep.Attribution.AttributionID {
		t.Fatal("C-06 cites the C-05 it grades, or the grade floats free of the evidence")
	}
	if len(rep.Attribution.ObserverNotes) == 0 ||
		rep.Attribution.ObserverNotes[0] != Version {
		t.Fatalf("notes %v: the grade must trace to the build that derived it",
			rep.Attribution.ObserverNotes)
	}
}

func TestAChosenGradeIsRejected(t *testing.T) {
	// The producer derives; a hand-written grade above the ceiling is a validation
	// failure, which is the point of the gate.
	rep, err := Attribute(newSubject(contracts.SignalBlock, 403))
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	rep.Status.Status = contracts.AttributionProbable
	if err := contracts.Validate(contracts.IDAttributionStatus, &rep.Status); err == nil {
		t.Fatal("one round with no log source may not be graded probable")
	}
	rep.Attribution.Status = contracts.AttributionConfirmed
	if err := contracts.Validate(contracts.IDAttribution, &rep.Attribution); err == nil {
		t.Fatal("C-05 may not carry confirmation at all")
	}
}
