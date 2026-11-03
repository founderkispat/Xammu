// Package attributor produces C-05 and C-06: which sources could have produced an
// observed signal, how far each was excluded, and the grade the exclusion earns.
//
// This is the stage where a WAF profiling tool can lie, so the rules are stacked
// against it. Every competing explanation is named and evaluated on every
// attribution, because an unrated alternative is an unevaluated escape hatch. The
// grade is never chosen: it is derived from the JAVI-016 conditions by
// contracts.DeriveStatus, and C-05 is refused by its own validator if it claims
// confirmation, which only the C-06 conditions gate can grant.
//
// The most common honest answer here is "not ruled out". A response that looks like
// a rejection can come from a filter, the application, a proxy, a load balancer, an
// authorization layer or a framework that rewrote the input, and HTTP evidence from
// one origin does not separate all of them. Saying so is the deliverable: an
// engineer reading it knows which test to run next, which is the alternative to
// being told something they cannot verify.
package attributor

import (
	"fmt"
	"sort"
	"time"

	"xammu/internal/contracts"
)

// Version is stamped into attribution notes so a grade can be traced to the build
// that derived it.
const Version = "xammu-attributor/1.0.0"

// Corroboration is a source outside the HTTP exchange that can agree or disagree
// with the inference: a filter's own log entry, or a configuration export. v1.0.0
// never fetches one by itself; it is supplied by an operator who has access, and an
// attribution that has none simply cannot rise above the HTTP ceiling.
type Corroboration struct {
	Kind     string
	Ref      string
	Agrees   bool
	Detail   string
	IsConfig bool
}

// Controls states what the run's own calibration probes did. Validity is derived
// here, from their signals, rather than accepted from a caller: "the control was
// valid" is a claim about evidence, not a permission to grant.
type Controls struct {
	PositiveRefs    []string
	PositiveSignals []contracts.Signal
	NegativeRefs    []string
	NegativeSignals []contracts.Signal
}

// PositiveValid reports whether at least one positive control read as a rejection.
func (c Controls) PositiveValid() bool { return contains(c.PositiveSignals, contracts.SignalBlock) }

// NegativeValid reports whether every negative reference read as ordinary handling.
// One benign probe that was itself rejected is enough to make the calibration
// unreliable, because the run can no longer tell a payload reaction from a blanket
// one.
func (c Controls) NegativeValid() bool {
	if len(c.NegativeSignals) == 0 {
		return false
	}
	for _, s := range c.NegativeSignals {
		if s != contracts.SignalPass {
			return false
		}
	}
	return true
}

func contains(in []contracts.Signal, want contracts.Signal) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

// Datum is one piece of evidence about the subject.
type Datum struct {
	RoundID        string
	Classification string
	Observation    string
	ProbeRef       string
	Signal         contracts.Signal
	StatusCode     int
}

// Subject is what is being attributed: one behavioural reading over one probe cell.
type Subject struct {
	RunID         string
	Ref           string
	AttackClass   contracts.AttackClass
	Vector        contracts.Vector
	Encoding      contracts.Encoding
	TargetOrigin  string
	Path          string
	Evidence      []Datum
	Controls      Controls
	Corroboration *Corroboration
	Now           time.Time
}

// Report is one attribution with its grade attached.
type Report struct {
	Attribution contracts.Attribution
	Status      contracts.AttributionStatusRecord
}

// Attribute evaluates every competing explanation and grades the result.
func Attribute(sub Subject) (Report, error) {
	if sub.RunID == "" || sub.Ref == "" {
		return Report{}, fmt.Errorf("attributor: a subject needs a run and a reference")
	}
	if len(sub.Evidence) == 0 {
		return Report{}, fmt.Errorf(
			"attributor: subject %s has no evidence: an attribution with nothing to attribute "+
				"is an opinion", sub.Ref)
	}
	at := sub.Now
	if at.IsZero() {
		return Report{}, fmt.Errorf("attributor: subject %s has no timestamp", sub.Ref)
	}

	conditions := conditionsOf(sub)
	basis := basisOf(sub, conditions)
	derived := contracts.DeriveStatus(conditions, basis)
	primary := primaryOf(sub)
	alts := evaluate(sub, primary)

	missing := missingFor(sub, conditions, alts)
	c05Status := derived
	if c05Status == contracts.AttributionConfirmed {
		// C-05 cannot carry confirmation: the conditions gate in C-06 is what
		// grants it, and a producer that could set it here would be grading itself.
		c05Status = contracts.AttributionSupportedByLogs
	}
	if contradicted(sub) {
		c05Status = contracts.AttributionRejected
	}
	if c05Status != contracts.AttributionUndetermined && len(missing) == 0 &&
		c05Status != contracts.AttributionConfirmed {
		// The validator requires a graded attribution to name what is absent. An
		// empty list here would fail validation, so the generic item keeps the
		// record honest instead of failing the run over a wording gap.
		missing = append(missing, "no further discriminating evidence is recorded for "+sub.Ref)
	}

	a := contracts.Attribution{
		AttributionID:   contracts.NewUUID(),
		RunID:           sub.RunID,
		SubjectID:       sub.Ref,
		SubjectContract: contracts.IDBehavioralClassification,
		AttributedAt:    at,
		Primary:         primary,
		Alternatives:    alts,
		Status:          c05Status,
		EvidenceBasis:   basis,
		RequiredMissing: missing,
		ObserverNotes: []string{
			Version,
			fmt.Sprintf("%d datum over %d round(s); controls positive=%v negative=%v",
				len(sub.Evidence), len(roundsOf(sub)), sub.Controls.PositiveValid(), sub.Controls.NegativeValid()),
		},
	}
	if err := contracts.Validate(contracts.IDAttribution, &a); err != nil {
		return Report{}, fmt.Errorf("attributor: attribution for %s rejected by C-05: %w", sub.Ref, err)
	}

	c06Status := derived
	justification := fmt.Sprintf(
		"derived from the conditions actually met: reproducible across %s, controls valid=%v, "+
			"corroborated=%v, basis %s", roundsPhrase(sub), sub.Controls.PositiveValid() && sub.Controls.NegativeValid(),
		conditions.CorroboratedByIndependentSrc, basis)
	if contradicted(sub) {
		c06Status = contracts.AttributionRejected
		justification = "the independent source recorded for " + sub.Ref + " disagrees with the HTTP " +
			"inference: " + sub.Corroboration.Detail
	}
	rec := contracts.AttributionStatusRecord{
		StatusID:        contracts.NewUUID(),
		RunID:           sub.RunID,
		AttributionID:   a.AttributionID,
		Status:          c06Status,
		EvidenceBasis:   basis,
		Conditions:      conditions,
		Justification:   justification,
		MissingEvidence: missing,
		DeterminedAt:    at,
	}
	if err := contracts.Validate(contracts.IDAttributionStatus, &rec); err != nil {
		return Report{}, fmt.Errorf("attributor: status record for %s rejected by C-06: %w", sub.Ref, err)
	}
	return Report{Attribution: a, Status: rec}, nil
}

// contradicted reports an independent source that disagrees with the inference.
func contradicted(sub Subject) bool {
	return sub.Corroboration != nil && !sub.Corroboration.Agrees
}

func conditionsOf(sub Subject) contracts.ConfirmedConditions {
	rounds := roundsOf(sub)
	cc := contracts.ConfirmedConditions{
		ReproducibleAcrossRounds: len(rounds) >= 2,
		ValidControlsInScope:     sub.Controls.PositiveValid() && sub.Controls.NegativeValid(),
	}
	if sub.Corroboration != nil && sub.Corroboration.Agrees {
		cc.CorroboratedByIndependentSrc = true
		cc.IndependentSourceKind = sub.Corroboration.Kind
		cc.IndependentSourceRef = sub.Corroboration.Ref
	}
	return cc
}

// roundsOf lists the distinct rounds that produced evidence for the subject.
func roundsOf(sub Subject) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range sub.Evidence {
		if d.RoundID == "" || seen[d.RoundID] {
			continue
		}
		seen[d.RoundID] = true
		out = append(out, d.RoundID)
	}
	sort.Strings(out)
	return out
}

func roundsPhrase(sub Subject) string {
	rounds := roundsOf(sub)
	if len(rounds) == 0 {
		return "no named round"
	}
	if len(rounds) == 1 {
		return "one round (" + rounds[0] + ")"
	}
	return fmt.Sprintf("%d rounds", len(rounds))
}

// basisOf names the sources that exist, which is what caps the grade: HTTP alone
// cannot reach confirmation, however clean it looks.
func basisOf(sub Subject, cc contracts.ConfirmedConditions) contracts.EvidenceBasis {
	switch {
	case sub.Corroboration != nil && sub.Corroboration.IsConfig:
		return contracts.BasisConfigExport
	case sub.Corroboration != nil:
		return contracts.BasisHTTPLogs
	case len(roundsOf(sub)) >= 2:
		return contracts.BasisHTTPRound
	case cc.ValidControlsInScope:
		return contracts.BasisHTTPControl
	default:
		return contracts.BasisHTTPOnly
	}
}

// primaryOf picks the explanation the evidence points at first. It is a summary of
// what the data already said, not a conclusion: each branch cites the observation
// that made it the leading candidate.
func primaryOf(sub Subject) contracts.AlternativeKind {
	signals := map[contracts.Signal]int{}
	for _, d := range sub.Evidence {
		signals[d.Signal]++
	}
	if signals[contracts.SignalTransportError] > 0 &&
		signals[contracts.SignalTransportError] >= len(sub.Evidence)-signals[contracts.SignalTransportError] {
		return contracts.AltNetworkOrClient
	}
	if signals[contracts.SignalRateLimited] > 0 {
		return contracts.AltRateLimiting
	}
	// Benign references rejected alongside the payload: whatever is answering is not
	// reading the payload.
	if contains(sub.Controls.NegativeSignals, contracts.SignalBlock) {
		return contracts.AltOriginApplication
	}
	return contracts.AltWAF
}

func containsSignal(sub Subject, want contracts.Signal) bool {
	for _, d := range sub.Evidence {
		if d.Signal == want {
			return true
		}
	}
	return false
}
