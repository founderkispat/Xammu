package contracts

import (
	"strconv"
	"time"
)

// AlternativeAssessment is one competing explanation, its state, and the reason.
// C-05 is only satisfied when every alternative carries both: an unrated
// alternative is an unevaluated escape hatch.
type AlternativeAssessment struct {
	Kind                 AlternativeKind  `json:"kind"`
	State                AlternativeState `json:"state"`
	Justification        string           `json:"justification"`
	TestThatWouldResolve string           `json:"test_that_would_resolve"`
	EvidenceRefs         []string         `json:"evidence_refs"`
}

// Attribution is C-05: which sources could have produced the observed signal,
// and how far each was excluded. It never asserts a cause on its own; the
// status record in C-06 is what grades the claim.
type Attribution struct {
	AttributionID   string                  `json:"attribution_id"`
	RunID           string                  `json:"run_id"`
	SubjectID       string                  `json:"subject_id"`
	SubjectContract ID                      `json:"subject_contract"`
	AttributedAt    time.Time               `json:"attributed_at"`
	Primary         AlternativeKind         `json:"primary_candidate"`
	Alternatives    []AlternativeAssessment `json:"alternatives"`
	Status          AttributionStatus       `json:"status"`
	EvidenceBasis   EvidenceBasis           `json:"evidence_basis"`
	RequiredMissing []string                `json:"required_but_missing"`
	ObserverNotes   []string                `json:"observer_notes,omitempty"`
}

func (Attribution) Contract() ID { return IDAttribution }

// ConfirmedConditions is the JAVI-016 gate. Three independent facts must all
// hold before attribution is called confirmed.
type ConfirmedConditions struct {
	ReproducibleAcrossRounds     bool   `json:"reproducible_across_independent_rounds"`
	ValidControlsInScope         bool   `json:"valid_positive_and_negative_controls"`
	CorroboratedByIndependentSrc bool   `json:"corroborated_by_independent_source"`
	IndependentSourceKind        string `json:"independent_source_kind,omitempty"`
	IndependentSourceRef         string `json:"independent_source_ref,omitempty"`
}

func (cc ConfirmedConditions) countSatisfied() int {
	n := 0
	if cc.ReproducibleAcrossRounds {
		n++
	}
	if cc.ValidControlsInScope {
		n++
	}
	if cc.CorroboratedByIndependentSrc {
		n++
	}
	return n
}

// AttributionStatusRecord is C-06: the graded statement about attribution, with
// the conditions that justify the grade.
type AttributionStatusRecord struct {
	StatusID        string              `json:"status_id"`
	RunID           string              `json:"run_id"`
	AttributionID   string              `json:"attribution_id"`
	Status          AttributionStatus   `json:"status"`
	EvidenceBasis   EvidenceBasis       `json:"evidence_basis"`
	Conditions      ConfirmedConditions `json:"confirmed_conditions"`
	Justification   string              `json:"justification"`
	MissingEvidence []string            `json:"what_would_raise_the_grade"`
	DeterminedAt    time.Time           `json:"determined_at"`
}

func (AttributionStatusRecord) Contract() ID { return IDAttributionStatus }

// DeriveStatus computes the strongest status the conditions and basis support.
// Producers call this instead of choosing a status, so an inflated grade is a
// bug that validation reports rather than a claim that reaches a report.
func DeriveStatus(conditions ConfirmedConditions, basis EvidenceBasis) AttributionStatus {
	if conditions.ReproducibleAcrossRounds && conditions.ValidControlsInScope &&
		conditions.CorroboratedByIndependentSrc &&
		(basis == BasisHTTPLogs || basis == BasisConfigExport) {
		return AttributionConfirmed
	}
	if conditions.CorroboratedByIndependentSrc && (basis == BasisHTTPLogs || basis == BasisConfigExport) {
		return AttributionSupportedByLogs
	}
	if conditions.ReproducibleAcrossRounds && conditions.ValidControlsInScope {
		return AttributionProbable
	}
	if conditions.ValidControlsInScope || basis == BasisHTTPControl || basis == BasisHTTPRound {
		return AttributionCompatible
	}
	return AttributionUndetermined
}

func registerAttributionContracts() {
	register(IDAttribution, func(payload any) error {
		a, err := cast[Attribution](IDAttribution, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDAttribution)
		uuidField(c, "attribution_id", a.AttributionID)
		c.required("run_id", a.RunID)
		c.required("subject_id", a.SubjectID)
		if !Registered(a.SubjectContract) {
			c.add("subject_contract", "unknown contract "+string(a.SubjectContract))
		}
		if a.AttributedAt.IsZero() {
			c.add("attributed_at", "required")
		}
		oneofT(c, "primary_candidate", a.Primary, AllAlternativeKinds()...)
		oneofT(c, "status", a.Status, AllAttributionStatuses()...)
		oneofT(c, "evidence_basis", a.EvidenceBasis, AllEvidenceBases()...)
		c.nonEmpty("alternatives", len(a.Alternatives))

		states := map[AlternativeKind]AlternativeState{}
		for i, alt := range a.Alternatives {
			prefix := "alternatives[]"
			oneofT(c, prefix+".kind", alt.Kind, AllAlternativeKinds()...)
			oneofT(c, prefix+".state", alt.State, AllAlternativeStates()...)
			if alt.State != AltNotInScope {
				c.required(prefix+".justification", alt.Justification)
				c.required(prefix+".test_that_would_resolve", alt.TestThatWouldResolve)
			}
			if _, dup := states[alt.Kind]; dup {
				c.add(prefix+".kind", "duplicate alternative "+string(alt.Kind))
			}
			states[alt.Kind] = alt.State
			_ = i
		}
		if _, ok := states[a.Primary]; !ok {
			c.add("primary_candidate", "must be one of the evaluated alternatives")
		}
		// WAF attribution is only meaningful if the competing explanations were
		// actually looked at.
		if (a.Status == AttributionProbable || a.Status == AttributionConfirmed) &&
			countRuledOut(states) < 2 {
			c.add("status", "requires at least two competing alternatives ruled out")
		}
		if a.Status == AttributionConfirmed {
			c.add("status", "confirmed_by_correlated_evidence is not emittable on C-05; "+
				"only the C-06 conditions gate can grant it")
		}
		if a.Status != AttributionUndetermined && len(a.RequiredMissing) == 0 &&
			a.Status != AttributionConfirmed {
			c.add("required_but_missing", "a graded attribution must state what evidence is absent")
		}
		return c.err()
	})

	register(IDAttributionStatus, func(payload any) error {
		s, err := cast[AttributionStatusRecord](IDAttributionStatus, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDAttributionStatus)
		uuidField(c, "status_id", s.StatusID)
		c.required("run_id", s.RunID)
		uuidField(c, "attribution_id", s.AttributionID)
		oneofT(c, "status", s.Status, AllAttributionStatuses()...)
		oneofT(c, "evidence_basis", s.EvidenceBasis, AllEvidenceBases()...)
		c.required("justification", s.Justification)
		if s.DeterminedAt.IsZero() {
			c.add("determined_at", "required")
		}
		// JAVI-016: the three conditions, all of them, and a non-HTTP source.
		if s.Status == AttributionConfirmed {
			if s.Conditions.countSatisfied() != 3 {
				c.add("confirmed_conditions",
					"confirmed_by_correlated_evidence requires all three conditions; got "+
						strconv.Itoa(s.Conditions.countSatisfied())+"/3")
			}
			if s.Conditions.CorroboratedByIndependentSrc && s.Conditions.IndependentSourceRef == "" {
				c.add("confirmed_conditions.independent_source_ref", "must identify the corroborating source")
			}
		}
		if s.Status == AttributionSupportedByLogs && !s.Conditions.CorroboratedByIndependentSrc {
			c.add("status", "supported_by_logs requires an independent source")
		}
		if s.Status == AttributionProbable &&
			!(s.Conditions.ReproducibleAcrossRounds && s.Conditions.ValidControlsInScope) {
			c.add("status", "probable requires independent reproduction plus valid controls")
		}
		derived := DeriveStatus(s.Conditions, s.EvidenceBasis)
		if rankOf(s.Status) > rankOf(derived) && s.Status != AttributionRejected {
			c.add("status", "exceeds the ceiling the conditions support; derived "+string(derived))
		}
		if s.Status != AttributionUndetermined && len(s.MissingEvidence) == 0 &&
			s.Status != AttributionConfirmed {
			c.add("what_would_raise_the_grade", "must state what would raise the grade")
		}
		return c.err()
	})
}

func countRuledOut(states map[AlternativeKind]AlternativeState) int {
	n := 0
	for k, s := range states {
		if k == AltWAF {
			continue
		}
		if s == AltRuledOut {
			n++
		}
	}
	return n
}

func rankOf(s AttributionStatus) int {
	for i, v := range AllAttributionStatuses() {
		if v == s {
			return i
		}
	}
	return -1
}

func init() { registerAttributionContracts() }
