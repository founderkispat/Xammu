package contracts

import (
	"strconv"
	"strings"
	"time"
)

// DiscoveryFinding is C-16, the contract that makes v1.0.0 useful. It pairs a
// measurement with the reasoning it supports, the evidence still missing, and
// the command that reproduces it.
//
// The four honesty fields (what_was_observed, what_is_inferred,
// what_evidence_is_missing, limitations) are mandatory: a finding that cannot
// state all four is a guess, and the validator refuses to emit it.
type DiscoveryFinding struct {
	FindingID   string      `json:"finding_id"`
	Ref         string      `json:"ref"`
	RunID       string      `json:"run_id"`
	DetectedAt  time.Time   `json:"detected_at"`
	FindingType FindingType `json:"finding_type"`
	ClaimType   ClaimType   `json:"claim_type"`

	WhatWasObserved       string   `json:"what_was_observed"`
	WhatIsInferred        string   `json:"what_is_inferred"`
	WhatEvidenceIsMissing string   `json:"what_evidence_is_missing"`
	Limitations           []string `json:"limitations"`

	AttributionStatus  AttributionStatus       `json:"attribution_status"`
	EvidenceBasis      EvidenceBasis           `json:"evidence_basis"`
	Alternatives       []AlternativeAssessment `json:"alternatives_evaluated"`
	EvidenceLevel      EvidenceLevel           `json:"evidence_level"`
	EvidenceProfileRef string                  `json:"evidence_profile_ref"`
	HypothesisRef      string                  `json:"hypothesis_ref,omitempty"`
	ObservationRefs    []string                `json:"observation_refs"`

	ReproductionCommand  string      `json:"reproduction_command"`
	Recommendation       string      `json:"recommendation"`
	RegressionTest       string      `json:"regression_test_to_run"`
	Priority             Priority    `json:"priority"`
	PriorityBasis        string      `json:"priority_basis"`
	MeasuredImpact       Ratio       `json:"measured_impact"`
	AffectedScope        string      `json:"affected_scope"`
	AttackClass          AttackClass `json:"attack_class,omitempty"`
	Vector               Vector      `json:"vector,omitempty"`
	Encoding             Encoding    `json:"encoding,omitempty"`
	SecurityEngineerNote string      `json:"security_engineer_note"`
	UnevaluatedReason    ReasonCode  `json:"unevaluated_reason,omitempty"`
}

func (DiscoveryFinding) Contract() ID { return IDDiscoveryFinding }

func registerFindingContract() {
	register(IDDiscoveryFinding, func(payload any) error {
		f, err := cast[DiscoveryFinding](IDDiscoveryFinding, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDDiscoveryFinding)
		uuidField(c, "finding_id", f.FindingID)
		c.required("ref", f.Ref)
		c.required("run_id", f.RunID)
		oneofT(c, "finding_type", f.FindingType, AllFindingTypes()...)
		oneofT(c, "claim_type", f.ClaimType, AllClaimTypes()...)
		oneofT(c, "attribution_status", f.AttributionStatus, AllAttributionStatuses()...)
		oneofT(c, "evidence_basis", f.EvidenceBasis, AllEvidenceBases()...)
		oneofT(c, "evidence_level", f.EvidenceLevel, AllEvidenceLevels()...)
		oneofT(c, "priority", f.Priority, AllPriorities()...)
		if f.DetectedAt.IsZero() {
			c.add("detected_at", "required")
		}
		if f.AttackClass != "" {
			oneofT(c, "attack_class", f.AttackClass, AllAttackClasses()...)
		}
		if f.Vector != "" {
			oneofT(c, "vector", f.Vector, AllVectors()...)
		}
		if f.Encoding != "" {
			oneofT(c, "encoding", f.Encoding, AllEncodings()...)
		}

		// The four honesty fields. Missing any one of these turns the delivery
		// into an assumption, so the finding is not published.
		for field, val := range map[string]string{
			"what_was_observed":        f.WhatWasObserved,
			"what_is_inferred":         f.WhatIsInferred,
			"what_evidence_is_missing": f.WhatEvidenceIsMissing,
		} {
			if strings.TrimSpace(val) == "" {
				c.add(field, "mandatory honesty field (C-16 rule): the finding is not publishable")
			}
		}
		if len(f.Limitations) == 0 {
			c.add("limitations", "mandatory honesty field: state what the finding does not demonstrate")
		} else {
			for i, l := range f.Limitations {
				if strings.TrimSpace(l) == "" {
					c.add("limitations[]", "empty limitation at index "+strconv.Itoa(i))
				}
			}
		}

		// Actionability: a finding the engineer cannot reproduce or cannot act
		// on has no place in the report.
		c.required("reproduction_command", f.ReproductionCommand)
		if f.ReproductionCommand != "" {
			if !strings.HasPrefix(f.ReproductionCommand, "xammu ") {
				c.add("reproduction_command", "must be a xammu command")
			}
			if !strings.Contains(f.ReproductionCommand, "--authorization") &&
				!strings.Contains(f.ReproductionCommand, "--run") {
				c.add("reproduction_command",
					"must bind to an authorization or an existing run so it cannot escape the authorized scope")
			}
		}
		c.required("recommendation", f.Recommendation)
		c.required("security_engineer_note", f.SecurityEngineerNote)
		c.required("affected_scope", f.AffectedScope)
		// An undetermined area has no evidence profile because it has no reading:
		// it cites the absence in the journal. Requiring a profile id here would
		// force the producer to invent one.
		if f.FindingType != FindingUndeterminedArea {
			c.required("evidence_profile_ref", f.EvidenceProfileRef)
		}
		c.nonEmpty("observation_refs", len(f.ObservationRefs))
		c.nonEmpty("alternatives_evaluated", len(f.Alternatives))
		for _, alt := range f.Alternatives {
			oneofT(c, "alternatives_evaluated[].kind", alt.Kind, AllAlternativeKinds()...)
			oneofT(c, "alternatives_evaluated[].state", alt.State, AllAlternativeStates()...)
			if alt.State != AltNotInScope {
				c.required("alternatives_evaluated[].justification", alt.Justification)
			}
		}

		// Priority is derived from measurement, never asserted.
		c.required("priority_basis", f.PriorityBasis)
		if f.Priority != PriorityLow {
			if f.MeasuredImpact.IsEmpty() {
				c.add("measured_impact",
					string(f.Priority)+" priority requires the coverage quantity it was derived from")
			}
			f.MeasuredImpact.validate(c, "measured_impact")
		}

		// Claim strength cannot outrun attribution strength.
		switch f.ClaimType {
		case ClaimAssociation:
			if rankOf(f.AttributionStatus) < rankOf(AttributionCompatible) {
				c.add("claim_type", "association needs at least compatible attribution")
			}
			if f.EvidenceLevel.rank() < EvidenceReplicatedWithControls.rank() {
				c.add("evidence_level", "association needs valid controls in the evidence profile")
			}
		case ClaimAttribution:
			if rankOf(f.AttributionStatus) < rankOf(AttributionProbable) {
				c.add("claim_type", "attribution claims need probable-or-stronger status")
			}
			if f.EvidenceLevel.rank() < EvidenceIndependentRounds.rank() {
				c.add("evidence_level", "attribution claims need independent rounds")
			}
		case ClaimConfirmed:
			if f.AttributionStatus != AttributionConfirmed {
				c.add("claim_type", "confirmed claims require confirmed_by_correlated_evidence")
			}
			if f.EvidenceLevel != EvidenceCorrelatedIndependent {
				c.add("evidence_level", "confirmed claims require correlated independent evidence")
			}
		}
		// A descriptive claim about the run's own coverage record is the one claim
		// that needs no evidence behind it: an undetermined area states that the
		// measurement did not produce a reading, and the journal is the evidence for
		// that sentence. Every other claim type still has to clear the ladder.
		describesAbsence := f.ClaimType == ClaimDescriptive && f.FindingType == FindingUndeterminedArea
		if !describesAbsence && f.EvidenceLevel.rank() < MinEvidenceLevel(f.ClaimType).rank() {
			c.add("evidence_level", "below the floor for claim_type "+string(f.ClaimType))
		}

		// An undetermined area is a declaration of ignorance, not a finding of
		// risk: it cannot carry an inferential claim.
		if f.FindingType == FindingUndeterminedArea {
			oneofT(c, "unevaluated_reason", f.UnevaluatedReason, AllReasonCodes()...)
			if f.ClaimType != ClaimDescriptive {
				c.add("claim_type", "undetermined_area must be descriptive")
			}
			if f.AttributionStatus != AttributionUndetermined {
				c.add("attribution_status", "undetermined_area must be undetermined")
			}
			if strings.Contains(strings.ToLower(f.WhatIsInferred), "vulnerab") ||
				strings.Contains(strings.ToLower(f.WhatIsInferred), "exploit") {
				c.add("what_is_inferred",
					"an undetermined area may not infer a vulnerability; XAMMU does not evaluate the application")
			}
		} else if f.UnevaluatedReason != "" {
			c.add("unevaluated_reason", "only set for undetermined_area")
		}

		// Over-blocking and gaps are coverage statements; both need the
		// population they were measured over (criterion 13).
		if f.FindingType == FindingOverBlocking || f.FindingType == FindingCoverageGap ||
			f.FindingType == FindingVectorAsymmetry || f.FindingType == FindingEncodingBypass {
			if f.MeasuredImpact.IsEmpty() {
				c.add("measured_impact", "coverage findings carry population and denominator")
			}
			if f.MeasuredImpact.Basis == "" {
				c.add("measured_impact.basis", "state what the denominator counts")
			}
		}
		return c.err()
	})
}

func init() { registerFindingContract() }
