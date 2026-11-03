package contracts

import (
	"time"
)

// Ratio is a measured quantity with its denominator stated in the same object.
// Percentages never travel alone: criterion 13 and the "explicit denominators"
// checklist item are enforced by this type rather than by review.
//
// A Ratio measures what happened. It is not a confidence score, and no Ratio in
// XAMMU is ever consumed as one.
type Ratio struct {
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
	Basis       string `json:"basis"`
	// ExcludedInconclusive and ExcludedInvalid are removed from the denominator
	// so that failed or indeterminate trials cannot inflate a rate (criterion 23).
	ExcludedInconclusive int    `json:"excluded_inconclusive"`
	ExcludedInvalid      int    `json:"excluded_invalid"`
	PopulationRef        string `json:"population_ref,omitempty"`
}

func (r Ratio) validate(c *Violations, field string) {
	c.required(field+".basis", r.Basis)
	if r.Denominator < 0 {
		c.add(field+".denominator", "must be >= 0")
	}
	if r.Numerator < 0 {
		c.add(field+".numerator", "must be >= 0")
	}
	if r.Numerator > r.Denominator {
		c.add(field+".numerator", "exceeds denominator")
	}
	if r.Numerator > 0 && r.Denominator == 0 {
		c.add(field+".denominator", "a non-zero numerator needs a denominator")
	}
	c.nonNegative(field+".excluded_inconclusive", r.ExcludedInconclusive)
	c.nonNegative(field+".excluded_invalid", r.ExcludedInvalid)
}

// IsEmpty marks a ratio that measured nothing; reports must render it as
// "no evaluated", not as zero.
func (r Ratio) IsEmpty() bool { return r.Denominator == 0 }

// EvidenceProfile is C-08: how much evidence exists for one subject, expressed
// ordinally. The claim ceiling is derived from the level, never set freely.
type EvidenceProfile struct {
	ProfileID            string        `json:"profile_id"`
	RunID                string        `json:"run_id"`
	SubjectRef           string        `json:"subject_ref"`
	SubjectKind          string        `json:"subject_kind"`
	CompiledAt           time.Time     `json:"compiled_at"`
	Level                EvidenceLevel `json:"evidence_level"`
	ClaimCeiling         ClaimType     `json:"claim_ceiling"`
	CeilingJustification string        `json:"ceiling_justification"`

	Population           int      `json:"population"`
	ValidTrials          int      `json:"valid_trials"`
	Inconclusive         int      `json:"inconclusive_trials"`
	InvalidTrials        int      `json:"invalid_trials"`
	Replicas             int      `json:"replicas"`
	Rounds               []string `json:"round_ids"`
	PositiveControlValid bool     `json:"positive_control_valid"`
	NegativeControlValid bool     `json:"negative_control_valid"`
	CorroborationSource  string   `json:"corroboration_source,omitempty"`
	Measured             Ratio    `json:"measured_rate"`
	MissingEvidence      []string `json:"missing_evidence"`
	Refs                 []string `json:"evidence_refs"`
}

func (EvidenceProfile) Contract() ID { return IDEvidenceProfile }

// HypothesisCheck records one prediction tested against evidence.
type HypothesisCheck struct {
	CheckID     string `json:"check_id"`
	Prediction  string `json:"prediction"`
	Result      string `json:"result"`
	EvidenceRef string `json:"evidence_ref"`
}

// Hypothesis is C-07. Outcomes are supported/refuted/inconclusive: the pipeline
// has no word for "confirmed", so a hypothesis cannot promote itself.
type Hypothesis struct {
	HypothesisID        string            `json:"hypothesis_id"`
	Ref                 string            `json:"ref"`
	RunID               string            `json:"run_id"`
	FormedAt            time.Time         `json:"formed_at"`
	Statement           string            `json:"statement"`
	AttackClass         AttackClass       `json:"attack_class,omitempty"`
	Vector              Vector            `json:"vector,omitempty"`
	Encoding            Encoding          `json:"encoding,omitempty"`
	Scope               string            `json:"scope"`
	Predictions         []string          `json:"predictions"`
	Falsifier           string            `json:"falsifier"`
	Checks              []HypothesisCheck `json:"checks"`
	Outcome             HypothesisOutcome `json:"outcome"`
	OutcomeReason       string            `json:"outcome_reason"`
	InconclusiveReason  ReasonCode        `json:"inconclusive_reason_code,omitempty"`
	EvidenceProfileRef  string            `json:"evidence_profile_ref"`
	ClaimType           ClaimType         `json:"claim_type"`
	AttributionRefs     []string          `json:"attribution_refs"`
	ReproductionCommand string            `json:"reproduction_command"`
	SourceFindingRef    string            `json:"source_finding_ref,omitempty"`
}

func (Hypothesis) Contract() ID { return IDHypothesis }

func registerHypothesisContracts() {
	register(IDEvidenceProfile, func(payload any) error {
		p, err := cast[EvidenceProfile](IDEvidenceProfile, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDEvidenceProfile)
		uuidField(c, "profile_id", p.ProfileID)
		c.required("run_id", p.RunID)
		c.required("subject_ref", p.SubjectRef)
		oneofT(c, "evidence_level", p.Level, AllEvidenceLevels()...)
		// A level-none profile supports no claim at all, so its ceiling is empty by
		// construction; every other level must carry the claim type its level caps at.
		if p.Level == EvidenceNone {
			if p.ClaimCeiling != "" {
				c.add("claim_ceiling", "level none carries no claim ceiling, got "+
					string(p.ClaimCeiling))
			}
		} else {
			oneofT(c, "claim_ceiling", p.ClaimCeiling, AllClaimTypes()...)
		}
		if p.CompiledAt.IsZero() {
			c.add("compiled_at", "required")
		}
		c.nonNegative("population", p.Population)
		c.nonNegative("valid_trials", p.ValidTrials)
		c.nonNegative("inconclusive_trials", p.Inconclusive)
		c.nonNegative("invalid_trials", p.InvalidTrials)
		c.nonNegative("replicas", p.Replicas)
		if p.ValidTrials+p.Inconclusive+p.InvalidTrials > p.Population {
			c.add("valid_trials", "trial classes exceed population")
		}
		c.required("ceiling_justification", p.CeilingJustification)
		p.Measured.validate(c, "measured_rate")

		// The denominator is a measurement over valid trials only.
		if !p.Measured.IsEmpty() && p.Measured.Denominator != p.ValidTrials {
			c.add("measured_rate.denominator",
				"must equal valid_trials; inconclusive and invalid trials are excluded (criterion 23)")
		}
		// Ceiling is derived, not chosen.
		if expected := MaxClaimType(p.Level); expected != p.ClaimCeiling {
			c.add("claim_ceiling", "level "+string(p.Level)+" caps claims at "+
				string(expected)+", got "+string(p.ClaimCeiling))
		}
		if p.Level == EvidenceIndependentRounds && len(p.Rounds) < 2 {
			c.add("round_ids", "independent rounds requires at least two round ids")
		}
		if p.Level == EvidenceReplicatedWithControls &&
			!(p.PositiveControlValid && p.NegativeControlValid) {
			c.add("positive_control_valid", "this level requires both controls valid")
		}
		if p.Level == EvidenceCorrelatedIndependent && p.CorroborationSource == "" {
			c.add("corroboration_source", "required for correlated evidence")
		}
		if p.Level == EvidenceNone && len(p.MissingEvidence) == 0 {
			c.add("missing_evidence", "an empty profile must say what is missing")
		}
		return c.err()
	})

	register(IDHypothesis, func(payload any) error {
		h, err := cast[Hypothesis](IDHypothesis, payload)
		if err != nil {
			return err
		}
		c := newViolations(IDHypothesis)
		uuidField(c, "hypothesis_id", h.HypothesisID)
		c.required("ref", h.Ref)
		c.required("run_id", h.RunID)
		c.required("statement", h.Statement)
		c.required("scope", h.Scope)
		oneofT(c, "outcome", h.Outcome, AllHypothesisOutcomes()...)
		oneofT(c, "claim_type", h.ClaimType, AllClaimTypes()...)
		c.nonEmpty("predictions", len(h.Predictions))
		c.required("falsifier", h.Falsifier)
		c.required("reproduction_command", h.ReproductionCommand)
		if h.FormedAt.IsZero() {
			c.add("formed_at", "required")
		}
		if h.AttackClass != "" {
			oneofT(c, "attack_class", h.AttackClass, AllAttackClasses()...)
		}
		if h.Vector != "" {
			oneofT(c, "vector", h.Vector, AllVectors()...)
		}
		if h.Encoding != "" {
			oneofT(c, "encoding", h.Encoding, AllEncodings()...)
		}
		c.required("outcome_reason", h.OutcomeReason)
		if h.Outcome == HypothesisInconclusive {
			oneofT(c, "inconclusive_reason_code", h.InconclusiveReason, AllReasonCodes()...)
		}
		if h.Outcome != HypothesisInconclusive && h.InconclusiveReason != "" {
			c.add("inconclusive_reason_code", "only set for an inconclusive outcome")
		}
		for i, chk := range h.Checks {
			c.required("checks[].prediction", chk.Prediction)
			c.oneof("checks[].result", chk.Result, "met", "unmet", "unevaluable")
			c.required("checks[].evidence_ref", chk.EvidenceRef)
			_ = i
		}
		if h.Outcome == HypothesisSupported && len(h.Checks) == 0 {
			c.add("checks", "a supported hypothesis must show the checks that support it")
		}
		if h.Outcome == HypothesisRefuted {
			met := false
			for _, chk := range h.Checks {
				if chk.Result == "unmet" {
					met = true
				}
			}
			if !met {
				c.add("checks", "refutation needs at least one unmet prediction")
			}
		}
		if h.ClaimType == ClaimConfirmed {
			c.add("claim_type", "a hypothesis may not self-certify; confirmation is a "+
				"C-06 determination")
		}
		return c.err()
	})
}

func init() { registerHypothesisContracts() }
