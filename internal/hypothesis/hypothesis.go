package hypothesis

import (
	"fmt"
	"strings"

	"xammu/internal/contracts"
)

// The three results a prediction can have once tested. They are the literal values
// C-07 accepts; a fourth state does not exist here.
const (
	MetResult         = "met"
	UnmetResult       = "unmet"
	UnevaluableResult = "unevaluable"
)

// Check is one prediction tested against evidence.
type Check struct {
	CheckID     string
	Prediction  string
	Result      string
	EvidenceRef string
}

// Obstacle types why a prediction could not be evaluated. An inconclusive outcome is
// always paired with one: "we did not get to it" is not a reason, but "the run was
// halted by a 429 before the second round" is, and it tells the engineer what to do.
type Obstacle struct {
	Reason contracts.ReasonCode
	Detail string
}

// Claim is the material a hypothesis is formed from. The statement, its predictions
// and its falsifier are written before the checks are run; the outcome, the claim
// type and the reason are all derived afterwards from the checks and the profile.
type Claim struct {
	RunID       string
	Ref         string
	Statement   string
	AttackClass contracts.AttackClass
	Vector      contracts.Vector
	Encoding    contracts.Encoding
	Scope       string
	Predictions []string
	Falsifier   string
	// ReproductionCommand is how a reader re-runs the test. The CLI generates it
	// bound to an authorization or an existing run so it cannot leave scope.
	ReproductionCommand string
	Checks              []Check
	Obstacles           []Obstacle
	// Profile is the C-08 record for this subject. Its level caps the claim type.
	Profile          contracts.EvidenceProfile
	AttributionRefs  []string
	SourceFindingRef string
}

// Derive builds C-07. The outcome rule is mechanical: a prediction that failed
// refutes, predictions that could not be tested leave the hypothesis inconclusive
// with a typed reason, and only a full set of met predictions supports. Nothing in
// this function reads the caller's preference, and the claim type is capped twice -
// once by the evidence level and once by the rule that a hypothesis cannot certify
// its own confirmation.
func Derive(c Claim) (contracts.Hypothesis, error) {
	switch {
	case c.RunID == "":
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis: a claim needs a run id")
	case c.Ref == "":
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis: a claim needs a reference")
	case strings.TrimSpace(c.Statement) == "":
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis %s: a statement is required", c.Ref)
	case len(c.Predictions) == 0:
		return contracts.Hypothesis{}, fmt.Errorf(
			"hypothesis %s: a statement with no prediction cannot be tested, only believed", c.Ref)
	case strings.TrimSpace(c.Falsifier) == "":
		return contracts.Hypothesis{}, fmt.Errorf(
			"hypothesis %s: without a stated falsifier, no evidence could ever refute it", c.Ref)
	case strings.TrimSpace(c.Scope) == "":
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis %s: a claim must state the scope it covers", c.Ref)
	case strings.TrimSpace(c.ReproductionCommand) == "":
		return contracts.Hypothesis{}, fmt.Errorf(
			"hypothesis %s: an unreproducible claim is not a finding anyone can check", c.Ref)
	case c.Profile.RunID != c.RunID:
		return contracts.Hypothesis{}, fmt.Errorf(
			"hypothesis %s cites an evidence profile from run %s, not this run %s",
			c.Ref, c.Profile.RunID, c.RunID)
	}
	if err := contracts.Validate(contracts.IDEvidenceProfile, &c.Profile); err != nil {
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis %s: its evidence profile is not a valid C-08: %w", c.Ref, err)
	}
	claimType, err := claimTypeFor(c)
	if err != nil {
		return contracts.Hypothesis{}, err
	}
	checks, err := normalizeChecks(c)
	if err != nil {
		return contracts.Hypothesis{}, err
	}

	var met, unmet, uneval []contracts.HypothesisCheck
	for _, chk := range checks {
		switch chk.Result {
		case MetResult:
			met = append(met, chk)
		case UnmetResult:
			unmet = append(unmet, chk)
		default:
			uneval = append(uneval, chk)
		}
	}

	h := contracts.Hypothesis{
		HypothesisID:        contracts.NewUUID(),
		Ref:                 c.Ref,
		RunID:               c.RunID,
		FormedAt:            c.Profile.CompiledAt,
		Statement:           c.Statement,
		AttackClass:         c.AttackClass,
		Vector:              c.Vector,
		Encoding:            c.Encoding,
		Scope:               c.Scope,
		Predictions:         append([]string(nil), c.Predictions...),
		Falsifier:           c.Falsifier,
		Checks:              checks,
		EvidenceProfileRef:  c.Profile.ProfileID,
		ClaimType:           claimType,
		AttributionRefs:     append([]string(nil), c.AttributionRefs...),
		ReproductionCommand: c.ReproductionCommand,
		SourceFindingRef:    c.SourceFindingRef,
	}
	switch {
	case len(unmet) > 0:
		h.Outcome = contracts.HypothesisRefuted
		h.OutcomeReason = fmt.Sprintf(
			"prediction %q was not met by the evidence in %s, which is what %s said would falsify "+
				"the statement; %d of %d predictions held",
			unmet[0].Prediction, unmet[0].EvidenceRef, c.Ref, len(met)+len(uneval), len(checks))
	case len(uneval) == 0 && len(met) == len(checks) && len(checks) > 0:
		h.Outcome = contracts.HypothesisSupported
		h.OutcomeReason = fmt.Sprintf(
			"all %d predictions were met by journaled evidence; evidence level %s caps the claim at %q "+
				"(C-07 never self-certifies confirmation, so the ceiling is %s)",
			len(checks), c.Profile.Level, claimType, Version)
	default:
		code, oerr := obstacleFor(c)
		if oerr != nil {
			return contracts.Hypothesis{}, oerr
		}
		h.Outcome = contracts.HypothesisInconclusive
		h.InconclusiveReason = code
		h.OutcomeReason = inconclusivePhrase(c, checks, met, uneval, code)
	}
	if err := contracts.Validate(contracts.IDHypothesis, &h); err != nil {
		return contracts.Hypothesis{}, fmt.Errorf("hypothesis %s rejected by C-07: %w", c.Ref, err)
	}
	return h, nil
}

// claimTypeFor reads the claim type off the profile, then applies the one rule C-07
// cannot enforce from inside itself: a hypothesis is not allowed to call itself
// confirmed, because confirmation is a C-06 determination over conditions a producer
// of hypotheses does not own.
func claimTypeFor(c Claim) (contracts.ClaimType, error) {
	if c.Profile.Level == contracts.EvidenceNone {
		return "", fmt.Errorf(
			"hypothesis %s: its subject has no valid trial, so there is nothing to hypothesize over. "+
				"An unevaluated zone is a C-16 undetermined-area finding, not a hypothesis", c.Ref)
	}
	ceiling := c.Profile.ClaimCeiling
	if ceiling == "" {
		ceiling = contracts.MaxClaimType(c.Profile.Level)
	}
	if ceiling == "" {
		return "", fmt.Errorf("hypothesis %s: evidence level %q yields no claim ceiling",
			c.Ref, c.Profile.Level)
	}
	if ceiling == contracts.ClaimConfirmed {
		return contracts.ClaimAttribution, nil
	}
	return ceiling, nil
}

// normalizeChecks fills identifiers and refuses a check that cites evidence the
// profile does not hold. A check against invented evidence is the most direct way to
// launder a conclusion, so every citation has to resolve. The profile itself
// resolves: a prediction that could not be tested is unevaluable according to the
// missing list the profile carries, and citing that list is honest.
func normalizeChecks(c Claim) ([]contracts.HypothesisCheck, error) {
	known := map[string]bool{c.Profile.ProfileID: true}
	for _, r := range c.Profile.Refs {
		known[r] = true
	}
	out := make([]contracts.HypothesisCheck, 0, len(c.Checks))
	for i, chk := range c.Checks {
		id := chk.CheckID
		if id == "" {
			id = fmt.Sprintf("chk.%d", i+1)
		}
		if strings.TrimSpace(chk.Prediction) == "" {
			return nil, fmt.Errorf("hypothesis %s check %s: no prediction stated", c.Ref, id)
		}
		switch chk.Result {
		case MetResult, UnmetResult, UnevaluableResult:
		default:
			return nil, fmt.Errorf(
				"hypothesis %s check %s: result %q is not one of %s, %s, %s",
				c.Ref, id, chk.Result, MetResult, UnmetResult, UnevaluableResult)
		}
		if strings.TrimSpace(chk.EvidenceRef) == "" {
			return nil, fmt.Errorf(
				"hypothesis %s check %s: a check without an evidence reference is an assertion", c.Ref, id)
		}
		if len(known) > 0 && !known[chk.EvidenceRef] {
			return nil, fmt.Errorf(
				"hypothesis %s check %s cites %s, which its evidence profile does not hold",
				c.Ref, id, chk.EvidenceRef)
		}
		out = append(out, contracts.HypothesisCheck{
			CheckID:     id,
			Prediction:  chk.Prediction,
			Result:      chk.Result,
			EvidenceRef: chk.EvidenceRef,
		})
	}
	return out, nil
}

// obstacleFor returns the typed reason for an inconclusive outcome. It is taken from
// the run's own recorded obstacles, never invented here; if the caller cannot name
// one, the outcome is not inconclusive, it is unexplained.
func obstacleFor(c Claim) (contracts.ReasonCode, error) {
	for _, o := range c.Obstacles {
		if o.Reason == "" {
			continue
		}
		if !validReason(o.Reason) {
			return "", fmt.Errorf("hypothesis %s: reason code %q is not in the contract's vocabulary",
				c.Ref, o.Reason)
		}
		return o.Reason, nil
	}
	return "", fmt.Errorf(
		"hypothesis %s cannot be left inconclusive without a reason: state the obstacle "+
			"(transport failure, rate-limit halt, exhausted budget, invalid control, indeterminate signal)", c.Ref)
}

func validReason(r contracts.ReasonCode) bool {
	for _, v := range contracts.AllReasonCodes() {
		if v == r {
			return true
		}
	}
	return false
}

func inconclusivePhrase(c Claim, checks, met, uneval []contracts.HypothesisCheck,
	code contracts.ReasonCode) string {
	detail := ""
	for _, o := range c.Obstacles {
		if o.Reason == code && strings.TrimSpace(o.Detail) != "" {
			detail = ": " + strings.TrimSpace(o.Detail)
			break
		}
	}
	if len(checks) == 0 {
		return fmt.Sprintf("no prediction of %s has been tested against evidence yet (%s%s)",
			c.Ref, code, detail)
	}
	return fmt.Sprintf("%d of %d predictions could not be evaluated (%s%s); %d held, none failed, "+
		"so the statement is neither supported nor refuted",
		len(uneval), len(checks), code, detail, len(met))
}
