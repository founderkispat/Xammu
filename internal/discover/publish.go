package discover

import (
	"fmt"
	"strings"

	"xammu/internal/contracts"
)

// draft is one finding before it is checked. The fields that C-16 makes mandatory
// are assembled here rather than at each detector, so a detector cannot forget one:
// the reproduction command, the UUID, the timestamps and the claim ladder are all
// filled by publish, and a draft that still cannot be published is an error out of
// Analyze.
type draft struct {
	Ref      string
	Type     contracts.FindingType
	Scope    string
	Class    contracts.AttackClass
	Vector   contracts.Vector
	Encoding contracts.Encoding

	Observed string
	Inferred string
	Missing  string
	Limits   []string

	Impact        contracts.Ratio
	Priority      contracts.Priority
	PriorityBasis string

	Recommendation string
	Note           string
	Regression     string

	Observations []string
	Alternatives []contracts.AlternativeAssessment
	Stance       stance
	ProfileRef   string
	Hypothesis   string

	// Reason is set only for undetermined areas, where C-16 requires a typed reason
	// for the absence and forbids an inferential claim about it.
	Reason contracts.ReasonCode
}

// publish turns a draft into a C-16 record and appends it to the report. Nothing
// reaches a reader that the contract would refuse.
func (ix *index) publish(d draft, rep *Report) error {
	if strings.TrimSpace(d.Regression) == "" {
		return fmt.Errorf("discover: finding %s has no regression test to run: a finding nobody can "+
			"re-test after a configuration change is a photograph, not a measurement", d.Ref)
	}
	f := contracts.DiscoveryFinding{
		FindingID:   contracts.NewUUID(),
		Ref:         d.Ref,
		RunID:       ix.in.RunID,
		DetectedAt:  ix.in.GeneratedAt,
		FindingType: d.Type,
		ClaimType:   d.Stance.Claim,

		WhatWasObserved:       d.Observed,
		WhatIsInferred:        d.Inferred,
		WhatEvidenceIsMissing: d.Missing,
		Limitations:           d.Limits,

		AttributionStatus:  d.Stance.Attribution,
		EvidenceBasis:      d.Stance.Basis,
		Alternatives:       d.Alternatives,
		EvidenceLevel:      d.Stance.Level,
		EvidenceProfileRef: d.ProfileRef,
		HypothesisRef:      d.Hypothesis,
		ObservationRefs:    d.Observations,

		ReproductionCommand:  ix.reproduce(d.Ref),
		Recommendation:       d.Recommendation,
		RegressionTest:       d.Regression,
		Priority:             d.Priority,
		PriorityBasis:        d.PriorityBasis,
		MeasuredImpact:       d.Impact,
		AffectedScope:        d.Scope,
		AttackClass:          d.Class,
		Vector:               d.Vector,
		Encoding:             d.Encoding,
		SecurityEngineerNote: d.Note,
		UnevaluatedReason:    d.Reason,
	}
	if d.Type == contracts.FindingUndeterminedArea {
		// An undetermined area is a declaration of ignorance. It cannot carry a
		// claim about behaviour, and its evidence is the absence in the journal,
		// so the ladder does not apply to it -- but neither does any inference.
		f.ClaimType = contracts.ClaimDescriptive
		f.AttributionStatus = contracts.AttributionUndetermined
		f.EvidenceBasis = contracts.BasisNone
		f.EvidenceLevel = contracts.EvidenceNone
		f.MeasuredImpact = contracts.Ratio{}
		f.Priority = contracts.PriorityLow
	}
	if err := contracts.Validate(contracts.IDDiscoveryFinding, f); err != nil {
		return fmt.Errorf("discover: finding %s is not publishable: %w", d.Ref, err)
	}
	rep.Findings = append(rep.Findings, f)
	rep.Counts[f.FindingType]++
	return nil
}

// withFlags appends the operator's placement choices to a command that shares the
// plan flags. Commands that take their own flags - a `xammu lab test` scenario - are
// built without it.
func (ix *index) withFlags(cmd string) string {
	if ix.in.CommandFlags == "" {
		return cmd
	}
	return cmd + " " + ix.in.CommandFlags
}

// withEngagement builds the step a reader takes to measure something this run did not:
// it carries the permission and the corpus, never this run's scope. A step that asked
// for the run's own --class would plan the class that was already planned, and the
// reader would spend requests to re-learn nothing.
func (ix *index) withEngagement(cmd string) string {
	if ix.in.EngagementFlags != "" {
		return cmd + " " + ix.in.EngagementFlags
	}
	return cmd + ix.authFlag()
}

// authFlag names the permission a copied command needs. The CLI already puts the
// reference of the loaded C-09 - and the directory it resolved in - into the shared
// plan flags, so naming it a second time here would publish one flag holding two
// different values. A caller that passes no plan flags at all still gets the reference,
// because a command that does not name its scope is not a reproduction of anything.
//
// The test is for the flag with its value separator, not for the prefix: the directory
// flag starts with the same characters, and matching the prefix would let a command
// that names only a directory claim to name a permission.
func (ix *index) authFlag() string {
	if strings.Contains(ix.in.CommandFlags, "--authorization ") {
		return ""
	}
	return " --authorization " + ix.in.AuthorizationRef
}

// reproduce binds the command to this authorization. A reader who copies it re-runs
// the measurement inside the same scope; a command that only names a run could be
// pointed at a different target.
func (ix *index) reproduce(ref string) string {
	cmd := fmt.Sprintf("xammu validate --finding %s%s", ref, ix.authFlag())
	if ix.in.Pass != nil && ix.in.Pass.RunID != "" && ix.in.RunID == ix.in.Pass.RunID {
		cmd = fmt.Sprintf("xammu validate --finding %s --run %s%s", ref, ix.in.RunID, ix.authFlag())
	}
	return ix.withFlags(cmd)
}

// altContext is what the run actually contains, measured rather than asserted: the
// competing explanations are graded against it, so an alternative is never marked
// ruled_out because marking it so was convenient.
type altContext struct {
	// ControlsDiscriminate is true when a valid positive control was refused and a
	// valid calibration exchange on the same route was not: the detector ensemble
	// separated the two shapes in this run.
	ControlsDiscriminate bool
	// RouteContrast is true when the run holds a refused exchange and a passed one
	// at the same path, so an origin-side explanation has been looked at.
	RouteContrast bool
	// RateLimited is true when any exchange in scope produced a 429.
	RateLimited bool
	// DifferenceIsContent is true when the finding's difference comes from the
	// payload rather than from where the payload was placed.
	DifferenceIsContent bool
	// Cited holds observation ids to attach to the graded alternatives.
	Cited []string
}

func (ix *index) altContext(rs []reading, differenceIsContent bool) altContext {
	ctx := altContext{
		ControlsDiscriminate: ix.positiveRefused && ix.anyCalibrationPassed(),
		RouteContrast:        ix.anyRefused && ix.anyCalibrationPassed(),
		RateLimited:          ix.anyRateLimited,
		DifferenceIsContent:  differenceIsContent,
		Cited:                ix.citations(rs, 6),
	}
	return ctx
}

func (ix *index) anyCalibrationPassed() bool {
	for _, tr := range ix.benign {
		if tr.Valid && tr.Signal == contracts.SignalPass {
			return true
		}
	}
	return false
}

// alternativesFor grades the competing explanations for an observed difference.
// Every entry states what it rests on and what test would settle it: a report that
// lists alternatives without a way to resolve them is decoration.
func alternativesFor(ctx altContext) []contracts.AlternativeAssessment {
	refs := ctx.Cited
	if len(refs) == 0 {
		refs = []string{}
	}
	none := []string{}

	out := []contracts.AlternativeAssessment{
		{
			Kind: contracts.AltWAF, State: contracts.AltSupported,
			Justification: alternativeReason(ctx,
				"the run contains both a refused exchange and an ordinarily handled one, and the "+
					"calibration pair on the same route separates the two shapes",
				"the difference is only ever seen on one side, so the engine is the candidate that fits "+
					"but is not separated from the alternatives"),
			TestThatWouldResolve: "authorized exchange that reaches the origin without the front end, " +
				"or the engine's own rule configuration",
			EvidenceRefs: refs,
		},
		{
			Kind: contracts.AltOriginApplication,
			State: alternativeState(ctx.RouteContrast,
				contracts.AltRuledOut, contracts.AltNotRuledOut),
			Justification: alternativeReason(ctx,
				"a valid benign exchange on the same route returned the origin's ordinary shape, so the "+
					"origin answers this path when it is not rejecting",
				"no authorized exchange isolates the origin's own handling of this path, so the origin's "+
					"input validation cannot be excluded as the source of the difference"),
			TestThatWouldResolve: "authorized request to the origin directly, bypassing the front end",
			EvidenceRefs:         refs,
		},
		{
			Kind: contracts.AltReverseProxyOrCDN, State: contracts.AltNotRuledOut,
			Justification: "the authorization covers one destination; nothing in the run distinguishes a " +
				"proxy or CDN layer from the engine it forwards to, so a refusal at an earlier hop would " +
				"look identical here",
			TestThatWouldResolve: "response header comparison across an authorized direct-origin exchange, " +
				"or the operator's topology",
			EvidenceRefs: none,
		},
		{
			Kind: contracts.AltRateLimiting,
			State: alternativeState(!ctx.RateLimited,
				contracts.AltRuledOut, contracts.AltNotRuledOut),
			Justification: alternativeReason(ctx,
				"no exchange in scope returned 429, and the refused responses carry the interstitial shape "+
					"rather than a throttling one",
				"at least one exchange in scope returned 429, so pacing and rejection are not separable "+
					"in this run"),
			TestThatWouldResolve: "status and Retry-After inspection already performed on every exchange",
			EvidenceRefs:         refs,
		},
		{
			Kind: contracts.AltHarnessArtifact, State: contracts.AltRuledOut,
			Justification: alternativeReason(ctx,
				"the same client, body shape and route produced both readings, and the calibration pair "+
					"moved with the payload rather than with the transport",
				"the readings differ only where the payload differs; a harness artefact would have moved "+
					"the calibration exchanges too, and they did not move"),
			TestThatWouldResolve: "replay of one refused and one passed exchange from the journal with the " +
				"same client",
			EvidenceRefs: refs,
		},
	}
	if !ctx.DifferenceIsContent {
		out = append(out, contracts.AlternativeAssessment{
			Kind: contracts.AltRoutingDivergence, State: contracts.AltNotRuledOut,
			Justification: "the finding compares locations, not payloads: a router or framework that maps " +
				"one transport to a different handler would produce the same difference before any engine " +
				"saw the request",
			TestThatWouldResolve: "origin-side access log entry for both placements, showing which handler " +
				"received each",
			EvidenceRefs: none,
		})
	} else {
		out = append(out,
			contracts.AlternativeAssessment{
				Kind: contracts.AltInputNormalization, State: contracts.AltNotRuledOut,
				Justification: "a framework that decodes or rejects the payload before the engine sees it can " +
					"produce the same reading difference; this run cannot tell the two apart because only " +
					"the response is authorized evidence",
				TestThatWouldResolve: "the origin's own error shape for the same payload, or its request " +
					"pipeline configuration",
				EvidenceRefs: none,
			},
			contracts.AlternativeAssessment{
				Kind: contracts.AltAuthZLayer, State: contracts.AltUnevaluable,
				Justification: "no authorized exchange carries an authenticated session, so an authorization " +
					"layer in front of the handler cannot be evaluated at all",
				TestThatWouldResolve: "an authorized authenticated request reproducing both readings",
				EvidenceRefs:         none,
			},
		)
	}
	return out
}

func alternativeState(cond bool, whenTrue, whenFalse contracts.AlternativeState) contracts.AlternativeState {
	if cond {
		return whenTrue
	}
	return whenFalse
}

func alternativeReason(ctx altContext, whenDiscriminates, whenSingleSide string) string {
	if ctx.ControlsDiscriminate {
		return whenDiscriminates
	}
	return whenSingleSide
}

// undeterminedAlternatives is the honest set for an area with no reading: nothing
// can be excluded, and saying so is the finding.
func (ix *index) undeterminedAlternatives(detail string) []contracts.AlternativeAssessment {
	return []contracts.AlternativeAssessment{
		{
			Kind: contracts.AltWAF, State: contracts.AltUnevaluable,
			Justification: "no valid reading exists for this zone, so no behaviour of the engine is " +
				"in evidence: " + detail,
			TestThatWouldResolve: "an authorized exchange that produces one valid reading",
			EvidenceRefs:         ix.absenceCitation("no-reading"),
		},
		{
			Kind: contracts.AltOriginApplication, State: contracts.AltUnevaluable,
			Justification: "the origin's own handling is equally unobserved: the absence of a reading says " +
				"nothing about either side of the path",
			TestThatWouldResolve: "a valid reading, or an authorized direct-origin exchange",
			EvidenceRefs:         ix.absenceCitation("no-reading"),
		},
		{
			Kind: contracts.AltHarnessArtifact, State: contracts.AltNotRuledOut,
			Justification: "the reason this zone has no reading has not been separated from a failure of " +
				"the run itself; the typed reason code states what was recorded, not what caused it",
			TestThatWouldResolve: "re-run of the planned exchange under the same authorization",
			EvidenceRefs:         ix.absenceCitation("no-reading"),
		},
	}
}
