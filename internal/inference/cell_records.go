package inference

import (
	"fmt"
	"sort"
	"time"

	"xammu/internal/attributor"
	"xammu/internal/contracts"
	"xammu/internal/hypothesis"
)

// buildProfile grades the evidence one cell holds. The counts come from the cell,
// the control flags from the attributor's own derivation of the control exchanges,
// and the claim ceiling from the ladder in the hypothesis package: this function
// chooses none of them.
func buildProfile(j *Journal, cell Cell, controls Controls, posValid, negValid bool,
	opts Options, at time.Time) (contracts.EvidenceProfile, error) {
	trials := hypothesis.Trials{
		Population:           len(cell.Trials),
		Valid:                cell.Valid,
		Inconclusive:         cell.Inconclusive,
		Invalid:              cell.Invalid,
		Replicas:             cell.Replicas(),
		Rounds:               cell.RoundIDs,
		PositiveControlValid: posValid,
		NegativeControlValid: negValid,
		CorroborationSource:  corroborationSource(opts.Corroboration[cell.Ref()]),
		Hits:                 blockCount(cell),
		HitBasis: "valid trials of this cell that the classifier read as signal_block, over the valid " +
			"trials of the same cell; the rate counts a response shape and not a cause",
		Refs: evidenceRefs(cell, controls),
	}
	return hypothesis.Profile(hypothesis.Subject{
		RunID: j.RunID, Ref: cell.Ref(), Kind: "probe_cell",
		Trials: trials, CompiledAt: at,
	})
}

// evidenceRefs lists the records a profile is built from: the cell's own
// classifications plus the calibration records its control-validity flags derive
// from. The controls belong in the list because a hypothesis about ordinary handling
// cites them, and a citation has to resolve to a record that exists in the bundle.
func evidenceRefs(cell Cell, controls Controls) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, t := range cell.Trials {
		add(t.ClassificationID)
	}
	for _, t := range controls.Positive {
		add(t.ClassificationID)
	}
	for _, t := range controls.Negative {
		add(t.ClassificationID)
	}
	sort.Strings(out)
	return out
}

func corroborationSource(c *attributor.Corroboration) string {
	if c == nil || !c.Agrees {
		return ""
	}
	return c.Kind
}

func blockCount(cell Cell) int {
	var n int
	for _, t := range cell.Trials {
		if t.Valid && t.Signal == contracts.SignalBlock {
			n++
		}
	}
	return n
}

func datums(cell Cell) []attributor.Datum {
	out := make([]attributor.Datum, 0, len(cell.Trials))
	for _, t := range cell.Trials {
		out = append(out, attributor.Datum{
			RoundID: t.RoundID, Classification: t.ClassificationID, Observation: t.ObservationID,
			ProbeRef: t.ProbeRef, Signal: t.Signal, StatusCode: t.StatusCode,
		})
	}
	return out
}

func cellTime(cell Cell) time.Time {
	var at time.Time
	for _, t := range cell.Trials {
		if t.At.After(at) {
			at = t.At
		}
	}
	return at
}

// claimFor states what one cell claims and tests it against the journal.
//
// Two statement shapes exist, chosen by what the cell actually read: a cell whose
// valid trials mostly rejected is tested as "something inspected the payload", a
// cell whose valid trials mostly passed is tested as "nothing inspected this payload
// at this path". Anything else - pacing, a redirect chain, no reading at all - says
// nothing about filtering, and the honest answer is the sentence in `skip`, which
// the discovery layer turns into an undetermined area rather than a forced claim.
func claimFor(j *Journal, cell Cell, controls Controls, negValid bool,
	profile contracts.EvidenceProfile, commandFlags string) (hypothesis.Claim, []hypothesis.Obstacle, string) {
	repro := fmt.Sprintf("xammu report --run %s --cell '%s'", j.RunID, cell.Ref())
	if commandFlags != "" {
		repro += " " + commandFlags
	}
	claim := hypothesis.Claim{
		RunID:       j.RunID,
		Ref:         "hyp." + cell.Ref(),
		AttackClass: cell.AttackClass,
		Vector:      cell.Vector,
		Encoding:    cell.Encoding,
		Scope: fmt.Sprintf("%s%s over %s/%s/%s", cell.Origin, cell.Path,
			cell.AttackClass, cell.Vector, cell.Encoding),
		Profile:             profile,
		AttributionRefs:     attributionRefs(j, cell),
		ReproductionCommand: repro,
	}
	var obstacles []hypothesis.Obstacle
	switch cell.MajorityReading() {
	case contracts.SignalBlock:
		claim.Statement = fmt.Sprintf(
			"The rejection shape observed at %s%s for %s injected in %s with %s encoding is produced by "+
				"a layer that inspects the request payload, not by the origin's ordinary handling of that path.",
			cell.Origin, cell.Path, cell.AttackClass, cell.Vector, cell.Encoding)
		claim.Falsifier = "a valid negative control at the same origin that the classifier also reads as " +
			"signal_block, because then the shape follows the request rather than the payload; or a " +
			"transport failure or a rate limit that accounts for the shape this cell reports."
		claim.Predictions = []string{
			"the reading repeats: two or more valid trials of this cell produced the same signal",
			"ordinary input at this origin is handled ordinarily: every benign reference and negative control read signal_pass",
			"the rejection distinguishes payload from ordinary input: this cell reads signal_block while the calibration cluster reads signal_pass",
		}
		claim.Checks, obstacles = blockChecks(cell, controls, negValid, profile)
	case contracts.SignalPass:
		claim.Statement = fmt.Sprintf(
			"Requests carrying %s in %s with %s encoding at %s%s are handled like ordinary input: no "+
				"layer on this path inspects this payload.",
			cell.AttackClass, cell.Vector, cell.Encoding, cell.Origin, cell.Path)
		claim.Falsifier = "a single valid trial of this cell that the classifier reads as signal_block, " +
			"or a calibration cluster that blocks ordinary input as well, which would make a pass " +
			"reading a shape this origin produces for everything."
		claim.Predictions = []string{
			"the reading repeats: two or more valid trials of this cell produced the same signal",
			"no valid trial of this cell was read as a rejection",
			"the cell's pass reading matches the calibration cluster's",
		}
		claim.Checks, obstacles = passChecks(cell, controls, negValid, profile)
	default:
		return hypothesis.Claim{}, nil, skipFor(cell)
	}
	return claim, obstacles, ""
}

func blockChecks(cell Cell, controls Controls, negValid bool,
	profile contracts.EvidenceProfile) ([]hypothesis.Check, []hypothesis.Obstacle) {
	var checks []hypothesis.Check
	var obstacles []hypothesis.Obstacle

	replica := cell.Replicas()
	const repeat = "the reading repeats: two or more valid trials of this cell produced the same signal"
	switch {
	case replica >= 2:
		checks = append(checks, hypCheck(repeat, hypothesis.MetResult,
			majorityRef(cell, contracts.SignalBlock)))
	case cell.Valid == 0:
		checks = append(checks, hypCheck(repeat, hypothesis.UnevaluableResult, profile.ProfileID))
		obstacles = append(obstacles, obstacle(cellBlocker(cell),
			"the cell has no valid trial, so repetition cannot be tested"))
	default:
		checks = append(checks, hypCheck(repeat, hypothesis.UnevaluableResult, profile.ProfileID))
		obstacles = append(obstacles, obstacle(contracts.ReasonNotYetAttempted,
			fmt.Sprintf("the cell holds %d valid trial(s); repetition needs a second one and this run "+
				"produced none, which leaves the prediction untested rather than false", cell.Valid)))
	}

	const baseline = "ordinary input at this origin is handled ordinarily: every benign reference and negative control read signal_pass"
	const discriminates = "the rejection distinguishes payload from ordinary input: this cell reads signal_block while the calibration cluster reads signal_pass"
	if len(controls.Negative) == 0 {
		checks = append(checks,
			hypCheck(baseline, hypothesis.UnevaluableResult, profile.ProfileID),
			hypCheck(discriminates, hypothesis.UnevaluableResult, profile.ProfileID))
		obstacles = append(obstacles, obstacle(contracts.ReasonCorpusGap,
			"the plan carried no benign reference or negative control for this origin, so nothing in "+
				"this run can separate a payload reaction from a blanket one"))
		return checks, obstacles
	}
	negEvidence := controls.Negative[0].ClassificationID
	if negValid {
		checks = append(checks,
			hypCheck(baseline, hypothesis.MetResult, negEvidence),
			hypCheck(discriminates, hypothesis.MetResult, negEvidence))
		return checks, obstacles
	}
	unmet := firstBlocked(controls.Negative)
	checks = append(checks,
		hypCheck(baseline, hypothesis.UnmetResult, unmet),
		hypCheck(discriminates, hypothesis.UnmetResult, unmet))
	return checks, obstacles
}

func passChecks(cell Cell, controls Controls, negValid bool,
	profile contracts.EvidenceProfile) ([]hypothesis.Check, []hypothesis.Obstacle) {
	var checks []hypothesis.Check
	var obstacles []hypothesis.Obstacle

	replica := cell.Replicas()
	const repeat = "the reading repeats: two or more valid trials of this cell produced the same signal"
	if replica >= 2 {
		checks = append(checks, hypCheck(repeat, hypothesis.MetResult,
			majorityRef(cell, contracts.SignalPass)))
	} else {
		checks = append(checks, hypCheck(repeat, hypothesis.UnevaluableResult, profile.ProfileID))
		reason := contracts.ReasonNotYetAttempted
		detail := fmt.Sprintf("the cell holds %d valid trial(s); repetition needs a second one", cell.Valid)
		if cell.Valid == 0 {
			reason = cellBlocker(cell)
			detail = "the cell has no valid trial"
		}
		obstacles = append(obstacles, obstacle(reason, detail))
	}

	const noReject = "no valid trial of this cell was read as a rejection"
	if blockCount(cell) > 0 {
		checks = append(checks, hypCheck(noReject, hypothesis.UnmetResult,
			majorityRef(cell, contracts.SignalBlock)))
	} else {
		checks = append(checks, hypCheck(noReject, hypothesis.MetResult,
			majorityRef(cell, contracts.SignalPass)))
	}

	const matches = "the cell's pass reading matches the calibration cluster's"
	switch {
	case len(controls.Negative) == 0:
		checks = append(checks, hypCheck(matches, hypothesis.UnevaluableResult, profile.ProfileID))
		obstacles = append(obstacles, obstacle(contracts.ReasonCorpusGap,
			"the run exchanged no calibration cluster, so ordinary handling has nothing to be "+
				"compared against"))
	case negValid:
		checks = append(checks, hypCheck(matches, hypothesis.MetResult,
			controls.Negative[0].ClassificationID))
	default:
		checks = append(checks, hypCheck(matches, hypothesis.UnmetResult, firstBlocked(controls.Negative)))
	}
	return checks, obstacles
}

func hypCheck(prediction, result, evidence string) hypothesis.Check {
	return hypothesis.Check{Prediction: prediction, Result: result, EvidenceRef: evidence}
}

func obstacle(reason contracts.ReasonCode, detail string) hypothesis.Obstacle {
	return hypothesis.Obstacle{Reason: reason, Detail: detail}
}

// majorityRef returns the classification id of a valid trial that produced the wanted
// signal, falling back to any valid trial so a check always cites a real record.
func majorityRef(cell Cell, want contracts.Signal) string {
	for _, t := range cell.Trials {
		if t.Valid && t.Signal == want {
			return t.ClassificationID
		}
	}
	for _, t := range cell.Trials {
		if t.Valid {
			return t.ClassificationID
		}
	}
	return ""
}

func firstBlocked(trials []Trial) string {
	for _, t := range trials {
		if t.Signal == contracts.SignalBlock {
			return t.ClassificationID
		}
	}
	if len(trials) > 0 {
		return trials[0].ClassificationID
	}
	return ""
}

func attributionRefs(j *Journal, cell Cell) []string {
	if a, ok := j.Attributions[cell.Ref()]; ok {
		return []string{a.AttributionID}
	}
	return nil
}

// skipFor explains, in the report's words, why a cell produced no hypothesis. Each
// sentence names the readings that caused it, so an undetermined area is countable
// and reproducible instead of mysterious.
func skipFor(cell Cell) string {
	majority := cell.MajorityReading()
	switch {
	case len(cell.Trials) == 0:
		return "the cell has no classified exchange at all: nothing was observed on this path"
	case cell.Valid == 0:
		return fmt.Sprintf("no valid trial in this cell (%s): the zone is undetermined, not quiet",
			signalTally(cell))
	case majority == contracts.SignalRateLimited:
		return fmt.Sprintf("every valid reading in this cell is a limit response (%s): the exchange "+
			"reports pacing, and pacing says nothing about whether a payload was inspected",
			signalTally(cell))
	case majority == contracts.SignalRedirect:
		return fmt.Sprintf("the dominant reading in this cell is a redirect chain (%s): the exchange "+
			"ended before any handling of the payload was observable", signalTally(cell))
	default:
		return fmt.Sprintf("the cell's readings are mixed (%s): no single statement about this path "+
			"is testable from them", signalTally(cell))
	}
}

func signalTally(cell Cell) string {
	var parts []string
	for _, s := range contracts.AllSignals() {
		if n := cell.Signals[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s x%d", s, n))
		}
	}
	if len(parts) == 0 {
		return "no signals"
	}
	return joinSorted(parts)
}

// cellBlocker types why a cell with no valid trial produced nothing, from the
// signals the journal actually holds rather than from a guess.
func cellBlocker(cell Cell) contracts.ReasonCode {
	switch {
	case len(cell.Trials) == 0:
		return contracts.ReasonNotYetAttempted
	case cell.Signals[contracts.SignalTransportError] > 0:
		return contracts.ReasonTransportFailure
	case cell.Signals[contracts.SignalRateLimited] > 0:
		return contracts.ReasonRateLimited
	case everyTrialFromAFailingOrigin(cell):
		// Checked before the inconclusive case on purpose: an indeterminate signal
		// arrived as a 5xx, and naming it "inconclusive" would hide that the zone is
		// unmeasurable because the destination is broken rather than ambiguous.
		return contracts.ReasonOriginUnstable
	case cell.Signals[contracts.SignalIndeterminate] > 0:
		return contracts.ReasonInconclusiveSignal
	default:
		return contracts.ReasonOriginUnstable
	}
}

// everyTrialFromAFailingOrigin reports that each exchange in the cell answered 5xx
// or better. It is what separates "the defence gave us nothing to read" from "the
// endpoint does not work", and only the second one makes the whole zone unassessable.
func everyTrialFromAFailingOrigin(cell Cell) bool {
	for _, t := range cell.Trials {
		if t.StatusCode < 500 {
			return false
		}
	}
	return len(cell.Trials) > 0
}

func obstacleDetail(cell Cell) string {
	return "readings: " + signalTally(cell) + statusTally(cell)
}

// statusTally names the statuses the cell actually saw, so an undetermined zone
// states the failure it blames rather than only the signal derived from it.
func statusTally(cell Cell) string {
	seen := map[int]bool{}
	var parts []string
	for _, t := range cell.Trials {
		if t.StatusCode == 0 || seen[t.StatusCode] {
			continue
		}
		seen[t.StatusCode] = true
		parts = append(parts, fmt.Sprintf("%d", t.StatusCode))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", statuses: " + joinSorted(parts)
}
