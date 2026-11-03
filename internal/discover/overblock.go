package discover

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/hypothesis"
	"xammu/internal/inference"
)

// overBlocking measures legitimate traffic against the legitimate population. The
// denominator is the corpus's own benign set -- negative controls and benign
// references -- because a rate over "the requests we liked" is not a false-positive
// rate at all.
//
// Refusals here are counted, not characterised: the finding says which shapes were
// refused and how often, and leaves the judgement about whether the allowlist should
// grow to the operator who owns the traffic.
func (ix *index) overBlocking(rep *Report) error {
	var rs []reading
	for _, tr := range ix.benign {
		item, err := ix.expectationOf(tr)
		if err != nil {
			return err
		}
		rs = append(rs, reading{Trial: tr, Item: item})
	}
	impact := ratioOfReadings(rs,
		"valid calibration exchanges the corpus defines as legitimate traffic (negative controls and "+
			"benign references), over every such exchange this run sent",
		"run:"+ix.in.RunID+"/round:"+ix.in.RoundID+"/controls",
		func(r reading) bool { return r.refused() })
	if impact.Numerator == 0 {
		return nil
	}
	refused := keep(rs, func(r reading) bool { return r.refused() })
	// The calibration exchanges are not a probe cell, so inference never graded them
	// and no cell's profile describes this population. Grading them here with the same
	// C-08 ladder keeps the finding's evidence level a measurement of the exchanges it
	// actually counted, instead of borrowing a probe cell's level it did not use.
	prof, err := ix.controlProfile(rs, impact)
	if err != nil {
		return err
	}
	var shapes []string
	for _, r := range refused {
		shapes = append(shapes, fmt.Sprintf("%s (%s in %s, expected %s)",
			command(r.Item.Canonical), r.Trial.CorpusRef, r.Item.Vector,
			r.Item.ExpectedBehavior))
	}
	sort.Strings(shapes)
	st, err := ix.stanceAt(prof.Level, ix.readings)
	if err != nil {
		return err
	}
	ctx := ix.altContext(refused, true)
	priority, basis := priorityFrom(percent(impact), impact.Denominator)
	declared := declaredOf(refused)
	observed := fmt.Sprintf(
		"%s valid exchanges the corpus defines as legitimate were refused. The refused shapes are %s. "+
			"Every one of them is declared to be handled ordinarily (%s).",
		ratioText(impact), strings.Join(shapes, "; "), declared)
	key := inference.CellKey{AttackClass: firstClass(refused), Vector: firstVector(refused)}
	return ix.publish(draft{
		Ref:  "OVB-" + sanitize(declared),
		Type: contracts.FindingOverBlocking,
		Scope: fmt.Sprintf("legitimate traffic on %s (%d exchange(s) in the measured population)",
			key.Vector, impact.Denominator),
		Class:    firstClass(refused),
		Vector:   firstVector(refused),
		Observed: observed,
		Inferred: fmt.Sprintf(
			"the refusal follows the content of the legitimate request rather than its transport, which "+
				"is compatible with a signature that matches ordinary text -- the declared expectation for "+
				"these probes is %s, so this run measured the opposite", declared),
		Missing: missingFor(st, strings.Join(prof.MissingEvidence, "; ")) +
			"; the matched rule and its condition list are inside the engine, " +
			"so only the configuration export or a hit counter shows which rule refused each shape",
		Limits: []string{
			"the measured population is the corpus's legitimate set, not the target's real traffic: the " +
				"rate is over what XAMMU sent, and a real client mix would produce a different one",
			"does not show any legitimate request is blocked in production, only that these shapes were " +
				"refused in this run",
			fmt.Sprintf("%d inconclusive and %d invalid trial(s) are outside this count",
				impact.ExcludedInconclusive, impact.ExcludedInvalid),
			"a refusal could also come from a layer in front of the engine; the alternatives list keeps " +
				"that open rather than closing it",
		},
		Impact:         impact,
		Priority:       priority,
		PriorityBasis:  basis,
		Recommendation: recommendationFor(contracts.FindingOverBlocking, firstVector(refused), anchorsOf(refused)),
		Note: fmt.Sprintf(
			"these %d legitimate shape(s) are refused; each is a client that will be refused in "+
				"production, and the review question is the allowlist rather than the rule coverage",
			len(shapes)),
		Regression:   labStep("over-blocking", declared),
		Observations: ix.citations(refused, 8),
		Alternatives: alternativesFor(ctx),
		ProfileRef:   prof.ProfileID,
		Stance:       st,
	}, rep)
}

// controlProfile grades the calibration population with C-08. The counts come from
// the exchanges this finding measured over, and the two control facts come from the
// run's own records, so the level is earned by the population the rate is stated
// over rather than borrowed from a probe cell that counted something else.
func (ix *index) controlProfile(rs []reading, impact contracts.Ratio) (contracts.EvidenceProfile, error) {
	return hypothesis.Profile(hypothesis.Subject{
		RunID: ix.in.RunID,
		Ref:   "run:" + ix.in.RunID + "/round:" + ix.in.RoundID + "/calibration",
		Kind:  "calibration",
		Trials: hypothesis.Trials{
			Population:           len(rs),
			Valid:                impact.Denominator,
			Inconclusive:         impact.ExcludedInconclusive,
			Invalid:              impact.ExcludedInvalid,
			Replicas:             majorityCount(rs),
			Rounds:               ix.roundsIn(rs),
			PositiveControlValid: ix.positiveRefused,
			NegativeControlValid: ix.anyCalibrationPassed(),
			Hits:                 impact.Numerator,
			HitBasis: "valid calibration exchanges the corpus defines as legitimate and this run " +
				"recorded as refused",
			Refs: ix.citations(rs, 0),
		},
		CompiledAt: ix.in.GeneratedAt,
	})
}

// declaredOf names the expectations the legitimate probes carry, so the finding
// quotes the corpus rather than asserting what the probes "should" have done.
func declaredOf(rs []reading) string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		k := string(r.Item.ExpectedBehavior)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// command quotes a probe the way an engineer would type it into a test, without
// claiming it is a shell command.
func command(s string) string { return strconv.Quote(s) }
