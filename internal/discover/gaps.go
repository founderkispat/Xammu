package discover

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/inference"
)

// coverageGaps reports cells where the corpus expects refusal and the run measured
// ordinary handling as the cell's majority reading.
//
// A cell is not reported when only some of its trials contradict the expectation.
// One flipped trial out of six is an unstable origin or a flaky detector, and a
// coverage statement built on it would claim more than the measurement says; that
// cell belongs in the run's health section instead.
func (ix *index) coverageGaps(rep *Report) error {
	keys := sortedCellKeys(ix.byCell)
	for _, key := range keys {
		rs := ix.byCell[key]
		expected := keep(rs, func(r reading) bool {
			return r.Item.ExpectedBehavior == contracts.ExpectBlock
		})
		if len(expected) == 0 {
			continue
		}
		// The ratio is taken over every trial of that expectation, not only the ones
		// that produced a reading: a cell that lost two exchanges to a transport error
		// has a denominator of six and two excluded trials, and a finding that filtered
		// them out first would report 0 of 6 with nothing named as left behind.
		impact := ratioOfReadings(expected,
			fmt.Sprintf("valid probes in %s expected to be refused by the corpus, over the %s "+
				"cell's valid trials", key.String(), ix.in.Partition),
			"cell:"+key.String(), func(r reading) bool { return r.refused() })
		contradicted := impact.Denominator - impact.Numerator
		if impact.Denominator == 0 || contradicted*2 <= impact.Denominator {
			continue
		}
		if err := ix.publishCoverageGap(key, expected, impact, contradicted, rep); err != nil {
			return err
		}
	}
	return nil
}

func (ix *index) publishCoverageGap(key inference.CellKey, rs []reading, impact contracts.Ratio,
	contradicted int, rep *Report) error {
	st, err := ix.stanceFor(rs)
	if err != nil {
		return err
	}
	ctx := ix.altContext(rs, true)
	points := 100 - percent(impact)
	priority, basis := priorityFrom(points, impact.Denominator)
	refs := refsOf(rs)
	scope := fmt.Sprintf("%s x %s x %s on %s %s", key.AttackClass, key.Vector, key.Encoding,
		verbForReadings(rs), key.Path)
	observed := fmt.Sprintf(
		"of %d valid trials in the %s cell, %d produced the block shape the corpus expects and %d were "+
			"handled ordinarily; majority reading %s. Expectation declared by %s. Corpus refs: %s.",
		impact.Denominator, key.String(), impact.Numerator, contradicted,
		majorityOf(rs), anchorsOf(rs), strings.Join(refs, ", "))
	note := fmt.Sprintf(
		"probes built on the %s signature are reaching this transport unrefused; take the %s cell to the "+
			"rule-set review for %s and check whether it is enabled for that transport",
		strings.Join(rulesOf(rs), ", "), key.Vector, key.AttackClass)
	return ix.publish(draft{
		Ref:      "GAP-" + sanitize(key.String()),
		Type:     contracts.FindingCoverageGap,
		Scope:    scope,
		Class:    key.AttackClass,
		Vector:   key.Vector,
		Encoding: key.Encoding,
		Observed: observed,
		Inferred: fmt.Sprintf(
			"handling in this cell contradicts the expectation the corpus declares, which is compatible "+
				"with the %s signature not being evaluated for %s traffic at %s",
			strings.Join(rulesOf(rs), " or "), key.Vector, key.Path),
		Missing: missingFor(st, ix.missingEvidenceNote(rs)),
		Limits: []string{
			"does not show the origin is vulnerable to " + string(key.AttackClass),
			"does not show no rule inspects this transport: it shows these probes were not refused",
			fmt.Sprintf("%d inconclusive and %d invalid trial(s) are outside this count",
				impact.ExcludedInconclusive, impact.ExcludedInvalid),
			"a partial contradiction inside the cell is not reported here; only the majority reading is",
		},
		Impact:         impact,
		Priority:       priority,
		PriorityBasis:  basis,
		Recommendation: recommendationFor(contracts.FindingCoverageGap, key.Vector, anchorsOf(rs)),
		Note:           note,
		Regression:     labStep("coverage-gap", key.String()),
		Observations:   ix.citations(rs, 8),
		Alternatives:   alternativesFor(ctx),
		ProfileRef:     ix.profileRef(rs),
		Hypothesis:     ix.hypothesisRef(rs),
		Stance:         st,
	}, rep)
}

// encodingBypasses compares each probe family's canonical form with its encoding
// replicas. The finding is the difference, so a family that was never refused in
// canonical form cannot produce a bypass: there would be nothing to walk past.
func (ix *index) encodingBypasses(rep *Report) error {
	for _, group := range ix.sortedGroups() {
		rs := ix.byGroup[group]
		canonical := keep(rs, func(r reading) bool {
			return r.Item.Encoding == contracts.EncodingCanonical && r.valid()
		})
		replicas := keep(rs, func(r reading) bool {
			return r.Item.Encoding != contracts.EncodingCanonical && r.valid()
		})
		if len(canonical) == 0 || len(replicas) == 0 {
			continue
		}
		blocked := ratioOfReadings(canonical,
			"valid canonical-form trials of group "+group, "group:"+group,
			func(r reading) bool { return r.refused() })
		if blocked.Numerator == 0 {
			continue
		}
		walked := ratioOfReadings(replicas,
			"valid encoding replicas of group "+group+", whose canonical form was refused",
			"group:"+group, func(r reading) bool { return r.passed() })
		if walked.Numerator == 0 {
			continue
		}
		if err := ix.publishEncodingBypass(group, canonical, replicas, blocked, walked, rep); err != nil {
			return err
		}
	}
	return nil
}

func (ix *index) publishEncodingBypass(group string, canonical, replicas []reading,
	blocked, walked contracts.Ratio, rep *Report) error {
	rs := append(append([]reading{}, canonical...), replicas...)
	st, err := ix.stanceFor(rs)
	if err != nil {
		return err
	}
	ctx := ix.altContext(rs, true)
	var encodings []string
	seen := map[contracts.Encoding]bool{}
	for _, r := range replicas {
		if r.passed() && !seen[r.Item.Encoding] {
			seen[r.Item.Encoding] = true
			encodings = append(encodings, string(r.Item.Encoding))
		}
	}
	sort.Strings(encodings)
	valid := blocked.Denominator + walked.Denominator
	points := percent(walked)
	priority, basis := priorityFrom(points, valid)
	scope := fmt.Sprintf("encoding family %s (%s x %s) on %s: canonical refused, %s handled ordinarily",
		group, firstClass(rs), firstVector(rs), firstPath(rs), strings.Join(encodings, ", "))
	observed := fmt.Sprintf(
		"within probe family %s, %s valid canonical-form trials produced the block shape and %s "+
			"valid encoding replicas were handled ordinarily (%s). The replicas are %s, authored from the "+
			"same canonical form %q.",
		group, ratioText(blocked), ratioText(walked),
		strings.Join(encodings, ", "), strings.Join(refsOf(replicas), ", "),
		canonical[0].Item.Canonical)
	return ix.publish(draft{
		Ref:      "BYP-" + sanitize(group),
		Type:     contracts.FindingEncodingBypass,
		Scope:    scope,
		Class:    firstClass(rs),
		Vector:   firstVector(rs),
		Encoding: firstEncoding(replicas),
		Observed: observed,
		Inferred: fmt.Sprintf(
			"the difference is the encoding of the payload, not its meaning, which is compatible with the " +
				"decoding applied before matching being shallower than the encoding applied to the probe; " +
				"the run cannot see how many decode passes the engine makes"),
		Missing: missingFor(st, ix.missingEvidenceNote(rs)) +
			"; the number of normalisation passes the engine applies is not observable from a response, " +
			"so the decoding depth is reasoned about from this difference and never measured directly",
		Limits: []string{
			"does not show any encoded payload gets through: it shows these encodings of this family were " +
				"not refused",
			"does not identify which component decodes; an origin-side normalisation would produce the " +
				"same readings and is not excluded",
			fmt.Sprintf("%d inconclusive and %d invalid trial(s) are outside this count",
				walked.ExcludedInconclusive+blocked.ExcludedInconclusive,
				walked.ExcludedInvalid+blocked.ExcludedInvalid),
		},
		Impact: contracts.Ratio{
			Numerator:   walked.Numerator,
			Denominator: valid,
			Basis: "encoding replicas of a refused family that were handled ordinarily, over every valid " +
				"trial in the comparison",
			ExcludedInconclusive: walked.ExcludedInconclusive + blocked.ExcludedInconclusive,
			ExcludedInvalid:      walked.ExcludedInvalid + blocked.ExcludedInvalid,
			PopulationRef:        "group:" + group,
		},
		Priority:      priority,
		PriorityBasis: basis,
		Recommendation: "normalise to a fixed depth before matching, then re-run this family: if the " +
			"difference disappears the cause was decoding depth; add the encodings that walked past to the " +
			"review list either way",
		Note: fmt.Sprintf(
			"these encodings of a signature the engine already detects were not refused; an operator "+
				"hardening rule coverage should treat %s as the test cases", strings.Join(encodings, ", ")),
		Regression:   labStep("encoding-bypass", group),
		Observations: ix.citations(rs, 8),
		Alternatives: alternativesFor(ctx),
		ProfileRef:   ix.profileRef(rs),
		Hypothesis:   ix.hypothesisRef(rs),
		Stance:       st,
	}, rep)
}
