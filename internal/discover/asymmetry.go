package discover

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/inference"
)

// vectorAsymmetries compares one probe family across the transports it was placed
// in. This is the finding a coverage statement about a single cell cannot make: the
// payload is the same, so the only variable is where it was put.
//
// It is reported per family rather than per cell pair because the family is what
// makes the comparison fair: two different signatures that happen to differ across
// vectors measure two things at once.
func (ix *index) vectorAsymmetries(rep *Report) error {
	for _, group := range ix.sortedGroups() {
		rs := ix.byGroup[group]
		byVector := map[contracts.Vector][]reading{}
		for _, r := range rs {
			if r.valid() {
				byVector[r.Item.Vector] = append(byVector[r.Item.Vector], r)
			}
		}
		if len(byVector) < 2 {
			continue
		}
		vectors := make([]contracts.Vector, 0, len(byVector))
		rates := map[contracts.Vector]contracts.Ratio{}
		for v, set := range byVector {
			vectors = append(vectors, v)
			rates[v] = ratioOfReadings(set,
				fmt.Sprintf("valid trials of family %s placed in the %s transport", group, v),
				"group:"+group+"/vector:"+string(v),
				func(r reading) bool { return r.refused() })
		}
		sort.Slice(vectors, func(i, k int) bool {
			if rates[vectors[i]].Numerator != rates[vectors[k]].Numerator {
				return percent(rates[vectors[i]]) > percent(rates[vectors[k]])
			}
			return vectors[i] < vectors[k]
		})
		most, least := vectors[0], vectors[len(vectors)-1]
		if majorityOf(byVector[most]) != contracts.SignalBlock ||
			majorityOf(byVector[least]) != contracts.SignalPass {
			continue
		}
		if err := ix.publishAsymmetry(group, most, least, byVector, rates, rep); err != nil {
			return err
		}
	}
	return nil
}

func (ix *index) publishAsymmetry(group string, most, least contracts.Vector,
	byVector map[contracts.Vector][]reading, rates map[contracts.Vector]contracts.Ratio, rep *Report) error {
	strong, weak := byVector[most], byVector[least]
	rs := append(append([]reading{}, strong...), weak...)
	st, err := ix.stanceFor(rs)
	if err != nil {
		return err
	}
	ctx := ix.altContext(rs, false)
	combined := contracts.Ratio{
		Numerator:   rates[least].Numerator,
		Denominator: rates[most].Denominator + rates[least].Denominator,
		Basis: fmt.Sprintf("valid trials of family %s that were refused, over both transports in the "+
			"comparison; the %s side contributed %d of %d and the %s side %d of %d",
			group, most, rates[most].Numerator, rates[most].Denominator,
			least, rates[least].Numerator, rates[least].Denominator),
		ExcludedInconclusive: rates[most].ExcludedInconclusive + rates[least].ExcludedInconclusive,
		ExcludedInvalid:      rates[most].ExcludedInvalid + rates[least].ExcludedInvalid,
		PopulationRef:        "group:" + group,
	}
	valid := rates[most].Denominator + rates[least].Denominator
	points := pointsBetween(rates[most], rates[least])
	priority, basis := priorityFrom(points, valid)
	canonical := canonicalFormOf(strong)
	observed := fmt.Sprintf(
		"one payload family, two transports: %s valid trials of %s placed in %s produced %s refusals, "+
			"and %s valid trials of the same family placed in %s produced %s. Expectations behind these "+
			"probes: %s.",
		ratioText(rates[most]), canonical, most, majorityWord(strong),
		ratioText(rates[least]), least, majorityWord(weak), anchorsOf(rs))
	var keys []inference.CellKey
	for _, r := range rs {
		found := false
		for _, k := range keys {
			if k == r.Key {
				found = true
			}
		}
		if !found {
			keys = append(keys, r.Key)
		}
	}
	sort.Slice(keys, func(i, k int) bool { return keys[i].String() < keys[k].String() })
	return ix.publish(draft{
		Ref:  "ASY-" + sanitize(group) + "-" + sanitize(string(most)) + "vs" + sanitize(string(least)),
		Type: contracts.FindingVectorAsymmetry,
		Scope: fmt.Sprintf("family %s (%s) compared across %s and %s on %s", group, canonical,
			most, least, firstPath(rs)),
		Class:    firstClass(rs),
		Vector:   least,
		Encoding: firstEncoding(rs),
		Observed: observed,
		Inferred: fmt.Sprintf(
			"the payload is constant across the comparison, so the difference is in the transport: this is "+
				"compatible with inspection being configured for %s and not for %s, and incompatible with "+
				"an explanation that rests on the payload's content", most, least),
		Missing: missingFor(st, ix.missingEvidenceNote(rs)) +
			"; the cell pair " + strings.Join(cellNames(rs), " and ") +
			" is the comparison, so an engine configuration export naming per-transport inspection would " +
			"settle it",
		Limits: []string{
			fmt.Sprintf("does not show the %s transport is unexamined by every rule: it shows this one "+
				"family was not refused there", least),
			"the two transports are different request shapes; an origin-side router that handles them " +
				"apart is not excluded",
			fmt.Sprintf("%d inconclusive and %d invalid trial(s) are outside this count",
				combined.ExcludedInconclusive, combined.ExcludedInvalid),
			"does not show any real payload reaches the origin: only that these probes were handled " +
				"ordinarily",
		},
		Impact:         combined,
		Priority:       priority,
		PriorityBasis:  basis,
		Recommendation: recommendationFor(contracts.FindingVectorAsymmetry, least, anchorsOf(rs)),
		Note: fmt.Sprintf(
			"inspection differs by transport for this family: the %s side is where the operator's coverage "+
				"decision has to be checked, because the same bytes are refused at %s", least, most),
		Regression:   labStep("vector-asymmetry", group),
		Observations: ix.citations(rs, 8),
		Alternatives: alternativesFor(ctx),
		ProfileRef:   ix.profileRef(rs),
		Hypothesis:   ix.hypothesisRef(rs),
		Stance:       st,
	}, rep)
}

// configurationConcerns reports refusals whose corpus grounding is a named policy
// rather than a signature: a refusal that depends on request metadata. Rule-table
// review cannot predict this behaviour, which is exactly why it is a separate
// finding type and not a coverage gap.
func (ix *index) configurationConcerns(rep *Report) error {
	byPolicy := map[string][]reading{}
	for _, r := range ix.readings {
		if !r.valid() {
			continue
		}
		for _, name := range policyAnchors(r.Item) {
			byPolicy[name] = append(byPolicy[name], r)
		}
	}
	names := make([]string, 0, len(byPolicy))
	for n := range byPolicy {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		rs := byPolicy[name]
		impact := ratioOfReadings(rs,
			fmt.Sprintf("valid exchanges whose corpus grounding is the policy %q, counted where the "+
				"policy is the named reason for the handling", name),
			"policy:"+name, func(r reading) bool { return r.refused() })
		if impact.Numerator == 0 {
			continue
		}
		if err := ix.publishConcern(name, rs, impact, rep); err != nil {
			return err
		}
	}
	return nil
}

func (ix *index) publishConcern(name string, rs []reading, impact contracts.Ratio, rep *Report) error {
	st, err := ix.stanceFor(rs)
	if err != nil {
		return err
	}
	ctx := ix.altContext(rs, false)
	priority, basis := priorityFrom(percent(impact), impact.Denominator)
	observed := fmt.Sprintf(
		"%s valid exchanges grounded on the declared policy %q were refused. The refusal did not depend on "+
			"the payload matched: these probes carry the same marker-shaped content as exchanges handled "+
			"ordinarily elsewhere in this run. Corpus refs: %s. Declared grounding: %s.",
		ratioText(impact), name, strings.Join(refsOf(rs), ", "), anchorsOf(rs))
	return ix.publish(draft{
		Ref:      "CFG-" + sanitize(name),
		Type:     contracts.FindingConfigurationConcern,
		Scope:    fmt.Sprintf("named policy %s on %s %s", name, verbForReadings(rs), firstPath(rs)),
		Class:    firstClass(rs),
		Vector:   firstVector(rs),
		Encoding: firstEncoding(rs),
		Observed: observed,
		Inferred: fmt.Sprintf(
			"handling at this location keys on request metadata rather than on content, which is compatible "+
				"with the declared policy %q being enforced before any signature match runs. These probes "+
				"carry the same marker-shaped content as exchanges this run saw handled ordinarily, so no "+
				"rule-table entry predicts the refusal -- which is the point an operator has to be told, "+
				"because a rule review would never produce it", name),
		Missing: missingFor(st, ix.missingEvidenceNote(rs)) +
			"; the policy's own definition and the counter it increments are outside the response, so the " +
			"configuration export is what would confirm the name of the setting",
		Limits: []string{
			"does not identify which component enforces the policy",
			"does not show the policy is intentional or accidental, only that handling depends on the " +
				"location's name rather than its content",
			fmt.Sprintf("%d inconclusive and %d invalid trial(s) are outside this count",
				impact.ExcludedInconclusive, impact.ExcludedInvalid),
		},
		Impact:         impact,
		Priority:       priority,
		PriorityBasis:  basis,
		Recommendation: recommendationFor(contracts.FindingConfigurationConcern, firstVector(rs), name),
		Note: fmt.Sprintf(
			"a refusal that keys on metadata is invisible to signature review and will also refuse "+
				"legitimate clients that use the same name pattern (%s); record it in the configuration "+
				"baseline rather than in the rule list", strings.Join(refsOf(rs), ", ")),
		Regression:   labStep("configuration-concern", name),
		Observations: ix.citations(rs, 8),
		Alternatives: alternativesFor(ctx),
		ProfileRef:   ix.profileRef(rs),
		Hypothesis:   ix.hypothesisRef(rs),
		Stance:       st,
	}, rep)
}

// policyAnchors names the declared policies an item is grounded on. The corpus writes
// them behind the declared-evidence prefix, in their own namespace, because a policy
// is an inspected artifact like a rule table; what differs is what it states.
func policyAnchors(item contracts.CorpusItem) []string {
	var out []string
	for _, v := range item.Validation {
		if namespace, id, ok := declaredID(v); ok && namespace == "policy" && id != "" {
			out = append(out, id)
		}
	}
	return out
}

func canonicalFormOf(rs []reading) string {
	for _, r := range rs {
		if r.Item.Canonical != "" {
			return strconv.Quote(r.Item.Canonical)
		}
	}
	return "the family's canonical form"
}

func majorityWord(rs []reading) string {
	switch majorityOf(rs) {
	case contracts.SignalBlock:
		return "the block shape"
	case contracts.SignalPass:
		return "ordinary handling"
	default:
		return "no agreeing reading"
	}
}
