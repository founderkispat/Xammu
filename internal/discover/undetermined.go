package discover

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// undeterminedAreas state where this run did not produce a reading, and why. They
// are the reason a partial run cannot be printed as a covered one: without them a
// reader sees four findings and infers a complete picture of the transports.
//
// The type carries the weakest claim C-16 allows (descriptive, undetermined
// attribution, no inference): an absence of measurement says something about the run
// and nothing about the defence. It may not name a risk, and the contract refuses the
// sentence if it tries.
func (ix *index) undeterminedAreas(rep *Report) error {
	if err := ix.unreadCells(rep); err != nil {
		return err
	}
	if err := ix.trailHealth(rep); err != nil {
		return err
	}
	if err := ix.unmeasuredScope(rep); err != nil {
		return err
	}
	return ix.unplannedItems(rep)
}

// unreadCells reports cells the pass graded but could not conclude.
func (ix *index) unreadCells(rep *Report) error {
	for _, v := range ix.in.Pass.Verdicts {
		if v.Skip == "" {
			continue
		}
		reason := contracts.ReasonInconclusiveSignal
		detail := v.Skip
		if len(v.Obstacles) > 0 {
			reason = v.Obstacles[0].Reason
			detail = fmt.Sprintf("%s (%s)", v.Skip, v.Obstacles[0].Detail)
		}
		rs := ix.byCell[v.Cell.CellKey]
		observed := fmt.Sprintf(
			"the run sent %d exchange(s) to %s and %d produced a valid reading (%d inconclusive, %d "+
				"invalid). Corpus refs in the cell: %s. The pass recorded: %s",
			len(v.Cell.Trials), v.Cell.CellKey.String(), v.Cell.Valid, v.Cell.Inconclusive,
			v.Cell.Invalid, strings.Join(refsOf(rs), ", "), detail)
		if err := ix.publishArea(areaInput{
			Ref:      "UND-" + sanitize(v.Cell.CellKey.String()),
			Reason:   reason,
			Class:    v.Cell.AttackClass,
			Vector:   v.Cell.Vector,
			Encoding: v.Cell.Encoding,
			Scope:    scopeOf(v.Cell.CellKey, rs),
			Cite:     sanitize(v.Cell.CellKey.String()),
			Observed: observed,
			Inferred: fmt.Sprintf(
				"nothing is inferred about the handling of %s: the cell has no valid reading to reason "+
					"from, so the zone stays undetermined for the typed reason recorded above",
				v.Cell.CellKey.String()),
			Missing: "a valid reading of this cell -- at least one exchange the classifier could place on " +
				"either side of the agreement, under this same authorization and destination",
			Limits: []string{
				"states that this run produced no measurement, not that the transport or class behaves any way",
				"the typed reason is what the pipeline recorded; it does not identify the component that " +
					"caused the missing reading",
			},
			ProfileRef:     ix.profileRef(rs),
			Recommendation: recommendationFor(contracts.FindingUndeterminedArea, v.Cell.Vector, anchorsOf(rs)),
			Note: fmt.Sprintf(
				"this cell is an unmeasured zone of the matrix: %d exchange(s) in, %d valid reading(s) out. "+
					"Any coverage statement about %s in this report has to say it is missing rather than "+
					"leave the reader to notice", len(v.Cell.Trials), v.Cell.Valid, v.Cell.Vector),
			Regression: labStep("undetermined", v.Cell.CellKey.String()),
		}, rep); err != nil {
			return err
		}
	}
	return nil
}

// trailHealth reports the two conditions that make the evidence itself disputable: a
// re-derivation that disagrees with the journal, and exchanges that were sent but
// never classified. Neither is a statement about the defence, and both belong in the
// report rather than in a footnote.
func (ix *index) trailHealth(rep *Report) error {
	if len(ix.in.Pass.Divergences) > 0 {
		var lines []string
		for _, d := range ix.in.Pass.Divergences {
			lines = append(lines, d.String())
		}
		sort.Strings(lines)
		if err := ix.publishArea(areaInput{
			Ref:    "UND-trail-divergence",
			Reason: contracts.ReasonInconclusiveSignal,
			Scope:  fmt.Sprintf("run %s: evidence trail re-derivation", ix.in.RunID),
			Cite:   "divergence",
			Observed: fmt.Sprintf(
				"re-deriving this run's journal produced %d disagreement(s) with the records already "+
					"written: %s", len(lines), strings.Join(lines, " | ")),
			Inferred: "nothing about the engine is inferred. What is not determined is whether the readings " +
				"in this pass are the readings the run recorded, so every cell a divergence touches is " +
				"unusable as evidence until the disagreement is resolved",
			Missing: "a reconciliation of each journaled record with the re-derived one: the artifact the run " +
				"used at the time, or an explanation of the version difference between them",
			Limits: []string{
				"a divergence is a defect in the evidence trail, not a behavioural observation",
				"the exchanges it names are still counted exactly as the journal recorded them; nothing here " +
					"re-reads them",
			},
			Recommendation: "run verify against this bundle and reconcile the named fields before quoting " +
				"any cell the divergence touches",
			Note: "the trail is what makes a report checkable; a divergence in it is the most important " +
				"line in this finding set even though it measures nothing about the defence",
			Regression: ix.withFlags("xammu verify --run " + ix.in.RunID),
		}, rep); err != nil {
			return err
		}
	}
	if len(ix.in.Pass.Missing) > 0 {
		missing := append([]string{}, ix.in.Pass.Missing...)
		sort.Strings(missing)
		if err := ix.publishArea(areaInput{
			Ref:    "UND-trail-missing",
			Reason: contracts.ReasonInconclusiveSignal,
			Scope:  fmt.Sprintf("run %s: exchanges without a reading", ix.in.RunID),
			Cite:   "missing",
			Observed: fmt.Sprintf(
				"%d exchange(s) have no derived record the pass could resolve: %s",
				len(missing), strings.Join(missing, ", ")),
			Inferred: "nothing is inferred about how those exchanges were handled: without a classification " +
				"there is no reading, and a finding built on an unread exchange would be a guess about a " +
				"response this run never interpreted",
			Missing: "the classification record for each named exchange, or the observation itself if the " +
				"journal line is what is absent",
			Limits: []string{
				"the count is of citations the pass could not resolve, not of failed requests",
				"these exchanges are absent from every denominator in the report, so no rate in this run is " +
					"affected by reading them",
			},
			Recommendation: "re-derive the classifications from the journaled observations; if the " +
				"observation itself is absent, the bundle is incomplete and should not be published",
			Note:       "an unread exchange is a hole in the trail, not a hole in the defence",
			Regression: ix.withFlags("xammu verify --run " + ix.in.RunID),
		}, rep); err != nil {
			return err
		}
	}
	return nil
}

// unmeasuredScope reports classes and transports the authorization covers that this
// run measured nothing about. The reason code distinguishes the two causes that look
// identical from the outside: the corpus has nothing to send, versus the corpus has
// something and the run did not send it.
func (ix *index) unmeasuredScope(rep *Report) error {
	measuredClasses := map[contracts.AttackClass]bool{}
	measuredVectors := map[contracts.Vector]bool{}
	for _, r := range ix.readings {
		measuredClasses[r.Item.AttackClass] = true
		measuredVectors[r.Item.Vector] = true
	}

	var classes []contracts.AttackClass
	for _, c := range ix.in.AuthorizedClasses {
		if !measuredClasses[c] {
			classes = append(classes, c)
		}
	}
	sort.Slice(classes, func(i, k int) bool { return classes[i] < classes[k] })
	for _, c := range classes {
		inPartition, inTree := ix.classInCorpus(c)
		reason := contracts.ReasonCorpusGap
		cause := fmt.Sprintf(
			"the probe partition carries %d item(s) of class %q; the whole tree carries %d item(s) of it",
			inPartition, c, inTree)
		if inPartition > 0 {
			reason = contracts.ReasonNotYetAttempted
			cause = fmt.Sprintf(
				"the probe partition carries %d item(s) of class %q and this run planned or sent none of "+
					"them", inPartition, c)
		}
		observed := fmt.Sprintf(
			"the authorization covers attack class %q. No exchange in this run carried that class. %s. "+
				"The pass measured %d class(es).", c, cause, len(measuredClasses))
		if err := ix.publishArea(areaInput{
			Ref:      "UND-class-" + sanitize(string(c)),
			Reason:   reason,
			Class:    c,
			Scope:    "attack class " + string(c) + ": unmeasured in this run",
			Cite:     "class-" + sanitize(string(c)),
			Observed: observed,
			Inferred: fmt.Sprintf(
				"nothing is inferred about how %q is handled. The absence is in this run's coverage, not in "+
					"the engine's behaviour: no exchange was measured, so the class is unmeasured rather "+
					"than examined", c),
			Missing: fmt.Sprintf(
				"corpus items of class %q that pass the inertness gate, plus a plan that sends them under "+
					"this authorization", c),
			Limits: []string{
				"an unmeasured class is not an unguarded class",
				"the reason code distinguishes a corpus that has nothing sendable from a run that sent " +
					"nothing; it does not explain why the corpus has nothing",
			},
			Recommendation: fmt.Sprintf(
				"either add gated items of class %q to the probe partition and re-authorize, or carry the "+
					"class as explicitly out of coverage in the report instead of leaving the reader to "+
					"notice its absence", c),
			Note: fmt.Sprintf(
				"the matrix row for %q is empty by construction: this build's inertness gate refuses the "+
					"shapes that would demonstrate it, which is a coverage decision and not a result", c),
			Regression: ix.withEngagement("xammu playbook --partition " + string(ix.in.Partition) + " --class " +
				string(c) + ix.authFlag()),
		}, rep); err != nil {
			return err
		}
	}

	var vectors []contracts.Vector
	for _, v := range ix.in.AuthorizedVectors {
		if !measuredVectors[v] {
			vectors = append(vectors, v)
		}
	}
	sort.Slice(vectors, func(i, k int) bool { return vectors[i] < vectors[k] })
	for _, v := range vectors {
		refs := ix.vectorInCorpus(v)
		reason := contracts.ReasonCorpusGap
		cause := fmt.Sprintf("the probe partition carries no item placed in the %q transport", v)
		if len(refs) > 0 {
			reason = contracts.ReasonNotYetAttempted
			cause = fmt.Sprintf("the probe partition carries %d item(s) for the %q transport and this run "+
				"sent none of them: %s", len(refs), v, strings.Join(refs, ", "))
		}
		observed := fmt.Sprintf(
			"the authorization covers the %q transport. No exchange in this run placed a probe there. %s",
			v, cause)
		if err := ix.publishArea(areaInput{
			Ref:      "UND-vector-" + sanitize(string(v)),
			Reason:   reason,
			Vector:   v,
			Scope:    "transport " + string(v) + ": unmeasured in this run",
			Cite:     "vector-" + sanitize(string(v)),
			Observed: observed,
			Inferred: fmt.Sprintf(
				"nothing is inferred about inspection of the %q transport. Every asymmetry this run measured "+
					"excludes it, so a comparison involving it is outside this report", v),
			Missing: fmt.Sprintf(
				"at least one valid exchange placing a probe in the %q transport, with the same controls "+
					"the measured transports used", v),
			Limits: []string{
				"an unmeasured transport is not an uninspected transport",
				"the coverage matrix in this report shows this transport as unmeasured rather than inferring " +
					"a reading for it",
			},
			Recommendation: fmt.Sprintf(
				"plan the %q items that exist in the partition, or state in the report that the transport was "+
					"never placed", v),
			Note: fmt.Sprintf(
				"the reader who needs the %q rows of the matrix is the one who will ask why they are empty; "+
					"this finding is that answer, in advance", v),
			Regression: ix.withEngagement("xammu playbook --partition " + string(ix.in.Partition) +
				" --vector " + string(v) + ix.authFlag()),
		}, rep); err != nil {
			return err
		}
	}
	return nil
}

// unplannedItems groups the selection's exclusions by reason, because forty lines of
// "budget ended" is one statement about the run rather than forty findings.
func (ix *index) unplannedItems(rep *Report) error {
	if len(ix.in.Unplanned) == 0 {
		return nil
	}
	byReason := map[contracts.ReasonCode][]Unplanned{}
	for _, u := range ix.in.Unplanned {
		byReason[u.Reason] = append(byReason[u.Reason], u)
	}
	codes := make([]contracts.ReasonCode, 0, len(byReason))
	for c := range byReason {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, k int) bool { return codes[i] < codes[k] })
	for _, code := range codes {
		group := byReason[code]
		sort.Slice(group, func(i, k int) bool { return group[i].Ref < group[k].Ref })
		var refs, details []string
		for _, u := range group {
			refs = append(refs, u.Ref)
			details = append(details, u.Detail)
		}
		observed := fmt.Sprintf(
			"%d corpus item(s) in partition %s were not planned by this run under reason code %q: %s. The "+
				"selection recorded: %s", len(group), ix.in.Partition, code,
			strings.Join(refs, ", "), strings.Join(unique(details), "; "))
		if err := ix.publishArea(areaInput{
			Ref:      "UND-unplanned-" + sanitize(string(code)),
			Reason:   code,
			Scope:    fmt.Sprintf("probes not run in partition %s: %d item(s)", ix.in.Partition, len(group)),
			Cite:     "unplanned-" + sanitize(string(code)),
			Observed: observed,
			Inferred: "nothing is inferred from these items: they were never sent, so they contribute no " +
				"trial to any rate in this report, and no cell of the coverage matrix is closed by them",
			Missing: "the exchanges themselves: a larger authorized budget, a wider authorization, or a " +
				"later run that plans the remaining cells",
			Limits: []string{
				"the exclusion list is the selection's own record; this finding adds no measurement to it",
				"a cell left unmeasured cannot be compared in the matrix, which is why those rows stay empty " +
					"rather than inferred",
			},
			Recommendation: "raise the request budget or accept a narrower matrix and say so; either way the " +
				"report carries the unrun list rather than dropping it",
			Note: "this is where the budget went. A reader who compares two runs with different budgets has to see this number to compare them honestly",
			Regression: ix.withEngagement("xammu playbook --partition " + string(ix.in.Partition) +
				ix.authFlag()),
		}, rep); err != nil {
			return err
		}
	}
	return nil
}

// areaInput is the shape of an undetermined-area finding. It exists as a struct
// rather than a seventeen-argument call because the two fields that must never be
// empty here -- the typed reason and the citation -- are the ones easy to drop.
type areaInput struct {
	Ref      string
	Reason   contracts.ReasonCode
	Observed string
	Inferred string
	Missing  string
	Limits   []string

	Class    contracts.AttackClass
	Vector   contracts.Vector
	Encoding contracts.Encoding
	Scope    string

	// Cite is the detail inside the absence citation, naming what is absent.
	Cite string

	ProfileRef     string
	Recommendation string
	Note           string
	Regression     string
}

func (ix *index) publishArea(a areaInput, rep *Report) error {
	if a.Reason == "" {
		return fmt.Errorf("discover: undetermined area %s has no reason code: an unevaluated zone always "+
			"carries a typed reason, because \"we did not get to it\" is not a reason", a.Ref)
	}
	return ix.publish(draft{
		Ref:            a.Ref,
		Type:           contracts.FindingUndeterminedArea,
		Reason:         a.Reason,
		Scope:          a.Scope,
		Class:          a.Class,
		Vector:         a.Vector,
		Encoding:       a.Encoding,
		Observed:       a.Observed,
		Inferred:       a.Inferred,
		Missing:        a.Missing,
		Limits:         a.Limits,
		Observations:   ix.absenceCitation(a.Cite),
		Alternatives:   ix.undeterminedAlternatives(a.Observed),
		ProfileRef:     a.ProfileRef,
		Recommendation: a.Recommendation,
		Note:           a.Note,
		Regression:     a.Regression,
		PriorityBasis: "no measurement exists for this zone, so nothing was ranked: an undetermined area is " +
			"always low because the finding reports the absence of a quantity rather than its size",
	}, rep)
}

// classInCorpus reports how many items of the class the probe partition carries and
// how many the whole tree carries. The two numbers answer different questions: the
// first says whether the run could have sent it, the second whether this build can
// send it at all.
func (ix *index) classInCorpus(c contracts.AttackClass) (inPartition, inTree int) {
	for _, name := range contracts.AllPartitionNames() {
		for _, item := range ix.in.Corpus.Items(name) {
			if item.AttackClass != c {
				continue
			}
			inTree++
			if name == ix.in.Partition {
				inPartition++
			}
		}
	}
	return inPartition, inTree
}

func (ix *index) vectorInCorpus(v contracts.Vector) []string {
	var refs []string
	for _, item := range ix.in.Corpus.Items(ix.in.Partition) {
		if item.Vector == v {
			refs = append(refs, item.Ref)
		}
	}
	sort.Strings(refs)
	return refs
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
