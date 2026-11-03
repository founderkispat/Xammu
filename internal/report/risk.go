package report

import (
	"fmt"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/discover"
)

// residualRisk builds the three separated statements. They stay separate because the
// difference between "measured, and conditional", "not yet demonstrated" and "not
// answerable from a response" is the difference an operator acts on differently; an
// aggregate risk figure would erase it.
func residualRisk(in Input, matrix contracts.CoverageMatrix, facts coverageFacts,
	findings []contracts.DiscoveryFinding) contracts.ResidualRisk {
	return contracts.ResidualRisk{
		ConditionalRisk:          conditional(in, matrix, facts, findings),
		ConditionNotDemonstrated: notDemonstrated(in, matrix, facts, findings),
		Undeterminable:           undeterminable(in, matrix, findings),
	}
}

func conditional(in Input, matrix contracts.CoverageMatrix, facts coverageFacts,
	findings []contracts.DiscoveryFinding) contracts.Scenario {
	top := topMeasured(findings)
	if top == nil {
		// Nothing measurable was published. The conditional statement then belongs to
		// the cells that did produce readings, which is the only evidence there is.
		return contracts.Scenario{
			Statement: fmt.Sprintf(
				"Every cell this run measured produced the same handling as its reference traffic, so the "+
					"conditional exposure is about coverage rather than about a bypass: refusal or ordinary "+
					"handling is asserted for %d cell(s) out of an authorized grid of %d, and %d cell(s) have "+
					"no valid reading at all. A claim that the defence holds where nothing was sent is not a "+
					"measurement this report can support.",
				facts.PairsWithSignal, facts.GridPairs, len(matrix.NotMeasured)),
			Scope: fmt.Sprintf("run %s: %d cell(s) with a valid reading of %d authorized",
				in.Run.RunID, facts.PairsWithSignal, facts.GridPairs),
			EvidenceRefs: append([]string{in.Evidence.ManifestPath},
				citeCount(matrix.NotMeasured)...),
			Verification: in.Evidence.VerifyCommand,
			Untested: append([]string{
				"the transports and classes the authorization covers but this plan never placed a probe in",
				"any behaviour of the unmeasured cells, which this run cannot describe in either direction",
			}, sortStrings(matrix.NotMeasured)[:minInt(len(matrix.NotMeasured), 6)]...),
		}
	}
	return contracts.Scenario{
		Statement: fmt.Sprintf(
			"Conditional exposure from finding %s (%s): %s The rate behind it is %d of %d valid trial(s)%s, "+
				"so the exposure is bounded by that measurement: it does not extend to encodings, transports "+
				"or paths this run did not place a probe in, and it is not a claim that any payload reaches "+
				"an application.",
			top.Ref, top.FindingType, sentence(top.WhatIsInferred), top.MeasuredImpact.Numerator,
			top.MeasuredImpact.Denominator, excludedTail(top.MeasuredImpact),
		),
		Scope:        top.AffectedScope,
		EvidenceRefs: nonEmptyRefs(append([]string{top.EvidenceProfileRef}, top.ObservationRefs...)),
		Verification: top.ReproductionCommand,
		Untested:     untestedFrom(*top, matrix),
	}
}

// sentence closes a quoted field the way prose needs. A finding writes its fields
// without a terminal period because they stand alone in their own column; here they are
// joined to the sentence around them, where the absence reads as a run-on.
func sentence(s string) string {
	s = strings.TrimRight(s, " ")
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// nonEmptyRefs drops references a scenario cannot name. An undetermined area has no
// evidence profile, and rendering the empty slot makes the list read as a defect in the
// trail rather than as the absence the finding states.
func nonEmptyRefs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// excludedTail states what is outside a ratio inside the sentence that quotes it. A
// reader who only ever sees the sentence still learns which exchanges were left out.
func excludedTail(r contracts.Ratio) string {
	if r.ExcludedInconclusive == 0 && r.ExcludedInvalid == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d inconclusive and %d invalid trial(s) outside the denominator)",
		r.ExcludedInconclusive, r.ExcludedInvalid)
}

func untestedFrom(f contracts.DiscoveryFinding, matrix contracts.CoverageMatrix) []string {
	out := append([]string(nil), f.Limitations...)
	if len(matrix.NotMeasured) > 0 {
		out = append(out, fmt.Sprintf(
			"%d cell(s) of the authorized grid have no valid reading, so the difference %s states is not "+
				"known to hold or fail outside the cells listed here", len(matrix.NotMeasured), f.Ref))
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func notDemonstrated(in Input, matrix contracts.CoverageMatrix, facts coverageFacts,
	findings []contracts.DiscoveryFinding) contracts.Scenario {
	top := topMeasured(findings)
	missing := "a source outside the HTTP response that agrees with the reading"
	ref := ""
	if top != nil {
		if top.WhatEvidenceIsMissing != "" {
			missing = top.WhatEvidenceIsMissing
		}
		ref = top.Ref
	}
	rounds := countRounds(matrix, in)
	source := "this report's own reading of the evidence ladder"
	if top != nil {
		source = fmt.Sprintf("the words of the finding that got closest (%s)", ref)
	}
	return contracts.Scenario{
		Statement: fmt.Sprintf(
			"Not demonstrated: that the handling measured here is the work of a perimeter rule rather than of "+
				"the origin application, a cache, a rate limiter or this harness. The strongest evidence grade "+
				"in this report is %q across %d cell(s), %d of which cite a source outside the response, and %d "+
				"round(s) contributed readings. The rung above needs independent rounds and corroboration; what "+
				"is missing, in %s: %s",
			highestLevel(findings), len(in.Pass.Verdicts), facts.Corroborated, rounds, source, sentence(missing)),
		Scope: fmt.Sprintf("attribution of every behavioural claim in run %s against authorization %s",
			in.Run.RunID, in.Auth.Ref),
		EvidenceRefs: append([]string{in.Evidence.ManifestPath,
			fmt.Sprintf("distribution:%s", contracts.DistAttributionStatus),
			fmt.Sprintf("distribution:%s", contracts.DistEvidenceBasis)},
			findingRefs(findings)...),
		Verification: in.withFlags(fmt.Sprintf("xammu playbook --partition %s --authorization %s --round round-2",
			in.Run.Partition, in.Auth.Ref)),
		Untested: []string{
			"a second round under its own authorization, which is the only way an in-run repetition becomes " +
				"independent reproduction",
			"the filter logs or rule configuration of the engine, which nothing in this run reads",
			"the origin's own behaviour when the same exchange arrives without the perimeter in front of it",
			fmt.Sprintf("%d cell(s) the plan never placed, where the question cannot even be asked",
				len(matrix.NotMeasured)),
		},
	}
}

func undeterminable(in Input, matrix contracts.CoverageMatrix,
	findings []contracts.DiscoveryFinding) contracts.Scenario {
	area := firstUndetermined(findings)
	if area == nil {
		return contracts.Scenario{
			Statement: fmt.Sprintf(
				"Undeterminable from a response: how deeply the engine normalises a payload before matching it, " +
					"and which internal component produced any single refusal. Both are properties of a system " +
					"that does not answer questions. This run's readings are the shapes of responses at one " +
					"destination, so a report built from them can say which forms were refused and which were " +
					"not; it cannot say why, and no quantity of further requests changes that.",
			),
			Scope: fmt.Sprintf("the whole of run %s: %d classified exchange(s), one destination, one round",
				in.Run.RunID, in.Run.Counters.Classified),
			EvidenceRefs: []string{in.Evidence.ManifestPath,
				fmt.Sprintf("detector_set:%s", in.Evidence.DetectorSetHash)},
			Verification: in.Evidence.VerifyCommand,
			Untested: []string{
				"the engine's decoding depth, which is not observable from any response this tool may request",
				"the identity of the component that produced a refusal, absent a log this run does not read",
				"application-layer behaviour behind the front end, which the authorization excludes",
			},
		}
	}
	return contracts.Scenario{
		Statement: fmt.Sprintf(
			"Undeterminable from this evidence, in the run's own words (%s): %s What would settle it: %s The "+
				"run cannot supply that from a response, which is why the zone stays open in the report instead "+
				"of being closed by an inference.",
			area.Ref, sentence(area.WhatIsInferred), sentence(area.WhatEvidenceIsMissing)),
		Scope:        area.AffectedScope,
		EvidenceRefs: nonEmptyRefs(append([]string{area.EvidenceProfileRef}, area.ObservationRefs...)),
		Verification: area.ReproductionCommand,
		Untested:     untestedFrom(*area, matrix),
	}
}

// unevaluatedZones is the fifth dimension's evidence: every undetermined finding
// becomes a declared blind spot with its typed reason, its remediation and the command
// that would close it. The unplanned ones additionally carry the request budget that
// was never spent on them.
func unevaluatedZones(in Input, matrix contracts.CoverageMatrix) []contracts.UnevaluatedZone {
	var zones []contracts.UnevaluatedZone
	spent := map[contracts.ReasonCode]bool{}
	for _, f := range in.Findings.Findings {
		if f.FindingType != contracts.FindingUndeterminedArea {
			continue
		}
		reason := f.UnevaluatedReason
		var notSpent int
		if !spent[reason] {
			spent[reason] = true
			notSpent = unplannedFor(in.Unplanned, reason)
		}
		zones = append(zones, contracts.UnevaluatedZone{
			Scope: f.AffectedScope,
			// A finding with no typed reason cannot reach this line: C-16 refuses an
			// undetermined area without one, so the fallback is arithmetic insurance
			// rather than a second truth.
			Reason:              orReason(reason, contracts.ReasonInconclusiveSignal),
			Detail:              f.WhatWasObserved,
			Remediation:         f.Recommendation,
			ReproductionCommand: f.ReproductionCommand,
			PlannedRequests:     notSpent,
		})
	}
	if len(zones) == 0 && len(matrix.NotMeasured) > 0 {
		zones = append(zones, syntheticZone(in, matrix))
	}
	return zones
}

func orReason(r contracts.ReasonCode, fallback contracts.ReasonCode) contracts.ReasonCode {
	if r != "" {
		return r
	}
	return fallback
}

// syntheticZone covers the case the discovery layer would have to miss: a grid the
// report calls unmeasured while no finding says so. Rather than let the two sections
// disagree, the report declares the gap itself, with the plan's own reason.
func syntheticZone(in Input, matrix contracts.CoverageMatrix) contracts.UnevaluatedZone {
	reason := contracts.ReasonCorpusGap
	cause := fmt.Sprintf("the probe partition %s offered nothing sendable for those cells", in.Run.Partition)
	if len(in.Unplanned) > 0 {
		reason = in.Unplanned[0].Reason
		cause = fmt.Sprintf("%d corpus item(s) were excluded by the selection: %s",
			len(in.Unplanned), in.Unplanned[0].Detail)
	}
	return contracts.UnevaluatedZone{
		Scope: fmt.Sprintf("run %s: %d authorized cell(s) with no valid reading",
			in.Run.RunID, len(matrix.NotMeasured)),
		Reason: reason,
		Detail: fmt.Sprintf(
			"The matrix lists %d cell(s) as unmeasured and no finding states them: %s. The cause recorded by "+
				"this run: %s", len(matrix.NotMeasured), strings.Join(matrix.NotMeasured, " | "), cause),
		Remediation: fmt.Sprintf(
			"plan the %d listed cell(s) in a new round under an authorization that covers them, or carry them "+
				"in the next report as declared out of coverage", len(matrix.NotMeasured)),
		ReproductionCommand: in.withFlags(fmt.Sprintf("xammu playbook --partition %s --authorization %s",
			in.Run.Partition, in.Auth.Ref)),
		PlannedRequests: unplannedTotal(in.Unplanned),
	}
}

func unplannedFor(in []discover.Unplanned, reason contracts.ReasonCode) int {
	var n int
	for _, u := range in {
		if u.Reason == reason {
			n++
		}
	}
	return n
}

func unplannedTotal(in []discover.Unplanned) int { return len(in) }

func topMeasured(in []contracts.DiscoveryFinding) *contracts.DiscoveryFinding {
	for i := range in {
		if in[i].FindingType != contracts.FindingUndeterminedArea {
			return &in[i]
		}
	}
	return nil
}

func firstUndetermined(in []contracts.DiscoveryFinding) *contracts.DiscoveryFinding {
	for i := range in {
		if in[i].FindingType == contracts.FindingUndeterminedArea {
			return &in[i]
		}
	}
	return nil
}

func highestLevel(in []contracts.DiscoveryFinding) contracts.EvidenceLevel {
	best := contracts.EvidenceNone
	for _, f := range in {
		if levelRank(f.EvidenceLevel) > levelRank(best) {
			best = f.EvidenceLevel
		}
	}
	return best
}

// countRounds counts the rounds that contributed a reading, not the rounds the run
// declares: a round that produced nothing cannot corroborate anything.
func countRounds(matrix contracts.CoverageMatrix, in Input) int {
	rounds := map[string]bool{}
	for _, v := range in.Pass.Verdicts {
		if v.Cell.Valid == 0 {
			continue
		}
		for _, r := range v.Cell.RoundIDs {
			if r != "" {
				rounds[r] = true
			}
		}
	}
	if len(rounds) == 0 && in.Run.RoundID != "" {
		return 1
	}
	return len(rounds)
}

// citeCount keeps a scenario's evidence references to a bounded, meaningful size: the
// manifest, and a statement of how many gaps the section lists.
func citeCount(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("unmeasured_cells:%d", len(in))}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// renderRisk is the markdown view of the three scenarios, in the order a reader has to
// weigh them.
func renderRisk(r contracts.ResidualRisk) string {
	var b strings.Builder
	for _, s := range []struct {
		title string
		sc    contracts.Scenario
	}{
		{"Conditional risk (measured, bounded)", r.ConditionalRisk},
		{"Condition not demonstrated (evidence gap)", r.ConditionNotDemonstrated},
		{"Undeterminable (not answerable from a response)", r.Undeterminable},
	} {
		b.WriteString("#### " + s.title + "\n\n" + s.sc.Statement + "\n\n")
		b.WriteString("- Scope: " + s.sc.Scope + "\n")
		evidence := joinLines(s.sc.EvidenceRefs, "; ")
		if evidence == "" {
			evidence = "none: this scenario states an absence and cites no measurement"
		}
		b.WriteString("- Evidence: " + evidence + "\n")
		b.WriteString("- Verify: `" + s.sc.Verification + "`\n")
		b.WriteString("- What was not tested:\n")
		for _, u := range s.sc.Untested {
			b.WriteString("  - " + u + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
