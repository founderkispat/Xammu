package report

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// dimensions builds the five sections that, between them, answer the seven questions
// C-15 pins to a dimension. Each statement carries its own numbers, taken from the
// same arithmetic the matrix and the distributions are built from: a reader who checks
// one section against another finds the same measurement, not two descriptions of it.
func dimensions(in Input, matrix contracts.CoverageMatrix, facts coverageFacts,
	dists []contracts.Distribution, findings []contracts.DiscoveryFinding,
	zones []contracts.UnevaluatedZone) []contracts.Dimension {
	byType := map[contracts.FindingType][]contracts.DiscoveryFinding{}
	for _, f := range findings {
		byType[f.FindingType] = append(byType[f.FindingType], f)
	}
	return []contracts.Dimension{
		{
			Kind:       contracts.DimCoverage,
			Title:      "Coverage: what this run measured, and the cells it left open",
			Questions:  contracts.QuestionsAnsweredBy(contracts.DimCoverage),
			Statements: coverageStatements(in, matrix, facts),
			Refs:       matrixRefs(matrix),
		},
		{
			Kind:       contracts.DimBehavior,
			Title:      "Behaviour: what the front end did with the exchanges it received",
			Questions:  contracts.QuestionsAnsweredBy(contracts.DimBehavior),
			Statements: behaviorStatements(in, facts, distByKind(dists, contracts.DistBehavioralSignal)),
			Refs: []string{
				fmt.Sprintf("run:%s/round:%s/classifications", in.Run.RunID, in.Pass.RoundID),
				fmt.Sprintf("distribution:%s", contracts.DistBehavioralSignal),
			},
		},
		{
			Kind:      contracts.DimAttribution,
			Title:     "Attribution: how far the evidence places the cause on the defence",
			Questions: contracts.QuestionsAnsweredBy(contracts.DimAttribution),
			Statements: attributionStatements(in, facts,
				distByKind(dists, contracts.DistAttributionStatus),
				distByKind(dists, contracts.DistEvidenceBasis)),
			Refs: []string{
				fmt.Sprintf("run:%s/attributions", in.Run.RunID),
				fmt.Sprintf("distribution:%s", contracts.DistAttributionStatus),
				fmt.Sprintf("distribution:%s", contracts.DistEvidenceBasis),
			},
		},
		{
			Kind:       contracts.DimDiscovery,
			Title:      "Discovery: the differences this run found and what to do about them",
			Questions:  contracts.QuestionsAnsweredBy(contracts.DimDiscovery),
			Statements: discoveryStatements(in, byType, findings),
			Refs:       findingRefs(findings),
		},
		{
			Kind:       contracts.DimUncertainty,
			Title:      "Uncertainty: what was not determined, and why it could not be",
			Questions:  contracts.QuestionsAnsweredBy(contracts.DimUncertainty),
			Statements: uncertaintyStatements(in, facts, zones),
			Refs: append([]string{
				in.Evidence.ManifestPath,
				fmt.Sprintf("distribution:%s", contracts.DistHypothesisOutcome),
			}, zoneRefs(zones)...),
		},
	}
}

func coverageStatements(in Input, matrix contracts.CoverageMatrix, facts coverageFacts) []string {
	classLine := "every authorized attack class produced at least one valid reading"
	if unmeasuredClasses(in, facts) > 0 {
		var names []string
		for _, c := range matrix.Classes {
			if classValid(in, facts, c) == 0 {
				names = append(names, string(c))
			}
		}
		if len(names) > 0 {
			classLine = fmt.Sprintf("no valid reading of class(es) %s inside this authorization",
				strings.Join(names, ", "))
		}
	}
	return []string{
		fmt.Sprintf(
			"The authorized grid is %d attack class(es) x %d transport(s) = %d cell(s). This run placed a "+
				"probe in %d of them and %d hold at least one valid reading; %d cell(s) are listed in the "+
				"matrix as unmeasured, each with the reason the pass recorded.",
			len(in.Auth.AllowedClasses), len(in.Auth.AllowedVectors), facts.GridPairs,
			facts.PlacedPairs, facts.PairsWithSignal, len(matrix.NotMeasured)),
		fmt.Sprintf(
			"Over the cells that produced readings: %d valid trial(s) of probe traffic, %d refused and %d "+
				"handled ordinarily by the classifier's agreement. %d inconclusive and %d invalid exchange(s) "+
				"are named in this sentence and are in no denominator anywhere in the report.",
			facts.ValidTrials, facts.Refused, facts.HandledOrdinary, facts.Inconclusive, facts.Invalid),
		fmt.Sprintf(
			"Coverage was measured across %d path(s) and %d encoding(s), rendered as %d class x transport "+
				"row(s) with %d encoding row(s) beneath them. A cell that mixed encodings is marked partial "+
				"rather than averaged, because an average of a refusal and a pass is a number that describes "+
				"neither.",
			facts.PathCount, facts.Encodings, len(matrix.Cells), facts.EncodingRows),
		fmt.Sprintf("At the transport level: %s.", transportGaps(in, matrix)),
		fmt.Sprintf("At the attack class level: %s.", classLine),
	}
}

func behaviorStatements(in Input, facts coverageFacts, dist *contracts.Distribution) []string {
	refusalPct := "0"
	if facts.ValidTrials > 0 {
		refusalPct = fmt.Sprintf("%d", facts.Refused*100/facts.ValidTrials)
	}
	out := []string{
		fmt.Sprintf(
			"Of the %d classified probe exchange(s) in this pass, %d carried the interstitial shape the "+
				"detector set associates with rejection, %d the shape of ordinary handling, %d were "+
				"indeterminate, %d were rate-limited and %d produced no response at all; %d valid trial(s) "+
				"landed on neither side of the agreement (a redirect, typically) and are bucketed as not "+
				"measured.",
			facts.ValidTrials+facts.Inconclusive+facts.Invalid, facts.Refused, facts.HandledOrdinary,
			facts.Signals["indeterminate"], facts.RateLimited, facts.TransportErrors, facts.Unplaced),
		fmt.Sprintf(
			"Against the valid trials only, %d of %d (%s%%) were refused. The denominator is the run's own "+
				"arithmetic; the distribution over %s states the same exchanges counted by signal so a reader "+
				"can see which buckets were empty rather than inferring it.",
			facts.Refused, facts.ValidTrials, refusalPct, contracts.DistBehavioralSignal),
		fmt.Sprintf(
			"The comparison every \"handled ordinarily\" reading rests on is a reference cluster of %d "+
				"ordinary exchange(s) collected by the pass itself. Without it, a 200 response would be a "+
				"status code rather than a reading, and no behaviour in this report could be stated at all.",
			in.Pass.ReferenceCount),
	}
	if dist != nil {
		out = append(out, fmt.Sprintf(
			"%d exchange(s) were rate-limited. Pacing is a limit placed on this run, not a protection result: "+
				"%s counts them in their own bucket and they are never part of a refusal rate.",
			bucketCount(*dist, "rate_limited"), contracts.DistBehavioralSignal))
	}
	return out
}

func attributionStatements(in Input, facts coverageFacts,
	status, basis *contracts.Distribution) []string {
	out := []string{
		fmt.Sprintf(
			"Of %d graded cell(s), %d carry an attribution record at all; %d sit at \"undetermined\", which "+
				"is the bucket this distribution keeps out of its denominator. An absent attribution is a "+
				"statement about the evidence, not about the defence.",
			len(in.Pass.Verdicts), len(in.Pass.Verdicts)-facts.Statuses[contracts.AttributionUndetermined],
			facts.Statuses[contracts.AttributionUndetermined]),
		fmt.Sprintf(
			"The strongest grade reached anywhere in the run is %s. The ladder above it requires a source "+
				"outside the HTTP response -- filter logs or a configuration export -- and %s.",
			highestStatus(facts.Statuses), corroborationSentence(facts)),
		fmt.Sprintf(
			"Evidence basis of the graded cells: %s. \"http_only\" means a response and nothing else, which "+
				"is why a finding that rests on it may describe a difference but may not name the component "+
				"that caused it.", renderCounts(intKeysToStrings(facts.Bases))),
	}
	if basis != nil {
		out = append(out, fmt.Sprintf(
			"%d cell(s) have no evidence basis of any kind (%s bucket %q). Those cells appear in the matrix "+
				"as readings without attribution and in the findings as descriptive claims only.",
			bucketCount(*basis, "none"), contracts.DistEvidenceBasis, "none"))
	}
	return out
}

func discoveryStatements(in Input, byType map[contracts.FindingType][]contracts.DiscoveryFinding,
	findings []contracts.DiscoveryFinding) []string {
	var typeParts []string
	for _, ty := range contracts.AllFindingTypes() {
		typeParts = append(typeParts, fmt.Sprintf("%s %d", ty, len(byType[ty])))
	}
	high := make([]string, 0, 3)
	var priorities []string
	byPriority := map[contracts.Priority]int{}
	for _, f := range findings {
		byPriority[f.Priority]++
		if f.Priority == contracts.PriorityHigh && len(high) < 3 {
			high = append(high, fmt.Sprintf("%s (%s: %d of %d valid trials, %s)",
				f.Ref, f.FindingType, f.MeasuredImpact.Numerator, f.MeasuredImpact.Denominator,
				f.AffectedScope))
		}
	}
	for _, p := range []contracts.Priority{contracts.PriorityHigh, contracts.PriorityMedium,
		contracts.PriorityLow} {
		priorities = append(priorities, fmt.Sprintf("%s %d", p, byPriority[p]))
	}
	measured := 0
	for _, f := range findings {
		if f.FindingType != contracts.FindingUndeterminedArea {
			measured++
		}
	}
	out := []string{
		fmt.Sprintf(
			"The pass published %d finding(s): %s. %d of them rest on a measurement; the rest state where the "+
				"run produced none, and they carry no risk claim by construction.",
			len(findings), strings.Join(typeParts, ", "), measured),
		fmt.Sprintf("Priority distribution: %s. Priority is computed from the size of the difference and "+
			"the number of valid trials behind it, never from how alarming a finding type sounds.",
			strings.Join(priorities, ", ")),
	}
	if len(high) > 0 {
		out = append(out, fmt.Sprintf(
			"The high-priority items a reviewer can act on today: %s. Each states the reading it contradicts, "+
				"the evidence a claim would need to rise, and one command to re-run the measurement.",
			strings.Join(high, "; ")))
	} else {
		out = append(out, "No finding reached high priority in this pass: every measured difference either "+
			"rests on too few valid trials or is contradicted by the run's own controls. That is a statement "+
			"about this run's evidence, not a clean result for the target.")
	}
	out = append(out, fmt.Sprintf(
		"Every finding cites %s as its reproduction surface, bound to authorization %s or to run %s, so a "+
			"reader who wants the measurement again cannot wander outside the scope that allowed it.",
		"xammu", in.Auth.Ref, in.Run.RunID))
	return out
}

func uncertaintyStatements(in Input, facts coverageFacts,
	zones []contracts.UnevaluatedZone) []string {
	byReason := map[contracts.ReasonCode]int{}
	var planned int
	for _, z := range zones {
		byReason[z.Reason]++
		planned += z.PlannedRequests
	}
	var reasonParts []string
	for _, code := range contracts.AllReasonCodes() {
		if n := byReason[code]; n > 0 {
			reasonParts = append(reasonParts, fmt.Sprintf("%s %d", code, n))
		}
	}
	if len(reasonParts) == 0 {
		reasonParts = append(reasonParts, "none declared")
	}
	out := []string{
		fmt.Sprintf(
			"The run stopped in state %q and %d of %d authorized requests were spent, so %d request(s) and %d "+
				"planned probe(s) remain. The report states the arithmetic rather than leaving a reader to "+
				"divide two numbers: %s",
			in.Run.State, in.Run.RequestsUsed, in.Run.RequestBudget,
			in.Run.RequestBudget-in.Run.RequestsUsed,
			in.Run.Counters.PlannedProbes-in.Run.Counters.ExecutedProbes, sentence(stateReason(in.Run))),
		fmt.Sprintf(
			"Undetermined areas: %d, typed as %s. Every one names what is absent and the command that would "+
				"produce a reading; %d planned request(s) were never spent on them.",
			len(zones), strings.Join(reasonParts, ", "), planned),
		fmt.Sprintf(
			"Evidence-trail health: %d re-derivation disagreement(s) with the journal and %d exchange(s) that "+
				"were sent but never classified. A divergence is a defect in the trail rather than a reading, "+
				"so it is reported before any rate is quoted from a cell it touches.",
			len(in.Pass.Divergences), len(in.Pass.Missing)),
		fmt.Sprintf(
			"The residual-risk block states three things separately: a conditional exposure the run measured, " +
				"a condition the evidence does not yet demonstrate, and a question this kind of measurement " +
				"cannot answer. They are not merged into one risk figure because merging them would hide which " +
				"of the three a reader is being told about."),
	}
	if in.Run.State != contracts.StateCompleted {
		out = append(out, fmt.Sprintf(
			"This run did not complete: its state is %q. A coverage claim from it is bounded by the %d cell(s) "+
				"it did reach, and the %d cell(s) it did not are listed as unmeasured rather than inferred from "+
				"the neighbours.",
			in.Run.State, facts.PairsWithSignal, len(zones)))
	}
	return out
}

// intKeysToStrings renders a typed count map for a sentence. The keys are contract
// values, so the output is the vocabulary the validator enforces, not a local label.
func intKeysToStrings[T ~string](in map[T]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}

func highestStatus(in map[contracts.AttributionStatus]int) contracts.AttributionStatus {
	order := []contracts.AttributionStatus{
		contracts.AttributionConfirmed, contracts.AttributionSupportedByLogs,
		contracts.AttributionProbable, contracts.AttributionCompatible,
		contracts.AttributionRejected, contracts.AttributionUndetermined,
	}
	for _, s := range order {
		if in[s] > 0 {
			return s
		}
	}
	return contracts.AttributionUndetermined
}

func corroborationSentence(facts coverageFacts) string {
	if facts.Corroborated > 0 {
		return fmt.Sprintf("%d cell(s) cite one, which is what lets their claim rise above the HTTP "+
			"ceiling", facts.Corroborated)
	}
	return "none was supplied to this run. Everything above it in the ladder is therefore out of reach " +
		"for this evidence, whatever the readings say"
}

func unmeasuredClasses(in Input, facts coverageFacts) int {
	var n int
	for _, c := range in.Auth.AllowedClasses {
		if classValid(in, facts, c) == 0 {
			n++
		}
	}
	return n
}

func classValid(in Input, facts coverageFacts, c contracts.AttackClass) int {
	var n int
	for _, v := range in.Pass.Verdicts {
		if v.Cell.AttackClass == c {
			n += v.Cell.Valid
		}
	}
	return n
}

func transportGaps(in Input, matrix contracts.CoverageMatrix) string {
	var none []string
	for _, v := range matrix.Vectors {
		var n int
		for _, cell := range matrix.Cells {
			if cell.Vector == v {
				n += cell.Aggregate.Denominator
			}
		}
		if n == 0 {
			none = append(none, string(v))
		}
	}
	if len(none) == 0 {
		return "every authorized transport produced at least one valid reading"
	}
	return "no valid reading in transport(s) " + strings.Join(none, ", ")
}

func distByKind(in []contracts.Distribution, kind contracts.DistributionKind) *contracts.Distribution {
	for i := range in {
		if in[i].Kind == kind {
			return &in[i]
		}
	}
	return nil
}

func bucketCount(d contracts.Distribution, name string) int {
	for _, b := range d.Buckets {
		if b.Name == name {
			return b.Count
		}
	}
	return 0
}

func matrixRefs(m contracts.CoverageMatrix) []string {
	out := []string{fmt.Sprintf("coverage_matrix:%d cell(s) rendered, %d unmeasured entry(ies) listed",
		len(m.Cells), len(m.NotMeasured))}
	for i, c := range m.Cells {
		if i >= 6 {
			out = append(out, fmt.Sprintf("grid:and %d further cell(s)", len(m.Cells)-i))
			break
		}
		out = append(out, fmt.Sprintf("grid:%s|%s", c.Class, c.Vector))
	}
	return out
}

func findingRefs(in []contracts.DiscoveryFinding) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		out = append(out, f.Ref)
	}
	if len(out) > 12 {
		out = append(out[:12], fmt.Sprintf("and %d further finding ref(s)", len(out)-12))
	}
	return out
}

func zoneRefs(in []contracts.UnevaluatedZone) []string {
	out := make([]string, 0, len(in))
	for _, z := range in {
		out = append(out, z.Scope)
	}
	if len(out) > 12 {
		out = append(out[:12], fmt.Sprintf("and %d further zone(s)", len(out)-12))
	}
	return out
}

// renderDimensions writes the five sections in question order, because the point of
// the structure is that a reader can check each of the seven questions against the
// section that owns it.
func renderDimensions(in []contracts.Dimension) string {
	var b strings.Builder
	for _, d := range in {
		questions := make([]string, 0, len(d.Questions))
		for _, q := range d.Questions {
			questions = append(questions, fmt.Sprintf("Q%d", q))
		}
		b.WriteString(fmt.Sprintf("### %s\n\nAnswers %s.\n\n", d.Title, strings.Join(questions, ", ")))
		for _, s := range d.Statements {
			b.WriteString("- " + s + "\n")
		}
		b.WriteString("\n_Data behind this section: " + strings.Join(d.Refs, "; ") + "_\n\n")
	}
	return b.String()
}

func sortStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
