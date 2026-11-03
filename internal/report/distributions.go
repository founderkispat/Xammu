package report

import (
	"fmt"
	"sort"

	"xammu/internal/contracts"
	"xammu/internal/inference"
)

// bucketOf places one classified exchange in the behavioural vocabulary C-15 fixes
// for this distribution. The precedence matters: a rate-limited or transport-failed
// exchange is named for what stopped it rather than counted as an ordinary invalid
// trial, and an invalid trial is never allowed to sit in the same bucket as a valid
// reading of the same shape. An indeterminate reading is named before validity is
// consulted, because the classifier's inability to place an exchange is the reading
// itself -- dropping those into not_measured would empty the bucket the denominator
// is defined to exclude and silently widen every rate. A redirect, a signal outside
// the block/pass pair, is not_measured: the run saw something and cannot say what it
// means.
func bucketOf(t inference.Trial) string {
	switch {
	case t.Signal == contracts.SignalRateLimited:
		return "rate_limited"
	case t.Signal == contracts.SignalTransportError:
		return "transport_error"
	case t.Signal == contracts.SignalIndeterminate:
		return "indeterminate"
	case !t.Valid:
		return "not_measured"
	case t.Signal == contracts.SignalBlock:
		return "compatible_block"
	case t.Signal == contracts.SignalPass:
		return "compatible_normal"
	default:
		return "not_measured"
	}
}

// buildDistributions renders the five counted views of the run. The bucket vocabulary
// comes from the contract, not from what the run produced: a kind whose non-scoring
// bucket is missing from the report is an error rather than a wider denominator, which
// is exactly the failure criterion 23 forbids.
func buildDistributions(in Input, facts coverageFacts) []contracts.Distribution {
	cells := len(in.Pass.Verdicts)
	var hyp, skipped int
	for _, v := range in.Pass.Verdicts {
		if v.Hypothesis != nil {
			hyp++
		}
		if v.Skip != "" {
			skipped++
		}
	}
	// The behavioural denominator is stated here rather than left for the reader to
	// add up: it is every exchange the pass classified minus the one bucket the
	// contract defines as non-scoring, which is deliberately not the set of valid
	// trials a finding's rate is computed over.
	var exchanges, indeterminate int
	for name, n := range facts.Signals {
		exchanges += n
		if name == "indeterminate" {
			indeterminate = n
		}
	}
	return []contracts.Distribution{
		newDistribution(
			fmt.Sprintf("Behavioural signal of every exchange the pass classified in run %s", in.Run.RunID),
			contracts.DistBehavioralSignal,
			fmt.Sprintf(
				"every probe exchange in %d graded cell(s), valid or not, counted once: %d exchange(s) in "+
					"all. The denominator excludes the %d indeterminate one(s) - exchanges the classifier "+
					"could not place on either side of the agreement - and nothing else, so the %d rate-limited "+
					"and %d transport-failed exchange(s) stay inside it: the run reached a state worth naming "+
					"even though the defence never saw a probe. That makes this denominator %d, while every "+
					"refusal rate elsewhere in this report is over the %d valid trial(s) alone. The two are "+
					"different arithmetic on purpose and neither is a correction of the other: this view "+
					"answers what the exchanges were, a finding answers what the defence did with probe "+
					"traffic it could read.",
				cells, exchanges, indeterminate, facts.RateLimited, facts.TransportErrors,
				exchanges-indeterminate, facts.ValidTrials),
			facts.Signals),
		newDistribution(
			"Attribution status of each graded cell",
			contracts.DistAttributionStatus,
			fmt.Sprintf(
				"one entry per cell the pass graded (%d). A cell with no attribution record is counted as "+
					"undetermined, which is the bucket excluded from the denominator: absence of attribution "+
					"cannot be read as evidence that the defence did something.", cells),
			intKeysToStrings(facts.Statuses)),
		newDistribution(
			"Evidence basis behind each attribution",
			contracts.DistEvidenceBasis,
			fmt.Sprintf(
				"one entry per graded cell (%d). \"none\" is the bucket kept out of the denominator: an "+
					"attribution resting on no evidence is not a grade. %d cell(s) cite a source outside the "+
					"HTTP response (filter logs or a configuration export), which is the only way a claim in "+
					"this report can rise above what a response shows.", cells, facts.Corroborated),
			intKeysToStrings(facts.Bases)),
		newDistribution(
			"Outcome of each hypothesis the pass formed",
			contracts.DistHypothesisOutcome,
			fmt.Sprintf(
				"the %d cell(s) that produced a hypothesis; %d cell(s) produced none and are reported as "+
					"undetermined areas instead, because an absence of measurement is not an outcome. "+
					"inconclusive is excluded from the denominator.", hyp, skipped),
			intKeysToStrings(facts.Outcomes)),
		newDistribution(
			"Verdict of every encoding row of the coverage matrix",
			contracts.DistCoverageVerdict,
			fmt.Sprintf(
				"the %d encoding row(s) of the matrix over %d cell(s). indeterminate rows are excluded from "+
					"the denominator: a row whose valid trials produced neither refusals nor ordinary "+
					"handling measured nothing, and counting it would inflate the coverage claim.",
				facts.EncodingRows, facts.PlacedPairs),
			facts.VerdictCounts[contracts.DistCoverageVerdict]),
	}
}

// newDistribution emits the whole declared vocabulary, zeros included. A reader who
// sees only the buckets that were filled cannot tell whether the vocabulary was narrow
// or the run was; a zero row answers that without any prose.
func newDistribution(name string, kind contracts.DistributionKind, basis string,
	counts map[string]int) contracts.Distribution {
	nonScoring := contracts.NonScoringBucket(kind)
	var sum, nonScoringCount int
	buckets := make([]contracts.Bucket, 0, len(contracts.AllDistributionBuckets(kind)))
	for _, b := range contracts.AllDistributionBuckets(kind) {
		n := counts[b]
		sum += n
		if b == nonScoring {
			nonScoringCount = n
		}
		buckets = append(buckets, contracts.Bucket{Name: b, Count: n})
	}
	// Anything the walk produced outside the vocabulary is a bug in this package, not
	// a bucket to invent: silently dropping it would be the widening the contract
	// forbids, so it is reported as an unmatched count instead.
	var unmatched int
	for b, n := range counts {
		if !contains(contracts.AllDistributionBuckets(kind), b) {
			unmatched += n
		}
	}
	if unmatched > 0 {
		basis += fmt.Sprintf(" (%d exchange(s) carried a value outside the declared vocabulary and are "+
			"counted nowhere; this is a defect in the report builder, not a finding)", unmatched)
	}
	return contracts.Distribution{
		Name:               name,
		Kind:               kind,
		Buckets:            buckets,
		Denominator:        sum - nonScoringCount,
		Basis:              basis,
		InconclusiveBucket: nonScoring,
		Excluded:           []string{nonScoring},
	}
}

func contains(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

// renderDistributions is the markdown view of the counted blocks.
func renderDistributions(in []contracts.Distribution) string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		var parts []string
		for _, b := range d.Buckets {
			mark := ""
			if b.Name == d.InconclusiveBucket {
				mark = " (excluded from the denominator)"
			}
			parts = append(parts, fmt.Sprintf("%s %d%s", b.Name, b.Count, mark))
		}
		out = append(out, fmt.Sprintf("**%s** (%s)\n\n- %s\n- denominator: %d\n- basis: %s\n",
			d.Name, d.Kind, joinLines(parts, "; "), d.Denominator, d.Basis))
	}
	return joinLines(out, "\n")
}

func renderCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return joinLines(parts, ", ")
}
