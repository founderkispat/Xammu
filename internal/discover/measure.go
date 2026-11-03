package discover

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/inference"
)

// ratioOf counts a measurement over the trials that produced a reading. Invalid and
// inconclusive trials leave the denominator and are named in the ratio rather than
// silently dropped (criterion 23): a rate over 6 of 9 exchanges has to say that 3
// exchanges are not in it.
func ratioOf(trials []inference.Trial, basis, populationRef string,
	pred func(inference.Trial) bool) contracts.Ratio {
	r := contracts.Ratio{Basis: basis, PopulationRef: populationRef}
	for _, tr := range trials {
		switch {
		case !tr.Valid && tr.Signal == contracts.SignalIndeterminate:
			r.ExcludedInconclusive++
		case !tr.Valid:
			r.ExcludedInvalid++
		default:
			r.Denominator++
			if pred(tr) {
				r.Numerator++
			}
		}
	}
	return r
}

func ratioOfReadings(rs []reading, basis, populationRef string,
	pred func(reading) bool) contracts.Ratio {
	trials := make([]inference.Trial, 0, len(rs))
	for _, r := range rs {
		trials = append(trials, r.Trial)
	}
	return ratioOf(trials, basis, populationRef, func(tr inference.Trial) bool {
		for i := range rs {
			if rs[i].Trial.ObservationID == tr.ObservationID {
				return pred(rs[i])
			}
		}
		return false
	})
}

// percent renders a ratio as whole percentage points, rounding half up. It is a
// display of the ratio, never a substitute for it: every finding carries both.
func percent(r contracts.Ratio) int {
	if r.Denominator == 0 {
		return 0
	}
	return (100*r.Numerator*2 + r.Denominator) / (2 * r.Denominator)
}

func ratioText(r contracts.Ratio) string {
	return fmt.Sprintf("%d/%d (%d%%)", r.Numerator, r.Denominator, percent(r))
}

// pointsBetween is the distance between two measured rates in percentage points.
// The priority of a coverage finding is derived from it, so the ranking is a
// function of the measurement rather than a judgement added afterwards.
func pointsBetween(a, b contracts.Ratio) int {
	d := percent(a) - percent(b)
	if d < 0 {
		return -d
	}
	return d
}

const (
	highPoints   = 50
	mediumPoints = 20
	highTrials   = 6
	mediumTrials = 4
)

// priorityFrom ranks a finding from its own numbers and returns the sentence that
// explains the ranking. A finding over two valid trials is not allowed to read as
// high: the sample is the reason, and the reason is stated in the basis.
func priorityFrom(points, valid int) (contracts.Priority, string) {
	switch {
	case points >= highPoints && valid >= highTrials:
		return contracts.PriorityHigh, fmt.Sprintf(
			"%d percentage points measured over %d valid trials: at or above %d points across at "+
				"least %d trials", points, valid, highPoints, highTrials)
	case points >= mediumPoints && valid >= mediumTrials:
		return contracts.PriorityMedium, fmt.Sprintf(
			"%d percentage points measured over %d valid trials: below the %d-point/%d-trial "+
				"threshold for high", points, valid, highPoints, highTrials)
	default:
		return contracts.PriorityLow, fmt.Sprintf(
			"%d percentage points measured over %d valid trials: too small a difference, too few "+
				"trials, or both, to rank above low", points, valid)
	}
}

// stance is the strength a finding is allowed to claim, computed from the graded
// evidence in the cells it cites. Nothing in this package chooses a claim type
// freely; C-16 refuses a claim that outruns its level, and this refuses it earlier
// so the error names the evidence rather than the contract.
type stance struct {
	Claim       contracts.ClaimType
	Attribution contracts.AttributionStatus
	Basis       contracts.EvidenceBasis
	Level       contracts.EvidenceLevel
}

func (ix *index) stanceFor(rs []reading) (stance, error) {
	return ix.stanceAt(ix.levelOf(rs), rs)
}

// stanceAt derives the strongest claim a finding may make at a given evidence level.
// The level is a parameter because not every finding's population is a probe cell:
// the over-block rate is measured over the calibration exchanges, which are graded by
// their own C-08 profile rather than by a cell's. The attribution still comes from
// the cells, so a finding can never be stronger than the run's weakest conclusion.
func (ix *index) stanceAt(level contracts.EvidenceLevel, rs []reading) (stance, error) {
	if level == contracts.EvidenceNone {
		return stance{}, fmt.Errorf(
			"discover: the cells behind this finding carry evidence level none, so no claim of any "+
				"kind is available: %s", strings.Join(cellNames(rs), ", "))
	}
	attribution, basis := ix.weakestAttribution(rs)
	if attribution == "" {
		attribution = contracts.AttributionCompatible
		basis = contracts.BasisHTTPOnly
	}
	st := stance{Claim: contracts.ClaimDescriptive, Attribution: attribution, Level: level, Basis: basis}
	// Association is the ceiling for this layer: it says two measured things move
	// together. Naming the mechanism would be an attribution claim, and C-07 already
	// owns that step -- a finding that wanted to say more cites the hypothesis
	// instead of outranking it.
	if levelRank(level) >= levelRank(contracts.EvidenceReplicatedWithControls) &&
		statusRank(attribution) >= statusRank(contracts.AttributionCompatible) {
		st.Claim = contracts.ClaimAssociation
		if basis == contracts.BasisNone || basis == contracts.BasisHTTPOnly {
			st.Basis = contracts.BasisHTTPControl
		}
	}
	if statusRank(attribution) < statusRank(contracts.AttributionCompatible) {
		st.Claim = contracts.ClaimDescriptive
	}
	return st, nil
}

// weakestAttribution reports the least entitled attribution among the cited cells,
// with the evidence basis that produced it. A finding is only as attributable as
// its weakest cell.
func (ix *index) weakestAttribution(rs []reading) (contracts.AttributionStatus, contracts.EvidenceBasis) {
	var weakest contracts.AttributionStatus
	var basis contracts.EvidenceBasis
	for _, r := range rs {
		a := r.Verdict.Attribution
		if a == nil {
			continue
		}
		if weakest == "" || statusRank(a.Status) < statusRank(weakest) {
			weakest, basis = a.Status, a.EvidenceBasis
		}
	}
	return weakest, basis
}

func (ix *index) weakestProfile(rs []reading) *contracts.EvidenceProfile {
	var best *contracts.EvidenceProfile
	for _, r := range rs {
		p := r.Verdict.Profile
		if p.ProfileID == "" {
			continue
		}
		if best == nil || levelRank(p.Level) < levelRank(best.Level) {
			local := p
			best = &local
		}
	}
	return best
}

// levelRank orders the evidence ladder. contracts keeps rank() to itself, so the
// ordering here is by published position in AllEvidenceLevels rather than by a
// private judgement of what "stronger" means.
func levelRank(l contracts.EvidenceLevel) int {
	for i, v := range contracts.AllEvidenceLevels() {
		if v == l {
			return i
		}
	}
	return -1
}

func statusRank(s contracts.AttributionStatus) int {
	for i, v := range contracts.AllAttributionStatuses() {
		if v == s {
			return i
		}
	}
	return -1
}

func (ix *index) levelOf(rs []reading) contracts.EvidenceLevel {
	p := ix.weakestProfile(rs)
	if p == nil {
		return contracts.EvidenceNone
	}
	return p.Level
}

// profileRef cites the C-08 record the level comes from. The weakest cell's profile
// is the one cited, so a finding can never be dressed up in the strongest cell's
// evidence.
func (ix *index) profileRef(rs []reading) string {
	p := ix.weakestProfile(rs)
	if p == nil {
		return ""
	}
	return p.ProfileID
}

// hypothesisRef is set only when every cited reading shares one hypothesis. Two
// cells concluded by different hypotheses do not have a single statement to point at.
func (ix *index) hypothesisRef(rs []reading) string {
	shared := ""
	for _, r := range rs {
		if r.Verdict.Hypothesis == nil {
			return ""
		}
		if shared == "" {
			shared = r.Verdict.Hypothesis.Ref
			continue
		}
		if shared != r.Verdict.Hypothesis.Ref {
			return ""
		}
	}
	return shared
}

// citations returns observation ids for observation_refs. They are capped because a
// finding whose evidence list is 40 ids long cites nothing readable; the population
// count in measured_impact is the complete statement, and the journal is the archive.
func (ix *index) citations(rs []reading, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if r.Trial.ObservationID == "" || seen[r.Trial.ObservationID] {
			continue
		}
		seen[r.Trial.ObservationID] = true
		out = append(out, r.Trial.ObservationID)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// absenceCitation labels a pointer that is deliberately not an observation id. An
// undetermined area has no reading to cite, and an observation_refs list full of
// UUIDs it never had would be a fabrication.
func (ix *index) absenceCitation(detail string) []string {
	return []string{"absence:" + ix.in.RunID + "/" + ix.in.RoundID + "/" + detail}
}

func cellNames(rs []reading) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		name := r.Key.String()
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// majorityCount is how many valid readings agreed on one signal. The evidence
// ladder calls that number "replicas", so a population graded here has to state it
// the same way a cell does.
func majorityCount(rs []reading) int {
	counts := map[contracts.Signal]int{}
	for _, r := range rs {
		if r.valid() {
			counts[r.Trial.Signal]++
		}
	}
	var best int
	for _, n := range counts {
		if n > best {
			best = n
		}
	}
	return best
}

// roundsIn names the separately authorized rounds a set of trials came from, with
// the run's own round always present: a profile that claims two rounds when the
// input names one would raise a level the run did not earn.
func (ix *index) roundsIn(rs []reading) []string {
	out := []string{ix.in.RoundID}
	seen := map[string]bool{ix.in.RoundID: true}
	for _, r := range rs {
		if r.Trial.RoundID == "" || seen[r.Trial.RoundID] {
			continue
		}
		seen[r.Trial.RoundID] = true
		out = append(out, r.Trial.RoundID)
	}
	sort.Strings(out)
	return out
}

func refsOf(rs []reading) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if seen[r.Trial.CorpusRef] {
			continue
		}
		seen[r.Trial.CorpusRef] = true
		out = append(out, r.Trial.CorpusRef)
	}
	sort.Strings(out)
	return out
}

func (ix *index) missingEvidenceNote(rs []reading) string {
	var out []string
	seen := map[string]bool{}
	for _, r := range rs {
		for _, m := range r.Verdict.Profile.MissingEvidence {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "; ")
}
