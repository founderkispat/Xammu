// Package hypothesis turns measured counts into the two records that decide how far
// a run may speak: C-08, an ordinal evidence profile, and C-07, a hypothesis whose
// outcome is derived from the predictions it actually tested.
//
// Neither record lets a caller state a conclusion. The evidence level is climbed rung
// by rung from facts about the trials - how many were valid, whether the reading
// repeated, whether the controls calibrated, whether a second round exists, whether
// a source outside HTTP agrees - and the claim ceiling is then read off that level by
// contracts.MaxClaimType instead of being chosen. A run that sent one request cannot
// write an attribution, and no argument at this call site changes that.
//
// The other half of the honesty is the missing list. Every profile names the rung it
// stopped climbing and the evidence that would earn the next one, because the
// engineer's real question is usually "what must I run to make this claim", not "what
// did you already conclude".
package hypothesis

import (
	"fmt"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// Version is stamped into the ceiling justification so a cap can be traced to the
// build that derived it.
const Version = "xammu-hypothesis/1.0.0"

// Trials is the measured arithmetic for one subject. The caller counts; this package
// only derives from the counts, so a trial class that does not fit inside the
// population is refused here rather than surfacing in a published report.
type Trials struct {
	// Population is every exchange attempted for the subject. Valid, Inconclusive
	// and Invalid partition it.
	Population   int
	Valid        int
	Inconclusive int
	Invalid      int
	// Replicas is how many valid trials of this subject produced the same reading.
	Replicas int
	// Rounds lists the separately authorized rounds that contributed trials. One
	// run can name only its own round; reaching the rounds level needs a second
	// run, which is the honest meaning of the requirement.
	Rounds []string

	PositiveControlValid bool
	NegativeControlValid bool

	// CorroborationSource names a source outside the HTTP response - a filter log
	// or a configuration export - that agrees with the inference. It is supplied by
	// an operator with access; nothing here fetches it.
	CorroborationSource string

	// Hits is the numerator of the measured rate and HitBasis states in one line
	// what a hit means for this subject. Denominator is always Valid.
	Hits     int
	HitBasis string

	// Refs are the evidence records the trials came from.
	Refs []string
}

// Subject is one thing the run has counts about: a probe cell, a vector pair, an
// encoding family or an attribution.
type Subject struct {
	RunID      string
	Ref        string
	Kind       string
	Trials     Trials
	CompiledAt time.Time
}

// rung is one step of the evidence ladder. `earned` decides whether the measured
// facts support standing on it; `missing` states, in the engineer's terms, what the
// run would have to add to climb higher.
type rung struct {
	level   contracts.EvidenceLevel
	earned  func(Trials) bool
	missing string
}

// ladder is ordered weakest to strongest. The conditions here mirror the checks the
// C-08 validator makes independently, so a profile that reached a level can always
// show the facts that justify it.
var ladder = []rung{
	{contracts.EvidenceSingleObservation, func(t Trials) bool { return t.Valid >= 1 },
		"at least one valid trial: every exchange recorded for this subject arrived " +
			"rate limited, transport failed, indeterminate or invalid"},
	{contracts.EvidenceReplicated, func(t Trials) bool { return t.Valid >= 2 && t.Replicas >= 2 },
		"the same reading reproduced by two or more valid trials inside this run"},
	{contracts.EvidenceReplicatedWithControls, func(t Trials) bool {
		return t.PositiveControlValid && t.NegativeControlValid
	}, "a valid positive control (a payload this run recorded as rejected) and a valid " +
		"negative control (a benign reference this run recorded as ordinarily handled)"},
	{contracts.EvidenceIndependentRounds, func(t Trials) bool { return len(t.Rounds) >= 2 },
		"repetition across two separately authorized rounds; one run cannot manufacture this"},
	{contracts.EvidenceCorrelatedIndependent, func(t Trials) bool {
		return strings.TrimSpace(t.CorroborationSource) != ""
	}, "agreement from a source outside the HTTP response, such as the filter's own log " +
		"entry or its configuration export"},
}

// climb walks the ladder until a rung is not earned and returns that rung's
// requirement as the thing missing. A subject with no valid trial never reaches the
// first rung.
func climb(t Trials) (contracts.EvidenceLevel, string) {
	if t.Valid == 0 {
		return contracts.EvidenceNone, ladder[0].missing
	}
	level := contracts.EvidenceNone
	for _, r := range ladder {
		if !r.earned(t) {
			return level, r.missing
		}
		level = r.level
	}
	return level, ""
}

// Profile builds C-08 for one subject and validates it before returning it.
func Profile(s Subject) (contracts.EvidenceProfile, error) {
	if s.RunID == "" {
		return contracts.EvidenceProfile{}, fmt.Errorf("hypothesis: a profile needs a run id")
	}
	if s.Ref == "" {
		return contracts.EvidenceProfile{}, fmt.Errorf("hypothesis: a profile needs a subject reference")
	}
	if strings.TrimSpace(s.Kind) == "" {
		return contracts.EvidenceProfile{}, fmt.Errorf(
			"hypothesis: subject %s needs a kind: a reader must know what the level grades", s.Ref)
	}
	if s.CompiledAt.IsZero() {
		return contracts.EvidenceProfile{}, fmt.Errorf(
			"hypothesis: profile for %s needs a compilation timestamp", s.Ref)
	}
	t := s.Trials
	if err := checkArithmetic(s.Ref, t); err != nil {
		return contracts.EvidenceProfile{}, err
	}
	// Deduplicated before climbing, not after: two entries naming one round are one
	// round, and the rung above it is the one that requires a second authorization.
	t.Rounds = dedupe(t.Rounds)

	level, missing := climb(t)
	ceiling := contracts.MaxClaimType(level)

	ratio := contracts.Ratio{
		Numerator:            t.Hits,
		Denominator:          t.Valid,
		Basis:                hitBasis(t),
		ExcludedInconclusive: t.Inconclusive,
		ExcludedInvalid:      t.Invalid,
		PopulationRef:        s.Ref,
	}
	p := contracts.EvidenceProfile{
		ProfileID:            contracts.NewUUID(),
		RunID:                s.RunID,
		SubjectRef:           s.Ref,
		SubjectKind:          s.Kind,
		CompiledAt:           s.CompiledAt,
		Level:                level,
		ClaimCeiling:         ceiling,
		CeilingJustification: ceilingPhrase(level, ceiling, t, missing),
		Population:           t.Population,
		ValidTrials:          t.Valid,
		Inconclusive:         t.Inconclusive,
		InvalidTrials:        t.Invalid,
		Replicas:             t.Replicas,
		Rounds:               dedupe(t.Rounds),
		PositiveControlValid: t.PositiveControlValid,
		NegativeControlValid: t.NegativeControlValid,
		CorroborationSource:  strings.TrimSpace(t.CorroborationSource),
		Measured:             ratio,
		MissingEvidence:      missingList(level, t, missing),
		Refs:                 append([]string(nil), t.Refs...),
	}
	if err := contracts.Validate(contracts.IDEvidenceProfile, &p); err != nil {
		return contracts.EvidenceProfile{}, fmt.Errorf(
			"hypothesis: evidence profile for %s rejected by C-08: %w", s.Ref, err)
	}
	return p, nil
}

// checkArithmetic refuses counts that cannot describe one population. A rate built on
// them would be a number nobody can check against the journal.
func checkArithmetic(ref string, t Trials) error {
	if t.Population < 0 || t.Valid < 0 || t.Inconclusive < 0 || t.Invalid < 0 || t.Replicas < 0 {
		return fmt.Errorf("hypothesis: subject %s has a negative trial count", ref)
	}
	if sum := t.Valid + t.Inconclusive + t.Invalid; sum > t.Population {
		return fmt.Errorf("hypothesis: subject %s accounts for %d trials in a population of %d: "+
			"a trial cannot be both counted and missing", ref, sum, t.Population)
	}
	if t.Hits > t.Valid {
		return fmt.Errorf("hypothesis: subject %s reports %d hits over %d valid trials: a hit "+
			"must be a valid trial", ref, t.Hits, t.Valid)
	}
	if t.Replicas > t.Valid {
		return fmt.Errorf("hypothesis: subject %s claims %d replicas from %d valid trials",
			ref, t.Replicas, t.Valid)
	}
	if t.Valid > 0 && strings.TrimSpace(t.HitBasis) == "" {
		return fmt.Errorf("hypothesis: subject %s has %d valid trial(s) but no stated basis: "+
			"a rate without its definition is a number nobody can check against the journal",
			ref, t.Valid)
	}
	return nil
}

func hitBasis(t Trials) string {
	if b := strings.TrimSpace(t.HitBasis); b != "" {
		return b
	}
	return "no valid trial: this rate is empty, not zero, and must be reported as unevaluated"
}

// ceilingPhrase states the cap and the reason in one line, so a reader of the report
// sees the derivation next to the claim it bounds.
func ceilingPhrase(level contracts.EvidenceLevel, ceiling contracts.ClaimType,
	t Trials, missing string) string {
	if level == contracts.EvidenceNone {
		return fmt.Sprintf("%s: level none because 0 of %d trial(s) were valid, so the claim "+
			"ceiling is empty - this subject supports no claim about the target at all", Version, t.Population)
	}
	return fmt.Sprintf("%s: level %s from %d valid trial(s) (%d replicas, %d round(s)) caps claims "+
		"at %q by contracts.MaxClaimType; %s", Version, level, t.Valid, t.Replicas,
		len(dedupe(t.Rounds)), ceiling, ceilingTail(missing))
}

func ceilingTail(missing string) string {
	if missing == "" {
		return "the ladder is fully climbed, so the ceiling is set by the strongest evidence level"
	}
	return "the next rung is unearned"
}

func missingList(level contracts.EvidenceLevel, t Trials, missing string) []string {
	var out []string
	if level == contracts.EvidenceNone {
		out = append(out, "no valid trial exists for this subject, so nothing about the target's "+
			"behaviour can be claimed; what this profile documents is the run's own coverage")
	}
	if missing != "" {
		out = append(out, "to raise the evidence level: "+missing)
	}
	if t.Inconclusive > 0 {
		out = append(out, fmt.Sprintf(
			"%d trial(s) returned an indeterminate signal and are excluded from the measured rate",
			t.Inconclusive))
	}
	if t.Invalid > 0 {
		out = append(out, fmt.Sprintf(
			"%d trial(s) were invalid through control failure, transport error or scope refusal "+
				"and are excluded from the measured rate", t.Invalid))
	}
	return out
}

func dedupe(in []string) []string {
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
