package report

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/inference"
)

// coverageFacts is the arithmetic behind the matrix, computed once. The executive
// summary, the dimensions and the distributions all read it, so a report cannot state
// one coverage number in its summary and a different one in its table.
type coverageFacts struct {
	GridPairs       int
	PlacedPairs     int
	PairsWithSignal int
	ValidTrials     int
	Refused         int
	HandledOrdinary int
	Inconclusive    int
	Invalid         int
	Unplaced        int
	RateLimited     int
	TransportErrors int
	EncodingRows    int
	Encodings       int
	PathCount       int
	UnmeasuredCells int
	VerdictCounts   map[contracts.DistributionKind]map[string]int
	Signals         map[string]int
	Levels          map[contracts.EvidenceLevel]int
	Statuses        map[contracts.AttributionStatus]int
	Bases           map[contracts.EvidenceBasis]int
	Outcomes        map[contracts.HypothesisOutcome]int
	Corroborated    int
}

// pairKey is one cell of the report's matrix: a class and a transport. The encoding
// and the path belong to the rows underneath, because the matrix answers "which
// locations were inspected", not "which bytes were sent".
type pairKey struct {
	Class  contracts.AttackClass
	Vector contracts.Vector
}

type encodingAgg struct {
	Encoding     contracts.Encoding
	Blocked      int
	Passed       int
	ValidTrials  int
	Inconclusive int
	Invalid      int
	ControlValid bool
	Level        contracts.EvidenceLevel
	Refs         []string
	cells        int
}

type pairAgg struct {
	Key        pairKey
	Encodings  map[contracts.Encoding]*encodingAgg
	order      []contracts.Encoding
	Population int
	Blocked    int
	Passed     int
	ValidTrial int
	Inconclus  int
	Invalid    int
	Level      contracts.EvidenceLevel
	ControlInv bool
	Rounds     map[string]bool
	Refs       []string
}

// buildMatrix turns the pass's cells into the class x transport view C-15 requires,
// and states which authorized cells the run left open.
func buildMatrix(in Input, grid [][2]string) (contracts.CoverageMatrix, coverageFacts) {
	facts := coverageFacts{
		GridPairs:     len(grid),
		VerdictCounts: map[contracts.DistributionKind]map[string]int{},
		Signals:       map[string]int{},
		Levels:        map[contracts.EvidenceLevel]int{},
		Statuses:      map[contracts.AttributionStatus]int{},
		Bases:         map[contracts.EvidenceBasis]int{},
		Outcomes:      map[contracts.HypothesisOutcome]int{},
	}
	pairs := map[pairKey]*pairAgg{}
	paths := map[string]bool{}
	encodings := map[contracts.Encoding]bool{}

	for _, v := range in.Pass.Verdicts {
		key := pairKey{Class: v.Cell.AttackClass, Vector: v.Cell.Vector}
		p := pairs[key]
		if p == nil {
			p = &pairAgg{Key: key, Encodings: map[contracts.Encoding]*encodingAgg{},
				Level: contracts.EvidenceCorrelatedIndependent, Rounds: map[string]bool{}}
			pairs[key] = p
		}
		paths[v.Cell.Path] = true
		encodings[v.Cell.Encoding] = true
		for _, r := range v.Cell.RoundIDs {
			if r != "" {
				p.Rounds[r] = true
			}
		}
		e := p.Encodings[v.Cell.Encoding]
		if e == nil {
			e = &encodingAgg{Encoding: v.Cell.Encoding, ControlValid: true,
				Level: contracts.EvidenceCorrelatedIndependent}
			p.Encodings[v.Cell.Encoding] = e
			p.order = append(p.order, v.Cell.Encoding)
		}
		row := collectTrials(v.Cell, e, &facts)
		e.cells++
		p.Population += len(v.Cell.Trials)
		e.ControlValid = e.ControlValid && v.Profile.PositiveControlValid && v.Profile.NegativeControlValid
		if v.Cell.Valid > 0 && levelRank(v.Profile.Level) < levelRank(e.Level) {
			e.Level = v.Profile.Level
		}
		facts.Levels[v.Profile.Level]++
		p.Blocked += row.blocked
		p.Passed += row.passed
		p.ValidTrial += v.Cell.Valid
		p.Inconclus += v.Cell.Inconclusive
		p.Invalid += v.Cell.Invalid
		if v.Cell.Valid > 0 && levelRank(v.Profile.Level) < levelRank(p.Level) {
			p.Level = v.Profile.Level
		}
		for _, o := range v.Obstacles {
			if o.Reason == contracts.ReasonControlInvalid {
				p.ControlInv = true
			}
		}
		if v.Attribution != nil {
			facts.Statuses[v.Attribution.Status]++
			facts.Bases[v.Attribution.EvidenceBasis]++
			if v.Attribution.EvidenceBasis == contracts.BasisHTTPLogs ||
				v.Attribution.EvidenceBasis == contracts.BasisConfigExport {
				facts.Corroborated++
			}
		} else {
			facts.Statuses[contracts.AttributionUndetermined]++
			facts.Bases[contracts.BasisNone]++
		}
		if v.Hypothesis != nil {
			facts.Outcomes[v.Hypothesis.Outcome]++
		}
		if len(e.Refs) < 8 {
			e.Refs = append(e.Refs, row.refs...)
		}
		if len(p.Refs) < 8 {
			p.Refs = append(p.Refs, row.refs...)
		}
	}

	facts.RateLimited = facts.Signals["rate_limited"]
	facts.TransportErrors = facts.Signals["transport_error"]

	var keys []pairKey
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, k int) bool {
		if keys[i].Class != keys[k].Class {
			return keys[i].Class < keys[k].Class
		}
		return keys[i].Vector < keys[k].Vector
	})

	matrix := contracts.CoverageMatrix{
		Classes: append([]contracts.AttackClass(nil), classNames(in.Auth.AllowedClasses)...),
		Vectors: append([]contracts.Vector(nil), vectorNames(in.Auth.AllowedVectors)...),
		Basis:   matrixBasis(in, facts),
	}
	verdicts := map[string]int{}
	for _, k := range keys {
		p := pairs[k]
		// A cell with no valid trial has no evidence ladder to quote: the walk starts
		// every aggregate at the top rung so it can only ever climb down, and a cell
		// that never received a reading would otherwise report the strongest ceiling in
		// the vocabulary as though it had earned it.
		level := p.Level
		if p.ValidTrial == 0 {
			level = contracts.EvidenceNone
		}
		cell := contracts.CoverageCell{
			Class:           k.Class,
			Vector:          k.Vector,
			Status:          statusOf(p),
			ClaimType:       contracts.MaxClaimType(level),
			Evidence:        level,
			ObservationRefs: dedupe(p.Refs, 8),
			Aggregate: contracts.Ratio{
				Numerator:   p.Blocked,
				Denominator: p.ValidTrial,
				Basis: fmt.Sprintf(
					"valid probe trials of class %q placed in the %q transport, over every path and "+
						"encoding this run used there; the numerator is the trials the classifier read as "+
						"a refusal", k.Class, k.Vector),
				ExcludedInconclusive: p.Inconclus,
				ExcludedInvalid:      p.Invalid,
				PopulationRef:        fmt.Sprintf("grid:%s|%s", k.Class, k.Vector),
			},
		}
		rowVerdicts := map[string]bool{}
		for _, enc := range sortedEncodings(p) {
			e := p.Encodings[enc]
			verdict := verdictOf(e)
			rowVerdicts[verdict] = true
			facts.EncodingRows++
			verdicts[verdict]++
			rowLevel := e.Level
			if e.ValidTrials == 0 {
				rowLevel = contracts.EvidenceNone
			}
			cell.Encodings = append(cell.Encodings, contracts.EncodingRow{
				Encoding:     e.Encoding,
				Blocked:      e.Blocked,
				Passed:       e.Passed,
				ValidTrials:  e.ValidTrials,
				Inconclusive: e.Inconclusive,
				ControlValid: e.ControlValid,
				Verdict:      verdict,
				Evidence:     rowLevel,
			})
		}
		if cell.Status == "measured" || cell.Status == "partial" {
			facts.PairsWithSignal++
		}
		matrix.Cells = append(matrix.Cells, cell)
	}
	facts.PlacedPairs = len(keys)
	facts.Encodings = len(encodings)
	facts.PathCount = len(paths)
	matrix.NotMeasured = notMeasuredCells(in, grid, pairs, facts)
	if len(matrix.NotMeasured) == 0 {
		// A matrix with no holes is not a matrix that measured the target; it is a
		// matrix whose grid was drawn around what the run happened to send. The
		// contract refuses such a matrix, and refusing here gives the operator the
		// reason instead of a validation error two layers away.
		matrix.NotMeasured = []string{fmt.Sprintf(
			"the authorized grid (%d class(es) x %d transport(s)) was fully placed: the report cannot "+
				"state an unmeasured cell, which means the grid was drawn from the plan rather than from "+
				"the authorization", len(matrix.Classes), len(matrix.Vectors))}
	}
	// The per-cell verdict distribution counts rows, so it is filled after the walk.
	facts.VerdictCounts[contracts.DistCoverageVerdict] = verdicts
	facts.UnmeasuredCells = len(matrix.NotMeasured)
	return matrix, facts
}

type rowCount struct {
	blocked int
	passed  int
	refs    []string
}

// collectTrials folds one inference cell into its matrix row and the run-wide signal
// tally. Doing both in one walk is what keeps the distribution and the table the same
// measurement: a trial is counted here, once, and nowhere else.
func collectTrials(cell inference.Cell, e *encodingAgg, facts *coverageFacts) rowCount {
	out := rowCount{}
	for _, t := range cell.Trials {
		facts.Signals[bucketOf(t)]++
		if !t.Valid {
			continue
		}
		e.ValidTrials++
		facts.ValidTrials++
		if len(out.refs) < 8 {
			out.refs = append(out.refs, t.ObservationID)
		}
		switch t.Signal {
		case contracts.SignalBlock:
			e.Blocked++
			facts.Refused++
			out.blocked++
		case contracts.SignalPass:
			e.Passed++
			facts.HandledOrdinary++
			out.passed++
		default:
			facts.Unplaced++
		}
	}
	e.Inconclusive += cell.Inconclusive
	e.Invalid += cell.Invalid
	facts.Inconclusive += cell.Inconclusive
	facts.Invalid += cell.Invalid
	return out
}

// statusOf grades a matrix cell. "measured" is reserved for a cell where nothing was
// lost and every encoding agreed, because anything less is a partial picture the
// reader has to be told about rather than shown as a result.
func statusOf(p *pairAgg) string {
	switch {
	case p.ControlInv:
		return "control_invalid"
	case p.ValidTrial == 0:
		return "not_measured"
	}
	agree := ""
	for _, enc := range sortedEncodings(p) {
		v := verdictOf(p.Encodings[enc])
		if v == "indeterminate" || v == "not_measured" {
			return "partial"
		}
		if agree == "" {
			agree = v
		} else if agree != v {
			return "partial"
		}
	}
	if p.Inconclus > 0 || p.Invalid > 0 {
		return "partial"
	}
	if levelRank(p.Level) < levelRank(contracts.EvidenceSingleObservation) {
		return "partial"
	}
	return "measured"
}

func verdictOf(e *encodingAgg) string {
	switch {
	case e.ValidTrials == 0:
		return "not_measured"
	case e.Blocked > 0 && e.Passed > 0:
		return "mixed"
	case e.Blocked > 0:
		return "blocked"
	case e.Passed > 0:
		return "passed"
	default:
		return "indeterminate"
	}
}

func sortedEncodings(p *pairAgg) []contracts.Encoding {
	out := append([]contracts.Encoding(nil), p.order...)
	sort.Slice(out, func(i, k int) bool { return out[i] < out[k] })
	return out
}

// notMeasuredCells lists what this run did not measure, in two tiers: first the
// authorized class x transport pairs with no valid reading, then -- when the plan
// covered every authorized pair -- the classes and transports this authorization
// never covered. The second tier is the honest remainder: a run can only be shown to
// have measured what it was allowed to send.
func notMeasuredCells(in Input, grid [][2]string, pairs map[pairKey]*pairAgg,
	facts coverageFacts) []string {
	var out []string
	for _, g := range grid {
		key := pairKey{Class: contracts.AttackClass(g[0]), Vector: contracts.Vector(g[1])}
		p := pairs[key]
		switch {
		case p == nil:
			out = append(out, fmt.Sprintf(
				"%s|%s: the plan placed no probe of class %s in the %s transport, so the cell has no "+
					"reading to report", g[0], g[1], g[0], g[1]))
		case p.ValidTrial == 0:
			out = append(out, fmt.Sprintf(
				"%s|%s: %d exchange(s) were sent and none produced a valid reading (%d inconclusive, %d "+
					"invalid)", g[0], g[1], p.Population, p.Inconclus, p.Invalid))
		}
	}
	if len(out) == 0 {
		unauthorizedClasses := missingFrom(in.Auth.AllowedClasses, contracts.AllAttackClasses())
		unauthorizedVectors := missingFrom(in.Auth.AllowedVectors, contracts.AllVectors())
		for _, c := range unauthorizedClasses {
			out = append(out, fmt.Sprintf(
				"%s|*: attack class %s is outside authorization %s, so no cell of it is measured by this run",
				c, c, in.Auth.Ref))
		}
		for _, v := range unauthorizedVectors {
			out = append(out, fmt.Sprintf(
				"*|%s: transport %s is outside authorization %s, so no cell of it is measured by this run",
				v, v, in.Auth.Ref))
		}
	}
	if len(out) <= maxListedGaps {
		return out
	}
	// Truncation only after sorting, and the remainder is counted rather than
	// dropped: a reader sees how many holes there are even when the list is long.
	sorted := append([]string(nil), out...)
	sort.Strings(sorted)
	return append(sorted[:maxListedGaps], fmt.Sprintf(
		"and %d further unmeasured cell(s) of the authorized grid (the matrix denominator excludes all of them)",
		len(sorted)-maxListedGaps))
}

// maxListedGaps keeps the report readable on a wide authorization without hiding a
// single gap: the list is truncated, the count never is.
const maxListedGaps = 24

func missingFrom[T ~string](have []T, all []T) []T {
	seen := map[T]bool{}
	for _, v := range have {
		seen[v] = true
	}
	var out []T
	for _, v := range all {
		if !seen[v] {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i] < out[k] })
	return out
}

func matrixBasis(in Input, facts coverageFacts) string {
	a := in.Auth
	return fmt.Sprintf(
		"the grid is the authorization's own scope: %d attack class(es) x %d transport(s) = %d cell(s), "+
			"authorized by %s. Rows inside a cell are the encodings the run placed there, and a cell "+
			"aggregates every path. A rate over valid trials only: %d inconclusive and %d invalid "+
			"exchange(s) are named outside the denominator rather than folded into it.",
		len(a.AllowedClasses), len(a.AllowedVectors), facts.GridPairs, a.Ref,
		facts.Inconclusive, facts.Invalid)
}

func classNames(in []contracts.AttackClass) []contracts.AttackClass {
	out := append([]contracts.AttackClass(nil), in...)
	sort.Slice(out, func(i, k int) bool { return out[i] < out[k] })
	return out
}

func vectorNames(in []contracts.Vector) []contracts.Vector {
	out := append([]contracts.Vector(nil), in...)
	sort.Slice(out, func(i, k int) bool { return out[i] < out[k] })
	return out
}

func dedupe(in []string, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// claimCell renders the ceiling C-08 assigns to an evidence level of "none", which is
// the empty claim: the cell supports no statement about behaviour at all, and a table
// has to say that rather than leave the column blank.
func claimCell(c contracts.ClaimType) string {
	if c == "" {
		return "no claim"
	}
	return string(c)
}

// renderMatrix is the markdown table. It is a rendering, not a second measurement:
// every number in it is read from the C-15 payload it documents.
func renderMatrix(m contracts.CoverageMatrix) string {
	var b strings.Builder
	b.WriteString("| class | transport | status | refused/valid | encodings | evidence | claim ceiling |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, c := range m.Cells {
		encs := make([]string, 0, len(c.Encodings))
		for _, e := range c.Encodings {
			encs = append(encs, fmt.Sprintf("%s %s %d/%d", e.Encoding, e.Verdict, e.Blocked, e.ValidTrials))
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d/%d | %s | %s | %s |\n",
			c.Class, c.Vector, c.Status, c.Aggregate.Numerator, c.Aggregate.Denominator,
			strings.Join(encs, "; "), c.Evidence, claimCell(c.ClaimType)))
	}
	return b.String()
}
