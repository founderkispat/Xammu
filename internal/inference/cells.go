package inference

import (
	"sort"
	"strings"
	"time"

	"xammu/internal/attributor"
	"xammu/internal/contracts"
	"xammu/internal/observer"
)

// CellKey identifies one probe cell: what was injected, where in the request it was
// placed, how it was encoded, and at which path.
//
// The path is part of the key on purpose. A rule that fires at /login and stays
// quiet at /search is a routing story, not a signature story, and folding the two
// together is how a report claims coverage the target never showed.
type CellKey struct {
	AttackClass contracts.AttackClass `json:"attack_class"`
	Vector      contracts.Vector      `json:"vector"`
	Encoding    contracts.Encoding    `json:"encoding"`
	Path        string                `json:"path"`
}

func (k CellKey) String() string {
	return strings.Join([]string{string(k.AttackClass), string(k.Vector), string(k.Encoding), k.Path}, "|")
}

// Ref is the stable subject reference the cell's attribution, evidence profile and
// findings cite. It is derived from the key rather than generated, so the same cell
// observed in two rounds has the same subject and the rounds are comparable.
func (k CellKey) Ref() string { return "cell:" + k.String() }

// Trial is one exchange inside a cell, as far as inference is concerned. Every field
// is a citation: a reader can go from a measured rate to the journal line behind it.
type Trial struct {
	RunID            string                `json:"run_id"`
	RoundID          string                `json:"round_id"`
	ProbeRef         string                `json:"probe_ref"`
	CorpusRef        string                `json:"corpus_item_ref"`
	ControlRole      contracts.ControlRole `json:"control_role"`
	ObservationID    string                `json:"observation_id"`
	AnalysisID       string                `json:"analysis_id"`
	ClassificationID string                `json:"classification_id"`
	Signal           contracts.Signal      `json:"signal"`
	StatusCode       int                   `json:"status_code"`
	Valid            bool                  `json:"valid_trial"`
	At               time.Time             `json:"classified_at"`
}

// Cell is one probe cell across every round in the journal.
type Cell struct {
	CellKey
	// Origin is the destination every trial in the cell was sent to. A cell never
	// mixes origins: a comparison across hosts is not one measurement.
	Origin   string   `json:"target_origin"`
	Trials   []Trial  `json:"trials"`
	RunIDs   []string `json:"run_ids"`
	RoundIDs []string `json:"round_ids"`

	Signals      map[contracts.Signal]int `json:"signals"`
	Valid        int                      `json:"valid_trials"`
	Inconclusive int                      `json:"inconclusive_trials"`
	Invalid      int                      `json:"invalid_trials"`
}

// majority returns the signal the most valid trials produced and how many produced
// it. Ties break by signal name so the answer does not depend on map order.
func (c Cell) majority() (contracts.Signal, int) {
	counts := map[contracts.Signal]int{}
	for _, t := range c.Trials {
		if t.Valid {
			counts[t.Signal]++
		}
	}
	var best contracts.Signal
	var n int
	for s, k := range counts {
		if k > n || (k == n && s < best) {
			best, n = s, k
		}
	}
	return best, n
}

// MajorityReading names the signal the cell mostly produced. An empty signal means
// the cell has no valid trial at all.
func (c Cell) MajorityReading() contracts.Signal {
	s, _ := c.majority()
	return s
}

// Replicas counts the valid trials that produced the majority reading. It is a count
// of repetition, not a measure of strength: two identical answers can come from the
// same flaky origin, which is why the evidence ladder asks for more than repetition.
func (c Cell) Replicas() int {
	_, n := c.majority()
	return n
}

// CellsBy is the grouping the batch pass and the discover layer both work from. The
// order is deterministic: sorted by key, so re-reading the same journal enumerates
// the same cells in the same sequence.
//
// Only probe and encoding-replica exchanges appear. The calibration roles are read by
// CollectControls instead, because a cell's rate claims how payloads were handled at
// this path, and the benign reference that anchors that comparison is not itself a
// payload. Folding them in would put the calibration traffic in the denominator it
// exists to validate, and one exchange would be counted twice in two different records.
//
// An exchange that was sent but never classified is a gap the caller reports from
// Journal.Missing, not a trial with a blank signal.
func (j *Journal) CellsBy(roundID string) []Cell {
	byRef := make(map[string]*Cell)
	for _, o := range j.Observations {
		cls, ok := j.Classified[o.ObservationID]
		if !ok {
			continue
		}
		switch contracts.ControlRole(o.Sent.ControlRole) {
		case contracts.RolePositiveControl, contracts.RoleNegativeControl, contracts.RoleBenignReference:
			continue
		}
		key := CellKey{
			AttackClass: contracts.AttackClass(o.Sent.AttackClass),
			Vector:      contracts.Vector(o.Sent.Vector),
			Encoding:    contracts.Encoding(o.Sent.Encoding),
			Path:        o.Target.Path,
		}
		cell := byRef[key.Ref()]
		if cell == nil {
			cell = &Cell{CellKey: key, Origin: originOf(o), Signals: map[contracts.Signal]int{}}
			byRef[key.Ref()] = cell
		}
		trial := Trial{
			RunID:            o.RunID,
			RoundID:          roundID,
			ProbeRef:         o.Sent.ProbeRef,
			CorpusRef:        o.Sent.CorpusRef,
			ControlRole:      contracts.ControlRole(o.Sent.ControlRole),
			ObservationID:    o.ObservationID,
			AnalysisID:       cls.AnalysisID,
			ClassificationID: cls.ClassificationID,
			Signal:           cls.Signal,
			StatusCode:       cls.StatusCode,
			Valid:            contracts.ValidTrial(o, cls),
			At:               cls.ClassifiedAt,
		}
		cell.Trials = append(cell.Trials, trial)
		cell.Signals[cls.Signal]++
		switch {
		case trial.Valid:
			cell.Valid++
		case cls.Signal == contracts.SignalIndeterminate:
			cell.Inconclusive++
		default:
			cell.Invalid++
		}
	}
	out := make([]Cell, 0, len(byRef))
	for _, cell := range byRef {
		sort.Slice(cell.Trials, func(i, k int) bool {
			if cell.Trials[i].ProbeRef != cell.Trials[k].ProbeRef {
				return cell.Trials[i].ProbeRef < cell.Trials[k].ProbeRef
			}
			return cell.Trials[i].ObservationID < cell.Trials[k].ObservationID
		})
		var runs, rounds []string
		for _, t := range cell.Trials {
			runs = append(runs, t.RunID)
			rounds = append(rounds, t.RoundID)
		}
		cell.RunIDs = sortedUnique(runs)
		cell.RoundIDs = sortedUnique(rounds)
		out = append(out, *cell)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].CellKey.String() < out[k].CellKey.String() })
	return out
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Controls is what the run's calibration probes did. It is read from their own
// classifications, never asserted: "the control was valid" is a claim about
// evidence, and the evidence is in the journal.
type Controls struct {
	Positive []Trial
	Negative []Trial
}

// CollectControls separates the calibration exchanges from the probe cells. Negative
// controls and benign references both calibrate the ordinary-handling side: they
// differ in intent, not in what the classifier can learn from them.
func (j *Journal) CollectControls(roundID string) Controls {
	var c Controls
	for _, o := range j.Observations {
		cls, ok := j.Classified[o.ObservationID]
		if !ok {
			continue
		}
		trial := Trial{
			RunID: o.RunID, RoundID: roundID, ProbeRef: o.Sent.ProbeRef,
			CorpusRef: o.Sent.CorpusRef, ControlRole: contracts.ControlRole(o.Sent.ControlRole),
			ObservationID: o.ObservationID, AnalysisID: cls.AnalysisID,
			ClassificationID: cls.ClassificationID, Signal: cls.Signal,
			StatusCode: cls.StatusCode, Valid: contracts.ValidTrial(o, cls),
			At: cls.ClassifiedAt,
		}
		switch trial.ControlRole {
		case contracts.RolePositiveControl:
			c.Positive = append(c.Positive, trial)
		case contracts.RoleNegativeControl, contracts.RoleBenignReference:
			c.Negative = append(c.Negative, trial)
		}
	}
	sort.Slice(c.Positive, func(i, k int) bool { return c.Positive[i].ProbeRef < c.Positive[k].ProbeRef })
	sort.Slice(c.Negative, func(i, k int) bool { return c.Negative[i].ProbeRef < c.Negative[k].ProbeRef })
	return c
}

// ForAttributor adapts the controls to the attributor's input. The attributor
// derives their validity itself from these signals, so this package cannot earn a
// grade by describing a control favourably.
func (c Controls) ForAttributor() attributor.Controls {
	return attributor.Controls{
		PositiveRefs:    refsOf(c.Positive),
		PositiveSignals: signalsOf(c.Positive),
		NegativeRefs:    refsOf(c.Negative),
		NegativeSignals: signalsOf(c.Negative),
	}
}

func refsOf(in []Trial) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, t.ClassificationID)
	}
	return out
}

func signalsOf(in []Trial) []contracts.Signal {
	out := make([]contracts.Signal, 0, len(in))
	for _, t := range in {
		out = append(out, t.Signal)
	}
	return out
}

// referenceShapes returns the shapes of the calibration exchanges, which is what an
// "ordinary handling" reading is contrasted against. Pass the observation id being
// classified to drop that exchange from its own cluster: a control that calibrates
// against itself reports whatever it did as ordinary handling, which is how a
// blanket block quietly becomes a pass.
func (j *Journal) referenceShapes(exclude string) []observer.Shape {
	shapes := j.Shapes()
	var out []observer.Shape
	for _, o := range j.Observations {
		if o.ObservationID == exclude {
			continue
		}
		switch contracts.ControlRole(o.Sent.ControlRole) {
		case contracts.RoleNegativeControl, contracts.RoleBenignReference:
			out = append(out, shapes[o.ObservationID])
		}
	}
	return out
}
