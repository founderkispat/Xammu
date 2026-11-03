package corpus

import (
	"fmt"
	"sort"
	"strings"

	"xammu/internal/contracts"
)

// MinBenignReferences is the smallest reference cluster the reference-contrast
// detector can reason over. One reference has nothing to stand beside, and
// inventing a baseline from a single sample is how a flaky origin becomes "normal".
const MinBenignReferences = 2

// SelectionRequest states what a run may test and how much it paid for.
type SelectionRequest struct {
	// Partition is where the diagnosis probes come from.
	Partition contracts.PartitionName
	// ControlsPartition is where the positive, negative and benign probes come
	// from. Keeping it separate is what lets the independent set be used for
	// measurement while the calibration set stays the only thing allowed to tune a
	// detector.
	ControlsPartition contracts.PartitionName

	Classes   []contracts.AttackClass
	Vectors   []contracts.Vector
	Encodings []contracts.Encoding

	// Budget is the number of exchanges the authorization allows for this
	// selection. Controls are paid for out of it, because a control is a request.
	Budget int
}

// Exclusion names a probe that was not selected and why, so a coverage report can
// say "not tested because the budget ended" instead of leaving the reader to
// infer it from an absence.
type Exclusion struct {
	Ref    string
	Reason string
}

// Selection is what a run will plan.
type Selection struct {
	Controls []contracts.CorpusItem
	Probes   []contracts.CorpusItem
	Excluded []Exclusion
	// Requests is the exchange count this selection costs, controls included.
	Requests int
}

// Items returns controls followed by probes: the order a planner should send them
// in, because a control that arrives after the traffic it validates is a control
// that arrived too late to change anything.
func (sel *Selection) Items() []contracts.CorpusItem {
	out := make([]contracts.CorpusItem, 0, len(sel.Controls)+len(sel.Probes))
	out = append(out, sel.Controls...)
	out = append(out, sel.Probes...)
	return out
}

// cell is one (class, vector, encoding, group) slot of the coverage matrix.
type cell struct {
	key   string
	items []contracts.CorpusItem
}

// Select chooses probes for a run.
//
// The budget is spent coverage-first: cells are served in round-robin, one probe
// per cell per pass, so a run that cannot afford the whole matrix leaves a
// truncated *spread* across classes and transports rather than a fully-tested
// first family and an untested rest.
// Every probe that did not fit is named in Excluded.
func (s *Set) Select(req SelectionRequest) (*Selection, error) {
	if req.Budget <= 0 {
		return nil, fmt.Errorf("corpus: selection budget is %d: a run with no authorized exchanges cannot "+
			"be planned from a corpus", req.Budget)
	}
	part, err := s.Partition(req.Partition)
	if err != nil {
		return nil, err
	}
	controlPart, err := s.Partition(req.ControlsPartition)
	if err != nil {
		return nil, err
	}

	allowedClasses := classSet(req.Classes)
	allowedVectors := vectorSet(req.Vectors)
	allowedEncodings := encodingSet(req.Encodings)

	controls := pickControls(controlPart, allowedClasses, allowedVectors, allowedEncodings)
	if err := controlsAreSufficient(controls); err != nil {
		return nil, fmt.Errorf("corpus: partition %s has no usable control set in %s: %w",
			req.Partition, req.ControlsPartition, err)
	}
	sel := &Selection{Controls: controls}
	sel.Requests = len(controls)

	cells, skipped := matrix(part, allowedClasses, allowedVectors, allowedEncodings)
	sort.Slice(cells, func(i, k int) bool { return cells[i].key < cells[k].key })

	// The pass order is class-first, and that is the whole of the coverage promise.
	// Serving the cells in key order means a budget shorter than one pass stops at the
	// alphabetically first classes: the plan then reports three attack classes measured
	// out of nine and calls the run covered, which is the difference between a partial
	// result and a false one. Rotating across classes instead spends the same budget on
	// a breadth of the matrix, so what is missing stays visible as missing.
	order := classFirstPass(cells)

	used := map[string]bool{}
	for {
		placed := false
		for _, ci := range order {
			if sel.Requests >= req.Budget {
				break
			}
			item, ok := nextInCell(&cells[ci], used)
			if !ok {
				continue
			}
			sel.Probes = append(sel.Probes, item)
			used[item.Ref] = true
			sel.Requests++
			placed = true
		}
		if !placed {
			break
		}
	}

	// A plan that holds calibration traffic and no probe cannot measure anything: the
	// controls exist to validate the reading of a payload, not to be the payload. The
	// budget decides this arithmetic, so it is refused here rather than after the run
	// has spent every request and has nothing to report.
	if len(sel.Probes) == 0 {
		var candidates int
		for _, c := range cells {
			candidates += len(c.items)
		}
		if candidates == 0 {
			return nil, fmt.Errorf("corpus: partition %s holds no probe in the authorized classes, "+
				"transports or encodings: a plan with no probe has nothing to compare, so there is no "+
				"run to make of it", req.Partition)
		}
		return nil, fmt.Errorf("corpus: the budget of %d request(s) is taken entirely by the %d "+
			"calibration exchange(s) that validate the detectors, so all %d in-scope probe(s) were "+
			"excluded and the plan holds none: raise --budget above %d or narrow the scope",
			req.Budget, len(sel.Controls), candidates, len(sel.Controls))
	}

	for _, item := range part.Items {
		if used[item.Ref] {
			continue
		}
		reason := "the authorized budget ended before this cell's next pass"
		if why, ok := skipped[item.Ref]; ok {
			reason = why
		} else if role, err := RoleOf(item.Purpose); err == nil &&
			role != contracts.RoleProbe && role != contracts.RoleEncodingReplica {
			reason = "calibration traffic: it validates the detectors, so it stays out of the denominator " +
				"it measures"
		}
		sel.Excluded = append(sel.Excluded, Exclusion{Ref: item.Ref, Reason: reason})
	}
	for _, item := range controlPart.Items {
		role, err := RoleOf(item.Purpose)
		if err != nil || role == contracts.RoleProbe || role == contracts.RoleEncodingReplica {
			continue
		}
		if in(controls, item.Ref) {
			continue
		}
		sel.Excluded = append(sel.Excluded, Exclusion{Ref: item.Ref,
			Reason: "control lives in a class, vector or encoding the authorization does not cover"})
	}
	sort.Slice(sel.Excluded, func(i, k int) bool { return sel.Excluded[i].Ref < sel.Excluded[k].Ref })
	return sel, nil
}

// classFirstPass returns the cell indices ordered so that one cell of every class in
// the matrix is served before a second cell of any one class. The classes keep their
// key order and the cells within a class keep their key order, so the rotation is
// deterministic and the same corpus yields the same plan twice.
func classFirstPass(cells []cell) []int {
	var groups [][]int
	byClass := map[string]int{}
	for i, c := range cells {
		class := c.key
		if bar := strings.Index(class, "|"); bar >= 0 {
			class = class[:bar]
		}
		idx, seen := byClass[class]
		if !seen {
			idx = len(groups)
			byClass[class] = idx
			groups = append(groups, nil)
		}
		groups[idx] = append(groups[idx], i)
	}
	var order []int
	for round := 0; ; round++ {
		placed := false
		for _, g := range groups {
			if round >= len(g) {
				continue
			}
			order = append(order, g[round])
			placed = true
		}
		if !placed {
			return order
		}
	}
}

func classSet(in []contracts.AttackClass) map[contracts.AttackClass]bool {
	out := map[contracts.AttackClass]bool{}
	for _, v := range in {
		out[v] = true
	}
	return out
}

func vectorSet(in []contracts.Vector) map[contracts.Vector]bool {
	out := map[contracts.Vector]bool{}
	for _, v := range in {
		out[v] = true
	}
	return out
}

func encodingSet(in []contracts.Encoding) map[contracts.Encoding]bool {
	out := map[contracts.Encoding]bool{}
	for _, v := range in {
		out[v] = true
	}
	return out
}

// pickControls returns the controls in scope, ordered so the reader sees the
// positive control first: it is the one that proves the detectors can fire.
func pickControls(p *Partition, classes map[contracts.AttackClass]bool,
	vectors map[contracts.Vector]bool, encodings map[contracts.Encoding]bool) []contracts.CorpusItem {
	var out []contracts.CorpusItem
	for _, item := range p.Items {
		role, err := RoleOf(item.Purpose)
		if err != nil || (role != contracts.RolePositiveControl && role != contracts.RoleNegativeControl &&
			role != contracts.RoleBenignReference) {
			continue
		}
		if !classes[item.AttackClass] || !vectors[item.Vector] || !encodings[item.Encoding] {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Purpose != out[k].Purpose {
			return out[i].Purpose < out[k].Purpose
		}
		return out[i].Ref < out[k].Ref
	})
	return out
}

func in(items []contracts.CorpusItem, ref string) bool {
	for _, i := range items {
		if i.Ref == ref {
			return true
		}
	}
	return false
}

// controlsAreSufficient refuses to plan a run whose controls cannot validate the
// detectors. Without them every cell ceiling stops at replicated_within_run and
// the report would read as though the run were choosing to be modest.
func controlsAreSufficient(controls []contracts.CorpusItem) error {
	var pos, neg, benign int
	for _, c := range controls {
		switch c.Purpose {
		case contracts.PurposePositiveControl:
			pos++
		case contracts.PurposeNegativeControl, contracts.PurposeOverBlockProbe:
			neg++
		case contracts.PurposeBenignReference:
			benign++
		}
	}
	var gaps []string
	if pos == 0 {
		gaps = append(gaps, "no positive control: nothing proves the detectors can fire at all, "+
			"so a block-shaped reading could not be told from an origin error")
	}
	if neg == 0 {
		gaps = append(gaps, "no negative control: nothing proves the detectors abstain on benign traffic, "+
			"so a pass-shaped reading could not be told from a detector that fires on everything")
	}
	if benign < MinBenignReferences {
		gaps = append(gaps, fmt.Sprintf("only %d benign reference(s): the reference-contrast detector needs "+
			"%d before it may call anything normal", benign, MinBenignReferences))
	}
	if len(gaps) > 0 {
		return fmt.Errorf("%s", strings.Join(gaps, "; "))
	}
	return nil
}

func matrix(p *Partition, classes map[contracts.AttackClass]bool,
	vectors map[contracts.Vector]bool, encodings map[contracts.Encoding]bool) ([]cell, map[string]string) {
	var cells []cell
	byKey := map[string]int{}
	skipped := map[string]string{}
	for _, item := range p.Items {
		role, err := RoleOf(item.Purpose)
		if err != nil {
			continue
		}
		if role != contracts.RoleProbe && role != contracts.RoleEncodingReplica {
			continue
		}
		if !classes[item.AttackClass] {
			skipped[item.Ref] = "attack class " + string(item.AttackClass) + " is not in the authorization"
			continue
		}
		if !vectors[item.Vector] {
			skipped[item.Ref] = "vector " + string(item.Vector) + " is not in the authorization"
			continue
		}
		if !encodings[item.Encoding] {
			skipped[item.Ref] = "encoding " + string(item.Encoding) + " is not in the authorization"
			continue
		}
		key := cellKey(item)
		if idx, seen := byKey[key]; seen {
			cells[idx].items = append(cells[idx].items, item)
			continue
		}
		byKey[key] = len(cells)
		cells = append(cells, cell{key: key, items: []contracts.CorpusItem{item}})
	}
	return cells, skipped
}

// cellKey is the planning unit: one class, one transport, one probe family. The
// encoding is deliberately NOT part of the key -- it is the axis that varies
// inside a family, and a budget spent cell-by-cell would otherwise treat a
// canonical probe and its six replicas as six independent slots and drain the
// budget on the alphabetically first family.
func cellKey(item contracts.CorpusItem) string {
	return strings.Join([]string{
		string(item.AttackClass), string(item.Vector), item.GroupID,
	}, "|")
}

// nextInCell picks the cell's next unused probe, holding an encoding replica
// back until its canonical twin has been planned: a replica is only interpretable
// against the canonical reading, and planning it first would spend budget on a
// comparison with nothing to compare to.
func nextInCell(c *cell, used map[string]bool) (contracts.CorpusItem, bool) {
	for _, item := range c.items {
		if used[item.Ref] {
			continue
		}
		if item.Encoding != contracts.EncodingCanonical && !canonicalUsed(c, item, used) {
			continue
		}
		return item, true
	}
	return contracts.CorpusItem{}, false
}

func canonicalUsed(c *cell, item contracts.CorpusItem, used map[string]bool) bool {
	if item.Provenance.DerivedFrom == "" {
		// No declared twin: the replica is its own group's canonical probe.
		return true
	}
	for _, other := range c.items {
		if other.Ref == item.Provenance.DerivedFrom {
			return used[other.Ref]
		}
	}
	return true
}
