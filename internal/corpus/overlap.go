package corpus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// OverlapDetectorVersion is recorded in every C-14 overlap check. The detector is
// a program, not a judgement, so its version belongs beside each verdict.
const OverlapDetectorVersion = "xammu-partition-overlap/1.0.0"

// Leak is one measured collision between two partitions.
type Leak struct {
	Kind       string // "group_id" or "ref"
	Value      string
	Partitions []contracts.PartitionName
	Refs       []string
}

func (l Leak) String() string {
	return fmt.Sprintf("%s %s shared by %s [%s]", l.Kind, l.Value,
		strings.Join(namesToStrings(l.Partitions), "+"), strings.Join(l.Refs, ","))
}

// Overlaps compares every partition against every other, by group first.
//
// Group-level collision is the finding that matters: C-13's own comment says the
// split is by group, never by item, so a canonical probe in development and its
// encoding replica in independent validation is a leak even though the two items
// are different records. A bare ref comparison would call that corpus clean.
//
// The second pass compares probe *text*, and it does so only against the
// independent partition: replaying development bytes under fresh group labels is
// the way a corpus is leaked in practice, because the reviewer sees three
// disjoint label sets while the traffic repeats. Reuse between development and
// calibration is the opposite case -- the calibration anchor is the same bytes on
// purpose, that is what makes it an anchor.
func (s *Set) Overlaps() []Leak {
	groups := map[string][]string{} // group -> partition names, in AllPartitionNames order
	for _, name := range contracts.AllPartitionNames() {
		p := s.Partitions[name]
		if p == nil {
			continue
		}
		for group := range p.Groups {
			groups[group] = append(groups[group], string(name))
		}
	}
	var leaks []Leak
	for group := range groups {
		leaks = append(leaks, partitionsHoldingGroup(s, group)...)
	}
	probes := map[string]map[contracts.PartitionName][]string{}
	for _, name := range contracts.AllPartitionNames() {
		p := s.Partitions[name]
		if p == nil {
			continue
		}
		for _, item := range p.Items {
			key := item.ProbeDigest
			if _, seen := probes[key]; !seen {
				probes[key] = map[contracts.PartitionName][]string{}
			}
			probes[key][name] = append(probes[key][name], item.Ref)
		}
	}
	for digest, holders := range probes {
		if len(holders) < 2 {
			continue
		}
		// Only the independent partition's integrity is absolute: an anchor text
		// shared between calibration and development is documented, not a leak.
		if _, independent := holders[contracts.PartitionIndependent]; !independent {
			continue
		}
		var parts []contracts.PartitionName
		var refs []string
		for _, name := range contracts.AllPartitionNames() {
			if r, ok := holders[name]; ok {
				parts = append(parts, name)
				refs = append(refs, prefixEach(name, r)...)
			}
		}
		leaks = append(leaks, Leak{Kind: "probe_digest", Value: digest,
			Partitions: parts, Refs: sortedCopy(refs)})
	}
	sort.Slice(leaks, func(i, k int) bool {
		if leaks[i].Value != leaks[k].Value {
			return leaks[i].Value < leaks[k].Value
		}
		return leaks[i].Kind < leaks[k].Kind
	})
	return leaks
}

// partitionsHoldingGroup returns one leak per group that more than one partition
// claims.
func partitionsHoldingGroup(s *Set, group string) []Leak {
	var parts []contracts.PartitionName
	var refs []string
	for _, name := range contracts.AllPartitionNames() {
		p := s.Partitions[name]
		if p == nil {
			continue
		}
		if mine := p.Groups[group]; len(mine) > 0 {
			parts = append(parts, name)
			refs = append(refs, prefixEach(name, mine)...)
		}
	}
	if len(parts) < 2 {
		return nil
	}
	return []Leak{{Kind: "group_id", Value: group, Partitions: parts, Refs: sortedCopy(refs)}}
}

// prefixEach labels each ref with the partition it came from, so a leak names
// where to look rather than only what collided.
func prefixEach(name contracts.PartitionName, refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, string(name)+"/"+r)
	}
	return out
}

// OverlapChecks builds the C-14 comparison list for one partition: one entry per
// other partition, each with the shared groups spelled out. A check never
// summarises: an empty shared_groups with a leak_detected verdict would be a
// claim the reviewer cannot re-derive.
func (s *Set) OverlapChecks(name contracts.PartitionName, at time.Time) []contracts.OverlapCheck {
	here := s.Partitions[name]
	if here == nil {
		return nil
	}
	var out []contracts.OverlapCheck
	for _, other := range contracts.AllPartitionNames() {
		if other == name {
			continue
		}
		there := s.Partitions[other]
		shared := sharedGroups(here, there)
		sharedRefs := sharedRefs(here, there)
		verdict := "clean"
		if len(shared) > 0 || len(sharedRefs) > 0 {
			verdict = "leak_detected"
		}
		out = append(out, contracts.OverlapCheck{
			Against:      other,
			SharedGroups: shared,
			SharedRefs:   sharedRefs,
			Verdict:      verdict,
			DetectorVer:  OverlapDetectorVersion,
			CheckedAt:    at.UTC(),
		})
	}
	return out
}

func sharedGroups(a, b *Partition) []string {
	if b == nil {
		return nil
	}
	var out []string
	for group := range a.Groups {
		if len(b.Groups[group]) > 0 {
			out = append(out, group)
		}
	}
	sort.Strings(out)
	return out
}

func sharedRefs(a, b *Partition) []string {
	if b == nil {
		return nil
	}
	inB := map[string]bool{}
	for _, i := range b.Items {
		inB[i.Ref] = true
	}
	var out []string
	for _, i := range a.Items {
		if inB[i.Ref] {
			out = append(out, i.Ref)
		}
	}
	sort.Strings(out)
	return out
}

// LeakageVerdict is the partition-level answer derived from its checks, so no
// caller can write "clean" by hand next to a check that says otherwise.
func LeakageVerdict(checks []contracts.OverlapCheck) string {
	for _, c := range checks {
		if c.Verdict == "leak_detected" {
			return "leak_detected"
		}
	}
	return "clean"
}

func namesToStrings(in []contracts.PartitionName) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, string(n))
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
