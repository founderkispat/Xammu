// Package corpus loads, gates and seals the probe corpus that a run draws from.
//
// Three properties are structural here rather than advisory:
//
//  1. The inertness gate is a precondition of loading, not a review step. A file
//     that claims verified_inert is re-checked by this package, and a claim that
//     disagrees with the gate is an error rather than an input. This is what keeps
//     XAMMU on the discovery side of the line: a probe with execution capability
//     never reaches the transport, so it can never be sent.
//
//  2. The probe digest is derived from the probe, never trusted from the file. An
//     editor who changes one half of the pair cannot keep the other half.
//
//  3. A partition is a set of *groups*, not a set of items. The split is by group,
//     so an encoding variant can never sit in development while its canonical twin
//     calibrates a detector. That invariant is what the overlap detector measures,
//     and a leak is reported instead of being silently absorbed.
package corpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// PartitionDir is the directory name a partition lives under at the corpus root.
var PartitionDir = map[contracts.PartitionName]string{
	contracts.PartitionDevelopment: "development",
	contracts.PartitionCalibration: "calibration",
	contracts.PartitionIndependent: "independent_validation",
}

// Partition is one loaded partition: the items on disk, their group index, and
// the gate's own opinion about each probe.
type Partition struct {
	Name contracts.PartitionName
	Dir  string

	// Items is in file order, then line order: the order a reviewer sees when
	// they open the directory, so a reported line number is actionable.
	Items []contracts.CorpusItem

	// Groups maps group_id to the refs that belong to it.
	Groups map[string][]string

	// SourceOf maps item_id to "file:line", for every diagnostic this package
	// raises after loading.
	SourceOf map[string]string

	// StaleGate lists refs whose recorded inertness claim disagrees with the gate
	// run at load time. Loading refuses the partition when this is non-empty; the
	// list survives on the struct so a caller can explain the refusal.
	StaleGate []string
}

// Set is the whole corpus: three partitions loaded together, because a partition
// cannot be judged for leakage on its own.
type Set struct {
	Root       string
	Partitions map[contracts.PartitionName]*Partition
	Gate       Policy
}

// Refs returns the sorted refs of a partition.
func (p *Partition) Refs() []string {
	out := make([]string, 0, len(p.Items))
	for _, i := range p.Items {
		out = append(out, i.Ref)
	}
	sort.Strings(out)
	return out
}

// Item returns the item carrying a ref, or nil.
func (p *Partition) Item(ref string) *contracts.CorpusItem {
	for idx := range p.Items {
		if p.Items[idx].Ref == ref {
			return &p.Items[idx]
		}
	}
	return nil
}

// Items returns the items of a partition, or nothing for a partition that is
// absent. Callers that must not silently read an empty partition use Partition().
func (s *Set) Items(name contracts.PartitionName) []contracts.CorpusItem {
	if p := s.Partitions[name]; p != nil {
		return p.Items
	}
	return nil
}

// Partition returns a loaded partition.
func (s *Set) Partition(name contracts.PartitionName) (*Partition, error) {
	p, ok := s.Partitions[name]
	if !ok {
		return nil, fmt.Errorf("corpus: partition %s is not loaded from %s", name, s.Root)
	}
	return p, nil
}

// Find locates a ref across every partition. A ref that resolves in two
// partitions is a leak the caller has to see, so both hits are reported.
func (s *Set) Find(ref string) ([]contracts.CorpusItem, error) {
	var out []contracts.CorpusItem
	for _, name := range contracts.AllPartitionNames() {
		p := s.Partitions[name]
		if p == nil {
			continue
		}
		if i := p.Item(ref); i != nil {
			out = append(out, *i)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("corpus: no item with ref %q under %s", ref, s.Root)
	}
	return out, nil
}

// Load reads every partition directory under root and runs the gate over each
// probe. A directory that is missing is an error, not an empty partition: a
// corpus with a partition quietly deleted is a corpus whose leakage verdict
// means nothing.
func Load(root string, gate Policy) (*Set, error) {
	if gate.MarkerToken == "" {
		return nil, fmt.Errorf("corpus: the inertness gate needs a marker token: a probe that is " +
			"not recognisable as diagnostic traffic in the target's logs cannot be authorized honestly")
	}
	set := &Set{Root: root, Partitions: map[contracts.PartitionName]*Partition{}, Gate: gate}
	for _, name := range contracts.AllPartitionNames() {
		dir := filepath.Join(root, PartitionDir[name])
		p, err := loadPartition(name, dir, gate)
		if err != nil {
			return nil, err
		}
		set.Partitions[name] = p
	}
	return set, nil
}

// loadPartition reads the .jsonl files of one directory in sorted order.
func loadPartition(name contracts.PartitionName, dir string, gate Policy) (*Partition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("corpus: partition %s has no directory at %s: a corpus missing a "+
				"partition cannot be judged for leakage, so it cannot be loaded", name, dir)
		}
		return nil, fmt.Errorf("corpus: cannot read partition directory %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("corpus: partition %s at %s holds no .jsonl files: an empty partition "+
			"produces a clean leakage verdict by absence rather than by measurement", name, dir)
	}
	sort.Strings(files)

	p := &Partition{
		Name:     name,
		Dir:      dir,
		Groups:   map[string][]string{},
		SourceOf: map[string]string{},
	}
	seenRef := map[string]string{}
	seenID := map[string]string{}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("corpus: cannot open %s: %w", file, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			raw := strings.TrimSpace(scanner.Text())
			if raw == "" || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "#") {
				continue
			}
			where := fmt.Sprintf("%s:%d", filepath.Base(file), line)
			item, err := parseItem([]byte(raw))
			if err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: %w", where, err)
			}
			if item.Partition != name {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s declares partition %q but lives in %s: the directory "+
					"is the authority on membership, so a moved file must be re-declared, not re-read",
					where, item.Partition, filepath.Base(dir))
			}
			if prev, dup := seenRef[item.Ref]; dup {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: ref %q already defined at %s: two probes with one "+
					"reference make every observation about that reference ambiguous", where, item.Ref, prev)
			}
			if prev, dup := seenID[item.ItemID]; dup {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: item_id %q already defined at %s", where, item.ItemID, prev)
			}
			seenRef[item.Ref] = where
			seenID[item.ItemID] = where

			if err := gate.Apply(item); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: ref %q: %w", where, item.Ref, err)
			}
			if staleGate(*item) {
				p.StaleGate = append(p.StaleGate, item.Ref)
			}
			if checkedInThePast(*item, time.Now().UTC()) {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: ref %q claims it was gated at %s, which is in the future: "+
					"a certification that has not happened yet is not a certification",
					where, item.Ref, item.Inertness.CheckedAt.Format(time.RFC3339))
			}
			if err := contracts.Validate(contracts.IDCorpusItem, item); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("corpus: %s: ref %q rejected by C-13: %w", where, item.Ref, err)
			}
			p.Items = append(p.Items, *item)
			p.Groups[item.GroupID] = append(p.Groups[item.GroupID], item.Ref)
			p.SourceOf[item.ItemID] = where
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("corpus: cannot finish reading %s: %w", file, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("corpus: cannot close %s: %w", file, err)
		}
	}
	if len(p.StaleGate) > 0 {
		return nil, fmt.Errorf("corpus: partition %s holds %d probe(s) gated by a different rule set than %s "+
			"(%s): re-certify them deliberately instead of letting a load quietly re-bless the older verdict",
			name, len(p.StaleGate), GateVersion, strings.Join(p.StaleGate, ", "))
	}
	return p, nil
}

// parseItem decodes one line, then derives the digest it must agree with.
func parseItem(raw []byte) (*contracts.CorpusItem, error) {
	var item contracts.CorpusItem
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&item); err != nil {
		return nil, fmt.Errorf("not a valid C-13 record: %w", err)
	}
	want := contracts.NewDigest([]byte(item.Probe))
	if item.ProbeDigest == "" {
		item.ProbeDigest = want
	} else if item.ProbeDigest != want {
		return nil, fmt.Errorf("probe_digest is %s but the probe in this file digests to %s: "+
			"the digest is derived from the probe, so editing one half of the pair is detected",
			item.ProbeDigest, want)
	}
	return &item, nil
}

// Usable reports whether the corpus may be used for the purposes a run needs.
// It is the gate the planner calls: a leaking independent partition is a corpus
// whose validation numbers describe tuning, not validation.
func (s *Set) Usable() error {
	leaks := s.Overlaps()
	if len(leaks) == 0 {
		return nil
	}
	var names []string
	for _, l := range leaks {
		names = append(names, l.String())
	}
	return fmt.Errorf("corpus: %d leakage finding(s) between partitions: %s: a run planned from this "+
		"corpus would report validation numbers that describe tuning", len(leaks), strings.Join(names, "; "))
}
