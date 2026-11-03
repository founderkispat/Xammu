package corpus

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// allowedUses states what each partition may be used for. The list is the whole
// defence against corpus leakage turning into a fake result: a run that tunes a
// detector on the independent partition is reporting its own tuning as validation,
// and C-14 refuses the combination at the contract layer.
var allowedUses = map[contracts.PartitionName][]string{
	contracts.PartitionDevelopment: {
		"profiling", "detector_development", "tuning", "threshold_setting", "regression",
	},
	contracts.PartitionCalibration: {
		"calibration", "profiling", "threshold_setting",
	},
	contracts.PartitionIndependent: {
		"independent_validation", "documentation",
	},
}

// BuildPartitions turns the loaded tree into the three C-14 records, with the
// overlap checks measured now rather than copied from a previous commit. at is
// supplied by the caller so a build is reproducible in a test.
func (s *Set) BuildPartitions(commitRef string, at time.Time) ([]contracts.CorpusPartition, error) {
	if strings.TrimSpace(commitRef) == "" {
		return nil, fmt.Errorf("corpus: no commit reference: a C-14 partition that does not name the tree it " +
			"sealed cannot be re-checked against the source a reviewer is looking at")
	}
	var out []contracts.CorpusPartition
	for _, name := range contracts.AllPartitionNames() {
		p, err := s.BuildPartition(name, commitRef, at)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// BuildPartition builds one C-14 record and validates it against the contract.
func (s *Set) BuildPartition(name contracts.PartitionName, commitRef string, at time.Time) (*contracts.CorpusPartition, error) {
	p, err := s.Partition(name)
	if err != nil {
		return nil, err
	}
	if len(p.Items) == 0 {
		return nil, fmt.Errorf("corpus: partition %s holds no items: C-14 requires members, and an empty "+
			"partition's clean leakage verdict is a statement about nothing", name)
	}
	// A probe-text collision between partitions cannot be written into C-14, whose
	// overlap record has slots for shared groups and shared refs only. Refusing is
	// the honest move: recording it as a shared ref would state a fact about the
	// labels that is not true about the traffic.
	for _, l := range s.Overlaps() {
		if l.Kind != "probe_digest" {
			continue
		}
		for _, n := range l.Partitions {
			if n == name {
				return nil, fmt.Errorf("corpus: partition %s shares probe text %s with %s: independent "+
					"validation that replays the same bytes measures tuning, and C-14 has no field that could "+
					"record this honestly", name, l.Value, strings.Join(namesToStrings(l.Partitions), "+"))
			}
		}
	}

	groups := make([]string, 0, len(p.Groups))
	for g := range p.Groups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	uses, ok := allowedUses[name]
	if !ok {
		return nil, fmt.Errorf("corpus: partition %q has no declared allowed uses", name)
	}
	rec := &contracts.CorpusPartition{
		PartitionID:    contracts.NewUUID(),
		Name:           name,
		MemberRefs:     p.Refs(),
		GroupIDs:       groups,
		OverlapChecks:  s.OverlapChecks(name, at),
		LeakageVerdict: LeakageVerdict(s.OverlapChecks(name, at)),
		// Every partition is sealed at build time. Sealing does not mean the tree
		// is immutable; it means this record is a claim about one commit, and a run
		// must refuse to cite it after the tree moved.
		Sealed:      true,
		AllowedUses: append([]string(nil), uses...),
		CreatedAt:   at.UTC(),
		CommitRef:   commitRef,
	}
	if err := contracts.Validate(contracts.IDCorpusPartition, rec); err != nil {
		return nil, fmt.Errorf("corpus: partition %s rejected by C-14: %w", name, err)
	}
	return rec, nil
}

// EnsureNoLeaks refuses a corpus whose partitions share groups. A leaking
// independent partition does not validate anything, so the run must stop here
// instead of reporting numbers that describe tuning.
func (s *Set) EnsureNoLeaks() error { return s.Usable() }

// EnsureAllows refuses a use that the partition's own C-14 record does not grant.
// The check reads the built record, not the package table, so a corpus file that
// was sealed with different permissions is honoured over this build's defaults.
func EnsureAllows(partitions []contracts.CorpusPartition, name contracts.PartitionName, use string) error {
	for _, p := range partitions {
		if p.Name != name {
			continue
		}
		for _, allowed := range p.AllowedUses {
			if allowed == use {
				if p.LeakageVerdict != "clean" && name == contracts.PartitionIndependent {
					return fmt.Errorf("corpus: %s is sealed for %s but its leakage verdict is %q: the "+
						"independent numbers would measure tuning", name, use, p.LeakageVerdict)
				}
				return nil
			}
		}
		return fmt.Errorf("corpus: partition %s is not sealed for %s (allowed: %s): using it anyway would make "+
			"the run's validation numbers describe detector tuning",
			name, use, strings.Join(p.AllowedUses, ", "))
	}
	return fmt.Errorf("corpus: partition %s is not part of the sealed corpus", name)
}
