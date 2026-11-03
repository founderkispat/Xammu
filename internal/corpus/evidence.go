package corpus

import (
	"fmt"
	"strings"
	"time"

	"xammu/internal/contracts"
)

// The two kinds of validation evidence C-13 accepts, named by the prefix of
// run_ref. The distinction is the difference between "the fixture's published
// rule table says this probe is blocked" and "we sent it and it was blocked".
// Only the second one is an observation, and a report that blurs them claims a
// measurement it never took.
const (
	// EvidenceDeclared prefixes a run_ref naming an inspected artifact: a rule
	// table, a configuration export, a documented behaviour.
	EvidenceDeclared = "lab-rule-table:"
	// EvidenceObserved prefixes a run_ref naming an executed run of XAMMU.
	EvidenceObserved = "lab-run:"
)

// KindOf classifies one evidence entry. An unrecognised prefix is refused rather
// than guessed, because a mislabelled entry is exactly how a declared expectation
// ends up reported as an observation.
func KindOf(runRef string) (string, error) {
	switch {
	case strings.HasPrefix(runRef, EvidenceDeclared):
		return "declared", nil
	case strings.HasPrefix(runRef, EvidenceObserved):
		return "observed", nil
	}
	return "", fmt.Errorf("corpus: validation run_ref %q has no known kind prefix: expected %s (an inspected "+
		"artifact) or %s (an executed run)", runRef, EvidenceDeclared, EvidenceObserved)
}

// EvidenceCheck verifies that every item's evidence entries are classifiable and
// that each entry names an artifact this build can point at.
func (s *Set) EvidenceCheck() error {
	for _, name := range contracts.AllPartitionNames() {
		p := s.Partitions[name]
		if p == nil {
			continue
		}
		for _, item := range p.Items {
			for _, v := range item.Validation {
				if _, err := KindOf(v.RunRef); err != nil {
					return fmt.Errorf("corpus: ref %q: %w", item.Ref, err)
				}
				if strings.TrimSpace(v.LabImageDigest) == "" {
					return fmt.Errorf("corpus: ref %q: evidence %q names no image digest, so it cannot be "+
						"tied to the build it was taken from", item.Ref, v.RunRef)
				}
			}
		}
	}
	return nil
}

// Unobserved lists the refs whose expectations are declared but never observed by
// an executed run of XAMMU. A non-empty answer is not an error: it is the honest
// precondition of a run whose report may say "first observation".
func (s *Set) Unobserved(name contracts.PartitionName) []string {
	p := s.Partitions[name]
	if p == nil {
		return nil
	}
	var out []string
	for _, item := range p.Items {
		if !hasObservedEvidence(item) {
			out = append(out, item.Ref)
		}
	}
	return out
}

func hasObservedEvidence(item contracts.CorpusItem) bool {
	for _, v := range item.Validation {
		if strings.HasPrefix(v.RunRef, EvidenceObserved) {
			return true
		}
	}
	return false
}

// AppendObservation records the evidence a finished run produced, so a probe's
// declared expectation is answered by an observation instead of re-asserted. It
// refuses to invent an entry: the run reference has to name a run, the digest has
// to name the image that served, and a result has to be stated.
func AppendObservation(item *contracts.CorpusItem, runRef, imageDigest, result string,
	observedAt time.Time, matchesExpectation bool) error {
	if item == nil {
		return fmt.Errorf("corpus: no item to record evidence on")
	}
	if !strings.HasPrefix(runRef, EvidenceObserved) {
		return fmt.Errorf("corpus: run_ref %q does not name an executed run (%s is the prefix): a run that "+
			"did not happen cannot be evidence", runRef, EvidenceObserved)
	}
	if !strings.HasPrefix(imageDigest, "sha256:") {
		return fmt.Errorf("corpus: run %s records image %q, which is not a digest: evidence that cannot be "+
			"tied to a build is not reproducible", runRef, imageDigest)
	}
	if strings.TrimSpace(result) == "" {
		return fmt.Errorf("corpus: run %s records no result for ref %q", runRef, item.Ref)
	}
	if observedAt.IsZero() {
		return fmt.Errorf("corpus: run %s has no observation time for ref %q", runRef, item.Ref)
	}
	item.Validation = append(item.Validation, contracts.CorpusValidationEvidence{
		RunRef: runRef, ObservedAt: observedAt.UTC(), Result: result,
		LabImageDigest: imageDigest, MatchesExpectation: matchesExpectation,
	})
	return nil
}
