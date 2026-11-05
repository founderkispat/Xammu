package effectiveness

import (
	"path/filepath"
	"testing"

	"xammu/internal/corpus"
)

// TestRepositoryCorpusLoadsAndMeetsTheFloor is the 1.1/1.2 acceptance check: the
// committed corpus loads through the inertness gate and both populations clear
// the Phase 1 minimum.
func TestRepositoryCorpusLoadsAndMeetsTheFloor(t *testing.T) {
	root := filepath.Join("..", "..", "corpus", "effectiveness")
	cases, err := Load(root, corpus.DefaultPolicy())
	if err != nil {
		t.Fatalf("load %s: %v", root, err)
	}
	counts := Count(cases)
	if err := counts.CheckMinimums(); err != nil {
		t.Fatal(err)
	}
	if counts.Attack != 300 || counts.Benign != 300 {
		t.Fatalf("counts = %d attack, %d benign; want 300 and 300", counts.Attack, counts.Benign)
	}
	if len(counts.OWASP) != 10 {
		t.Fatalf("attack classes with an OWASP reference = %d; want 10", len(counts.OWASP))
	}
	for _, c := range cases {
		if c.Gate.Verdict != "verified" {
			t.Fatalf("case %s was admitted with gate verdict %q", c.ID, c.Gate.Verdict)
		}
	}
}
