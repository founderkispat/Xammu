package corpus_test

import (
	"path/filepath"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
)

// TestReadmePlanningSnippet is not documentation: it is the code block from
// corpus/README.md, compiled. A snippet that does not build is a defect in the doc.
func TestReadmePlanningSnippet(t *testing.T) {
	root := filepath.Join("..", "..", "corpus")
	commitRef := "0123456789abcdef0123456789abcdef01234567"

	set, err := corpus.Load(root, corpus.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := set.EvidenceCheck(); err != nil {
		t.Fatal(err)
	}
	partitions, err := set.BuildPartitions(commitRef, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := corpus.EnsureAllows(partitions, contracts.PartitionDevelopment, "detector_development"); err != nil {
		t.Fatal(err)
	}
	if missing := set.Unobserved(contracts.PartitionDevelopment); len(missing) == 0 {
		t.Fatal("no ref carries declared-only evidence: the README's claim about this build is wrong")
	}
	sel, err := set.Select(corpus.SelectionRequest{
		Partition:         contracts.PartitionDevelopment,
		ControlsPartition: contracts.PartitionCalibration,
		Classes:           contracts.AllAttackClasses(),
		Vectors:           contracts.AllVectors(),
		Encodings:         contracts.AllEncodings(),
		Budget:            60,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range sel.Items() {
		if _, err := corpus.Place(item, corpus.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sel.Items()) == 0 {
		t.Fatal("the snippet planned nothing")
	}
}
