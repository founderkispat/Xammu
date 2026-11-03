package corpus

import (
	"reflect"
	"testing"
)

func TestClassFirstPassServesEveryClassBeforeASecondCell(t *testing.T) {
	cells := []cell{
		{key: "a|query|g1"},
		{key: "a|query|g2"},
		{key: "a|query|g3"},
		{key: "b|query|g1"},
		{key: "b|query|g2"},
		{key: "c|query|g1"},
	}
	want := []int{0, 3, 5, 1, 4, 2}
	if got := classFirstPass(cells); !reflect.DeepEqual(got, want) {
		t.Fatalf("pass order %v, expected %v: the budget must buy breadth first", got, want)
	}

	// Every cell is served exactly once, so a budget that covers the matrix plans all
	// of it rather than dropping a slot to the rotation.
	seen := map[int]bool{}
	for _, i := range classFirstPass(cells) {
		if seen[i] {
			t.Fatalf("cell %d served twice", i)
		}
		seen[i] = true
	}
	if len(seen) != len(cells) {
		t.Fatalf("%d of %d cells served", len(seen), len(cells))
	}

	// The rotation is derived from the keys, so the same corpus yields the same plan.
	if got := classFirstPass(cells); !reflect.DeepEqual(got, want) {
		t.Fatalf("a second derivation reordered the plan: %v", got)
	}
}

// A key with no bar is the class on its own rather than a parse failure: the matrix
// always joins three fields, but the rotation should not depend on that.
func TestClassFirstPassTreatsABareKeyAsItsOwnClass(t *testing.T) {
	cells := []cell{{key: "a|x|g1"}, {key: "solo"}, {key: "a|x|g2"}}
	want := []int{0, 1, 2}
	if got := classFirstPass(cells); !reflect.DeepEqual(got, want) {
		t.Fatalf("pass order %v, expected %v", got, want)
	}
}
