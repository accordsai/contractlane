package canonhash

import "testing"

func TestSumObjectDeterministicForSameState(t *testing.T) {
	a := map[string]any{
		"b": 2,
		"a": map[string]any{"y": 2, "x": 1},
	}
	b := map[string]any{
		"a": map[string]any{"x": 1, "y": 2},
		"b": 2,
	}

	ha, _, err := SumObject(a)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	hb, _, err := SumObject(b)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ha != hb {
		t.Fatalf("expected same hash, got %s vs %s", ha, hb)
	}
}

func TestSumObjectChangesWhenStateChanges(t *testing.T) {
	a := map[string]any{"a": 1}
	b := map[string]any{"a": 2}
	ha, _, _ := SumObject(a)
	hb, _, _ := SumObject(b)
	if ha == hb {
		t.Fatalf("expected different hashes")
	}
}
