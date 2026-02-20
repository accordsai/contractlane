package store

import "testing"

func TestHashTokenDeterministic(t *testing.T) {
	a := HashToken("token-1")
	b := HashToken("token-1")
	c := HashToken("token-2")
	if a != b {
		t.Fatalf("expected deterministic hash")
	}
	if a == c {
		t.Fatalf("expected different hashes for different tokens")
	}
}
