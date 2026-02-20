package main

import "testing"

func TestParseBearer(t *testing.T) {
	tok, ok := parseBearer("Bearer abc123")
	if !ok || tok != "abc123" {
		t.Fatalf("expected parsed bearer token, got ok=%v token=%q", ok, tok)
	}

	_, ok = parseBearer("abc123")
	if ok {
		t.Fatal("expected parse failure without Bearer prefix")
	}
}
