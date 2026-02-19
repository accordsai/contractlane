package contractlane

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCanonicalUtilities_Golden(t *testing.T) {
	v := map[string]any{"b": 2, "a": 1}
	b, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got, want := string(b), `{"a":1,"b":2}`; got != want {
		t.Fatalf("canonical bytes mismatch: got=%s want=%s", got, want)
	}
	if got, want := SHA256Hex(b), "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"; got != want {
		t.Fatalf("sha256 mismatch: got=%s want=%s", got, want)
	}
	if got, want := mustCanonicalSHA256Hex(t, v), "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"; got != want {
		t.Fatalf("canonical sha mismatch: got=%s want=%s", got, want)
	}
}

func TestParseSigV1EnvelopeV1Strict_RejectsNonUTC(t *testing.T) {
	_, err := ParseSigV1EnvelopeV1Strict(map[string]any{
		"version":      "sig-v1",
		"algorithm":    "ed25519",
		"public_key":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"signature":    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"payload_hash": strings.Repeat("a", 64),
		"issued_at":    "2026-02-20T01:02:03+01:00",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProofBundleVerifyReport_StableCodes(t *testing.T) {
	report := VerifyProofBundleV1Report(ProofBundleV1{})
	if report.OK {
		t.Fatal("expected failure")
	}
	if report.Code == "" {
		t.Fatal("expected code")
	}
}

func TestProofBundleIDFromFixture(t *testing.T) {
	b, err := os.ReadFile("../../../conformance/fixtures/agent-commerce-offline/proof_bundle_v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	proof, err := ParseProofBundleV1Strict(raw)
	if err != nil {
		t.Fatalf("ParseProofBundleV1Strict: %v", err)
	}
	id, err := ComputeProofID(proof)
	if err != nil {
		t.Fatalf("ComputeProofID: %v", err)
	}
	wantB, err := os.ReadFile("../../../conformance/fixtures/agent-commerce-offline/proof_bundle_v1.id")
	if err != nil {
		t.Fatalf("read id fixture: %v", err)
	}
	want := strings.TrimSpace(string(wantB))
	if id != want {
		t.Fatalf("proof_id mismatch: got=%s want=%s", id, want)
	}
}

func TestConstructors_GenerateNonce(t *testing.T) {
	intent, err := NewCommerceIntentV1(CommerceIntentV1{
		Version:     "commerce-intent-v1",
		IntentID:    "ci_1",
		ContractID:  "ctr_1",
		BuyerAgent:  "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		SellerAgent: "agent:pk:ed25519:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
		Items:       []CommerceIntentItemV1{{SKU: "sku", Qty: 1, UnitPrice: CommerceAmountV1{Currency: "USD", Amount: "1"}}},
		Total:       CommerceAmountV1{Currency: "USD", Amount: "1"},
		ExpiresAt:   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("NewCommerceIntentV1: %v", err)
	}
	if strings.TrimSpace(intent.Nonce) == "" {
		t.Fatal("expected nonce")
	}
}

func mustCanonicalSHA256Hex(t *testing.T, v any) string {
	t.Helper()
	h, err := CanonicalSHA256Hex(v)
	if err != nil {
		t.Fatalf("CanonicalSHA256Hex: %v", err)
	}
	return h
}
