package contractlane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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

func TestParseSigV2EnvelopeV2Strict_HappyPath(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	env, err := SigV2Sign("contract-action", strings.Repeat("a", 64), priv, time.Date(2026, 2, 20, 1, 2, 3, 0, time.UTC), "kid_v2")
	if err != nil {
		t.Fatalf("SigV2Sign: %v", err)
	}
	parsed, err := ParseSigV2EnvelopeV2Strict(map[string]any{
		"version":      "sig-v2",
		"algorithm":    "es256",
		"public_key":   base64.RawURLEncoding.EncodeToString(pub),
		"signature":    env.Signature,
		"payload_hash": env.PayloadHash,
		"issued_at":    env.IssuedAt,
		"context":      env.Context,
		"key_id":       env.KeyID,
	})
	if err != nil {
		t.Fatalf("ParseSigV2EnvelopeV2Strict: %v", err)
	}
	if parsed.Version != "sig-v2" || parsed.Algorithm != "es256" {
		t.Fatalf("unexpected parsed envelope: %+v", parsed)
	}
}

func TestSigV2Sign_ProducesVerifiableEnvelope(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{"a": 1, "b": "x"}
	env, err := SignSigV2ES256(payload, priv, time.Date(2026, 2, 20, 1, 2, 3, 0, time.UTC), "contract-action")
	if err != nil {
		t.Fatalf("SignSigV2ES256: %v", err)
	}
	if env.Version != "sig-v2" || env.Algorithm != "es256" {
		t.Fatalf("unexpected v2 envelope: %+v", env)
	}
	if _, err := VerifySignatureEnvelope(payload, env); err != nil {
		t.Fatalf("VerifySignatureEnvelope: %v", err)
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
