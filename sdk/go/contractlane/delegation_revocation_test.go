package contractlane

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestValidateDelegationRevocation_ValidVectorAndStableHash(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(31, 32))
	issuerAgent, err := AgentIDFromEd25519PublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey: %v", err)
	}
	payload := DelegationRevocationV1{
		Version:      "delegation-revocation-v1",
		RevocationID: "rev_01JREVOCATION0000000000000001",
		DelegationID: "del_01JDELEGATION0000000000000001",
		IssuerAgent:  issuerAgent,
		Nonce:        "cmV2b2NhdGlvbl9ub25jZV92MQ",
		IssuedAt:     "2026-02-21T00:00:00Z",
		Reason:       "operator override",
	}
	sig, err := SignDelegationRevocationV1(payload, priv, time.Date(2026, 2, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationRevocationV1: %v", err)
	}
	hash, parsed, issuer, err := ValidateDelegationRevocation(payload, sig)
	if err != nil {
		t.Fatalf("ValidateDelegationRevocation: %v", err)
	}
	if issuer != issuerAgent {
		t.Fatalf("unexpected issuer agent: got %s want %s", issuer, issuerAgent)
	}
	if parsed.Version != payload.Version || parsed.RevocationID != payload.RevocationID || parsed.DelegationID != payload.DelegationID {
		t.Fatalf("parsed payload mismatch: got %+v", parsed)
	}
	const expectedHash = "f08a189a2fbc4690270c7c610b330f0e7b0b17aaf9a40e5aca7108f179f0b5f6"
	if hash != expectedHash {
		t.Fatalf("unexpected hash: got %s want %s", hash, expectedHash)
	}
	hash2, err := HashDelegationRevocationV1(payload)
	if err != nil {
		t.Fatalf("HashDelegationRevocationV1: %v", err)
	}
	if hash2 != hash {
		t.Fatalf("hash is not stable: %s vs %s", hash2, hash)
	}
}

func TestValidateDelegationRevocation_RejectsWrongContext(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(32, 32))
	issuerAgent, _ := AgentIDFromEd25519PublicKey(priv.Public().(ed25519.PublicKey))
	payload := DelegationRevocationV1{
		Version:      "delegation-revocation-v1",
		RevocationID: "rev_1",
		DelegationID: "del_1",
		IssuerAgent:  issuerAgent,
		Nonce:        "cmV2b2NhdGlvbl9ub25jZQ",
		IssuedAt:     "2026-02-21T00:00:00Z",
	}
	sig, err := SignDelegationRevocationV1(payload, priv, time.Date(2026, 2, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationRevocationV1: %v", err)
	}
	sig.Context = "delegation"
	_, _, _, err = ValidateDelegationRevocation(payload, sig)
	if err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("expected signature context error, got %v", err)
	}
}

func TestParseDelegationRevocationV1Strict_RejectsMalformedAgentID(t *testing.T) {
	_, err := ParseDelegationRevocationV1Strict(map[string]any{
		"version":       "delegation-revocation-v1",
		"revocation_id": "rev_1",
		"delegation_id": "del_1",
		"issuer_agent":  "agent:pk:ed25519:not-base64url",
		"nonce":         "cmV2b2NhdGlvbl9ub25jZQ",
		"issued_at":     "2026-02-21T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "issuer_agent") {
		t.Fatalf("expected issuer_agent validation error, got %v", err)
	}
}

func TestParseDelegationRevocationV1Strict_RejectsUnknownKey(t *testing.T) {
	_, err := ParseDelegationRevocationV1Strict(map[string]any{
		"version":       "delegation-revocation-v1",
		"revocation_id": "rev_1",
		"delegation_id": "del_1",
		"issuer_agent":  "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"nonce":         "cmV2b2NhdGlvbl9ub25jZQ",
		"issued_at":     "2026-02-21T00:00:00Z",
		"extra":         "nope",
	})
	if err == nil {
		t.Fatal("expected unknown-key strict parsing error")
	}
}
