package contractlane

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"contractlane/pkg/evp"
)

func sampleOfflineArtifacts(t *testing.T) map[string]any {
	t.Helper()

	intentA := fixedCommerceIntentV1()
	intentA.IntentID = "ci_b"
	intentB := fixedCommerceIntentV1()
	intentB.IntentID = "ci_a"
	intentA.ContractID = "ctr_offline_reference"
	intentB.ContractID = "ctr_offline_reference"

	buyerKey := bytesRepeat(21, 32)
	sellerKey := bytesRepeat(22, 32)
	buyerPriv := ed25519.NewKeyFromSeed(buyerKey)
	sellerPriv := ed25519.NewKeyFromSeed(sellerKey)
	buyerAgent, err := AgentIDFromEd25519PublicKey(buyerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey buyer: %v", err)
	}
	sellerAgent, err := AgentIDFromEd25519PublicKey(sellerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey seller: %v", err)
	}
	intentA.BuyerAgent = buyerAgent
	intentA.SellerAgent = sellerAgent
	intentB.BuyerAgent = buyerAgent
	intentB.SellerAgent = sellerAgent

	intentHashA, err := HashCommerceIntentV1(intentA)
	if err != nil {
		t.Fatalf("HashCommerceIntentV1 A: %v", err)
	}
	intentHashB, err := HashCommerceIntentV1(intentB)
	if err != nil {
		t.Fatalf("HashCommerceIntentV1 B: %v", err)
	}

	accA := fixedCommerceAcceptV1()
	accA.IntentHash = intentHashA
	accA.ContractID = "ctr_offline_reference"
	accB := fixedCommerceAcceptV1()
	accB.IntentHash = intentHashB
	accB.ContractID = "ctr_offline_reference"

	sigIntentA, err := SignCommerceIntentV1(intentA, buyerPriv, time.Date(2026, 2, 20, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1 A: %v", err)
	}
	sigIntentB, err := SignCommerceIntentV1(intentB, buyerPriv, time.Date(2026, 2, 20, 12, 2, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1 B: %v", err)
	}
	sigAcceptA, err := SignCommerceAcceptV1(accA, sellerPriv, time.Date(2026, 2, 20, 12, 3, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceAcceptV1 A: %v", err)
	}
	sigAcceptB, err := SignCommerceAcceptV1(accB, sellerPriv, time.Date(2026, 2, 20, 12, 4, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceAcceptV1 B: %v", err)
	}

	maxUses := int64(10)
	delegation := DelegationV1{
		Version:      "delegation-v1",
		DelegationID: "del_01HZX9Y0H2J7F2S0P5R8M6T4YA",
		IssuerAgent:  buyerAgent,
		SubjectAgent: buyerAgent,
		Scopes:       []string{DelegationScopeCommerceIntentSign},
		Constraints: DelegationConstraintsV1{
			ContractID:        "ctr_offline_reference",
			CounterpartyAgent: sellerAgent,
			MaxAmount: &CommerceAmountV1{
				Currency: "USD",
				Amount:   "250",
			},
			ValidFrom:  "2026-01-01T00:00:00Z",
			ValidUntil: "2026-12-31T23:59:59Z",
			MaxUses:    &maxUses,
		},
		Nonce:    "ZGVsZWdhdGlvbl9ub25jZV92MQ",
		IssuedAt: "2026-02-20T12:06:00Z",
	}
	delegationSig, err := SignDelegationV1(delegation, buyerPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationV1: %v", err)
	}

	return map[string]any{
		"anchors": []any{},
		"webhook_receipts": []any{
			sampleStripeReceipt("evt_pi_succeeded_ci_a", "payment_intent.succeeded", intentB.ContractID, intentB.IntentID, intentHashB, 2600, "usd", "pi_ci_a"),
			sampleStripeReceipt("evt_pi_failed_ci_b", "payment_intent.payment_failed", intentA.ContractID, intentA.IntentID, intentHashA, 2600, "usd", "pi_ci_b"),
		},
		"commerce_intents": []SignedCommerceIntentV1{
			{Intent: intentA, BuyerSignature: sigIntentA},
			{Intent: intentB, BuyerSignature: sigIntentB},
		},
		"commerce_accepts": []SignedCommerceAcceptV1{
			{Accept: accA, SellerSignature: sigAcceptA},
			{Accept: accB, SellerSignature: sigAcceptB},
		},
		"delegations": []SignedDelegationV1{
			{Delegation: delegation, IssuerSignature: delegationSig},
		},
	}
}

func sampleStripeReceipt(eventID, eventType, contractID, intentID, intentHash string, amountMinor int64, currency, objectID string) map[string]any {
	return map[string]any{
		"provider":          "stripe",
		"provider_event_id": eventID,
		"request_sha256":    "req_" + strings.TrimPrefix(eventID, "evt_"),
		"payload": map[string]any{
			"id":      eventID,
			"type":    eventType,
			"created": 1771598400, // 2026-02-20T12:00:00Z
			"data": map[string]any{
				"object": map[string]any{
					"id":       objectID,
					"amount":   amountMinor,
					"currency": currency,
					"metadata": map[string]any{
						"contract_id": contractID,
						"intent_id":   intentID,
						"intent_hash": intentHash,
					},
				},
			},
		},
	}
}

func TestOfflineArtifacts_DeterministicSorting(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	normalized, err := normalizeOfflineArtifacts(artifacts)
	if err != nil {
		t.Fatalf("normalizeOfflineArtifacts: %v", err)
	}

	intents, _ := normalized["commerce_intents"].([]any)
	if len(intents) != 2 {
		t.Fatalf("expected 2 intents, got %d", len(intents))
	}
	i0 := intents[0].(map[string]any)["intent"].(map[string]any)["intent_id"].(string)
	i1 := intents[1].(map[string]any)["intent"].(map[string]any)["intent_id"].(string)
	if !(i0 < i1) {
		t.Fatalf("intents not sorted by intent_id: %s, %s", i0, i1)
	}

	accepts, _ := normalized["commerce_accepts"].([]any)
	if len(accepts) != 2 {
		t.Fatalf("expected 2 accepts, got %d", len(accepts))
	}
	a0 := accepts[0].(map[string]any)["accept"].(map[string]any)["intent_hash"].(string)
	a1 := accepts[1].(map[string]any)["accept"].(map[string]any)["intent_hash"].(string)
	if !(a0 < a1) {
		t.Fatalf("accepts not sorted by intent_hash: %s, %s", a0, a1)
	}

	attestations, _ := normalized["settlement_attestations"].([]any)
	if len(attestations) != 2 {
		t.Fatalf("expected 2 settlement_attestations, got %d", len(attestations))
	}
	s0 := attestations[0].(map[string]any)["provider_event_id"].(string)
	s1 := attestations[1].(map[string]any)["provider_event_id"].(string)
	if !(s0 < s1) {
		t.Fatalf("settlement_attestations not sorted by provider_event_id: %s, %s", s0, s1)
	}

	delegations, _ := normalized["delegations"].([]any)
	if len(delegations) != 1 {
		t.Fatalf("expected 1 delegation, got %d", len(delegations))
	}
	d0 := delegations[0].(map[string]any)["delegation"].(map[string]any)["delegation_id"].(string)
	if d0 == "" {
		t.Fatalf("expected non-empty delegation id")
	}
}

func TestBuildOfflineEvidenceBundle_StableBytes(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	b1, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle #1: %v", err)
	}
	b2, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle #2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("expected byte-identical evidence bundle output")
	}
}

func TestBuildOfflineEvidenceBundle_EVPVerifyPasses(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	b, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	res, err := evp.VerifyBundleJSON(b)
	if err != nil {
		t.Fatalf("VerifyBundleJSON error: %v", err)
	}
	if res.Status != evp.StatusVerified {
		t.Fatalf("expected VERIFIED, got %s details=%v", res.Status, res.Details)
	}
}

func TestGenerateOfflineCommerceFixtures(t *testing.T) {
	if os.Getenv("UPDATE_FIXTURES") != "1" {
		t.Skip("set UPDATE_FIXTURES=1 to write fixtures")
	}
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	outDir := filepath.Join(root, "conformance", "fixtures", "agent-commerce-offline")
	if err := WriteOfflineEvidenceFiles(outDir, sampleOfflineArtifacts(t)); err != nil {
		t.Fatalf("WriteOfflineEvidenceFiles: %v", err)
	}

	evidencePath := filepath.Join(outDir, "evidence.json")
	b, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("ReadFile evidence fixture: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("fixture evidence invalid json: %v", err)
	}
}
