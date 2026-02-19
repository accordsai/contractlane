package contractlane

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestHashedArtifactSet_DeterministicAndDedupe(t *testing.T) {
	s := newHashedArtifactSet()
	s.upsert("b", map[string]any{"v": 2})
	s.upsert("a", map[string]any{"v": 1})
	s.upsert("b", map[string]any{"v": 99})

	hashes := s.sortedHashes()
	if !reflect.DeepEqual(hashes, []string{"a", "b"}) {
		t.Fatalf("unexpected hashes order: %+v", hashes)
	}
	items := s.sortedItems()
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestHostedCommerceAccumulator_IntentDedupeAndStableOrder(t *testing.T) {
	intentA := fixedCommerceIntentV1()
	intentA.IntentID = "ci_b"
	intentA.Nonce = "bm9uY2VfYg"
	intentA.ExpiresAt = "2026-02-20T13:00:00Z"

	intentB := fixedCommerceIntentV1()
	intentB.IntentID = "ci_a"
	intentB.Nonce = "bm9uY2VfYQ"
	intentB.ExpiresAt = "2026-02-20T12:00:00Z"

	priv := ed25519.NewKeyFromSeed(bytesRepeat(10, 32))
	sigA, _ := SignCommerceIntentV1(intentA, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	sigB, _ := SignCommerceIntentV1(intentB, priv, time.Date(2026, 2, 20, 11, 1, 0, 0, time.UTC))
	va, _ := validateCommerceIntentSubmission(intentA, sigA)
	vb, _ := validateCommerceIntentSubmission(intentB, sigB)

	acc1 := newHostedCommerceAccumulator()
	acc1.upsertSignedIntent(va, sigA)
	acc1.upsertSignedIntent(vb, sigB)
	acc1.upsertSignedIntent(va, sigA)

	acc2 := newHostedCommerceAccumulator()
	acc2.upsertSignedIntent(vb, sigB)
	acc2.upsertSignedIntent(va, sigA)

	b1, _ := json.Marshal(acc1.sortedIntentItems())
	b2, _ := json.Marshal(acc2.sortedIntentItems())
	if string(b1) != string(b2) {
		t.Fatalf("expected stable ordering independent of insertion order")
	}
}

func TestHostedCommerceAccumulator_IntentAcceptOrderParity(t *testing.T) {
	intent := fixedCommerceIntentV1()
	priv := ed25519.NewKeyFromSeed(bytesRepeat(11, 32))
	intentSig, _ := SignCommerceIntentV1(intent, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	vIntent, _ := validateCommerceIntentSubmission(intent, intentSig)

	acc := CommerceAcceptV1{
		Version:    "commerce-accept-v1",
		ContractID: intent.ContractID,
		IntentHash: vIntent.IntentHash,
		AcceptedAt: "2026-02-20T12:05:00Z",
		Nonce:      "YWNjZXB0X25vbmNlX3Yx",
		Metadata:   map[string]any{},
	}
	accSig, _ := SignCommerceAcceptV1(acc, priv, time.Date(2026, 2, 20, 11, 5, 0, 0, time.UTC))
	vAccept, _ := validateCommerceAcceptSubmission(acc, accSig)

	a := newHostedCommerceAccumulator()
	a.upsertSignedIntent(vIntent, intentSig)
	a.upsertSignedAccept(vAccept, accSig)

	b := newHostedCommerceAccumulator()
	b.upsertSignedAccept(vAccept, accSig)
	b.upsertSignedIntent(vIntent, intentSig)

	ab1, _ := json.Marshal(map[string]any{
		"commerce_intents": a.sortedIntentItems(),
		"commerce_accepts": a.sortedAcceptItems(),
	})
	ab2, _ := json.Marshal(map[string]any{
		"commerce_intents": b.sortedIntentItems(),
		"commerce_accepts": b.sortedAcceptItems(),
	})
	if string(ab1) != string(ab2) {
		t.Fatalf("expected order parity across insert orders")
	}
}

func TestBuildContractProofBundle_EmbedsEvidenceHashesUnchanged(t *testing.T) {
	evidenceBytes, err := BuildOfflineEvidenceBundle(sampleOfflineArtifacts(t))
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	hashes := evidence["hashes"].(map[string]any)

	proof, err := buildContractProofBundle(
		map[string]any{"contract_id": "ctr_offline_reference", "state": "EFFECTIVE"},
		evidence,
		map[string]any{
			"authorization_required":     true,
			"required_scopes":            []string{DelegationScopeCommerceIntentSign},
			"settlement_required_status": "PAID",
		},
	)
	if err != nil {
		t.Fatalf("buildContractProofBundle: %v", err)
	}
	req := proof["requirements"].(map[string]any)
	if req["evidence_manifest_hash"] != hashes["manifest_hash"] {
		t.Fatalf("manifest hash mismatch in proof bundle")
	}
	if req["evidence_bundle_hash"] != hashes["bundle_hash"] {
		t.Fatalf("bundle hash mismatch in proof bundle")
	}
}
