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

	"github.com/accordsai/contractlane/pkg/evp"
)

func TestVerifySettlementProofV1_Fixture(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("ReadFile evidence: %v", err)
	}
	proofBytes, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("ReadFile proof: %v", err)
	}
	if err := VerifySettlementProofV1(evidenceBytes, proofBytes); err != nil {
		t.Fatalf("VerifySettlementProofV1: %v", err)
	}
}

func TestVerifySettlementProofV1_RejectsTamper(t *testing.T) {
	evidencePath, _ := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)

	_, proofBytes, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	proof.IssuedAtUTC = "2026-02-18T00:00:00+01:00"
	tampered, _ := json.Marshal(proof)
	err = VerifySettlementProofV1(evidenceBytes, tampered)
	if err == nil {
		t.Fatal("expected tampered proof to fail")
	}
	if !strings.Contains(err.Error(), "issued_at_utc") {
		t.Fatalf("expected issued_at_utc error, got: %v", err)
	}
}

func TestVerifySettlementProofV1_RejectsMissingPaidAttestation(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	artifacts := evidence["artifacts"].(map[string]any)
	artifacts["settlement_attestations"] = []any{}

	tampered, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := VerifySettlementProofV1(tampered, proofBytes); err == nil {
		t.Fatal("expected missing settlement attestations to fail")
	}
}

func TestVerifySettlementProofV1_RejectsNonPaidStatus(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	artifacts := evidence["artifacts"].(map[string]any)
	att := artifacts["settlement_attestations"].([]any)
	for _, it := range att {
		row := it.(map[string]any)
		if row["intent_id"] == "ci_a" {
			row["status"] = "FAILED"
		}
	}

	tampered, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if err := VerifySettlementProofV1(tampered, proofBytes); err == nil {
		t.Fatal("expected non-PAID settlement attestation to fail")
	}
}

func TestVerifySettlementProofV1_RejectsPaymentAmountMismatch(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	if proof.Payment == nil {
		t.Fatalf("expected payment requirement in fixture proof")
	}
	proof.Payment.Amount.Amount = "999"
	tampered, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := VerifySettlementProofV1(evidenceBytes, tampered); err == nil {
		t.Fatal("expected payment amount mismatch to fail")
	}
}

func TestVerifySettlementProofV1_AuthorizationSelfIssuedPasses(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)
	if err := VerifySettlementProofV1(evidenceBytes, proofBytes); err != nil {
		t.Fatalf("expected self-issued delegation auth to pass: %v", err)
	}
}

func TestVerifySettlementProofV1_AuthorizationRootIssuedNeedsTrust(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	delegations := artifacts["delegations"].([]SignedDelegationV1)
	del := delegations[0].Delegation

	issuerSeed := bytesRepeat(33, 32)
	issuerPriv := ed25519.NewKeyFromSeed(issuerSeed)
	issuerAgent, err := AgentIDFromEd25519PublicKey(issuerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("issuer agent id: %v", err)
	}
	del.IssuerAgent = issuerAgent
	payload := del
	sig, err := SignDelegationV1(payload, issuerPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationV1: %v", err)
	}
	delegations[0] = SignedDelegationV1{Delegation: payload, IssuerSignature: sig}
	artifacts["delegations"] = delegations

	tamperedEvidence, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	_, proofBytes, err := BuildSettlementProofV1(tamperedEvidence, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}

	if err := VerifySettlementProofV1WithOptions(tamperedEvidence, proofBytes, SettlementProofVerifyOptions{}); err == nil {
		t.Fatal("expected untrusted root-issued delegation to fail")
	}
	if err := VerifySettlementProofV1WithOptions(tamperedEvidence, proofBytes, SettlementProofVerifyOptions{TrustAgents: []string{issuerAgent}}); err != nil {
		t.Fatalf("expected trusted root-issued delegation to pass: %v", err)
	}
}

func TestVerifySettlementProofV1_AuthorizationMissingDelegationFails(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	artifacts["delegations"] = []SignedDelegationV1{}
	evidenceBytes, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	_, proofBytes, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}
	err = VerifySettlementProofV1(evidenceBytes, proofBytes)
	if err == nil || !strings.Contains(err.Error(), DelegationFailureMissing) {
		t.Fatalf("expected %s, got %v", DelegationFailureMissing, err)
	}
}

func TestVerifySettlementProofV1_AuthorizationExpiredDelegationFails(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	ds := artifacts["delegations"].([]SignedDelegationV1)
	ds[0].Delegation.Constraints.ValidFrom = "2026-01-01T00:00:00Z"
	ds[0].Delegation.Constraints.ValidUntil = "2026-01-31T00:00:00Z"
	ds[0].IssuerSignature, _ = SignDelegationV1(ds[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(21, 32)), time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	artifacts["delegations"] = ds
	evidenceBytes, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	_, proofBytes, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}
	err = VerifySettlementProofV1(evidenceBytes, proofBytes)
	if err == nil || !strings.Contains(err.Error(), DelegationFailureExpired) {
		t.Fatalf("expected %s, got %v", DelegationFailureExpired, err)
	}
}

func TestVerifySettlementProofV1_AuthorizationAmountExceededFails(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	ds := artifacts["delegations"].([]SignedDelegationV1)
	ds[0].Delegation.Constraints.MaxAmount = &CommerceAmountV1{Currency: "USD", Amount: "10"}
	ds[0].IssuerSignature, _ = SignDelegationV1(ds[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(21, 32)), time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	artifacts["delegations"] = ds
	evidenceBytes, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	_, proofBytes, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}
	err = VerifySettlementProofV1(evidenceBytes, proofBytes)
	if err == nil || !strings.Contains(err.Error(), DelegationFailureAmountExceeded) {
		t.Fatalf("expected %s, got %v", DelegationFailureAmountExceeded, err)
	}
}

func TestVerifySettlementProofV1_AuthorizationRevokedFails(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	ds := artifacts["delegations"].([]SignedDelegationV1)
	target := ds[0].Delegation
	issuerPriv := ed25519.NewKeyFromSeed(bytesRepeat(21, 32))
	revPayload := DelegationRevocationV1{
		Version:      "delegation-revocation-v1",
		RevocationID: "rev_test_" + target.DelegationID,
		DelegationID: target.DelegationID,
		IssuerAgent:  target.IssuerAgent,
		Nonce:        "cmV2b2NhdGlvbl9ub25jZQ",
		IssuedAt:     "2026-02-20T12:30:00Z",
	}
	revSig, err := SignDelegationRevocationV1(revPayload, issuerPriv, time.Date(2026, 2, 20, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationRevocationV1: %v", err)
	}
	artifacts["delegation_revocations"] = []SignedDelegationRevocationV1{
		{Revocation: revPayload, IssuerSignature: revSig},
	}
	evidenceBytes, err := BuildOfflineEvidenceBundle(artifacts)
	if err != nil {
		t.Fatalf("BuildOfflineEvidenceBundle: %v", err)
	}
	_, proofBytes, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}
	err = VerifySettlementProofV1(evidenceBytes, proofBytes)
	if err == nil || !strings.Contains(err.Error(), DelegationFailureRevoked) {
		t.Fatalf("expected %s, got %v", DelegationFailureRevoked, err)
	}
}

func TestVerifySettlementProofV1_RulesRequireSettlementPaidPasses(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	proof.Requirements = &SettlementProofRequirements{
		Rules: &RulesV1{
			Version: "rules-v1",
			Rules: []RuleV1Item{
				{
					RuleID: "rl_paid",
					When:   mustPredicate(t, map[string]any{"has_commerce_intent": true}),
					Then: RuleEffectV1{
						Require: &RuleRequireEffectV1{
							Name:      "settlement_paid",
							Predicate: mustPredicate(t, map[string]any{"settlement_status_is": "PAID"}),
						},
					},
				},
			},
		},
	}
	updated, _ := json.Marshal(proof)
	if err := VerifySettlementProofV1(evidenceBytes, updated); err != nil {
		t.Fatalf("expected rules require settlement paid to pass: %v", err)
	}
}

func TestVerifySettlementProofV1_RulesRequireSettlementPaidFails(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	proof.Requirements = &SettlementProofRequirements{
		Rules: &RulesV1{
			Version: "rules-v1",
			Rules: []RuleV1Item{
				{
					RuleID: "rl_paid_fail",
					When:   mustPredicate(t, map[string]any{"has_commerce_intent": true}),
					Then: RuleEffectV1{
						Require: &RuleRequireEffectV1{
							Name:      "settlement_paid",
							Predicate: mustPredicate(t, map[string]any{"settlement_status_is": "DISPUTED"}),
						},
					},
				},
			},
		},
	}
	updated, _ := json.Marshal(proof)
	err := VerifySettlementProofV1(evidenceBytes, updated)
	if err == nil || !strings.Contains(err.Error(), "rules_requirement_failed") {
		t.Fatalf("expected rules_requirement_failed, got %v", err)
	}
	if !strings.Contains(err.Error(), "rule_id=rl_paid_fail") || !strings.Contains(err.Error(), "require=settlement_paid") || !strings.Contains(err.Error(), "failure_reason=status_mismatch") {
		t.Fatalf("expected deterministic rules failure detail, got %v", err)
	}
}

func TestVerifySettlementProofV1_RulesRequireAmountMatchFails(t *testing.T) {
	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, _ := os.ReadFile(evidencePath)
	proofBytes, _ := os.ReadFile(proofPath)

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	proof.Requirements = &SettlementProofRequirements{
		Rules: &RulesV1{
			Version: "rules-v1",
			Rules: []RuleV1Item{
				{
					RuleID: "rl_amount_fail",
					When:   mustPredicate(t, map[string]any{"has_commerce_intent": true}),
					Then: RuleEffectV1{
						Require: &RuleRequireEffectV1{
							Name: "amount_match",
							Predicate: mustPredicate(t, map[string]any{
								"settlement_amount_is": map[string]any{"currency": "USD", "amount": "999"},
							}),
						},
					},
				},
			},
		},
	}
	updated, _ := json.Marshal(proof)
	err := VerifySettlementProofV1(evidenceBytes, updated)
	if err == nil || !strings.Contains(err.Error(), "rules_requirement_failed") {
		t.Fatalf("expected rules_requirement_failed, got %v", err)
	}
	if !strings.Contains(err.Error(), "rule_id=rl_amount_fail") || !strings.Contains(err.Error(), "require=amount_match") || !strings.Contains(err.Error(), "failure_reason=amount_mismatch") {
		t.Fatalf("expected deterministic amount_mismatch rules detail, got %v", err)
	}
}

func TestBuildSettlementProofV1_Deterministic(t *testing.T) {
	evidencePath, _ := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("ReadFile evidence: %v", err)
	}

	opts := BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	}
	p1, b1, err := BuildSettlementProofV1(evidenceBytes, opts)
	if err != nil {
		t.Fatalf("BuildSettlementProofV1 #1: %v", err)
	}
	p2, b2, err := BuildSettlementProofV1(evidenceBytes, opts)
	if err != nil {
		t.Fatalf("BuildSettlementProofV1 #2: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("expected deterministic bytes")
	}
	if p1.IntentID != "ci_a" || p2.IntentID != "ci_a" {
		t.Fatalf("expected selected intent ci_a")
	}
	if err := VerifySettlementProofV1(evidenceBytes, b1); err != nil {
		t.Fatalf("verify built proof: %v", err)
	}
}

func TestGenerateSettlementProofFixture(t *testing.T) {
	if os.Getenv("UPDATE_FIXTURES") != "1" {
		t.Skip("set UPDATE_FIXTURES=1 to write settlement proof fixture")
	}

	evidencePath, proofPath := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("ReadFile evidence fixture: %v", err)
	}
	res, err := evp.VerifyBundleJSON(evidenceBytes)
	if err != nil || res.Status != evp.StatusVerified {
		t.Fatalf("evidence fixture must verify first: status=%s err=%v", res.Status, err)
	}

	_, out, err := BuildSettlementProofV1(evidenceBytes, BuildSettlementProofV1Options{
		ContractID:  "ctr_offline_reference",
		IntentID:    "ci_a",
		IssuedAtUTC: "2026-02-18T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSettlementProofV1: %v", err)
	}
	if err := os.WriteFile(proofPath, out, 0o644); err != nil {
		t.Fatalf("write proof fixture: %v", err)
	}
}

func TestSettlementProofFixture_UsesIssuedAtUTCKey(t *testing.T) {
	_, proofPath := settlementFixturePaths(t)
	b, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("ReadFile proof fixture: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatalf("Unmarshal proof fixture: %v", err)
	}
	if _, ok := root["issued_at_utc"]; !ok {
		t.Fatalf("expected top-level issued_at_utc")
	}
	if _, ok := root["issued_at"]; ok {
		t.Fatalf("top-level issued_at key must not exist")
	}
}

func settlementFixturePaths(t *testing.T) (evidencePath, proofPath string) {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	fixtureDir := filepath.Join(root, "conformance", "fixtures", "agent-commerce-offline")
	return filepath.Join(fixtureDir, "evidence.json"), filepath.Join(fixtureDir, "settlement_proof.json")
}

func mustPredicate(t *testing.T, v any) PredicateV1 {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	var p PredicateV1
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}
	return p
}
