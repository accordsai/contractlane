package contractlane

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProofBundleV1_ComputeIDDeterministic(t *testing.T) {
	evidencePath, _ := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence fixture: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence fixture: %v", err)
	}
	proof, err := BuildProofBundleV1(ContractExportV1{
		ContractID:      "ctr_offline_reference",
		PrincipalID:     "prn_offline",
		TemplateID:      "tpl_offline_reference",
		TemplateVersion: "v1",
		State:           "OFFLINE",
	}, evidence, nil, nil)
	if err != nil {
		t.Fatalf("BuildProofBundleV1: %v", err)
	}
	id1, err := ComputeProofID(proof)
	if err != nil {
		t.Fatalf("ComputeProofID #1: %v", err)
	}
	id2, err := ComputeProofID(proof)
	if err != nil {
		t.Fatalf("ComputeProofID #2: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("proof_id not deterministic: %s vs %s", id1, id2)
	}
	const expected = "4a1d398c70bc9be62373669f54d78263117415f635de8b65af611c0fa50c4dff"
	if id1 != expected {
		t.Fatalf("unexpected proof_id: got %s want %s", id1, expected)
	}
}

func TestVerifyProofBundleV1_OK(t *testing.T) {
	evidencePath, _ := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence fixture: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence fixture: %v", err)
	}
	proof, err := BuildProofBundleV1(ContractExportV1{
		ContractID:      "ctr_offline_reference",
		PrincipalID:     "prn_offline",
		TemplateID:      "tpl_offline_reference",
		TemplateVersion: "v1",
		State:           "OFFLINE",
	}, evidence, nil, nil)
	if err != nil {
		t.Fatalf("BuildProofBundleV1: %v", err)
	}
	id, err := VerifyProofBundleV1(proof)
	if err != nil {
		t.Fatalf("VerifyProofBundleV1: %v", err)
	}
	gotID, _ := ComputeProofID(proof)
	if id != gotID {
		t.Fatalf("verified proof_id mismatch: got=%s want=%s", id, gotID)
	}
}

func TestVerifyProofBundleV1_TamperFails(t *testing.T) {
	evidencePath, _ := settlementFixturePaths(t)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence fixture: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence fixture: %v", err)
	}
	proof, err := BuildProofBundleV1(ContractExportV1{
		ContractID:      "ctr_offline_reference",
		PrincipalID:     "prn_offline",
		TemplateID:      "tpl_offline_reference",
		TemplateVersion: "v1",
		State:           "OFFLINE",
	}, evidence, nil, nil)
	if err != nil {
		t.Fatalf("BuildProofBundleV1: %v", err)
	}
	proof.Bundle.Contract.ContractID = "ctr_tampered"
	if _, err := VerifyProofBundleV1(proof); err == nil {
		t.Fatal("expected tampered proof bundle verification to fail")
	}
}

func TestProofBundleV1_FixtureVector(t *testing.T) {
	b, err := os.ReadFile("../../../conformance/fixtures/agent-commerce-offline/proof_bundle_v1.json")
	if err != nil {
		t.Fatalf("read proof bundle fixture: %v", err)
	}
	idb, err := os.ReadFile("../../../conformance/fixtures/agent-commerce-offline/proof_bundle_v1.id")
	if err != nil {
		t.Fatalf("read proof bundle id fixture: %v", err)
	}
	expectedID := strings.TrimSpace(string(idb))
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal proof bundle fixture: %v", err)
	}
	proof, err := ParseProofBundleV1Strict(raw)
	if err != nil {
		t.Fatalf("ParseProofBundleV1Strict: %v", err)
	}
	gotID, err := VerifyProofBundleV1(proof)
	if err != nil {
		t.Fatalf("VerifyProofBundleV1: %v", err)
	}
	if gotID != expectedID {
		t.Fatalf("proof_id mismatch: got %s want %s", gotID, expectedID)
	}
}
