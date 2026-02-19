package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	clsdk "contractlane/sdk/go/contractlane"
	"contractlane/services/cel/internal/store"
)

func TestParseEvidenceIncludeFlagsDefaultAll(t *testing.T) {
	got, err := parseEvidenceIncludeFlags("")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !(got.render && got.signatures && got.approvals && got.events && got.variables) {
		t.Fatalf("expected all include flags enabled by default")
	}
}

func TestParseEvidenceIncludeFlagsRejectsInvalid(t *testing.T) {
	if _, err := parseEvidenceIncludeFlags("render,unknown"); err == nil {
		t.Fatalf("expected invalid include error")
	}
}

func TestComputeBundleHashStable(t *testing.T) {
	artifacts := []map[string]any{
		{"artifact_id": "a", "sha256": "1"},
		{"artifact_id": "b", "sha256": "2"},
	}
	h1 := computeBundleHashFromManifest("evidence-v1", "ctr_1", "sha256:abc", artifacts)
	h2 := computeBundleHashFromManifest("evidence-v1", "ctr_1", "sha256:abc", artifacts)
	if h1 != h2 {
		t.Fatalf("expected stable bundle hash")
	}
}

func TestCanonicalSHA256DeterministicForMapOrder(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1}
	b := map[string]any{"a": 1, "b": 2}
	ha, _, err := canonicalSHA256(a)
	if err != nil {
		t.Fatalf("hash err: %v", err)
	}
	hb, _, err := canonicalSHA256(b)
	if err != nil {
		t.Fatalf("hash err: %v", err)
	}
	if ha != hb {
		t.Fatalf("expected equal hashes")
	}
}

func TestValidateEvidenceManifestCoverageOK(t *testing.T) {
	artifacts := map[string]any{
		"contract_record": map[string]any{"contract_id": "ctr_1"},
		"render":          map[string]any{"rendered": "hello"},
	}
	artifactList := []map[string]any{
		{
			"artifact_type": "contract_record",
			"hash_of":       "artifacts.contract_record",
			"hash_rule":     "canonical_json_sorted_keys_v1",
		},
		{
			"artifact_type": "render",
			"hash_of":       "artifacts.render.rendered",
			"hash_rule":     "utf8_v1",
		},
	}
	if err := validateEvidenceManifestCoverage(artifacts, artifactList); err != nil {
		t.Fatalf("expected coverage validation success, got err: %v", err)
	}
}

func TestValidateEvidenceManifestCoverageRejectsMissingDescriptor(t *testing.T) {
	artifacts := map[string]any{
		"contract_record": map[string]any{"contract_id": "ctr_1"},
		"render":          map[string]any{"rendered": "hello"},
	}
	artifactList := []map[string]any{
		{
			"artifact_type": "contract_record",
			"hash_of":       "artifacts.contract_record",
			"hash_rule":     "canonical_json_sorted_keys_v1",
		},
	}
	if err := validateEvidenceManifestCoverage(artifacts, artifactList); err == nil {
		t.Fatalf("expected missing descriptor validation error")
	}
}

func TestPerformRFC3161AnchorConfirmed(t *testing.T) {
	fixedToken := []byte("fixed-tsa-token")
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(fixedToken)
	}))
	defer tsa.Close()

	t.Setenv("RFC3161_TSA_ALLOWLIST", tsa.URL)
	status, proof, anchoredAt := performRFC3161Anchor(context.Background(), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]any{
		"tsa_url": tsa.URL,
	})
	if status != "CONFIRMED" {
		t.Fatalf("expected CONFIRMED status, got %s with proof=%v", status, proof)
	}
	if anchoredAt == nil {
		t.Fatalf("expected anchoredAt to be set")
	}
	if got := proof["timestamp_token_b64"]; got != base64.StdEncoding.EncodeToString(fixedToken) {
		t.Fatalf("unexpected timestamp token proof value %v", got)
	}
}

func TestPerformRFC3161AnchorFailedDeterministicCode(t *testing.T) {
	_ = os.Unsetenv("RFC3161_TSA_URL")
	_ = os.Unsetenv("RFC3161_TSA_ALLOWLIST")
	status, proof, anchoredAt := performRFC3161Anchor(context.Background(), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]any{})
	if status != "FAILED" {
		t.Fatalf("expected FAILED status, got %s", status)
	}
	if anchoredAt != nil {
		t.Fatalf("expected nil anchoredAt for failed anchor")
	}
	if got := proof["error_code"]; got != "TSA_URL_REQUIRED" {
		t.Fatalf("expected TSA_URL_REQUIRED error_code, got %v", got)
	}
}

func TestProofRequirementsForContractMatchesPolicy(t *testing.T) {
	c := store.Contract{RiskLevel: "HIGH"}
	req := proofRequirementsForContract(c)
	if req["authorization_required"] != true {
		t.Fatalf("expected authorization_required=true for HIGH risk")
	}
	scopes, ok := req["required_scopes"].(map[string]any)
	if !ok {
		t.Fatalf("required_scopes missing")
	}
	if scopes["commerce_intent"] != clsdk.DelegationScopeCommerceIntentSign {
		t.Fatalf("unexpected commerce_intent scope: %v", scopes["commerce_intent"])
	}
	if scopes["commerce_accept"] != clsdk.DelegationScopeCommerceAcceptSign {
		t.Fatalf("unexpected commerce_accept scope: %v", scopes["commerce_accept"])
	}
	if req["settlement_required_status"] != "PAID" {
		t.Fatalf("unexpected settlement_required_status: %v", req["settlement_required_status"])
	}
}

func TestContractSnapshotForProofExcludesTimestamps(t *testing.T) {
	c := store.Contract{
		ContractID:      "ctr_1",
		State:           "EFFECTIVE",
		TemplateID:      "tpl_1",
		TemplateVersion: stringPtr("v1"),
	}
	snap := contractSnapshotForProof(c)
	if _, ok := snap["created_at"]; ok {
		t.Fatalf("contract snapshot must not include created_at")
	}
	if _, ok := snap["generated_at"]; ok {
		t.Fatalf("contract snapshot must not include generated_at")
	}
	if snap["contract_id"] != "ctr_1" || snap["state"] != "EFFECTIVE" {
		t.Fatalf("unexpected snapshot payload: %+v", snap)
	}
}

func TestBuildContractProofBundleEmbedsEvidenceUnchanged(t *testing.T) {
	evidence := map[string]any{
		"bundle_version": "evidence-v1",
		"hashes": map[string]any{
			"manifest_hash": "sha256:abc",
			"bundle_hash":   "sha256:def",
		},
		"artifacts": map[string]any{
			"anchors":          []any{},
			"webhook_receipts": []any{},
		},
	}
	proof, err := clsdk.BuildContractProofBundle(
		map[string]any{"contract_id": "ctr_1", "state": "EFFECTIVE"},
		evidence,
		proofRequirementsForContract(store.Contract{RiskLevel: "HIGH"}),
	)
	if err != nil {
		t.Fatalf("BuildContractProofBundle: %v", err)
	}
	gotEvidence, ok := proof["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("proof missing evidence object")
	}
	if !reflect.DeepEqual(gotEvidence, evidence) {
		gb, _ := json.Marshal(gotEvidence)
		eb, _ := json.Marshal(evidence)
		t.Fatalf("embedded evidence changed\n got=%s\nwant=%s", gb, eb)
	}
	req, ok := proof["requirements"].(map[string]any)
	if !ok {
		t.Fatalf("proof missing requirements object")
	}
	if req["evidence_manifest_hash"] != "sha256:abc" || req["evidence_bundle_hash"] != "sha256:def" {
		t.Fatalf("unexpected evidence hash binding in requirements: %+v", req)
	}
}

func stringPtr(s string) *string { return &s }
