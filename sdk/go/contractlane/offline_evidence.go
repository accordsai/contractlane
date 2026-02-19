package contractlane

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"contractlane/pkg/evidencehash"
)

type SignedCommerceIntentV1 struct {
	Intent         CommerceIntentV1 `json:"intent"`
	BuyerSignature SigV1Envelope    `json:"buyer_signature"`
}

type SignedCommerceAcceptV1 struct {
	Accept          CommerceAcceptV1 `json:"accept"`
	SellerSignature SigV1Envelope    `json:"seller_signature"`
}

func BuildOfflineEvidenceBundle(artifacts map[string]any) ([]byte, error) {
	normalized, err := normalizeOfflineArtifacts(artifacts)
	if err != nil {
		return nil, err
	}

	packetHex, _, err := evidencehash.CanonicalSHA256(map[string]any{"artifacts": normalized})
	if err != nil {
		return nil, err
	}
	packetHash := "sha256:" + packetHex
	contractID := "ctr_offline_reference"

	artifactTypes := []string{"anchors", "commerce_accepts", "commerce_intents", "delegations", "settlement_attestations", "webhook_receipts"}
	artifactList := make([]map[string]any, 0, len(artifactTypes))
	for _, t := range artifactTypes {
		payload := normalized[t]
		sha, _, err := evidencehash.CanonicalSHA256(payload)
		if err != nil {
			return nil, err
		}
		artifactList = append(artifactList, map[string]any{
			"artifact_type": t,
			"artifact_id":   artifactIDForOfflineType(t),
			"content_type":  "application/json",
			"hash_of":       "artifacts." + t,
			"hash_rule":     "canonical_json_sorted_keys_v1",
			"sha256":        sha,
		})
	}

	sort.Slice(artifactList, func(i, j int) bool {
		ti := strings.TrimSpace(artifactList[i]["artifact_type"].(string))
		tj := strings.TrimSpace(artifactList[j]["artifact_type"].(string))
		if ti == tj {
			return artifactList[i]["artifact_id"].(string) < artifactList[j]["artifact_id"].(string)
		}
		return ti < tj
	})

	manifest := map[string]any{
		"canonicalization": map[string]any{
			"json":               "JCS-like sorted keys",
			"newlines":           "\\n",
			"encoding":           "utf-8",
			"bundle_v":           "evidence-v1",
			"manifest_hash_rule": "canonical_json_sorted_keys_v1",
			"bundle_hash_rule":   "concat_artifact_hashes_v1",
		},
		"artifacts": artifactList,
	}
	manifestHash, _, err := evidencehash.CanonicalSHA256(manifest)
	if err != nil {
		return nil, err
	}
	bundleHash := evidencehash.ComputeBundleHashFromManifest(
		"evidence-v1",
		contractID,
		packetHash,
		artifactList,
	)

	root := map[string]any{
		"bundle_version": "evidence-v1",
		"generated_at":   "2026-02-20T12:10:00Z",
		"principal_id":   "prn_offline",
		"request_id":     "req_offline_reference",
		"contract": map[string]any{
			"contract_id":         contractID,
			"state":               "OFFLINE",
			"template_id":         "tpl_offline_reference",
			"template_version":    "v1",
			"packet_hash":         packetHash,
			"diff_hash":           "sha256:" + evidencehash.HashStringSHA256Hex(packetHex+":diff"),
			"risk_hash":           "sha256:" + evidencehash.HashStringSHA256Hex(packetHex+":risk"),
			"determinism_version": "evidence-v1",
			"variables_hash":      evidencehash.HashStringSHA256Hex("{}"),
		},
		"hashes": map[string]any{
			"bundle_hash":   "sha256:" + bundleHash,
			"manifest_hash": "sha256:" + manifestHash,
		},
		"manifest":  manifest,
		"artifacts": normalized,
	}
	_, bytes, err := evidencehash.CanonicalSHA256(root)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func WriteOfflineEvidenceFiles(dir string, artifacts map[string]any) error {
	normalized, err := normalizeOfflineArtifacts(artifacts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	intentsBytes, err := canonicalJSONBytes(normalized["commerce_intents"])
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "commerce_intents.json"), intentsBytes, 0o644); err != nil {
		return err
	}

	acceptsBytes, err := canonicalJSONBytes(normalized["commerce_accepts"])
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "commerce_accepts.json"), acceptsBytes, 0o644); err != nil {
		return err
	}

	delegationsBytes, err := canonicalJSONBytes(normalized["delegations"])
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "delegations.json"), delegationsBytes, 0o644); err != nil {
		return err
	}

	evidenceBytes, err := BuildOfflineEvidenceBundle(normalized)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence.json"), evidenceBytes, 0o644); err != nil {
		return err
	}
	return nil
}

func normalizeOfflineArtifacts(in map[string]any) (map[string]any, error) {
	if in == nil {
		in = map[string]any{}
	}
	out := map[string]any{}

	intents, err := normalizeSignedIntents(in["commerce_intents"])
	if err != nil {
		return nil, err
	}
	sort.Slice(intents, func(i, j int) bool {
		return intents[i].Intent.IntentID < intents[j].Intent.IntentID
	})
	intentsPayload := make([]any, 0, len(intents))
	for _, it := range intents {
		if err := VerifyCommerceIntentV1(it.Intent, it.BuyerSignature); err != nil {
			return nil, err
		}
		intentsPayload = append(intentsPayload, map[string]any{
			"intent":          commerceIntentPayload(it.Intent),
			"buyer_signature": signatureEnvelopePayload(it.BuyerSignature),
		})
	}
	out["commerce_intents"] = intentsPayload

	accepts, err := normalizeSignedAccepts(in["commerce_accepts"])
	if err != nil {
		return nil, err
	}
	sort.Slice(accepts, func(i, j int) bool {
		return accepts[i].Accept.IntentHash < accepts[j].Accept.IntentHash
	})
	acceptsPayload := make([]any, 0, len(accepts))
	for _, ac := range accepts {
		if err := VerifyCommerceAcceptV1(ac.Accept, ac.SellerSignature); err != nil {
			return nil, err
		}
		acceptsPayload = append(acceptsPayload, map[string]any{
			"accept":           commerceAcceptPayload(ac.Accept),
			"seller_signature": signatureEnvelopePayload(ac.SellerSignature),
		})
	}
	out["commerce_accepts"] = acceptsPayload

	delegations, err := normalizeSignedDelegations(in["delegations"])
	if err != nil {
		return nil, err
	}
	sort.Slice(delegations, func(i, j int) bool {
		return delegations[i].Delegation.DelegationID < delegations[j].Delegation.DelegationID
	})
	delegationsPayload := make([]any, 0, len(delegations))
	for _, d := range delegations {
		n, err := normalizeDelegationV1(d.Delegation)
		if err != nil {
			return nil, err
		}
		if err := VerifyDelegationV1(n, d.IssuerSignature); err != nil {
			return nil, err
		}
		delegationsPayload = append(delegationsPayload, map[string]any{
			"delegation":       delegationPayloadMap(n),
			"issuer_signature": signatureEnvelopePayload(d.IssuerSignature),
		})
	}
	out["delegations"] = delegationsPayload

	anchors, err := normalizeAnyArray(in["anchors"])
	if err != nil {
		return nil, err
	}
	out["anchors"] = anchors

	webhooks, err := normalizeAnyArray(in["webhook_receipts"])
	if err != nil {
		return nil, err
	}
	out["webhook_receipts"] = webhooks

	attestations, err := DeriveSettlementAttestationsFromReceipts(webhooks)
	if err != nil {
		return nil, err
	}
	attestPayload := make([]any, 0, len(attestations))
	for _, att := range attestations {
		attestPayload = append(attestPayload, map[string]any{
			"version":            att.Version,
			"provider":           att.Provider,
			"provider_event_id":  att.ProviderEventID,
			"provider_object_id": att.ProviderObjectID,
			"contract_id":        att.ContractID,
			"intent_id":          att.IntentID,
			"intent_hash":        att.IntentHash,
			"status":             att.Status,
			"amount": map[string]any{
				"currency": att.Amount.Currency,
				"amount":   att.Amount.Amount,
			},
			"occurred_at": att.OccurredAt,
			"derived_from": map[string]any{
				"receipt_request_hash": att.DerivedFrom.ReceiptRequestHash,
			},
		})
	}
	out["settlement_attestations"] = attestPayload

	return out, nil
}

func signatureEnvelopePayload(sig SigV1Envelope) map[string]any {
	out := map[string]any{
		"version":      sig.Version,
		"algorithm":    sig.Algorithm,
		"public_key":   sig.PublicKey,
		"signature":    sig.Signature,
		"payload_hash": sig.PayloadHash,
		"issued_at":    sig.IssuedAt,
	}
	if strings.TrimSpace(sig.KeyID) != "" {
		out["key_id"] = sig.KeyID
	}
	if strings.TrimSpace(sig.Context) != "" {
		out["context"] = sig.Context
	}
	return out
}

func normalizeSignedIntents(v any) ([]SignedCommerceIntentV1, error) {
	if v == nil {
		return []SignedCommerceIntentV1{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []SignedCommerceIntentV1
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("commerce_intents must be an array of {intent,buyer_signature}")
	}
	return out, nil
}

func normalizeSignedAccepts(v any) ([]SignedCommerceAcceptV1, error) {
	if v == nil {
		return []SignedCommerceAcceptV1{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []SignedCommerceAcceptV1
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("commerce_accepts must be an array of {accept,seller_signature}")
	}
	return out, nil
}

func normalizeSignedDelegations(v any) ([]SignedDelegationV1, error) {
	if v == nil {
		return []SignedDelegationV1{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []SignedDelegationV1
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("delegations must be an array of {delegation,issuer_signature}")
	}
	return out, nil
}

func normalizeAnyArray(v any) ([]any, error) {
	if v == nil {
		return []any{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("artifact must be a JSON array")
	}
	return out, nil
}

func canonicalJSONBytes(v any) ([]byte, error) {
	_, b, err := evidencehash.CanonicalSHA256(v)
	return b, err
}

func artifactIDForOfflineType(artifactType string) string {
	switch artifactType {
	case "anchors":
		return "anchors.json"
	case "webhook_receipts":
		return "webhook_receipts.json"
	case "commerce_intents":
		return "commerce_intents.json"
	case "commerce_accepts":
		return "commerce_accepts.json"
	case "delegations":
		return "delegations.json"
	case "settlement_attestations":
		return "settlement_attestations.json"
	default:
		return artifactType + ".json"
	}
}
