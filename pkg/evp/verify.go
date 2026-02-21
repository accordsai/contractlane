package evp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/accordsai/contractlane/pkg/evidencehash"
)

func VerifyBundleJSON(bundleBytes []byte) (Result, error) {
	var bundle EvidenceBundleV1
	var rawRoot map[string]any
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "invalid_json"}}, nil
	}
	if err := json.Unmarshal(bundleBytes, &rawRoot); err != nil {
		return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "invalid_json"}}, nil
	}
	if strings.TrimSpace(bundle.BundleVersion) == "" ||
		strings.TrimSpace(bundle.Contract.ContractID) == "" ||
		strings.TrimSpace(bundle.Contract.PacketHash) == "" ||
		strings.TrimSpace(bundle.Hashes.BundleHash) == "" ||
		strings.TrimSpace(bundle.Hashes.ManifestHash) == "" ||
		bundle.Manifest.Artifacts == nil ||
		bundle.Artifacts == nil {
		return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "missing_required_fields"}}, nil
	}
	if bundle.BundleVersion != "evidence-v1" {
		return Result{Status: StatusUnsupportedDeterminismVersion, Details: map[string]any{"bundle_version": bundle.BundleVersion}}, nil
	}
	if bundle.Contract.DeterminismVersion != "evidence-v1" {
		return Result{Status: StatusUnsupportedDeterminismVersion, Details: map[string]any{"contract_determinism_version": bundle.Contract.DeterminismVersion}}, nil
	}
	if strings.TrimSpace(bundle.Manifest.Canonicalization.ManifestHashRule) == "" ||
		strings.TrimSpace(bundle.Manifest.Canonicalization.BundleHashRule) == "" {
		return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "missing_hash_rules"}}, nil
	}
	if bundle.Manifest.Canonicalization.ManifestHashRule != "canonical_json_sorted_keys_v1" ||
		bundle.Manifest.Canonicalization.BundleHashRule != "concat_artifact_hashes_v1" {
		return Result{
			Status: StatusUnsupportedDeterminismVersion,
			Details: map[string]any{
				"manifest_hash_rule": bundle.Manifest.Canonicalization.ManifestHashRule,
				"bundle_hash_rule":   bundle.Manifest.Canonicalization.BundleHashRule,
			},
		}, nil
	}

	seen := map[string]struct{}{}
	for i, item := range bundle.Manifest.Artifacts {
		artifactType := strings.TrimSpace(fmt.Sprint(item["artifact_type"]))
		artifactID := strings.TrimSpace(fmt.Sprint(item["artifact_id"]))
		if artifactType == "" || artifactID == "" {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "manifest_artifact_missing_fields", "index": i}}, nil
		}
		k := artifactType + "\x00" + artifactID
		if _, ok := seen[k]; ok {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "duplicate_manifest_artifact", "artifact_type": artifactType, "artifact_id": artifactID}}, nil
		}
		seen[k] = struct{}{}
		if i > 0 {
			prev := bundle.Manifest.Artifacts[i-1]
			prevType := strings.TrimSpace(fmt.Sprint(prev["artifact_type"]))
			prevID := strings.TrimSpace(fmt.Sprint(prev["artifact_id"]))
			if strings.Compare(prevType, artifactType) > 0 || (prevType == artifactType && strings.Compare(prevID, artifactID) > 0) {
				return Result{Status: StatusInvalidOrdering, Details: map[string]any{"index": i, "artifact_type": artifactType, "artifact_id": artifactID}}, nil
			}
		}
	}

	for _, item := range bundle.Manifest.Artifacts {
		artifactType := strings.TrimSpace(fmt.Sprint(item["artifact_type"]))
		artifactID := strings.TrimSpace(fmt.Sprint(item["artifact_id"]))
		expectedHex := strings.TrimSpace(fmt.Sprint(item["sha256"]))
		hashOf := strings.TrimSpace(fmt.Sprint(item["hash_of"]))
		hashRule := strings.TrimSpace(fmt.Sprint(item["hash_rule"]))
		if artifactType == "" || artifactID == "" || expectedHex == "" {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "manifest_artifact_missing_hash"}}, nil
		}
		if hashOf == "" || hashRule == "" {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "manifest_artifact_missing_hash_rule", "artifact_type": artifactType, "artifact_id": artifactID}}, nil
		}
		if _, ok := bundle.Artifacts[artifactType]; !ok {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "artifact_payload_missing", "artifact_type": artifactType, "artifact_id": artifactID}}, nil
		}
		target, ok := resolveHashTarget(rawRoot, hashOf)
		if !ok {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "artifact_hash_of_path_not_found", "artifact_type": artifactType, "artifact_id": artifactID, "hash_of": hashOf}}, nil
		}
		computedHex, err := computeByHashRule(hashRule, target)
		if err != nil {
			return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "artifact_hash_rule_invalid", "artifact_type": artifactType, "artifact_id": artifactID, "hash_rule": hashRule}}, nil
		}
		if computedHex != expectedHex {
			return Result{
				Status: StatusInvalidArtifactHash,
				Details: map[string]any{
					"artifact_type": artifactType,
					"artifact_id":   artifactID,
					"expected":      expectedHex,
					"computed":      computedHex,
				},
			}, nil
		}
	}

	manifestObj, ok := rawRoot["manifest"]
	if !ok {
		return Result{Status: StatusMalformedBundle, Details: map[string]any{"reason": "missing_manifest"}}, nil
	}
	computedManifestHex, _, err := evidencehash.CanonicalSHA256(manifestObj)
	if err != nil {
		return Result{}, err
	}
	expectedManifestHex := stripSHA256Prefix(bundle.Hashes.ManifestHash)
	if computedManifestHex != expectedManifestHex {
		return Result{
			Status: StatusInvalidManifestHash,
			Details: map[string]any{
				"expected": expectedManifestHex,
				"computed": computedManifestHex,
			},
		}, nil
	}

	computedBundleHex := evidencehash.ComputeBundleHashFromManifest(
		bundle.BundleVersion,
		bundle.Contract.ContractID,
		bundle.Contract.PacketHash,
		bundle.Manifest.Artifacts,
	)
	expectedBundleHex := stripSHA256Prefix(bundle.Hashes.BundleHash)
	if computedBundleHex != expectedBundleHex {
		return Result{
			Status: StatusInvalidBundleHash,
			Details: map[string]any{
				"expected": expectedBundleHex,
				"computed": computedBundleHex,
			},
		}, nil
	}

	return Result{Status: StatusVerified}, nil
}

func stripSHA256Prefix(v string) string {
	s := strings.TrimSpace(v)
	return strings.TrimPrefix(s, "sha256:")
}

func computeByHashRule(rule string, value any) (string, error) {
	switch rule {
	case "utf8_v1":
		s, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("utf8_v1 requires string")
		}
		return evidencehash.HashStringSHA256Hex(s), nil
	case "canonical_json_sorted_keys_v1":
		h, _, err := evidencehash.CanonicalSHA256(value)
		return h, err
	default:
		return "", fmt.Errorf("unsupported hash rule")
	}
}

func resolveHashTarget(root map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil, false
	}
	var current any = root
	for i := 0; i < len(parts); i++ {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := m[parts[i]]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}
