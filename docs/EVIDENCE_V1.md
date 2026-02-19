# EVIDENCE_V1

`evidence-v1` is the deterministic contract evidence export format.

## Core Fields

- `bundle_version = "evidence-v1"`
- `contract.determinism_version = "evidence-v1"`
- `hashes.manifest_hash = "sha256:<hex>"`
- `hashes.bundle_hash = "sha256:<hex>"`

## Canonicalization

Manifest canonicalization fields include:

- `manifest_hash_rule = "canonical_json_sorted_keys_v1"`
- `bundle_hash_rule = "concat_artifact_hashes_v1"`

Artifact hashing uses canonical JSON SHA-256 unless artifact-specific rule states otherwise.

## Determinism

- Stable artifact ordering is required.
- Bundle/hash results must be byte-stable for unchanged state.
- No protocol semantics depend on wall clock randomness.
