# Offline Evidence Verification (Slice 10)

`pkg/evp` verifies a Contract Lane evidence bundle offline and fail-closed.

## API

```go
result, err := evp.VerifyBundleJSON(bundleBytes)
```

`result.Status` is one of:

- `VERIFIED`
- `INVALID_BUNDLE_HASH`
- `INVALID_MANIFEST_HASH`
- `INVALID_ARTIFACT_HASH`
- `INVALID_ORDERING`
- `UNSUPPORTED_DETERMINISM_VERSION`
- `MALFORMED_BUNDLE`

## Notes

- Verification is deterministic and offline only.
- Hashing semantics are shared from `pkg/evidencehash` to avoid drift from server logic.
- Current verifier supports `evidence-v1` and:
  - `manifest_hash_rule=canonical_json_sorted_keys_v1`
  - `bundle_hash_rule=concat_artifact_hashes_v1`
