# PROOF_BUNDLE_V1

Proof bundle schema version:

- `version = "proof-bundle-v1"`
- `protocol = "contract-lane"`
- `protocol_version = "1"`

## Endpoint

- `GET /cel/contracts/{id}/proof-bundle?format=json`

Response shape:

```json
{
  "proof": { "...": "proof-bundle-v1 object" },
  "proof_id": "<sha256_hex(canonical_json(proof))>"
}
```

## Hash Rule

`proof_id` is computed over canonical JSON of the `proof` object only (not the response wrapper).
