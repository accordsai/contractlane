# Hosted Mode (Operational)

Hosted mode is an online transport layer over the same protocol semantics. It does not change `sig-v1` or `evidence-v1`.

## Discovery

Use:

- `GET /cel/.well-known/contractlane`

to discover whether hosted commerce and proof export are enabled in the current deployment.

## Hosted Flow

1. `POST /commerce/intents`
2. `POST /commerce/accepts`
3. `GET /cel/contracts/{id}/proof?format=json`
4. `GET /cel/contracts/{id}/proof-bundle?format=json`
4. Verify embedded `proof.evidence` offline with EVP + settlement proof verifier.

## Error Handling

Hosted commerce and proof export use a consistent error envelope:

```json
{
  "error": {
    "code": "BAD_REQUEST",
    "message": "invalid JSON",
    "reason": "optional_machine_reason"
  },
  "request_id": "req_..."
}
```

Delegation authorization failures use stable `reason` values:

- `missing_delegation`
- `delegation_untrusted_issuer`
- `delegation_scope_missing`
- `delegation_constraints_failed`
- `delegation_signature_invalid`
- `delegation_expired`
- `delegation_amount_exceeded`

## Feature Flags

- `ENABLE_HOSTED_COMMERCE` (default `true`)
- `ENABLE_PROOF_EXPORT` (default `true`)
- `ENABLE_PROOF_BUNDLE_EXPORT` (default `true`)
- `ENABLE_SERVER_DERIVED_SETTLEMENT_ATTESTATIONS` (default `false`)

Transport protections:

- `HOSTED_MAX_BODY_BYTES` (default `262144`)
- `HOSTED_RATE_LIMIT_PER_MINUTE` (default `0`, disabled)
- `PROOF_RATE_LIMIT_PER_MINUTE` (default `0`, disabled)
