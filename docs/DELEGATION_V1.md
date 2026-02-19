# DELEGATION_V1

Delegation payload version:

- `version = "delegation-v1"`

Signed artifact entry:

```json
{
  "delegation": { "...": "delegation-v1 payload" },
  "issuer_signature": { "...": "sig-v1 with context=delegation" }
}
```

## Required Model

- `delegation_id`
- `issuer_agent`
- `subject_agent`
- `scopes` (non-empty, known values)
- `constraints` (closed schema)
- `nonce` (base64url, no padding)
- `issued_at` (UTC `Z`)

## Deterministic Failure Reasons

- `missing_delegation`
- `delegation_untrusted_issuer`
- `delegation_scope_missing`
- `delegation_constraints_failed`
- `delegation_signature_invalid`
- `delegation_expired`
- `delegation_amount_exceeded`
- `delegation_revoked`
