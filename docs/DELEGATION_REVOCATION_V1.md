# DELEGATION_REVOCATION_V1

Revocation payload version:

- `version = "delegation-revocation-v1"`

Signed artifact entry:

```json
{
  "revocation": { "...": "delegation-revocation-v1 payload" },
  "issuer_signature": { "...": "sig-v1 with context=delegation-revocation" }
}
```

## Required Fields

- `revocation_id`
- `delegation_id`
- `issuer_agent`
- `nonce` (base64url, no padding)
- `issued_at` (UTC `Z`)

Optional:

- `reason`

## v1 Enforcement

Any valid revocation for a delegation invalidates it. v1 does not use revocation ordering semantics.
