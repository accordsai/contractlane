# Delegation v1 (Offline-First)

Delegation payload (closed schema):

```json
{
  "version": "delegation-v1",
  "delegation_id": "del_<ulid>",
  "issuer_agent": "agent:pk:ed25519:...",
  "subject_agent": "agent:pk:ed25519:...",
  "scopes": ["commerce:intent:sign", "commerce:accept:sign"],
  "constraints": {
    "contract_id": "*" ,
    "counterparty_agent": "*",
    "max_amount": { "currency": "USD", "amount": "250" },
    "valid_from": "RFC3339 UTC",
    "valid_until": "RFC3339 UTC",
    "max_uses": 1,
    "purpose": "*"
  },
  "nonce": "<base64url-no-padding>",
  "issued_at": "RFC3339 UTC"
}
```

Implemented scopes:
- `commerce:intent:sign`
- `commerce:accept:sign`

Reserved scopes:
- `cel:action:execute`
- `cel:approval:sign`
- `settlement:attest`

Evidence artifact:
- `artifacts.delegations`: array of
  - `{ "delegation": <delegation-v1>, "issuer_signature": <sig-v1> }`
  - sorted by `delegation.delegation_id` ascending.

Reserved revocation surface (not enforced in Slice 18):
- `artifacts.delegation_revocations` with entries:
  - `version: "delegation-revocation-v1"`
  - `revocation_id`
  - `delegation_id`
  - `issuer_agent`
  - `revoked_at` (RFC3339 UTC)
  - optional `reason`
- future signature binding context: `delegation-revocation`.
