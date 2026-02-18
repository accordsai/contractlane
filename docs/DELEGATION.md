# Delegation V1 (Slice 11)

Delegation enables a human actor to grant scoped authority to an agent actor within the same principal.

## Model

`delegation_records` stores append-only delegation grants with optional expiration and revocation timestamp.

Scope:
- `actions`: supported values are `contract.execute` and `gate.resolve`
- `templates`: optional allowlist of template IDs
- `max_risk_level`: optional `LOW|MEDIUM|HIGH`

Signature:
- `algorithm`: `HMAC-SHA256`
- `signed_payload_hash`: `sha256:<hex>` over canonical JSON payload
- `signature_bytes`: base64 HMAC over `signed_payload_hash`

## IAL APIs

- `POST /ial/delegations`
- `POST /ial/delegations/{delegation_id}/revoke`

Both require bearer auth. Principal is derived from bearer identity and cannot cross principal boundaries.

## CEL Authorization

For AGENT calls:
1. direct scope check applies first
2. if denied, active delegations are evaluated for equivalent capability

Delegation never changes contract transitions; it only allows/denies the actor for an action.

## Evidence

CEL evidence bundle now includes:
- artifact type: `delegation_records`
- artifact id: `delegations:active`

This artifact is hashed and listed in manifest like all others, so offline verification remains self-contained.

## Signature Payload Shapes

Create (`POST /ial/delegations`) signs this canonical payload:

```json
{
  "principal_id": "<principal_id>",
  "delegator_actor_id": "<human_actor_id>",
  "delegate_actor_id": "<agent_actor_id>",
  "scope": { "actions": ["contract.execute"], "templates": ["tpl_x"], "max_risk_level": "LOW" },
  "expires_at": "<RFC3339 or null>",
  "delegation_version": "delegation-v1"
}
```

Revoke (`POST /ial/delegations/{id}/revoke`) signs this canonical payload:

```json
{
  "principal_id": "<principal_id>",
  "delegation_id": "<delegation_id>",
  "delegator_actor_id": "<human_actor_id>",
  "delegate_actor_id": "<agent_actor_id>",
  "revoked_at": "<RFC3339>",
  "delegation_version": "delegation-v1"
}
```

Signature derivation:
- `signed_payload_hash = "sha256:" + sha256(json.Marshal(payload))`
- `signature_bytes = base64(HMAC_SHA256(secret, signed_payload_hash))`
- `algorithm = "HMAC-SHA256"`
- `secret = IAL_DELEGATION_HMAC_SECRET` (default `dev_delegation_secret`)

## End-to-End Test

Run the delegated authorization proof:

```bash
bash scripts/test_slice11_delegation.sh
```

Defaults:
- `CEL_URL=http://localhost:8082`
- `IAL_URL=http://localhost:8081`

The script verifies:
1. agent denied on CEL action
2. delegation created in IAL
3. same agent allowed
4. delegation revoked
5. same agent denied again
