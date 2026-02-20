# Hosted Agent Journey (Public Deployment)

This is the fastest path for an agent integrator using a hosted Contract Lane provider.

Use this flow when you are **not** self-hosting CEL/IAL.

## Outcome

By the end of this flow you will:
- obtain `principal_id`, `actor_id`, and bearer token
- choose a template
- create a contract
- optionally apply contract-specific rules requirements
- submit action approvals with `sig-v1`
- fetch and verify `proof-bundle-v1` offline

## 1) Provision Identity (Public Signup)

Public signup endpoints:
- `POST /public/v1/signup/start`
- `POST /public/v1/signup/verify`
- `POST /public/v1/signup/complete`

After `complete`, you should have:
- `principal_id`
- `actor_id`
- one-time credential/token (store securely)

Use that token for all CEL calls:

`Authorization: Bearer <token>`

Important:
- In hosted mode, do not assume `/ial/*` is publicly exposed.
- Identity provisioning is provider-operated control plane.

## 2) Discover and Select a Template

List templates:
- `GET /cel/templates`

Inspect one template:
- `GET /cel/templates/{template_id}/governance`

Select template based on:
- contract type/jurisdiction
- required variables
- action gates (`FORCE_HUMAN`, `ALLOW_AUTOMATION`, `DEFER`)

See `docs/TEMPLATE_MODEL.md` for template scope.

## 3) Create Contract

Call:
- `POST /cel/contracts`

Payload shape:

```json
{
  "actor_context": {
    "principal_id": "11111111-1111-1111-1111-111111111111",
    "actor_id": "22222222-2222-2222-2222-222222222222",
    "actor_type": "AGENT"
  },
  "template_id": "tpl_nda_us_v1",
  "counterparty": {
    "name": "Buyer Inc",
    "email": "legal@buyer.example"
  },
  "initial_variables": {
    "effective_date": "2026-02-20"
  }
}
```

SDK wrappers:
- Go: `CreateContract(...)`
- Python: `create_contract(...)`
- TypeScript: `createContract(...)`

## 4) Set/Review Variables

Set variables:
- `POST /cel/contracts/{contract_id}/variables:bulkSet`

Read values + gate status:
- `GET /cel/contracts/{contract_id}/variables`

If review is required:
- `POST /cel/contracts/{contract_id}/variables:review`

Variables are immutable at and after `SIGNATURE_SENT`.

## 5) Contract-Level Rules (If Needed)

Use rules for per-contract conditions; do not treat rules as template edits.

Examples:
- require settlement status `PAID`
- require settlement amount `USD 49`
- permit transition `SIGNATURE_SENT -> EFFECTIVE` only when predicate is true

Hosted-mode application model (current implementation):
- There is no public endpoint in this flow for end-clients to submit `rules-v1` directly.
- Rules used by CEL transition validation are operator-managed policy input (for example deployment config).
- As an integrator, coordinate required rule policy with your provider, then verify resulting proof/evidence artifacts offline.

What agents should do:
1. Express your desired rule intent to provider/operator (for example paid settlement requirement).
2. Execute normal contract/action/approval flow.
3. Verify returned proof bundle with SDK helpers; validation includes rules checks when rules are present in proof data.

References:
- `docs/RULES_V1.md`
- `docs/TEMPLATE_MODEL.md`

## 6) Execute Action and Decide Approval (sig-v1)

Attempt action:
- `POST /cel/contracts/{contract_id}/actions/{action}`

If response is `BLOCKED` with `APPROVE_ACTION`, call:
- `POST /cel/approvals/{approval_request_id}:decide`

Provide:
- `signed_payload`
- `signature_envelope` (`sig-v1`, context `contract-action` when present)

Concrete request/response chain:

1. Attempt action:

```bash
curl -sS -X POST "$BASE_URL/cel/contracts/$CONTRACT_ID/actions/SEND_FOR_SIGNATURE" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: act-001" \
  -d '{
    "actor_context": {
      "principal_id": "'"$PRINCIPAL_ID"'",
      "actor_id": "'"$ACTOR_ID"'",
      "actor_type": "AGENT",
      "idempotency_key": "act-001"
    }
  }'
```

Typical blocked response:

```json
{
  "status": "BLOCKED",
  "action": "SEND_FOR_SIGNATURE",
  "next_step": {
    "type": "APPROVE_ACTION",
    "approval_request_id": "aprq_..."
  }
}
```

2. Submit approval decision:

`POST /cel/approvals/{approval_request_id}:decide`

```json
{
  "actor_context": {
    "principal_id": "11111111-1111-1111-1111-111111111111",
    "actor_id": "22222222-2222-2222-2222-222222222222",
    "actor_type": "AGENT"
  },
  "decision": "APPROVE",
  "signed_payload": {
    "contract_id": "ctr_...",
    "action": "SEND_FOR_SIGNATURE",
    "approval_request_id": "aprq_..."
  },
  "signature_envelope": {
    "version": "sig-v1",
    "algorithm": "ed25519",
    "public_key": "<base64>",
    "signature": "<base64>",
    "payload_hash": "<hex>",
    "issued_at": "2026-02-20T00:00:00Z",
    "context": "contract-action"
  }
}
```

Typical response:

```json
{
  "approval_request_id": "aprq_...",
  "status": "APPROVED"
}
```

3. Retry action:

`POST /cel/contracts/{contract_id}/actions/SEND_FOR_SIGNATURE`

Typical response:

```json
{
  "status": "DONE",
  "action": "SEND_FOR_SIGNATURE",
  "state": "SIGNATURE_SENT"
}
```

## 7) Fetch Proof and Verify Offline

Fetch:
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

Expected response:

```json
{
  "proof": { "...": "proof-bundle-v1 object" },
  "proof_id": "<sha256_hex(canonical_json(proof))>"
}
```

Verify with SDK helpers:
- Go: `ParseProofBundleV1Strict`, `ComputeProofID`, `VerifyProofBundleV1`
- Python: `compute_proof_id`, `verify_proof_bundle_v1`
- TypeScript: `computeProofId`, `verifyProofBundleV1`

Treat verification pass as the trust boundary.

## Minimal Endpoint Set for Hosted Integrators

- `POST /public/v1/signup/start`
- `POST /public/v1/signup/verify`
- `POST /public/v1/signup/complete`
- `GET /cel/templates`
- `GET /cel/templates/{template_id}/governance`
- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/variables:bulkSet`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`
