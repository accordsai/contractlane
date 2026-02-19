# V1 API Spec (Locked)

## IAL
- POST /ial/principals
- GET  /ial/principals/{principal_id}
- POST /ial/actors/agents
- GET  /ial/actors?principal_id=&type=
- POST /ial/invites
- GET  /ial/invites/{invite_id}
- POST /ial/webauthn/register/start (stub)
- POST /ial/webauthn/register/finish (dev stub: invite_token "dev:<invite_id>")
- POST /ial/verify-signature (stub)
- PUT  /ial/actors/{actor_id}/policy-profile
- GET  /ial/actors/{actor_id}/policy-profile

## CEL
- GET  /cel/templates
- POST /cel/principals/{principal_id}/templates/{template_id}/enable
- GET  /cel/templates/{template_id}/governance
- POST /cel/contracts
- GET  /cel/contracts/{contract_id}
- GET  /cel/contracts
- POST /cel/contracts/{contract_id}/variables:bulkSet
- GET  /cel/contracts/{contract_id}/variables
- POST /cel/contracts/{contract_id}/variables:review
- POST /cel/contracts/{contract_id}:validate (stub)
- POST /cel/contracts/{contract_id}:render (stub)
- POST /cel/contracts/{contract_id}/actions/{action}  (KEY)
- POST /cel/contracts/{contract_id}/approvals:route
- GET  /cel/contracts/{contract_id}/approvals
- POST /cel/approvals/{approval_request_id}:decide
- POST /cel/contracts/{contract_id}/anchors
- GET  /cel/contracts/{contract_id}/anchors
- POST /cel/contracts/{contract_id}:sendForSignature (stub -> SIGNATURE_SENT)
- GET  /cel/contracts/{contract_id}/signature
- GET  /cel/contracts/{contract_id}/events
- GET  /cel/contracts/{contract_id}/evidence-bundle
- GET  /cel/contracts/{contract_id}/evidence

## Execution
- POST /exec/contracts/{contract_id}/sendForSignature
- POST /exec/webhooks/esign/{provider}
- POST /webhooks/{provider}/{endpoint_token}

## Approval Decide Payload (sig-v1 support)

`POST /cel/approvals/{approval_request_id}:decide` accepts the existing fields and additionally supports:

- `signature_envelope` (optional): `sig-v1` envelope object.

If `signature_envelope.context` is present, it must equal `"contract-action"`.

Legacy request shape remains supported.

## Evidence Artifacts

`GET /cel/contracts/{contract_id}/evidence` includes always-present artifacts:

- `webhook_receipts` (array)
- `anchors` (array)

## Anchors Endpoints

- `POST /cel/contracts/{contract_id}/anchors`
- `GET /cel/contracts/{contract_id}/anchors`

Anchor type notes:

- `dev_stub` is dev-mode gated.
- `rfc3161` is supported when configured/available.

## Webhook Ingestion Routing

Execution ingress endpoint:

- `POST /webhooks/{provider}/{endpoint_token}`

Routing is configured via `webhook_endpoints` records scoped by `(provider, endpoint_token)`, which map incoming webhook requests to a principal and verification secret.

## Stripe Webhook Setup (Execution)

To route Stripe webhooks to a principal, create a `webhook_endpoints` row with `provider='stripe'`, a unique `endpoint_token`, and a per-endpoint `secret`:

```sql
INSERT INTO webhook_endpoints (principal_id, provider, endpoint_token, secret)
VALUES ('11111111-1111-1111-1111-111111111111', 'stripe', 'stripe_dev_token_1', 'whsec_example_only');
```

Execution verifies Stripe signatures from the `Stripe-Signature` header using Stripe v1 semantics:
- header contains `t=<unix_ts>` and `v1=<hex_hmac>`
- signed payload is `t + "." + raw_body_bytes`
- HMAC-SHA256 is computed with the endpoint `secret`

Example webhook request shape (placeholder values only):

```bash
curl -X POST "http://localhost:8083/exec/webhooks/stripe/stripe_dev_token_1" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=1700000000,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  -d '{"id":"evt_example","type":"payment_intent.succeeded"}'
```
