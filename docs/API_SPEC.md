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
- POST /cel/contracts/{contract_id}:sendForSignature (stub -> SIGNATURE_SENT)
- GET  /cel/contracts/{contract_id}/signature
- GET  /cel/contracts/{contract_id}/events
- GET  /cel/contracts/{contract_id}/evidence-bundle

## Execution
- POST /exec/contracts/{contract_id}/sendForSignature
- POST /exec/webhooks/esign/{provider}

