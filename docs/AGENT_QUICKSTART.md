# Agent Quickstart

This quickstart is the shortest practical path for an agent integrator.

For hosted/public deployments, use `docs/HOSTED_AGENT_JOURNEY.md` as the primary entrypoint.

## Install an SDK

Go:

`go get github.com/accordsai/contractlane/sdk/go/contractlane@v1.0.0`

Python:

`pip install contractlane==1.0.0`

TypeScript:

`npm install @contractlane/sdk`

## Prerequisites

- A running Contract Lane node.
- An agent signing key (`ed25519` recommended).
- API access token/scopes for the target deployment.
- Hosted mode: obtain `principal_id` + `actor_id` + token from your provider onboarding flow (do not assume public `/ial/*` access).

## 1) Create a Contract

Call:

`POST /cel/contracts`

Store returned `contract_id`.

SDK wrappers:

- Go: `CreateContract(...)`
- Python: `create_contract(...)`
- TypeScript: `createContract(...)`

## 2) Populate Variables

Call:

`POST /cel/contracts/{contract_id}/variables:bulkSet`

## 3) Execute Contract Action

Call:

`POST /cel/contracts/{contract_id}/actions/{action}`

If the response indicates approval is required, proceed to step 4.

## 4) Decide Approval (sig-v1)

Call:

`POST /cel/approvals/{approval_request_id}:decide`

Include:

- `signed_payload`
- `signature_envelope` (`sig-v1`, context `contract-action` when present)

## 5) Fetch Evidence / Proof

- `GET /cel/contracts/{contract_id}/evidence?format=json`
- `GET /cel/contracts/{contract_id}/proof?format=json`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

For proof bundle:

- `proof_id = sha256_hex(canonical_json(proof))`

## 6) Verify Offline

- Verify evidence with EVP.
- Verify proof/proof-bundle with SDK verifier helpers.

For exact hosted request/response examples (signup -> template -> contract -> action/approval -> proof verify), use:

- `docs/HOSTED_AGENT_JOURNEY.md`

## Optional Operator Path: Template Admin via SDK

If you are operating a hosted node (admin path), SDKs now expose template authoring wrappers for:

- create/update/publish/archive/clone templates
- list templates with admin filters
- add/remove PRIVATE template shares for principal access

Use deterministic idempotency keys on mutating calls and handle `422 TEMPLATE_LINT_FAILED` by surfacing `error.details[]` to the authoring UI/logs.

Full authoring lifecycle and lint catalog:

- `docs/TEMPLATE_AUTHORING.md`
- `docs/TEMPLATE_LINT_ERRORS.md`

## Optional Hosted Commerce

- `POST /commerce/intents` (context `commerce-intent`)
- `POST /commerce/accepts` (context `commerce-accept`)

## Protocol Identifier Note

The following identifiers are intentionally different by surface:

- Capability discovery: `protocol.name="contractlane"`, version `v1`
- Settlement proof: `protocol="contractlane"`, version `v1`
- Proof bundle: `protocol="contract-lane"`, version `1`

Use `docs/PROTOCOL.md` as the authoritative source.

Template scope and policy layering are documented in `docs/TEMPLATE_MODEL.md`.

If you are an operator adding/editing templates (not typical end-client flow):

- `docs/TEMPLATE_AUTHORING.md`
- `docs/TEMPLATE_LINT_ERRORS.md`
