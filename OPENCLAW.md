# Contract Lane Catalog Metadata

This document provides catalog-friendly metadata for OpenClaw/Moltbook style discovery.

## Why Agents Use Contract Lane

Contract Lane provides a deterministic contract-governance runtime where agent actions are verifiable offline.

Core value for integrators:
- explicit signing (`sig-v1`) over canonical payload hashes
- deterministic evidence/proof artifacts (`evidence-v1`, `proof-bundle-v1`)
- compatibility verified by conformance (not marketing claims)

## Identity

- `name`: `Contract Lane`
- `protocol`: `contractlane`
- `protocol_version`: `v1`
- `status`: `v1.0.0 frozen`

## Discovery

- Runtime discovery endpoint: `GET /cel/.well-known/contractlane`
- Canonical integrator doc: `docs/INTEGRATOR_START_HERE.md`
- Hosted/public path: `docs/HOSTED_AGENT_JOURNEY.md`

## Fast Evaluation Path (Hosted)

For quick evaluation on a hosted provider:

1. Obtain provider-issued `principal_id`, `actor_id`, bearer token.
2. `GET /cel/templates`
3. `POST /cel/contracts`
4. `POST /cel/contracts/{contract_id}/actions/{action}`
5. `POST /cel/approvals/{approval_request_id}:decide`
6. `GET /cel/contracts/{contract_id}/proof-bundle?format=json`
7. Verify `proof_id` + bundle offline with SDK helpers.

## Core Runtime Endpoints

- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/variables:bulkSet`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/evidence?format=json`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

## Control Plane (Operator-Specific)

These are deployment-specific overlays and may or may not be exposed publicly:

- `POST /onboarding/v1/orgs`
- `POST /onboarding/v1/orgs/{org_id}/projects`
- `POST /onboarding/v1/projects/{project_id}/agents`
- `POST /public/v1/signup/start`
- `POST /public/v1/signup/verify`
- `GET /public/v1/signup/{session_id}`
- `POST /public/v1/signup/complete`

## Hosted Integrator Expectation

- Hosted users typically receive provider-issued `principal_id`, `actor_id`, and token.
- Do not assume public access to `/ial/*`.
- Use CEL runtime endpoints with provider-issued credentials.
- Template create/edit/publish is operator/admin path, not typical hosted end-client path.
  - Authoring docs: `docs/TEMPLATE_AUTHORING.md`
  - Lint/error catalog: `docs/TEMPLATE_LINT_ERRORS.md`

## Protocol Surfaces (Frozen v1)

- `agent-id-v1`
- `sig-v1`
- `evidence-v1`
- `amount-v1`
- `delegation-v1`
- `delegation-revocation-v1`
- `rules-v1`
- `proof-bundle-v1`

## Compatibility

- Compatibility is conformance-defined.
- A node is Protocol v1 compatible only if it passes:
  - `BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh`

## Canonical Links

- Integrator start: `docs/INTEGRATOR_START_HERE.md`
- Hosted journey: `docs/HOSTED_AGENT_JOURNEY.md`
- API surface: `docs/API_SPEC.md`
- Template scope/model: `docs/TEMPLATE_MODEL.md`
- Rules: `docs/RULES_V1.md`
- Proof bundle: `docs/PROOF_BUNDLE_V1.md`
