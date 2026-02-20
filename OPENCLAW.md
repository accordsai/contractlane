# Contract Lane Catalog Metadata

This document provides catalog-friendly metadata for OpenClaw/Moltbook style discovery.

## Identity

- `name`: `Contract Lane`
- `protocol`: `contractlane`
- `protocol_version`: `v1`
- `status`: `v1.0.0 frozen`

## Discovery

- Runtime discovery endpoint: `GET /cel/.well-known/contractlane`
- Canonical integrator doc: `docs/INTEGRATOR_START_HERE.md`

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
