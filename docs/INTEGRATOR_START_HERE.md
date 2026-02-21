# Integrator Start Here

This is the canonical onboarding page for external agent integrators.

## Choose Your Path

Most users should start here:

- Hosted/public deployment: `docs/HOSTED_AGENT_JOURNEY.md`

If you are running your own infrastructure:

- Self-hosted/operator path: continue below and see `docs/ONBOARDING_SERVICE.md`

## Read In This Order

1. `docs/PROTOCOL.md` (authoritative identifiers and compatibility rule)
2. `docs/API_SPEC.md` (locked route surface)
3. `docs/HOSTED_AGENT_JOURNEY.md` (hosted end-to-end flow)
4. `docs/TEMPLATE_MODEL.md` (template scope: deployment/principal/actor/contract)
5. `docs/RULES_V1.md` (per-contract validation requirements)
6. `docs/SIG_V1.md` and `docs/AGENT_ID_V1.md`
7. `docs/EVIDENCE_V1.md` and `docs/PROOF_BUNDLE_V1.md`
8. `docs/CONFORMANCE.md`

## Non-Negotiable v1 Rules

- Canonical JSON hashing must match protocol definitions exactly.
- `sig-v1` signs decoded payload-hash bytes, not raw payload JSON bytes.
- `evidence-v1` hash semantics are fixed.
- `proof-bundle-v1` ID is computed over `proof` object only:
  - `proof_id = sha256_hex(canonical_json(proof))`

## Minimum Endpoints Most Integrators Use

Hosted/public canonical flow:

- `docs/HOSTED_AGENT_JOURNEY.md`

- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/variables:bulkSet`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/evidence?format=json`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

## Identity Provisioning (Hosted vs Self-Hosted)

Hosted deployment (most integrators):

- Use provider-issued credentials and IDs (`principal_id`, `actor_id`, token).
- Call CEL endpoints directly.
- Do not assume `/ial/*` endpoints are publicly exposed.
- Credentials may be issued via onboarding control plane (`docs/ONBOARDING_SERVICE.md`).
- Capability discovery at `/cel/.well-known/contractlane` does not currently enumerate onboarding/public-signup endpoints; treat those as provider-specific control-plane surfaces.

Self-hosted deployment:

- You may expose and use IAL routes (for example `POST /ial/principals`, `POST /ial/actors/agents`).
- If IAL is on a separate host, configure SDK/app `CONTRACTLANE_IAL_BASE_URL` accordingly.

Template authoring note:

- Authoring is an admin/operator path (`docs/TEMPLATE_AUTHORING.md`).
- Agent integrators typically consume published templates via `GET /cel/templates`.
- Template authoring lint failures are documented in `docs/TEMPLATE_LINT_ERRORS.md`.

## Discovery Map (Hosted Integrators)

Use this map if your goal is "connect to public provider, create contracts, sign, verify":

1. Identity + token provisioning: `docs/HOSTED_AGENT_JOURNEY.md` section "Provision Identity".
2. Template discovery and selection: `docs/HOSTED_AGENT_JOURNEY.md` section "Discover and Select a Template".
3. Contract create + variables + actions + approvals: `docs/HOSTED_AGENT_JOURNEY.md` sections 3-6.
4. Proof verification boundary: `docs/HOSTED_AGENT_JOURNEY.md` section "Fetch Proof and Verify Offline".
5. If you also operate templates: `docs/TEMPLATE_AUTHORING.md` + `docs/TEMPLATE_LINT_ERRORS.md`.

## Agent Identity + Signature Contexts

- Agent IDs: `agent:pk:ed25519:<base64url_no_padding_32_byte_pubkey>`
- Common contexts:
  - `contract-action`
  - `commerce-intent`
  - `commerce-accept`
  - `delegation`
  - `delegation-revocation`

## Compatibility Gate

A node is protocol-compatible only if it passes repository conformance.

Run:

`BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh`

## OpenClaw Listing Blurb

Contract Lane is a deterministic contract-governance and proof protocol for agents.
It exposes verifiable `evidence-v1` and `proof-bundle-v1` artifacts, uses `sig-v1`
for signed actions, and supports offline verification.

Compatibility identifiers:

- Capability discovery: `protocol.name="contractlane"`, `protocol.versions` includes `v1`
- Proof bundle: `version="proof-bundle-v1"`, `protocol="contract-lane"`, `protocol_version="1"`

Common integration endpoints:

- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/evidence?format=json`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

For catalog metadata and hosted-evaluation summary, see:
- `OPENCLAW.md`
