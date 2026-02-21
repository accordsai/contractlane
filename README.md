# Contract Lane v1.0.0

Contract Lane Protocol v1.0.0 is frozen in this repository.

## Quickstart

```bash
make up-dev
make test
make smoke
BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh
```

## Production Demo (Docker)

```bash
# 1) Edit .env (at minimum: POSTGRES_PASSWORD, IAL_DELEGATION_HMAC_SECRET, EXEC_WEBHOOK_SECRET)
# 2) Start production stack
make up-prod
```
NOTE: to make this production safe you will need some kind of SSL termination, or an nginx reverse proxy in front of the service.
`make up-prod` will print warnings if default secrets are still present in `.env`.

## Specs

- `OPENCLAW.md`
- `docs/HOSTED_AGENT_JOURNEY.md` (hosted/public primary path)
- `docs/INTEGRATOR_START_HERE.md`
- `docs/TEMPLATE_MODEL.md`
- `docs/TEMPLATE_AUTHORING.md`
- `docs/TEMPLATE_LINT_ERRORS.md`
- `docs/PROTOCOL.md`
- `docs/SIG_V1.md`
- `docs/AGENT_ID_V1.md`
- `docs/EVIDENCE_V1.md`
- `docs/AMOUNT_V1.md`
- `docs/DELEGATION_V1.md`
- `docs/DELEGATION_REVOCATION_V1.md`
- `docs/RULES_V1.md`
- `docs/PROOF_BUNDLE_V1.md`
- `docs/CONFORMANCE.md`
- `docs/GUARANTEES.md`
- `docs/VERSIONING.md`
- `docs/RELEASE.md`

## Existing Service Docs

- `docs/API_SPEC.md`
- `docs/DESIGN.md`
- `docs/STATE_MACHINE.md`
- `docs/GATING.md`
- `docs/DB_SCHEMA.md`
- `docs/ONBOARDING_SERVICE.md`
- `docs/PUBLISH_CHECKLIST.md`

## Onboarding Control Plane

- New companion service: `services/onboarding` (default port `8084`)
- Purpose: org/project bootstrap, IAL principal provisioning, agent credential issuance
- Runs as an overlay stack alongside existing Contract Lane services using `docker-compose.onboarding.yml`
- Bring up with `make onboarding-up`, validate with `make onboarding-smoke`, tear down with `make onboarding-down`
- Overlay services attach to `${CONTRACTLANE_SHARED_NETWORK}` (default `contractlane_default`) so onboarding can reach existing `postgres` and `ial` hosts
- Public ingress recommendation: reverse-proxy `/onboarding/*` and `/public/*` to onboarding service; keep IAL private
