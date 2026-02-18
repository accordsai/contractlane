# Contract Lane (V1) — Headless Backend MVP (Go microservices)

This repository is generated from a **locked V1 specification** (domain model, gating rules, API routes + JSON, DB schema, docker topology).
It is intentionally **headless** (no UI) in this phase.

## Quickstart (dev)
Prereqs: Docker + Docker Compose.

```bash
make up-dev
make migrate
make test
make smoke
```

## Local Dev Token + Terms Program Seed (IAL bootstrap)
CEL endpoints use bearer auth. For local-only usage, enable the dev bootstrap endpoint in IAL.

```bash
IAL_DEV_BOOTSTRAP=true make up
eval "$(scripts/dev_seed.sh)"
```

This exports:
- `TOKEN` (bearer token)
- `PRINCIPAL_ID`
- `ACTOR_ID`
- `GATE_STATUS` (`DONE` or `BLOCKED`)

Example: create/publish a gate program, resolve, then render

```bash
curl -sS -X POST http://localhost:8082/cel/dev/seed-template \
  -H 'content-type: application/json' \
  -d "{\"principal_id\":\"$PRINCIPAL_ID\"}" >/dev/null

curl -sS -X POST http://localhost:8082/cel/programs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRINCIPAL_ID\",\"actor_id\":\"$ACTOR_ID\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"dev-prog-create-1\"},\"key\":\"terms_current\",\"mode\":\"STRICT_RECONSENT\"}" >/dev/null

curl -sS -X POST http://localhost:8082/cel/programs/terms_current/publish \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRINCIPAL_ID\",\"actor_id\":\"$ACTOR_ID\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"dev-prog-publish-1\"},\"required_template_id\":\"tpl_nda_us_v1\",\"required_template_version\":\"v1\"}" >/dev/null

CID="$(curl -sS -X POST http://localhost:8082/cel/gates/terms_current/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"external_subject_id":"dev-user-1","actor_type":"HUMAN","idempotency_key":"dev-resolve-1"}' | jq -r '.contract_id')"

curl -sS "http://localhost:8082/cel/contracts/$CID/render?format=text&locale=en-US" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## SDK Tests (Local Only)
Run SDK correctness checks locally against a real docker-compose stack.

```bash
make up
make sdk-test
make down
```

Run shared conformance checks:

```bash
make up
make sdk-conformance
make down
```

Notes:
- `sdk-test` runs Go, TypeScript, and Python SDK suites.
- TypeScript uses `npm ci` + build before tests.
- Python uses `python3` explicitly.
- Integration tests target `CL_BASE_URL` (default `http://localhost:8080`).

## Services
- `services/ial` — Identity & Authority Layer
- `services/cel` — Contract Execution Layer
- `services/execution` — Connector/worker layer (stubbed in V1)

## Spec (Codex should read these first)
- `AGENTS.md`
- `docs/DESIGN.md`
- `docs/API_SPEC.md`
- `docs/STATE_MACHINE.md`
- `docs/GATING.md`
- `docs/DB_SCHEMA.md`
- `docs/DELEGATION.md`
