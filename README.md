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
