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

