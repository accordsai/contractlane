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

`make up-prod` will print warnings if default secrets are still present in `.env`.

## Specs

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
