# Publish Checklist

## Versioning

- Protocol version remains `v1.0.0` unless protocol semantics changed.
- For control-plane additions only (like onboarding), do **not** bump protocol version.
- Update `CHANGELOG.md` with an unreleased section summarizing operational additions.

## Safety Checks

- Run full tests: `go test ./... -count=1`
- Run core smoke: `make smoke`
- Run onboarding smoke (if enabled): `make onboarding-smoke`
- Run conformance against CEL: `BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh`

## Docs Required Before Publish

- `README.md` includes onboarding overlay instructions
- `docs/API_SPEC.md` includes onboarding endpoint list
- `docs/DB_SCHEMA.md` references onboarding tables
- `docs/ONBOARDING_SERVICE.md` includes setup + agent usage + nginx route snippet

## Deployment

- Validate non-default secrets in `.env`
- Confirm onboarding env values:
  - `ONBOARDING_DATABASE_URL`
  - `ONBOARDING_IAL_BASE_URL`
  - `ONBOARDING_BOOTSTRAP_TOKEN`
  - `CONTRACTLANE_SHARED_NETWORK`
- Confirm IAL remains private; only CEL/onboarding are externally routed

## Cleanup

- Remove dead compose services/config not used by deployment mode
- Verify no accidental debug defaults are committed
- Confirm migration order and rollback files exist for new migrations
