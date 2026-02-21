# Changelog

## Unreleased

- Added onboarding control-plane service (`services/onboarding`) in Go.
- Added onboarding overlay deployment (`docker-compose.onboarding.yml`) to run alongside existing Contract Lane services.
- Added onboarding migration `000017_onboarding_control_plane` with audit/idempotency/project/credential tables.
- Added onboarding operational docs and publish checklist.
- Go SDK standalone module tag corrected to `sdk/go/contractlane/v1.0.2` for `go get` consumption.

## v1.0.0

- Protocol frozen.
- Includes:
  - `agent-id-v1`
  - `sig-v1`
  - `amount-v1`
  - `evidence-v1`
  - `delegation-v1`
  - `delegation-revocation-v1`
  - `rules-v1`
  - `proof-bundle-v1`
- Conformance suite defines compatibility.
