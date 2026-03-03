# Changelog

## Unreleased

- Added additive `sig-v2` (ES256/P-256) support while preserving frozen `sig-v1` Ed25519 semantics.
- Added additive `agent-id-v2` support for P-256 public key identities.
- Added capability discovery/conformance coverage for mixed signature environments (`sig-v1` + `sig-v2`).
- Added additive `sig-v3` (`webauthn-es256`) support for approval decisions (`contract-action` context).
- Added IAL WebAuthn credential registration/assertion challenge endpoints and `verify-signature` `sig-v3-webauthn` path.
- Added conformance coverage for `sig-v3` happy-path and rejection cases (replay/origin/actor binding).
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
