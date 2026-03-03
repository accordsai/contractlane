# CONFORMANCE

Conformance defines compatibility for protocol v1.0.0.

Control-plane onboarding/public-signup endpoints are operational overlays and are not part of protocol conformance compatibility.

## Run

```bash
BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh
```

## Required Compatibility Signals

- Capability discovery at `/cel/.well-known/contractlane`:
  - `protocol.name = "contractlane"`
  - `protocol.versions` contains `"v1"`
  - `evidence.bundle_versions` contains `"evidence-v1"`
  - `signatures.envelopes` contains `"sig-v1"`
  - `signatures.envelopes` contains `"sig-v2"`
  - `signatures.envelopes` contains `"sig-v3"`
  - `signatures.algorithms` contains `"ed25519"`
  - `signatures.algorithms` contains `"es256"`
  - `signatures.algorithms` contains `"webauthn-es256"`

## Summary Output

Runner emits a final JSON summary with:

- `protocol = "contractlane"`
- `protocol_version = "v1"`

Current suite includes signature coverage for:

- `sig-v1` approval happy path
- `sig-v2` approval happy/negative paths
- `sig-v3` approval happy path plus replay/origin/actor-binding rejection cases
