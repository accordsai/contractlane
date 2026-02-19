# CONFORMANCE

Conformance defines compatibility for protocol v1.0.0.

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
  - `signatures.algorithms` contains `"ed25519"`

## Summary Output

Runner emits a final JSON summary with:

- `protocol = "contractlane"`
- `protocol_version = "v1"`
