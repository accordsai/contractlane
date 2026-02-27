# Contract Lane Protocol v1.0.0 (Frozen)

This document is normative for protocol compatibility in this repository.

## Scope

Protocol v1.0.0 includes:

- `agent-id-v1`
- `sig-v1`
- `evidence-v1`
- `amount-v1`
- `delegation-v1`
- `delegation-revocation-v1`
- `rules-v1`
- `proof-bundle-v1`

Additive post-freeze surfaces implemented without changing v1 semantics:

- `sig-v2` (ES256 / P-256)
- `agent-id-v2` (P-256 identity encoding)

## Identifier Matrix (Authoritative)

These values are intentionally not all identical and must be treated as separate surfaces:

1. Capability discovery (`GET /cel/.well-known/contractlane`)
- `protocol.name = "contractlane"`
- `protocol.versions` contains `"v1"`

2. Settlement proof (`settlement-proof-v1`)
- `protocol = "contractlane"`
- `protocol_version = "v1"`

3. Proof bundle (`proof-bundle-v1`)
- `protocol = "contract-lane"`
- `protocol_version = "1"`

## Compatibility Rule

A node is Protocol v1 compatible only if it passes the repository conformance suite.
