# Signature Envelope v1 (sig-v1)

## Purpose

`sig-v1` defines the frozen Ed25519 signature envelope for Contract Lane protocol messages.

It is used for approvals, delegations, settlement proofs, and any governed action requiring cryptographic attestation.

## Canonical Hashing

`payload_hash` is computed as:

`sha256(canonical_json(payload))`

Canonical JSON rules:

- Object keys are sorted lexicographically at every level.
- Array ordering is stable and deterministic (caller must provide deterministic array order).
- Encoding is UTF-8.
- Newline normalization uses `\n`.
- No insignificant whitespace.

These rules must align with Contract Lane evidence canonicalization philosophy.

## Envelope Schema

Envelope is a JSON object with these required fields:

- `version`: string, must equal `"sig-v1"`
- `algorithm`: string, must equal `"ed25519"`
- `public_key`: base64 encoded 32-byte Ed25519 public key
- `signature`: base64 encoded 64-byte Ed25519 signature
- `payload_hash`: lowercase hex SHA-256 of canonical payload bytes
- `issued_at`: RFC3339Nano UTC timestamp

Optional fields:

- `key_id`: string
- `context`: string

## Domain Separation

`context` is optional but strongly recommended for domain separation. Suggested values:

- `contract-action`
- `delegation-issuance`
- `settlement-proof`

## Verification Rules

Verification must fail closed:

1. Reject if `algorithm` is not `"ed25519"`.
2. Recompute canonical payload hash and reject if it does not equal `payload_hash`.
3. Verify signature bytes using `algorithm` + `public_key`; reject if invalid.
4. Reject if `issued_at` is missing or not valid RFC3339Nano UTC format.

## Algorithm

### `ed25519`

- `public_key`: base64, 32 bytes
- `signature`: base64, 64 bytes

## Backwards Compatibility

`sig-v1` remains unchanged for existing clients. P-256 is introduced additively via `sig-v2` (`docs/SIG_V2.md`).
