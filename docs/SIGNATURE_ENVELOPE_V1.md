# Signature Envelope v1 (sig-v1)

## Purpose

`sig-v1` defines an algorithm-neutral signature envelope for Contract Lane protocol messages.

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
- `algorithm`: string, algorithm registry identifier
- `public_key`: string, encoding depends on `algorithm`
- `signature`: string, encoding depends on `algorithm`
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

1. Reject unsupported `algorithm`.
2. Recompute canonical payload hash and reject if it does not equal `payload_hash`.
3. Verify signature bytes using `algorithm` + `public_key`; reject if invalid.
4. Reject if `issued_at` is missing or not valid RFC3339Nano UTC format.

## Algorithm Registry (Initial)

### `ed25519`

- `public_key`: base64, 32 bytes
- `signature`: base64, 64 bytes

### `secp256k1`

- `public_key`: hex, 33-byte compressed key
- `signature`: base64

### `rsa-pss-sha256`

- `public_key`: base64 DER SPKI
- `signature`: base64

## Backwards Compatibility

Existing internal signature formats may continue to be accepted by implementation-specific paths, but protocol v1 signing going forward is `sig-v1`.
