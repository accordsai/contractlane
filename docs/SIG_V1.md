# SIG_V1

`sig-v1` is the protocol signature envelope.

## Envelope

Required fields:

- `version` = `"sig-v1"`
- `algorithm` (v1 requires `ed25519` for conformance)
- `public_key` (base64, 32 bytes for ed25519)
- `signature` (base64, 64 bytes for ed25519)
- `payload_hash` (lowercase hex SHA-256, 64 chars)
- `issued_at` (RFC3339/RFC3339Nano UTC with trailing `Z`)

Optional:

- `key_id`
- `context`

## Signing Input

`sig-v1` signs the 32 decoded bytes of `payload_hash` (not raw payload bytes).

## Contexts Used in v1

- `contract-action`
- `commerce-intent`
- `commerce-accept`
- `delegation`
- `delegation-revocation`
