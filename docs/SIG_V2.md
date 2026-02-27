# SIG_V2

`sig-v2` is the additive signature envelope version for ES256 (P-256 ECDSA).

## Envelope

Required fields:

- `version` = `"sig-v2"`
- `algorithm` = `"es256"`
- `public_key` = base64url (no padding) SEC1 uncompressed P-256 key (`0x04 || X(32) || Y(32)`), exactly 65 bytes
- `signature` = base64url (no padding) raw64 `r||s` (32-byte big-endian each), exactly 64 bytes
- `payload_hash` = lowercase hex SHA-256 (64 chars)
- `issued_at` = RFC3339/RFC3339Nano UTC with trailing `Z`

Optional:

- `key_id`
- `context`

## Signing Input

Like `sig-v1`, `sig-v2` signs the 32 decoded bytes of `payload_hash` (not raw payload bytes).

## Verification Rules

- Reject unknown/malformed keys.
- Reject non-UTC timestamps or non-`Z` format.
- Reject non-lowercase/invalid `payload_hash`.
- Reject malformed `public_key` (must be valid P-256 SEC1 uncompressed point).
- Reject malformed signatures (canonical raw64 required for emitters).

Compatibility note:

- API boundary verifiers may accept DER ECDSA signatures for input compatibility, but SDKs emit canonical raw64.
