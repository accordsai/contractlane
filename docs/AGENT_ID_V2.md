# AGENT_ID_V2

Canonical format:

`agent:v2:pk:p256:<base64url_no_padding_sec1_uncompressed_pubkey>`

Where:

- `p256` public key bytes are SEC1 uncompressed format: `0x04 || X(32) || Y(32)` (65 bytes total).
- Base64url uses RFC 4648 URL-safe alphabet with no padding.

## Rules

- Prefix and labels are lowercase and fixed.
- Segment count is exact: `agent`, `v2`, `pk`, `p256`, `<base64url>`.
- Decoded key must be exactly 65 bytes, first byte `0x04`, and represent a valid point on P-256.

## Rejection Conditions

- Wrong segment count or prefix.
- Unsupported algorithm.
- Invalid base64url alphabet or padding present (`=`).
- Wrong key length.
- Malformed/off-curve SEC1 key.
