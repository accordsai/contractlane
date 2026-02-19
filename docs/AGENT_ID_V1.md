# AGENT_ID_V1

Canonical format:

`agent:pk:ed25519:<base64url_no_padding_32_byte_pubkey>`

## Rules

- Prefix and labels are lowercase and fixed.
- Base64url uses RFC 4648 URL-safe alphabet.
- Padding (`=`) is not allowed.
- Decoded public key length must be exactly 32 bytes.

## Rejection Conditions

- Wrong segment count or prefix.
- Unsupported algorithm.
- Invalid base64url.
- Incorrect decoded key length.
