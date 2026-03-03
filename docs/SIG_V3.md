# SIG_V3

`sig-v3` is an additive signature envelope for WebAuthn ES256 approval decisions.

## Scope (Phase 1)

- Supported context: `contract-action`
- Supported flow: human approval decision submission (`POST /cel/approvals/{approval_request_id}:decide`)
- Existing `sig-v1` and `sig-v2` behavior remains unchanged.

## Envelope

Required fields:

- `version` = `"sig-v3"`
- `algorithm` = `"webauthn-es256"`
- `credential_id` = base64url (no padding)
- `challenge_id` = challenge identifier from `/ial/webauthn/assertions/start`
- `client_data_json` = base64url (no padding), raw WebAuthn `clientDataJSON` bytes
- `authenticator_data` = base64url (no padding), raw WebAuthn `authenticatorData` bytes
- `signature` = base64url (no padding), DER ECDSA signature bytes
- `payload_hash` = lowercase hex SHA-256 (64 chars)
- `issued_at` = RFC3339/RFC3339Nano UTC with trailing `Z`
- `context` = `"contract-action"`

Optional:

- `key_id`

## Verification Rules

Verification is strict and fail-closed:

- Reject unknown envelope keys.
- Reject any non-base64url/no-padding binary field.
- Reject non-lowercase or malformed `payload_hash`.
- Reject non-UTC `issued_at` values.
- Require `clientDataJSON.type == "webauthn.get"`.
- Require challenge match to server-issued challenge.
- Require origin in configured allowlist.
- Require RP ID hash match.
- Require UP and UV flags.
- Verify signature over:
  - `authenticatorData || SHA256(clientDataJSON)`
- Enforce credential binding to actor/principal.
- Enforce single-use, non-expired challenge.
- Enforce non-regressing sign counter when previous/current counters are non-zero.

## Notes

- `sig-v3` uses DER ECDSA for the envelope signature field.
- `sig-v3` does not change evidence hashing, proof hashing, or `sig-v1`/`sig-v2` semantics.
