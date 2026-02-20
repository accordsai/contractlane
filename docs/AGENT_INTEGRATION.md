# Agent Integration Guide (Protocol v1)

This guide is practical integration guidance for agents consuming Contract Lane Protocol v1.

## Minimum Implementation

An integrating agent should implement:

- `sig-v1` signing (at least `ed25519`) with required `issued_at` (UTC RFC3339/RFC3339Nano with `Z`).
- Canonical payload hashing exactly as required by protocol objects.
- Contract Lane API calls for contract actions and approvals.
- Offline verification of returned evidence/proof artifacts.

## What Is Optional

- Running CEL/IAL/Execution yourself (optional if you use a hosted node).
- Webhook ingestion implementation.
- Anchoring implementation.

## Agent Identity (v1)

`agent-id-v1` format is:

`agent:pk:ed25519:<base64url_no_padding_32_byte_pubkey>`

See `docs/AGENT_ID_V1.md`.

## Core Endpoints

- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/variables:bulkSet`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/evidence?format=json`
- `GET /cel/contracts/{contract_id}/proof?format=json`
- `GET /cel/contracts/{contract_id}/proof-bundle?format=json`

Optional hosted commerce endpoints:

- `POST /commerce/intents`
- `POST /commerce/accepts`

## Canonical Flow

1. Create contract.
2. Populate required variables.
3. Execute action(s); respond to approval requests when needed.
4. Fetch evidence/proof artifacts.
5. Verify artifacts offline before trusting final state.

## Security Notes

- Never sign non-canonical payload variants.
- Validate `context` when using signature envelopes.
- Verify proofs/evidence offline before settlement decisions.
- Rotate keys with `key_id` if your key management supports it.

## Go Snippet (sig-v1 signing shape)

```go
payloadHashHex := evidencehash.CanonicalSHA256(payload)
payloadHashBytes, _ := hex.DecodeString(payloadHashHex)
sig := ed25519.Sign(privateKey, payloadHashBytes)

env := signature.EnvelopeV1{
  Version:     "sig-v1",
  Algorithm:   "ed25519",
  PublicKey:   base64.StdEncoding.EncodeToString(publicKey),
  Signature:   base64.StdEncoding.EncodeToString(sig),
  PayloadHash: payloadHashHex,
  IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
  Context:     "contract-action",
}
```

## See Also

- `docs/INTEGRATOR_START_HERE.md`
- `docs/API_SPEC.md`
- `docs/PROTOCOL.md`
- `docs/CONFORMANCE.md`
