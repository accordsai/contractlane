# Agent Integration Guide (Contract Lane Protocol v1)

## Scope

This guide is practical integration guidance for agents consuming Contract Lane Protocol v1.

## Minimum Agent Implementation

An agent must implement:

- Generate and store a signing keypair (recommended: `ed25519`).
- Build `sig-v1` signature envelopes with required `issued_at`.
- Call Contract Lane API endpoints for contract and approval workflow.
- Fetch and verify evidence bundles using EVP.

## What Agents Do Not Need To Implement

- You do not need to run CEL/IAL/Execution if using a hosted Contract Lane node.
- You do not need to implement anchoring to be protocol-compatible.
- You do not need to implement webhook ingestion to be protocol-compatible.

## Endpoints Agents Use

Core endpoints used by agents:

- `POST /cel/contracts`
- `POST /cel/contracts/{contract_id}/variables:bulkSet`
- `POST /cel/contracts/{contract_id}/actions/{action}`
- `GET /cel/contracts/{contract_id}`
- `POST /cel/approvals/{approval_request_id}:decide`
- `GET /cel/contracts/{contract_id}/evidence`
- `GET /cel/contracts/{contract_id}/events`

Optional, depending on deployment:

- `POST /cel/contracts/{contract_id}/anchors`
- `GET /cel/contracts/{contract_id}/anchors`

## Canonical Flows

### 1) Create Contract -> Approvals -> Evidence Verify

1. Agent creates contract.
2. Agent fills variables.
3. Agent attempts action (`SEND_FOR_SIGNATURE` or other).
4. If blocked on approval, a human submits `:decide` with `sig-v1`.
5. Contract progresses.
6. Agent fetches evidence bundle.
7. Agent verifies bundle with EVP before trusting state.

### 2) Stripe Webhook -> Receipt Captured -> Evidence Verify

1. Signature provider posts webhook.
2. Node verifies signature and records `webhook_receipts_v2`.
3. Receipt is linked to contract when possible.
4. Agent fetches evidence bundle.
5. Agent verifies EVP; receipts appear in `webhook_receipts` artifact.

### 3) Anchor Bundle Hash (Optional) -> Evidence Verify

1. Agent (or operator) requests anchor for `bundle_hash`/`manifest_hash`.
2. Node stores anchor result (`anchors_v1`).
3. Agent fetches evidence bundle.
4. Agent verifies EVP and inspects `anchors` artifact as additional attestation.

## Protocol Identity Recommendation

Use an algorithm-neutral agent identity string:

`agent_id = "agent:" + algorithm + ":" + sha256(public_key_bytes)[:32]`

Example:

`agent:ed25519:7f5c9e1a2b3c4d5e6f708192a3b4c5d6`

`key_id` in `sig-v1` is optional, but recommended to support key rotation and audit traceability.

## Security Guidance

- `issued_at` is required in `sig-v1` and should always be UTC RFC3339Nano.
- Agents should verify evidence bundles after execution before treating actions as final.
- Keep private keys isolated and rotate keys with clear `key_id` lifecycle.

## Go Snippet: Create sig-v1 Envelope + Decide

```go
payload := map[string]any{
  "contract_id": contractID,
  "approval_request_id": approvalRequestID,
  "nonce": nonce,
}
hashHex, _, _ := evidencehash.CanonicalSHA256(payload) // lowercase hex
hashBytes, _ := hex.DecodeString(hashHex)
sig := ed25519.Sign(privateKey, hashBytes)

env := signature.EnvelopeV1{
  Version: "sig-v1",
  Algorithm: "ed25519",
  PublicKey: base64.StdEncoding.EncodeToString(publicKey),
  Signature: base64.StdEncoding.EncodeToString(sig),
  PayloadHash: hashHex,
  IssuedAt: time.Now().UTC().Format(time.RFC3339Nano),
  Context: "contract-action",
}

// POST /cel/approvals/{approval_request_id}:decide
// body includes actor_context, decision, signed_payload, signature_envelope
```

## Go Snippet: Verify Evidence Bundle with EVP

```go
respBytes := mustHTTPGet("/cel/contracts/" + contractID + "/evidence")
result, err := evp.VerifyBundleJSON(respBytes)
if err != nil || result.Status != evp.StatusVerified {
  return fmt.Errorf("evidence verification failed: %v status=%s", err, result.Status)
}
```
