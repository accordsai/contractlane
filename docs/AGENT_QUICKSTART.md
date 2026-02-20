
````markdown
# Agent Quickstart

This guide shows the minimal lifecycle for agent-to-agent commerce using Contract Lane v1.0.0.

It assumes:
- The reference server is running locally
- You can generate Ed25519 signatures
- You can make HTTP requests

---

## 1. Create a Contract

Create a deterministic contract object representing agreed terms.

Example:

```json
{
  "service": "api_usage",
  "rate": "0.05",
  "currency": "USD",
  "max_spend": "1000",
  "duration_days": 30
}
````

POST to:

```
POST /cel/contracts
```

The server returns a `contract_id`.

---

## 2. Sign the Contract (sig-v1)

Both agents sign the canonical payload hash of the contract using `sig-v1`.

Signature envelope format:

```json
{
  "version": "sig-v1",
  "algorithm": "ed25519",
  "public_key": "...",
  "signature": "...",
  "payload_hash": "...",
  "issued_at": "RFC3339 UTC Z",
  "context": "contract-action"
}
```

Submit the signature via:

```
POST /cel/contracts/{id}/actions/sign
```

Once both required parties sign, contract state transitions deterministically.

---

## 3. Submit Commerce Intent (Buyer)

The buyer agent submits a commerce intent:

```
POST /commerce/intents
```

This includes:

* Contract reference
* Amount (amount-v1 normalized)
* Currency
* Nonce
* Signature (sig-v1, context="commerce-intent")

---

## 4. Submit Commerce Accept (Seller)

The seller submits a matching accept:

```
POST /commerce/accepts
```

Signed using context `"commerce-accept"`.

---

## 5. Settlement Event Occurs

A payment provider (e.g., Stripe) triggers a webhook.

The server derives a deterministic settlement attestation artifact:

* PAID
* FAILED
* REFUNDED
* DISPUTED

Settlement is cryptographically bound to:

* Contract ID
* Intent hash
* Amount (exact string match)

---

## 6. Export Proof Bundle

At any time:

```
GET /cel/contracts/{id}/proof-bundle?format=json
```

Returns:

```json
{
  "proof": { ... },
  "proof_id": "..."
}
```

Where:

```
proof_id = sha256_hex(canonical_json(proof))
```

This proof bundle contains:

* Contract snapshot
* Signatures
* Commerce artifacts
* Delegations
* Revocations
* Settlement attestations

---

## 7. Verify Offline

Using the SDK:

```
verify_proof_bundle_v1(proof)
```

Verification checks:

* Canonical hash consistency
* Signature validity
* Delegation + revocation rules
* Settlement requirements
* Rules-v1 predicates

If valid, the proof is independently verifiable without server access.

---

# What Contract Lane Does

* Deterministic contract state transitions
* Canonical hashing of governed actions
* Verifiable delegation and revocation
* Cryptographic settlement semantics
* Portable proof bundles

# What It Does Not Do

* Negotiate legal language
* Interpret ambiguous clauses
* Replace payment processors
* Replace identity providers
* Replace human legal review

It is the deterministic settlement and authorization layer beneath agent commerce.

---

# Minimal Lifecycle Summary

1. Negotiate terms (outside Contract Lane)
2. Create structured contract
3. Sign deterministically
4. Execute commerce
5. Derive settlement
6. Export proof bundle
7. Verify independently

---

For full protocol details, see:

* PROTOCOL.md
* PROOF_BUNDLE_V1.md
* EVIDENCE_V1.md
* RULES_V1.md

```


