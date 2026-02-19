Below is your updated `README.md` content with the Apache 2.0 license section properly inserted.

You should also add a separate `LICENSE` file at the root containing the full Apache 2.0 license text (I can generate that next if you'd like).

---

````markdown
# Contract Lane

**A deterministic settlement and authorization protocol for autonomous agents.**

Contract Lane is a cryptographically verifiable contract execution layer designed for agent-to-agent commerce.

It provides:

- Deterministic state transitions  
- Canonical JSON hashing  
- Structured signature envelopes (`sig-v1`)  
- Content-addressed proof bundles (`proof-bundle-v1`)  
- Settlement attestations derived from payment events  
- Delegation + revocation semantics  
- Deterministic rules enforcement  
- A conformance-verified reference implementation  

It is not a marketplace.  
It is not a payment processor.  
It is not a workflow engine.

It is a **protocol layer**.

---

## Why Contract Lane Exists

As autonomous agents begin transacting with each other, we need more than APIs.

We need:

- Contracts with deterministic execution semantics  
- Proof objects that are portable and verifiable offline  
- Authorization that can be delegated and revoked  
- Settlement states that have cryptographic meaning  
- A way to verify “this happened” without trusting a server  

Contract Lane defines that layer.

Every governed action must be bound to:

- A contract state  
- A canonical payload hash  
- A signature with explicit context  
- Evidence artifacts  
- A content-addressed proof bundle  

If you can produce a `proof_id`, you can independently verify what occurred.

---

## Core Guarantees

### Determinism

All hashed surfaces use canonical JSON.  
No timestamps or nondeterministic fields are included in cryptographic material.

Exporting the same contract twice yields the same `proof_id`.

---

### Proof Portability

`proof-bundle-v1` is content-addressed:

```text
proof_id = sha256_hex(canonical_json(proof))
````

A proof bundle can be:

* Exported from one node
* Verified offline
* Stored independently
* Re-verified without server access

The protocol does not require centralized trust.

---

### Authorization with Revocation

Delegations are first-class artifacts.

Revocation is deterministic:

> Any valid revocation invalidates the target delegation.

Authorization failures are explicit and verifiable.

---

### Conformance-Defined Compatibility

Compatibility is defined by the conformance suite.

If an implementation passes conformance, it is protocol-compatible.

Breaking changes require a new version (`*-v2`).

---

## What Is Frozen in v1.0.0

The following surfaces are locked:

* `agent-id-v1`
* `sig-v1`
* `amount-v1`
* `evidence-v1`
* `delegation-v1`
* `delegation-revocation-v1`
* `rules-v1`
* `proof-bundle-v1`

No breaking changes will be made to these schemas.

---

## Quickstart

Run the reference implementation:

```bash
make test
make smoke
BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh
```

If conformance is green, your node is protocol-compatible.

---

## Architecture Overview

Contract Lane consists of:

### CEL (Contract Execution Layer)

Deterministic state machine for contract transitions.

### Signature Layer (`sig-v1`)

Canonical hash + context-bound Ed25519 signatures.

### Evidence Engine (`evidence-v1`)

Deterministic artifact collection and bundle hashing.

### Authorization Layer

Delegation + revocation semantics.

### Rules Engine (`rules-v1`)

Deterministic policy enforcement (validation only; no automation).

### Proof Bundle (`proof-bundle-v1`)

Portable, content-addressed proof object.

---

## Philosophy

* No governed action without contract state.
* No contract state without evidence.
* No evidence without canonical hashing.
* No signature without explicit context.
* No settlement without cryptographic meaning.
* No authorization without revocation capability.
* No compatibility without conformance.

Contract Lane is designed to be a long-lived settlement substrate for agent commerce.

---

## License

Contract Lane is licensed under the **Apache License 2.0**.

You may use, modify, and distribute this software in accordance with the terms of the license.

See the [LICENSE](./LICENSE) file for the full license text.

```

---
