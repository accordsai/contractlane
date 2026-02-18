# PROJECT_CONTEXT.md

---

# Project Overview

Contract Lane is a headless legal-financial execution layer designed for integration into AI agents and backend systems.

It provides:

* Structured contract templating
* Variable governance
* Agent-to-agent negotiation
* Identity-aware approval gating
* Deterministic execution state transitions
* Audit-grade evidence bundling
* Signature orchestration

The system is API-first and runs as containerized microservices. UI is deferred until backend invariants are stable.

The system enforces programmable human-in-the-loop control at both template and identity levels.

---

# Core Objectives

1. Provide an execution-safe contract layer for AI agents.
2. Allow agents to:

   * Instantiate contracts from templates
   * Modify variables
   * Attempt lifecycle actions
3. Automatically determine when human approval is required.
4. Support:

   * Template-level governance
   * Identity-level governance
   * Variable-level governance
5. Produce deterministic, audit-grade evidence bundles.
6. Ensure idempotent, retry-safe operations.
7. Maintain full event audit history.
8. Remain headless-first (UI added later).

---

# System Architecture

Microservices:

* **IAL (Identity & Authority Layer)**
* **CEL (Contract Execution Layer)**
* **Execution Service** (signature orchestration)

Infrastructure:

* Go services
* PostgreSQL
* Docker Compose (dev)
* NGINX for SSL termination (future)
* Headless smoke-test driven development

Services communicate over HTTP (JSON).

Authoritative development invariant:

```
make test && make smoke
```

---

# Identity Model

## Actors

Two actor types:

* HUMAN
* AGENT

Each actor belongs to a principal (workspace).

Actors have:

* actor_id
* roles (e.g., LEGAL, FINANCE)
* status (ACTIVE / REVOKED)

## Principals

A principal represents a legal workspace.

Principals own:

* actors
* templates (enabled)
* contracts

## Policy Profiles

Each HUMAN actor may have a policy profile:

* automation_level:

  * A0_FULL_MANUAL
  * A1_GUARDED
  * A2_FAST_LANE
  * A3_AGENT_FIRST

* action_gates:

  * Map of action → FORCE_HUMAN | ALLOW_AUTOMATION | DEFER

* variable_rules:

  * for_type → policy
  * for_key → policy

Policies:

* AGENT_ALLOWED
* HUMAN_REQUIRED
* AGENT_FILL_HUMAN_REVIEW
* DEFER_TO_IDENTITY

---

# Approval / Execution Flow

## Contract Lifecycle (simplified)

States include:

* DRAFT_CREATED
* READY_TO_SIGN
* SIGNATURE_SENT
* EFFECTIVE
* REJECTED
* ARCHIVED

## Attempt Action Pattern

Endpoint:

```
POST /cel/contracts/{id}/actions/{action}
```

Response:

* DONE
* BLOCKED (with next_step)
* REJECTED

Possible `next_step.type`:

* FILL_VARIABLES
* REVIEW_VARIABLES
* APPROVE_ACTION

## Gating Resolution Order

1. Template variable policy
2. Identity variable rules (if template defers)
3. Template action gate
4. Identity action gate (if template defers)

Template rules override identity when explicitly set.

## Variable Handling

Each template variable defines:

* var_key
* var_type
* required (boolean)
* set_policy

Variable-level gating:

* HUMAN_REQUIRED blocks until set by human
* AGENT_FILL_HUMAN_REVIEW requires human review if agent-filled
* AGENT_ALLOWED passes
* DEFER_TO_IDENTITY resolves to identity rule

Variables freeze at `SIGNATURE_SENT`.

## Approvals

Approval request created when:

* Action gate requires human
* Variable gating unresolved

Approval request contains:

* approval_request_id
* contract_id
* action
* required_roles
* review_url (token-based)

Approval decision:

```
POST /cel/approvals/{id}:decide
```

Stores:

* signed_payload
* signature_object
* signed_payload_hash

---

# Cryptographic Model

V1:

* WebAuthn assertion (stubbed verification)
* HMAC bearer tokens for agents

Stored:

* signed_payload (canonical JSON)
* signed_payload_hash (sha256)
* signature_object

Future:

* secp256k1 support for agent identity
* Nitro Enclaves for execution isolation

All approval decisions must include:

* contract_id
* approval_request_id
* packet_hash
* diff_hash
* risk_hash
* nonce

Hashes are stored for audit determinism.

---

# Data Model

Core tables:

* principals
* actors
* agent_credentials
* webauthn_credentials
* policy_profiles
* templates
* template_governance
* template_variables
* principal_templates
* contracts
* contract_variables
* changesets
* approval_requests
* approval_decisions
* signature_envelopes
* contract_events
* idempotency_keys

Contracts include:

* template_id
* state
* packet_hash
* diff_hash
* risk_hash

Contract variables include:

* value
* source (HUMAN | AGENT | SYSTEM)
* review_status

All state transitions logged in `contract_events`.

---

# External Integrations

Planned:

* DocuSign
* AdobeSign
* Signature provider webhooks

Execution Service responsibilities:

* Create signature envelopes
* Receive webhook updates
* Transition contract state

UI (future phase):

* Next.js frontend
* Component library
* Asset system
* Review flows

---

# Security Assumptions

1. All operations authenticated (agent token or human WebAuthn).
2. Agents scoped via permissions.
3. Idempotency required for all mutation endpoints.
4. No variable modification allowed after SIGNATURE_SENT.
5. Approval decisions require signed payload validation.
6. Template governance immutable once used by a contract.
7. Audit log append-only.

---

# Constraints

* Headless-first architecture.
* Deterministic state machine.
* Explicit human gating resolution.
* No UI-generated logic.
* All lifecycle changes must flow through Attempt Action endpoint.
* Smoke test must remain green.
* Spec in `/docs` is authoritative and immutable during implementation.

---

# Open Questions

1. How to designate default approver when template defers to identity?
2. How to resolve identity governance when caller is AGENT?
3. Multi-approver workflows (parallel vs sequential)?
4. Risk scoring engine implementation?
5. Canonical hashing format for packet/diff/risk?
6. Production WebAuthn verification pipeline?
7. secp256k1 agent identity support timeline?
8. Nitro enclave integration architecture?
9. External counsel routing (if supported in future)?
10. UI design system strategy and component taxonomy?

---

End of document.

