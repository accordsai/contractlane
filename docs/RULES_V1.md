# Rules v1 (`rules-v1`)

`rules-v1` is a deterministic validation layer.

It is used to express contract-specific conditions like:
- "proof requires settlement status PAID"
- "this transition is only permitted when condition X is true"

Rules do **not** automatically mutate state.

## Why Agents Use Rules

Templates define reusable defaults for many contracts.
Rules define per-contract requirements without forking template definitions.

Common use case:
- Keep template `price` optional.
- Add a contract-specific rule requiring paid settlement for one deal.

## Schema

```json
{
  "version": "rules-v1",
  "rules": [
    {
      "rule_id": "rl_example",
      "description": "optional",
      "when": { "has_commerce_intent": true },
      "then": {
        "require": {
          "name": "must_be_paid",
          "predicate": { "settlement_status_is": "PAID" }
        }
      }
    }
  ]
}
```

Validation guarantees:
- `version` must equal `rules-v1`
- `rules` must be non-empty
- `rule_id` must be unique
- `require.name` must be unique across rules
- unknown fields are rejected (strict parsing)

## Predicates (Closed Set)

Each predicate object must contain exactly one operator.

- `contract_state_is: "<STATE>"`
- `has_commerce_intent: true`
- `has_commerce_accept: true`
- `settlement_status_is: "PAID" | "FAILED" | "REFUNDED" | "DISPUTED"`
- `settlement_amount_is: { "currency":"USD", "amount":"49" }`
- `authorization_satisfied_for: "<scope>"`
- `all: [predicate, ...]` (non-empty)
- `any: [predicate, ...]` (non-empty)
- `not: predicate`

Notes:
- `has_commerce_intent` and `has_commerce_accept` only accept `true`.
- `settlement_amount_is` uses amount-v1 normalization/comparison semantics.
- `authorization_satisfied_for` reuses delegation evaluation logic.

## Effects

Rules support two deterministic effects:

1. `require`
- Meaning: if unsatisfied, verification fails.

2. `permit_transition`
- Meaning: specific `(from,to)` transition is permitted only when predicate is true.
- This is a validation hook, not automation.

Effect shape:

```json
{
  "require": {
    "name": "must_be_paid",
    "predicate": { "settlement_status_is": "PAID" }
  },
  "permit_transition": {
    "from": "SIGNATURE_SENT",
    "to": "EFFECTIVE",
    "if": { "settlement_status_is": "PAID" }
  }
}
```

Either or both effects may be present in `then`.

## Deterministic Evaluation Output

Evaluation result version: `rules-eval-v1`

Result order is stable:
- same order as input `rules`
- effect entries in deterministic order

Failure reasons are closed and stable:
- `predicate_false`
- `missing_required_artifact`
- `authorization_failed`
- `amount_mismatch`
- `status_mismatch`

## Practical Patterns

### Pattern A: Require PAID settlement

```json
{
  "version": "rules-v1",
  "rules": [
    {
      "rule_id": "rl_paid_required",
      "when": { "has_commerce_intent": true },
      "then": {
        "require": {
          "name": "settlement_paid",
          "predicate": { "settlement_status_is": "PAID" }
        }
      }
    }
  ]
}
```

### Pattern B: Require exact paid amount

```json
{
  "version": "rules-v1",
  "rules": [
    {
      "rule_id": "rl_paid_amount",
      "when": { "has_commerce_intent": true },
      "then": {
        "require": {
          "name": "paid_amount_usd_49",
          "predicate": {
            "all": [
              { "settlement_status_is": "PAID" },
              { "settlement_amount_is": { "currency": "USD", "amount": "49" } }
            ]
          }
        }
      }
    }
  ]
}
```

### Pattern C: Transition gate without automation

```json
{
  "version": "rules-v1",
  "rules": [
    {
      "rule_id": "rl_effective_needs_paid",
      "when": { "contract_state_is": "SIGNATURE_SENT" },
      "then": {
        "permit_transition": {
          "from": "SIGNATURE_SENT",
          "to": "EFFECTIVE",
          "if": { "settlement_status_is": "PAID" }
        }
      }
    }
  ]
}
```

## Agent Integration Guidance

Use rules when you need per-contract policy without changing template schema.

Recommended approach:
1. Keep reusable governance in templates.
2. Use `rules-v1` for deal-specific conditions (settlement, authorization, transition permission).
3. Verify proof/evidence offline using SDK verification helpers.

Related docs:
- `docs/TEMPLATE_MODEL.md`
- `docs/DELEGATION_V1.md`
- `docs/DELEGATION_REVOCATION_V1.md`
- `docs/AMOUNT_V1.md`
- `docs/PROOF_BUNDLE_V1.md`
