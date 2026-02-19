# RULES_V1

Rules schema version:

- `version = "rules-v1"`

Rules are deterministic validation hooks. They do not trigger automatic state transitions.

## Effects

- `require`: must evaluate true for verification success.
- `permit_transition`: validation gate for specific `(from,to)` transitions.

## Deterministic Evaluation Output

Rules evaluation returns stable reason codes, including:

- `predicate_false`
- `missing_required_artifact`
- `authorization_failed`
- `amount_mismatch`
- `status_mismatch`
