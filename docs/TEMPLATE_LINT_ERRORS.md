# Template Lint Errors (Admin Authoring)

This catalog describes deterministic lint errors returned by template admin authoring endpoints.

Primary response shape:

```json
{
  "error": {
    "code": "TEMPLATE_LINT_FAILED",
    "message": "template validation failed",
    "details": [
      { "path": "...", "code": "...", "message": "..." }
    ]
  },
  "request_id": "req_..."
}
```

The `details[]` array is deterministic and sorted by:
1. `path`
2. `code`
3. `message`

## Where It Applies

- `POST /cel/admin/templates`
- `PUT /cel/admin/templates/{template_id}`
- `POST /cel/admin/templates/{template_id}:publish` (stricter publish profile)

## Common Error Codes

Top-level/schema:
- `REQUIRED`
- `FORMAT_INVALID`
- `ENUM_INVALID`
- `VERSION_MISMATCH`
- `LIMIT_EXCEEDED`

Template gates:
- `ACTION_UNSUPPORTED`
- `GATE_INVALID`
- `REQUIRED` (publish profile requires `SEND_FOR_SIGNATURE`)

Variable shape/constraints:
- `DUPLICATE`
- `CONSTRAINT_DISALLOWED`
- `TYPE_INVALID`
- `VALUE_INVALID`
- `RANGE_INVALID`
- `CURRENCY_MISMATCH`
- `VALUE_NON_CANONICAL` (publish profile)

Slots:
- `REFERENCE_INVALID`
- `CONFLICT`
- `VALUE_INVALID`

State/profile:
- `STATE_INVALID` (for example archived template publish attempt)

## Path Examples

- `template_id`
- `template_version`
- `template_gates.SEND_FOR_SIGNATURE`
- `variables[0].key`
- `variables[0].constraints.allowed_values[0]`
- `protected_slots[1]`
- `prohibited_slots[0]`

## Quick Triage Playbook

1. Fix `REQUIRED` and `FORMAT_INVALID` first.
2. Fix enum/gate errors (`ENUM_INVALID`, `ACTION_UNSUPPORTED`, `GATE_INVALID`).
3. Fix variable constraints (`CONSTRAINT_DISALLOWED`, `RANGE_INVALID`, `CURRENCY_MISMATCH`).
4. For publish errors, normalize `allowed_values` to canonical variable values.
5. Retry with a new `Idempotency-Key` if request body changed.

## Related Docs

- `docs/TEMPLATE_AUTHORING.md`
- `docs/TEMPLATE_MODEL.md`
- `docs/RULES_V1.md`
