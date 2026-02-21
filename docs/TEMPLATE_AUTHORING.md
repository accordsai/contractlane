# Template Authoring (Admin/Operator)

This document describes additive CEL template authoring endpoints for hosted/operator usage.

These endpoints do not change protocol proof/signature semantics.

## Security Model

- Endpoints are admin-only.
- Disabled by default (`ENABLE_TEMPLATE_ADMIN_API=false`).
- Auth mode is configurable:
  - `TEMPLATE_ADMIN_AUTH_MODE=bootstrap` (default): `Authorization: Bearer <TEMPLATE_ADMIN_BOOTSTRAP_TOKEN>`
  - `TEMPLATE_ADMIN_AUTH_MODE=agent_scope`: agent bearer token with scope `TEMPLATE_ADMIN_REQUIRED_SCOPE` (default `cel.admin:templates`)
- Mutating endpoints require `Idempotency-Key`.

## Endpoints

- `POST /cel/admin/templates`
- `PUT /cel/admin/templates/{template_id}`
- `POST /cel/admin/templates/{template_id}:publish`
- `POST /cel/admin/templates/{template_id}:archive`
- `POST /cel/admin/templates/{template_id}:clone`
- `GET /cel/admin/templates/{template_id}/shares`
- `POST /cel/admin/templates/{template_id}/shares`
- `DELETE /cel/admin/templates/{template_id}/shares/{principal_id}`
- `GET /cel/admin/templates/{template_id}`
- `GET /cel/admin/templates?status=&visibility=&owner_principal_id=&contract_type=&jurisdiction=`

## Request Shape (Create/Update)

```json
{
  "template_id": "tpl_nda_us_v2",
  "template_version": "v2",
  "contract_type": "NDA",
  "jurisdiction": "US",
  "display_name": "NDA (US) v2",
  "risk_tier": "LOW",
  "visibility": "GLOBAL",
  "owner_principal_id": null,
  "metadata": {
    "plan_tier": "FREE",
    "labels": ["public", "nda"]
  },
  "template_gates": {
    "SEND_FOR_SIGNATURE": "DEFER"
  },
  "protected_slots": [],
  "prohibited_slots": [],
  "variables": [
    {
      "key": "effective_date",
      "type": "DATE",
      "required": true,
      "sensitivity": "NONE",
      "set_policy": "AGENT_ALLOWED",
      "constraints": {}
    }
  ]
}
```

## Authoring Workflow (Operator)

Use this exact sequence for predictable results:

1. Create draft (`POST /cel/admin/templates`) with full governance + variables.
2. Update draft (`PUT /cel/admin/templates/{template_id}`) until lint-clean.
3. Publish (`POST /cel/admin/templates/{template_id}:publish`).
4. Optionally share private templates (`POST /cel/admin/templates/{template_id}/shares`).
5. Archive old versions (`POST /cel/admin/templates/{template_id}:archive`).

Clone shortcut:
- `POST /cel/admin/templates/{template_id}:clone` to copy governance/variables into a new `DRAFT`.

## Lifecycle

1. Create draft (`POST /cel/admin/templates`) -> status `DRAFT`
2. Update (`PUT /cel/admin/templates/{template_id}`) while not archived
3. Publish (`POST ...:publish`) -> status `PUBLISHED`
4. Archive (`POST ...:archive`) -> status `ARCHIVED`
5. Optional clone (`POST ...:clone`) -> new template with status `DRAFT`

Only `PUBLISHED` templates are accepted by runtime contract creation/use.
Publish runs a stricter lint profile; failures return `422 TEMPLATE_LINT_FAILED` with deterministic `error.details[]` (`path`, `code`, `message`).

Lint reference:
- `docs/TEMPLATE_LINT_ERRORS.md`

## Visibility Rules

- `GLOBAL`: available deployment-wide.
- `PRIVATE`: owned by one principal (`owner_principal_id`).
  - owner principal can enable/use.
  - non-owner principal can enable/use only when explicitly shared via admin share endpoints.

## Example: Create + Publish

```bash
curl -sS -X POST "$BASE_URL/cel/admin/templates" \
  -H "Authorization: Bearer $TEMPLATE_ADMIN_BOOTSTRAP_TOKEN" \
  -H "Idempotency-Key: tpl-create-001" \
  -H "Content-Type: application/json" \
  -d @template.json

curl -sS -X POST "$BASE_URL/cel/admin/templates/tpl_nda_us_v2:publish" \
  -H "Authorization: Bearer $TEMPLATE_ADMIN_BOOTSTRAP_TOKEN" \
  -H "Idempotency-Key: tpl-publish-001" \
  -H "Content-Type: application/json" \
  -d '{}'

curl -sS -X POST "$BASE_URL/cel/admin/templates/tpl_nda_us_v2:clone" \
  -H "Authorization: Bearer $TEMPLATE_ADMIN_BOOTSTRAP_TOKEN" \
  -H "Idempotency-Key: tpl-clone-001" \
  -H "Content-Type: application/json" \
  -d '{"template_id":"tpl_nda_us_v3","template_version":"v3"}'
```

## Example: Deterministic Lint Failure Shape

```json
{
  "error": {
    "code": "TEMPLATE_LINT_FAILED",
    "message": "template validation failed",
    "details": [
      {
        "path": "variables[0].key",
        "code": "FORMAT_INVALID",
        "message": "invalid variable key format: Bad-Key"
      }
    ]
  },
  "request_id": "req_..."
}
```
