# Python SDK

Package path: `sdk/python/contractlane`

Run tests:

```bash
cd sdk/python
python3 -m pytest -q
```

## Template Admin Methods

Operator/admin wrappers for CEL template authoring are available as thin pass-through calls:

- `create_template`
- `update_template`
- `publish_template`
- `archive_template`
- `clone_template`
- `get_template_admin`
- `list_templates_admin`
- `list_template_shares`
- `add_template_share`
- `remove_template_share`

CamelCase aliases are also available (for parity with existing SDK style), for example `createTemplate`.

Use `idempotency_key` on mutating calls.

For lint failures, the SDK preserves deterministic error details from:

- `422 TEMPLATE_LINT_FAILED`
- `SDKError.details` (array/object passthrough)
