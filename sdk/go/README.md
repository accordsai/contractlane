# Go SDK

Package path: `sdk/go/contractlane`

Run tests:

```bash
go test ./sdk/go/contractlane -count=1
```

## Template Admin Methods

Operator/admin wrappers for CEL template authoring are available as thin pass-through calls:

- `CreateTemplate`
- `UpdateTemplate`
- `PublishTemplate`
- `ArchiveTemplate`
- `CloneTemplate`
- `GetTemplateAdmin`
- `ListTemplatesAdmin`
- `ListTemplateShares`
- `AddTemplateShare`
- `RemoveTemplateShare`

Use `Idempotency-Key` on mutating calls via the method argument.

For lint failures, the SDK preserves deterministic error details from:

- `422 TEMPLATE_LINT_FAILED`
- `Error.Details` (array/object passthrough)
