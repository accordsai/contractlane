# Go SDK

Go module path:

- `github.com/accordsai/contractlane/sdk/go/contractlane`

Install:

```bash
go get github.com/accordsai/contractlane/sdk/go/contractlane@v1.0.2
```

Migration note:

- Old local import style: `contractlane/sdk/go/contractlane`
- Canonical import path going forward: `github.com/accordsai/contractlane/sdk/go/contractlane`

Run tests:

```bash
go test ./sdk/go/contractlane -count=1
cd sdk/go/contractlane && GOCACHE=/tmp/go-build go test ./... -count=1
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
