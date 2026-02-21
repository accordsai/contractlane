# TypeScript SDK Local Setup

Use deterministic installs for this SDK.

One-time setup (generates `package-lock.json`):

```bash
npm install
```

All future installs:

```bash
npm ci
```

Build and test:

```bash
npm run build
npm test
```

## Template Admin Methods

Operator/admin wrappers for CEL template authoring are available as thin pass-through calls:

- `createTemplate`
- `updateTemplate`
- `publishTemplate`
- `archiveTemplate`
- `cloneTemplate`
- `getTemplateAdmin`
- `listTemplatesAdmin`
- `listTemplateShares`
- `addTemplateShare`
- `removeTemplateShare`

Use `opts.idempotencyKey` on mutating calls.

For lint failures, the SDK preserves deterministic error details from:

- `422 TEMPLATE_LINT_FAILED`
- `ContractLaneError.details` (array/object passthrough)
