# RELEASE

v1.0.0 release checklist:

```bash
make test
make smoke
BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh
git tag -a v1.0.0 -m "Contract Lane Protocol v1.0.0 — Frozen"
git push origin v1.0.0
```

SDK publish notes:

1. Go SDK: publish/tag from `sdk/go`.
2. Python SDK: build/publish from `sdk/python`.
3. TypeScript SDK: build/publish from `sdk/typescript`.

Only publish SDK artifacts after conformance passes.
