# RELEASE

v1.0.0 release checklist:

```bash
make test
make smoke
BASE_URL=http://localhost:8082 ./conformance/runner/run_local_conformance.sh
cd sdk/go/contractlane && GOCACHE=/tmp/go-build go test ./... -count=1
git tag -a v1.0.0 -m "Contract Lane Protocol v1.0.0 — Frozen"
git push origin v1.0.0
```

SDK publish notes:

1. Go SDK:
   - module path: `github.com/accordsai/contractlane/sdk/go/contractlane`
   - module tag format: `sdk/go/contractlane/vX.Y.Z`
   - example:
     - `git tag -a sdk/go/contractlane/v1.0.0 -m "Go SDK v1.0.0"`
     - `git push origin sdk/go/contractlane/v1.0.0`
2. Python SDK:
   - package: `contractlane` (PyPI)
   - version source: `sdk/python/pyproject.toml` (`[project].version`)
   - build/publish:
     - `cd sdk/python`
     - `python3 -m pip install --upgrade build twine`
     - `python3 -m build`
     - `python3 -m twine upload dist/*`
   - install:
     - `pip install contractlane==1.0.0`
3. TypeScript SDK: build/publish from `sdk/typescript`.

Only publish SDK artifacts after conformance passes.
