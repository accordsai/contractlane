#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${CL_BASE_URL:-http://localhost:8080}"
IAL_BASE_URL="${CL_IAL_BASE_URL:-http://localhost:8081}"
PY_SDK_VENV="$ROOT/sdk/python/.venv"
PY_SDK_PYTHON="$PY_SDK_VENV/bin/python"

required_cases=(
  gate_status_done.json
  gate_status_blocked.json
  gate_resolve_requires_idempotency.json
  error_model_401.json
  retry_429_then_success.json
)

for c in "${required_cases[@]}"; do
  test -f "$ROOT/conformance/cases/$c"
  jq -e . "$ROOT/conformance/cases/$c" >/dev/null
 done

cd "$ROOT/sdk/typescript"
test -f package-lock.json || { echo "sdk/typescript/package-lock.json is required for npm ci"; exit 1; }
npm ci
npm run build
CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" npm test

if [[ ! -x "$PY_SDK_PYTHON" ]]; then
  python3 -m venv "$PY_SDK_VENV"
fi
PYTHONNOUSERSITE=1 "$PY_SDK_PYTHON" -m pip install --no-build-isolation -e "$ROOT/sdk/python[dev]" >/dev/null
PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" "$PY_SDK_PYTHON" -m pytest "$ROOT/sdk/python/tests" -q -k conformance

cd "$ROOT"
CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" go test ./sdk/go/contractlane -count=1 -run Conformance

echo "local conformance passed"
