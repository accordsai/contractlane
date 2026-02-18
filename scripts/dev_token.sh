#!/usr/bin/env bash
set -euo pipefail

BASE_IAL="${BASE_IAL:-http://localhost:8081/ial}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

tmp="$(mktemp)"
status="$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "$BASE_IAL/dev/bootstrap" -H 'content-type: application/json' -d '{}')"
if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
  echo "bootstrap failed: HTTP $status" >&2
  cat "$tmp" >&2
  rm -f "$tmp"
  exit 1
fi
resp="$(cat "$tmp")"
rm -f "$tmp"

token="$(echo "$resp" | jq -er '.credentials.token')"
principal_id="$(echo "$resp" | jq -er '.principal.principal_id')"
actor_id="$(echo "$resp" | jq -er '.agent.actor_id')"

echo "export TOKEN=$token"
echo "export PRINCIPAL_ID=$principal_id"
echo "export ACTOR_ID=$actor_id"
