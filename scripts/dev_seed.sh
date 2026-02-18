#!/usr/bin/env bash
set -euo pipefail

BASE_IAL="${BASE_IAL:-http://localhost:8081/ial}"
BASE_CEL="${BASE_CEL:-http://localhost:8082/cel}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

bootstrap="$(curl -sS -X POST "$BASE_IAL/dev/bootstrap" -H 'content-type: application/json' -d '{}')"
token="$(echo "$bootstrap" | jq -er '.credentials.token')"
principal_id="$(echo "$bootstrap" | jq -er '.principal.principal_id')"
actor_id="$(echo "$bootstrap" | jq -er '.agent.actor_id')"

status_resp="$(curl -sS "$BASE_CEL/gates/terms_current/status?external_subject_id=dev-seed-user&actor_type=HUMAN" -H "Authorization: Bearer $token")"
status="$(echo "$status_resp" | jq -er '.status')"
if [[ "$status" != "DONE" && "$status" != "BLOCKED" ]]; then
  echo "unexpected gate status: $status" >&2
  echo "$status_resp" >&2
  exit 1
fi

echo "export TOKEN=$token"
echo "export PRINCIPAL_ID=$principal_id"
echo "export ACTOR_ID=$actor_id"
echo "export GATE_STATUS=$status"
