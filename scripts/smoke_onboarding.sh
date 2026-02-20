#!/usr/bin/env bash
set -euo pipefail

BASE_ONBOARDING="${BASE_ONBOARDING:-http://localhost:8084/onboarding/v1}"
ONBOARDING_TOKEN="${ONBOARDING_BOOTSTRAP_TOKEN:-dev_onboarding_token}"
RUN_ID="$(date +%s)-$RANDOM"

if ! command -v jq >/dev/null 2>&1; then
  echo "Missing dependency: jq is required by scripts/smoke_onboarding.sh" >&2
  exit 1
fi

curl_json() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local tmp status
  tmp="$(mktemp)"

  if [[ -n "$data" ]]; then
    status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H 'content-type: application/json' \
      -H "Authorization: Bearer $ONBOARDING_TOKEN" \
      -d "$data")"
  else
    status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
  fi

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "HTTP $status from $method $url" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    exit 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

echo "== Onboarding health =="
curl -sf http://localhost:8084/health >/dev/null

echo "== Onboarding org/project/agent bootstrap =="
ORG_RESP="$(curl_json POST "$BASE_ONBOARDING/orgs" "{\"name\":\"Acme Onboarding $RUN_ID\",\"admin_email\":\"owner+$RUN_ID@example.com\"}")"
ORG_ID="$(echo "$ORG_RESP" | jq -er '.org.org_id')"

PROJECT_RESP="$(curl_json POST "$BASE_ONBOARDING/orgs/$ORG_ID/projects" "{\"name\":\"Treasury\",\"jurisdiction\":\"US\",\"timezone\":\"UTC\"}")"
PROJECT_ID="$(echo "$PROJECT_RESP" | jq -er '.project.project_id')"
PRN_ID="$(echo "$PROJECT_RESP" | jq -er '.project.principal_id')"

AGENT_RESP="$(curl_json POST "$BASE_ONBOARDING/projects/$PROJECT_ID/agents" "{\"name\":\"OnboardingBot\",\"scopes\":[\"cel.contracts:write\",\"cel.approvals:decide\"]}")"
ACTOR_ID="$(echo "$AGENT_RESP" | jq -er '.agent.actor_id')"
TOKEN="$(echo "$AGENT_RESP" | jq -er '.credential.token')"

echo "org_id=$ORG_ID project_id=$PROJECT_ID principal_id=$PRN_ID actor_id=$ACTOR_ID"
[[ "$TOKEN" == agt_live_* ]] || { echo "unexpected token format" >&2; exit 1; }

echo "onboarding smoke passed"
