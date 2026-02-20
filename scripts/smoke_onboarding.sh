#!/usr/bin/env bash
set -euo pipefail

BASE_ONBOARDING="${BASE_ONBOARDING:-http://localhost:8084/onboarding/v1}"
BASE_PUBLIC_SIGNUP="${BASE_PUBLIC_SIGNUP:-http://localhost:8084/public/v1/signup}"
ONBOARDING_TOKEN="${ONBOARDING_BOOTSTRAP_TOKEN:-dev_onboarding_token}"
PUBLIC_CHALLENGE="${ONBOARDING_PUBLIC_SIGNUP_CHALLENGE_TOKEN:-}"
PUBLIC_DEV_MODE="${ONBOARDING_PUBLIC_SIGNUP_DEV_MODE:-false}"
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

curl_json_public() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local tmp status
  tmp="$(mktemp)"

  if [[ -n "$data" ]]; then
    if [[ -n "$PUBLIC_CHALLENGE" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
        -H 'content-type: application/json' \
        -H "X-Signup-Challenge: $PUBLIC_CHALLENGE" \
        -d "$data")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
        -H 'content-type: application/json' \
        -d "$data")"
    fi
  else
    if [[ -n "$PUBLIC_CHALLENGE" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
        -H "X-Signup-Challenge: $PUBLIC_CHALLENGE")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
    fi
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

if [[ "${PUBLIC_DEV_MODE,,}" == "true" ]]; then
  echo "== Public signup flow (dev mode) =="
  START_RESP="$(curl_json_public POST "$BASE_PUBLIC_SIGNUP/start" "{\"email\":\"public+$RUN_ID@example.com\",\"org_name\":\"Public Org $RUN_ID\"}")"
  SESSION_ID="$(echo "$START_RESP" | jq -er '.signup_session.session_id')"
  CODE="$(echo "$START_RESP" | jq -er '.challenge.verification_code')"

  VERIFY_RESP="$(curl_json_public POST "$BASE_PUBLIC_SIGNUP/verify" "{\"session_id\":\"$SESSION_ID\",\"verification_code\":\"$CODE\"}")"
  STATUS="$(echo "$VERIFY_RESP" | jq -er '.signup_session.status')"
  [[ "$STATUS" == "VERIFIED" ]] || { echo "expected VERIFIED status" >&2; exit 1; }

  COMPLETE_RESP="$(curl_json_public POST "$BASE_PUBLIC_SIGNUP/complete" "{\"session_id\":\"$SESSION_ID\",\"project_name\":\"Public Project\",\"agent_name\":\"Public Agent\",\"scopes\":[\"cel.contracts:write\"]}")"
  COMPLETE_STATUS="$(echo "$COMPLETE_RESP" | jq -er '.status')"
  COMPLETE_TOKEN="$(echo "$COMPLETE_RESP" | jq -er '.credential.token')"
  [[ "$COMPLETE_STATUS" == "COMPLETED" ]] || { echo "expected COMPLETED status" >&2; exit 1; }
  [[ "$COMPLETE_TOKEN" == agt_live_* ]] || { echo "unexpected public signup token format" >&2; exit 1; }
fi

echo "onboarding smoke passed"
