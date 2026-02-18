#!/usr/bin/env bash
set -euo pipefail

CEL_URL="${CEL_URL:-http://localhost:8082}"
IAL_URL="${IAL_URL:-http://localhost:8081}"
DELEGATION_SECRET="${IAL_DELEGATION_HMAC_SECRET:-dev_delegation_secret}"
RUN_ID="${RUN_ID:-slice11-$(date +%s)-$RANDOM}"

for dep in curl jq python3; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "Missing dependency: $dep" >&2
    exit 1
  fi
done

normalize_auth() {
  local v="${1:-}"
  if [[ -z "$v" ]]; then
    echo ""
    return
  fi
  if [[ "$v" == Authorization:* ]]; then
    echo "$v"
    return
  fi
  if [[ "$v" == Bearer\ * ]]; then
    echo "Authorization: $v"
    return
  fi
  echo "Authorization: Bearer $v"
}

curl_capture() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local auth="${4-}"
  local tmp
  tmp="$(mktemp)"
  if [[ -n "$data" ]]; then
    if [[ -n "$auth" ]]; then
      CURL_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -H "$auth" -d "$data")"
    else
      CURL_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -d "$data")"
    fi
  else
    if [[ -n "$auth" ]]; then
      CURL_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth")"
    else
      CURL_STATUS="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
    fi
  fi
  CURL_BODY="$(cat "$tmp")"
  rm -f "$tmp"
}

probe_ial_base() {
  local bases=("" "/ial" "/v1/ial" "/api/ial")
  for b in "${bases[@]}"; do
    curl_capture POST "${IAL_URL}${b}/delegations" '{}'
    if [[ "$CURL_STATUS" != "404" ]]; then
      echo "$b"
      return
    fi
  done
  echo "Unable to discover IAL base path under ${IAL_URL}" >&2
  exit 1
}

sign_payload() {
  local payload_json="$1"
  PAYLOAD_JSON="$payload_json" DELEGATION_SECRET="$DELEGATION_SECRET" python3 - <<'PY'
import base64, hashlib, hmac, json, os
payload = json.loads(os.environ["PAYLOAD_JSON"])
secret = os.environ["DELEGATION_SECRET"].encode("utf-8")
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
hex_hash = hashlib.sha256(canonical).hexdigest()
signed_payload_hash = "sha256:" + hex_hash
sig = base64.b64encode(hmac.new(secret, signed_payload_hash.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
print(json.dumps({
    "signed_payload_hash": signed_payload_hash,
    "signature_bytes": sig,
    "algorithm": "HMAC-SHA256"
}, separators=(",", ":")))
PY
}

fail_missing_inputs() {
  echo "Could not derive required test inputs." >&2
  echo "Set these env vars explicitly and re-run:" >&2
  echo "  AGENT_AUTH, DELEGATOR_ACTOR_ID, DELEGATE_ACTOR_ID, CONTRACT_ID, PRINCIPAL_ID, HUMAN_AUTH" >&2
  exit 1
}

IAL_BASE="$(probe_ial_base)"
BASE_IAL="${IAL_URL}${IAL_BASE}"
BASE_CEL="${CEL_URL}/cel"

PRINCIPAL_ID="${PRINCIPAL_ID:-}"
SETUP_AGENT_ACTOR_ID="${SETUP_AGENT_ACTOR_ID:-${ACTOR_ID:-}}"
SETUP_AGENT_AUTH="$(normalize_auth "${SETUP_AGENT_AUTH:-${TOKEN:-}}")"
AGENT_AUTH="$(normalize_auth "${AGENT_AUTH:-}")"
HUMAN_AUTH="$(normalize_auth "${HUMAN_AUTH:-}")"
DELEGATOR_ACTOR_ID="${DELEGATOR_ACTOR_ID:-}"
DELEGATE_ACTOR_ID="${DELEGATE_ACTOR_ID:-}"
CONTRACT_ID="${CONTRACT_ID:-}"
TEMPLATE_ID="${TEMPLATE_ID:-}"

# Bootstrap dev token context if missing.
if [[ -z "$PRINCIPAL_ID" || -z "$SETUP_AGENT_AUTH" || -z "$SETUP_AGENT_ACTOR_ID" ]]; then
  if [[ -x ./scripts/dev_token.sh ]]; then
    DEV_ENV="$(BASE_IAL="$BASE_IAL" ./scripts/dev_token.sh)" || DEV_ENV=""
    if [[ -n "$DEV_ENV" ]]; then
      eval "$DEV_ENV"
      PRINCIPAL_ID="${PRINCIPAL_ID:-}"
      SETUP_AGENT_ACTOR_ID="${SETUP_AGENT_ACTOR_ID:-${ACTOR_ID:-}}"
      SETUP_AGENT_AUTH="$(normalize_auth "${SETUP_AGENT_AUTH:-${TOKEN:-}}")"
    fi
  fi
fi

# Optional fallback: parse smoke output.
if [[ -z "$PRINCIPAL_ID" || -z "$SETUP_AGENT_AUTH" || -z "$SETUP_AGENT_ACTOR_ID" || -z "$CONTRACT_ID" ]]; then
  if [[ "${SLICE11_FROM_SMOKE:-}" != "1" ]]; then
    if [[ ! -f /tmp/smoke.out ]]; then
      ./scripts/smoke.sh >/tmp/smoke.out 2>&1 || true
    fi
    if [[ -f /tmp/smoke.out ]]; then
      CONTRACT_ID="${CONTRACT_ID:-$(grep -Eo 'ctr_[a-z0-9-]+' /tmp/smoke.out | head -n1 || true)}"
      DELEGATE_ACTOR_ID="${DELEGATE_ACTOR_ID:-$(grep -Eo 'act_[a-z0-9-]+' /tmp/smoke.out | head -n1 || true)}"
    fi
  fi
fi

if [[ -z "$PRINCIPAL_ID" || -z "$SETUP_AGENT_AUTH" || -z "$SETUP_AGENT_ACTOR_ID" ]]; then
  fail_missing_inputs
fi

# Ensure we have a human delegator + human auth.
if [[ -z "$HUMAN_AUTH" || -z "$DELEGATOR_ACTOR_ID" ]]; then
  email="delegator-${RUN_ID}@example.local"
  invite_req="$(jq -cn --arg p "$PRINCIPAL_ID" --arg e "$email" '{principal_id:$p,invitee:{email:$e},requested_roles:["LEGAL"],expires_in_hours:24}')"
  curl_capture POST "$BASE_IAL/invites" "$invite_req"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "invite failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  invite_id="$(echo "$CURL_BODY" | jq -er '.invite.invite_id')"

  curl_capture POST "$BASE_IAL/webauthn/register/finish" "$(jq -cn --arg t "dev:${invite_id}" '{invite_token:$t,attestation_response:{}}')"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "register finish failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  DELEGATOR_ACTOR_ID="$(echo "$CURL_BODY" | jq -er '.actor.actor_id')"

  ml_start_req="$(jq -cn --arg p "$PRINCIPAL_ID" --arg e "$email" '{principal_id:$p,email:$e,redirect_url:"https://example.local/return"}')"
  curl_capture POST "$BASE_IAL/auth/magic-link/start" "$ml_start_req"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "magic-link start failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  ml_url="$(echo "$CURL_BODY" | jq -er '.magic_link_url')"
  ml_token="$(echo "$ml_url" | sed -E 's/.*token=([^&]+).*/\1/')"
  curl_capture POST "$BASE_IAL/auth/magic-link/finish" "$(jq -cn --arg t "$ml_token" '{token:$t}')"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "magic-link finish failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  HUMAN_TOKEN="$(echo "$CURL_BODY" | jq -er '.credentials.token')"
  HUMAN_AUTH="$(normalize_auth "$HUMAN_TOKEN")"
fi

# Ensure delegate agent auth exists (low-scope agent).
if [[ -z "$AGENT_AUTH" || -z "$DELEGATE_ACTOR_ID" ]]; then
  low_req="$(jq -cn --arg p "$PRINCIPAL_ID" '{principal_id:$p,name:"DelegationLowScope",auth:{mode:"HMAC",scopes:["exec.signatures:send"]}}')"
  curl_capture POST "$BASE_IAL/actors/agents" "$low_req"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "create low-scope agent failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  DELEGATE_ACTOR_ID="$(echo "$CURL_BODY" | jq -er '.agent.actor_id')"
  low_token="$(echo "$CURL_BODY" | jq -er '.credentials.token')"
  AGENT_AUTH="$(normalize_auth "$low_token")"
fi

# Ensure template + contract exist.
if [[ -z "$TEMPLATE_ID" ]]; then
  curl_capture POST "$BASE_CEL/dev/seed-template" "$(jq -cn --arg p "$PRINCIPAL_ID" '{principal_id:$p}')"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "seed template failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  TEMPLATE_ID="$(echo "$CURL_BODY" | jq -er '.template_id')"
fi
curl_capture POST "$BASE_CEL/principals/$PRINCIPAL_ID/templates/$TEMPLATE_ID/enable" "$(jq -cn --arg a "$DELEGATOR_ACTOR_ID" '{enabled_by_actor_id:$a,override_gates:{}}')"
[[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "enable template failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }

if [[ -z "$CONTRACT_ID" ]]; then
  create_req="$(jq -cn \
    --arg p "$PRINCIPAL_ID" \
    --arg a "$SETUP_AGENT_ACTOR_ID" \
    --arg t "$TEMPLATE_ID" \
    --arg k "slice11-contract-$RUN_ID" \
    '{actor_context:{principal_id:$p,actor_id:$a,actor_type:"AGENT",idempotency_key:$k},template_id:$t,counterparty:{name:"Delegation Vendor",email:"legal@delegation.example"},initial_variables:{effective_date:"2026-02-18"}}')"
  curl_capture POST "$BASE_CEL/contracts" "$create_req" "$SETUP_AGENT_AUTH"
  [[ "$CURL_STATUS" =~ ^20[01]$ ]] || { echo "create contract failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
  CONTRACT_ID="$(echo "$CURL_BODY" | jq -er '.contract.contract_id')"
fi

if [[ -z "$AGENT_AUTH" || -z "$DELEGATOR_ACTOR_ID" || -z "$DELEGATE_ACTOR_ID" || -z "$CONTRACT_ID" || -z "$PRINCIPAL_ID" || -z "$HUMAN_AUTH" ]]; then
  fail_missing_inputs
fi

action_body() {
  local idem="$1"
  jq -cn --arg p "$PRINCIPAL_ID" --arg a "$DELEGATE_ACTOR_ID" --arg k "$idem" \
    '{actor_context:{principal_id:$p,actor_id:$a,actor_type:"AGENT",idempotency_key:$k}}'
}

echo "Slice11 e2e: deny -> delegate -> allow -> revoke -> deny"

# 1) Denied before delegation.
curl_capture POST "$BASE_CEL/contracts/$CONTRACT_ID/actions/SEND_FOR_SIGNATURE" "$(action_body "slice11-deny-$RUN_ID")" "$AGENT_AUTH"
if [[ "$CURL_STATUS" != "401" && "$CURL_STATUS" != "403" ]]; then
  echo "Expected pre-delegation denial (401/403), got $CURL_STATUS: $CURL_BODY" >&2
  exit 1
fi

# 2) Create delegation.
expires_at="$(date -u -v+20M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || python3 - <<'PY'
import datetime
print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
create_payload="$(jq -cn \
  --arg p "$PRINCIPAL_ID" \
  --arg dgr "$DELEGATOR_ACTOR_ID" \
  --arg dge "$DELEGATE_ACTOR_ID" \
  --arg t "$TEMPLATE_ID" \
  --arg e "$expires_at" \
  '{principal_id:$p,delegator_actor_id:$dgr,delegate_actor_id:$dge,scope:{actions:["contract.execute"],templates:[$t],max_risk_level:"LOW"},expires_at:$e,delegation_version:"delegation-v1"}')"
create_sig="$(sign_payload "$create_payload")"
create_req="$(jq -cn \
  --arg p "$PRINCIPAL_ID" \
  --arg dgr "$DELEGATOR_ACTOR_ID" \
  --arg dge "$DELEGATE_ACTOR_ID" \
  --arg t "$TEMPLATE_ID" \
  --arg e "$expires_at" \
  --argjson sig "$create_sig" \
  '{principal_id:$p,delegator_actor_id:$dgr,delegate_actor_id:$dge,scope:{actions:["contract.execute"],templates:[$t],max_risk_level:"LOW"},expires_at:$e,signature:$sig}')"
curl_capture POST "$BASE_IAL/delegations" "$create_req" "$HUMAN_AUTH"
[[ "$CURL_STATUS" == "200" || "$CURL_STATUS" == "201" ]] || { echo "delegation create failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }
delegation_id="$(echo "$CURL_BODY" | jq -er '.delegation_id')"

# 3) Allowed after delegation (must not be auth denied).
curl_capture POST "$BASE_CEL/contracts/$CONTRACT_ID/actions/SEND_FOR_SIGNATURE" "$(action_body "slice11-allow-$RUN_ID")" "$AGENT_AUTH"
if [[ "$CURL_STATUS" == "401" || "$CURL_STATUS" == "403" ]]; then
  echo "Expected delegated authorization success (non-401/403), got $CURL_STATUS: $CURL_BODY" >&2
  exit 1
fi

# 4) Revoke delegation.
revoked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
revoke_payload="$(jq -cn \
  --arg p "$PRINCIPAL_ID" \
  --arg id "$delegation_id" \
  --arg dgr "$DELEGATOR_ACTOR_ID" \
  --arg dge "$DELEGATE_ACTOR_ID" \
  --arg r "$revoked_at" \
  '{principal_id:$p,delegation_id:$id,delegator_actor_id:$dgr,delegate_actor_id:$dge,revoked_at:$r,delegation_version:"delegation-v1"}')"
revoke_sig="$(sign_payload "$revoke_payload")"
revoke_req="$(jq -cn --arg r "$revoked_at" --argjson sig "$revoke_sig" '{revoked_at:$r,signature:$sig}')"
curl_capture POST "$BASE_IAL/delegations/$delegation_id/revoke" "$revoke_req" "$HUMAN_AUTH"
[[ "$CURL_STATUS" == "200" || "$CURL_STATUS" == "201" ]] || { echo "delegation revoke failed ($CURL_STATUS): $CURL_BODY" >&2; exit 1; }

# 5) Denied again after revoke.
curl_capture POST "$BASE_CEL/contracts/$CONTRACT_ID/actions/SEND_FOR_SIGNATURE" "$(action_body "slice11-deny2-$RUN_ID")" "$AGENT_AUTH"
if [[ "$CURL_STATUS" != "401" && "$CURL_STATUS" != "403" ]]; then
  echo "Expected post-revoke denial (401/403), got $CURL_STATUS: $CURL_BODY" >&2
  exit 1
fi

echo "SLICE 11 delegation e2e PASS"
