#!/usr/bin/env bash
set -euo pipefail

BASE_IAL="http://localhost:8081/ial"
BASE_CEL="http://localhost:8082/cel"
RUN_ID="$(date +%s)-$RANDOM"
WEBHOOK_SECRET="${EXEC_WEBHOOK_SECRET:-dev_webhook_secret}"

if ! command -v jq >/dev/null 2>&1; then
  echo "Missing dependency: jq is required by scripts/smoke.sh" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "Missing dependency: openssl is required by scripts/smoke.sh" >&2
  exit 1
fi

curl_json() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local auth_header="${4-}"
  local extra_header="${5-}"
  local tmp status
  tmp="$(mktemp)"

  if [[ -n "$data" ]]; then
    if [[ -n "$auth_header" && -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H 'content-type: application/json' \
      -H "$auth_header" \
      -H "$extra_header" \
      -d "$data")"
    elif [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H 'content-type: application/json' \
      -H "$auth_header" \
      -d "$data")"
    elif [[ -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H 'content-type: application/json' \
      -H "$extra_header" \
      -d "$data")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" \
      -H 'content-type: application/json' \
      -d "$data")"
    fi
  else
    if [[ -n "$auth_header" && -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth_header" -H "$extra_header")"
    elif [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth_header")"
    elif [[ -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$extra_header")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
    fi
  fi

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "HTTP $status from $method $url" >&2
    echo "Response body:" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

curl_json_expect_status() {
  local expect_status="$1"
  local method="$2"
  local url="$3"
  local data="${4-}"
  local auth_header="${5-}"
  local extra_header="${6-}"
  local tmp status
  tmp="$(mktemp)"

  if [[ -n "$data" ]]; then
    if [[ -n "$auth_header" && -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -H "$auth_header" -H "$extra_header" -d "$data")"
    elif [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -H "$auth_header" -d "$data")"
    elif [[ -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -H "$extra_header" -d "$data")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -d "$data")"
    fi
  else
    if [[ -n "$auth_header" && -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth_header" -H "$extra_header")"
    elif [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth_header")"
    elif [[ -n "$extra_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$extra_header")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
    fi
  fi

  if [[ "$status" != "$expect_status" ]]; then
    echo "Expected HTTP $expect_status from $method $url, got $status" >&2
    echo "Response body:" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    exit 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

canon_json() {
  jq -cS . <<<"$1"
}

gen_sig_v1_envelope() {
  local payload_json="$1"
  local tmp
  tmp="scripts/sigv1_tmp_$RANDOM$RANDOM.go"
  cat >"$tmp" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-sigv1 <payload-json>")
		os.Exit(2)
	}
	var payload any
	if err := json.Unmarshal([]byte(os.Args[1]), &payload); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	sum := sha256.Sum256(b)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	sig := ed25519.Sign(priv, sum[:])
	env := map[string]any{
		"version":      "sig-v1",
		"algorithm":    "ed25519",
		"public_key":   base64.StdEncoding.EncodeToString(pub),
		"signature":    base64.StdEncoding.EncodeToString(sig),
		"payload_hash": hex.EncodeToString(sum[:]),
		"issued_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"context":      "contract-action",
	}
	out, err := json.Marshal(env)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	fmt.Print(string(out))
}
EOF
  go run "$tmp" "$payload_json"
  rm -f "$tmp"
}

assert_json_equal() {
  local left="$1"
  local right="$2"
  local label="$3"
  if [[ "$(canon_json "$left")" != "$(canon_json "$right")" ]]; then
    echo "$label responses differ on retry" >&2
    echo "first:  $(canon_json "$left")" >&2
    echo "second: $(canon_json "$right")" >&2
    exit 1
  fi
}

sign_webhook_signature() {
  local body="$1"
  local digest
  digest="$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -hex | awk '{print $2}')"
  printf 'sha256=%s' "$digest"
}

post_signed_webhook() {
  local body="$1"
  local event_id="$2"
  local signature_override="${3-}"
  local sig status tmp
  sig="${signature_override:-$(sign_webhook_signature "$body")}"
  tmp="$(mktemp)"
  status="$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "http://localhost:8083/exec/webhooks/esign/internal" \
    -H 'content-type: application/json' \
    -H "X-Webhook-Id: $event_id" \
    -H "X-Webhook-Signature: $sig" \
    -d "$body")"
  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "HTTP $status from signed webhook post" >&2
    echo "Response body:" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

post_signed_webhook_expect_status() {
  local expect_status="$1"
  local body="$2"
  local event_id="$3"
  local signature_override="${4-}"
  local sig status tmp
  sig="${signature_override:-$(sign_webhook_signature "$body")}"
  tmp="$(mktemp)"
  status="$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "http://localhost:8083/exec/webhooks/esign/internal" \
    -H 'content-type: application/json' \
    -H "X-Webhook-Id: $event_id" \
    -H "X-Webhook-Signature: $sig" \
    -d "$body")"
  if [[ "$status" != "$expect_status" ]]; then
    echo "Expected HTTP $expect_status from signed webhook post, got $status" >&2
    echo "Response body:" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    exit 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

echo "== Health checks =="
curl_json GET "http://localhost:8081/health" >/dev/null
curl_json GET "http://localhost:8082/health" >/dev/null
curl_json GET "http://localhost:8083/health" >/dev/null
echo "OK"

echo "== Create principal =="
PRINCIPAL="$(curl_json POST "$BASE_IAL/principals" \
  '{"name":"Acme Inc","jurisdiction":"US","timezone":"America/Los_Angeles"}')"
PRN="$(echo "$PRINCIPAL" | jq -er '.principal.principal_id')"
echo "principal_id=$PRN"

echo "== Create agent =="
AGENT="$(curl_json POST "$BASE_IAL/actors/agents" \
  "{\"principal_id\":\"$PRN\",\"name\":\"DealBot\",\"auth\":{\"mode\":\"HMAC\",\"scopes\":[\"cel.contracts:write\",\"cel.contracts:read\",\"exec.signatures:send\"]}}")"
AGT="$(echo "$AGENT" | jq -er '.agent.actor_id')"
AGENT_TOKEN="$(echo "$AGENT" | jq -er '.credentials.token')"
AGENT_AUTH="Authorization: Bearer $AGENT_TOKEN"
echo "agent_id=$AGT"

AGENT_LOW="$(curl_json POST "$BASE_IAL/actors/agents" \
  "{\"principal_id\":\"$PRN\",\"name\":\"ReadBot\",\"auth\":{\"mode\":\"HMAC\",\"scopes\":[\"exec.signatures:send\"]}}")"
AGT_LOW="$(echo "$AGENT_LOW" | jq -er '.agent.actor_id')"
AGENT_LOW_TOKEN="$(echo "$AGENT_LOW" | jq -er '.credentials.token')"
AGENT_LOW_AUTH="Authorization: Bearer $AGENT_LOW_TOKEN"

echo "== Subject mapping resolve/create =="
SUBJECT_KEY="ext-user-$RUN_ID"
curl_json_expect_status 400 POST "$BASE_IAL/subjects:resolve" \
  "{\"principal_id\":\"$PRN\",\"external_subject_id\":\"$SUBJECT_KEY\"}" \
  >/dev/null
SUB_CREATE="$(curl_json POST "$BASE_IAL/subjects:resolve" \
  "{\"principal_id\":\"$PRN\",\"external_subject_id\":\"$SUBJECT_KEY\",\"actor_type_if_needed\":\"AGENT\"}")"
SUB_ACTOR="$(echo "$SUB_CREATE" | jq -er '.subject.actor_id')"
SUB_TYPE="$(echo "$SUB_CREATE" | jq -er '.subject.actor_type')"
[[ "$SUB_TYPE" == "AGENT" ]] || { echo "Expected AGENT subject mapping, got $SUB_TYPE"; exit 1; }
SUB_GET="$(curl_json POST "$BASE_IAL/subjects:resolve" \
  "{\"principal_id\":\"$PRN\",\"external_subject_id\":\"$SUBJECT_KEY\"}")"
SUB_ACTOR_2="$(echo "$SUB_GET" | jq -er '.subject.actor_id')"
[[ "$SUB_ACTOR" == "$SUB_ACTOR_2" ]] || { echo "Expected stable actor mapping, got $SUB_ACTOR vs $SUB_ACTOR_2"; exit 1; }

echo "== Invite human (dev stub enrollment) =="
# NOTE: IAL MVP handler only accepts principal_id, invitee.email, requested_roles, expires_in_hours
INVRESP="$(curl_json POST "$BASE_IAL/invites" \
  "{\"principal_id\":\"$PRN\",\"invitee\":{\"email\":\"sam+$RUN_ID@acme.com\"},\"requested_roles\":[\"LEGAL\"],\"expires_in_hours\":72}")"
INV="$(echo "$INVRESP" | jq -er '.invite.invite_id')"

ENR="$(curl_json POST "$BASE_IAL/webauthn/register/finish" \
  "{\"invite_token\":\"dev:$INV\",\"attestation_response\":{}}")"
ACT_H="$(echo "$ENR" | jq -er '.actor.actor_id')"
HUMAN_EMAIL="sam+$RUN_ID@acme.com"
echo "human_actor_id=$ACT_H"

INVRESP2="$(curl_json POST "$BASE_IAL/invites" \
  "{\"principal_id\":\"$PRN\",\"invitee\":{\"email\":\"ops+$RUN_ID@acme.com\"},\"requested_roles\":[\"OPS\"],\"expires_in_hours\":72}")"
INV2="$(echo "$INVRESP2" | jq -er '.invite.invite_id')"
ENR2="$(curl_json POST "$BASE_IAL/webauthn/register/finish" \
  "{\"invite_token\":\"dev:$INV2\",\"attestation_response\":{}}")"
ACT_WRONG="$(echo "$ENR2" | jq -er '.actor.actor_id')"

echo "== Human auth magic-link (MVP-real) =="
ML_START="$(curl_json POST "$BASE_IAL/auth/magic-link/start" \
  "{\"principal_id\":\"$PRN\",\"email\":\"$HUMAN_EMAIL\",\"redirect_url\":\"https://platform.example/return\"}")"
ML_URL="$(echo "$ML_START" | jq -er '.magic_link_url')"
ML_TOKEN="$(echo "$ML_URL" | sed -E 's/.*token=([^&]+).*/\1/')"
ML_FINISH="$(curl_json POST "$BASE_IAL/auth/magic-link/finish" \
  "{\"token\":\"$ML_TOKEN\"}")"
HUMAN_SESSION_TOKEN="$(echo "$ML_FINISH" | jq -er '.credentials.token')"
HUMAN_AUTH="Authorization: Bearer $HUMAN_SESSION_TOKEN"
printf "export HUMAN_AUTH=%q\n" "$HUMAN_AUTH" >> /tmp/accords_env.sh
printf "export AGENT_AUTH=%q\n" "$AGENT_AUTH" >> /tmp/accords_env.sh
ME="$(curl_json GET "$BASE_IAL/auth/me" "" "$HUMAN_AUTH")"
ME_ACTOR="$(echo "$ME" | jq -er '.actor.actor_id')"
[[ "$ME_ACTOR" == "$ACT_H" ]] || { echo "Expected auth/me actor $ACT_H, got $ME_ACTOR"; exit 1; }

echo "== Set policy profile =="
curl_json PUT "$BASE_IAL/actors/$ACT_H/policy-profile" \
  "{\"principal_id\":\"$PRN\",\"automation_level\":\"A2_FAST_LANE\",\"action_gates\":{\"SEND_FOR_SIGNATURE\":\"FORCE_HUMAN\"},\"variable_rules\":[{\"for_type\":\"MONEY\",\"policy\":\"AGENT_FILL_HUMAN_REVIEW\"},{\"for_key\":\"party_address\",\"policy\":\"HUMAN_REQUIRED\"}]}" \
  >/dev/null

echo "== Seed template (CEL dev endpoint) =="
curl_json POST "$BASE_CEL/dev/seed-template" \
  "{\"principal_id\":\"$PRN\"}" \
  >/dev/null

TPLS="$(curl_json GET "$BASE_CEL/templates?contract_type=NDA&jurisdiction=US")"
TPL="$(echo "$TPLS" | jq -er '.templates[0].template_id')"
echo "template_id=$TPL"

GOV="$(curl_json GET "$BASE_CEL/templates/$TPL/governance")"
PARTY_POLICY="$(echo "$GOV" | jq -er '.variables[] | select((.key // .Key)=="party_address") | (.set_policy // .SetPolicy)')"
PRICE_POLICY="$(echo "$GOV" | jq -er '.variables[] | select((.key // .Key)=="price") | (.set_policy // .SetPolicy)')"
ACTION_GATE="$(echo "$GOV" | jq -er '.template_gates.SEND_FOR_SIGNATURE')"
[[ "$PARTY_POLICY" == "DEFER_TO_IDENTITY" ]] || { echo "Expected party_address DEFER_TO_IDENTITY, got $PARTY_POLICY"; exit 1; }
[[ "$PRICE_POLICY" == "DEFER_TO_IDENTITY" ]] || { echo "Expected price DEFER_TO_IDENTITY, got $PRICE_POLICY"; exit 1; }
[[ "$ACTION_GATE" == "DEFER" ]] || { echo "Expected SEND_FOR_SIGNATURE template gate DEFER, got $ACTION_GATE"; exit 1; }

curl_json POST "$BASE_CEL/principals/$PRN/templates/$TPL/enable" \
  "{\"enabled_by_actor_id\":\"$ACT_H\",\"override_gates\":{}}" \
  >/dev/null

echo "== Compliance program create/publish =="
PROG_CREATE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"prog-create-$RUN_ID\"},\"key\":\"terms_current\",\"mode\":\"STRICT_RECONSENT\"}"
PROG_CREATE="$(curl_json POST "$BASE_CEL/programs" "$PROG_CREATE_REQ" "$AGENT_AUTH")"
PROG_CREATE_REPLAY="$(curl_json POST "$BASE_CEL/programs" "$PROG_CREATE_REQ" "$AGENT_AUTH")"
assert_json_equal "$PROG_CREATE" "$PROG_CREATE_REPLAY" "programs:create"
PROG_MODE="$(echo "$PROG_CREATE" | jq -er '.program.mode')"
[[ "$PROG_MODE" == "STRICT_RECONSENT" ]] || { echo "Expected STRICT_RECONSENT, got $PROG_MODE"; exit 1; }

PROG_GET="$(curl_json GET "$BASE_CEL/programs/terms_current" "" "$AGENT_AUTH")"
PROG_KEY="$(echo "$PROG_GET" | jq -er '.program.key')"
[[ "$PROG_KEY" == "terms_current" ]] || { echo "Expected terms_current key, got $PROG_KEY"; exit 1; }

PROG_PUBLISH_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"prog-publish-$RUN_ID\"},\"required_template_id\":\"$TPL\",\"required_template_version\":\"v1\"}"
PROG_PUBLISH="$(curl_json POST "$BASE_CEL/programs/terms_current/publish" "$PROG_PUBLISH_REQ" "$AGENT_AUTH")"
PROG_PUBLISH_REPLAY="$(curl_json POST "$BASE_CEL/programs/terms_current/publish" "$PROG_PUBLISH_REQ" "$AGENT_AUTH")"
assert_json_equal "$PROG_PUBLISH" "$PROG_PUBLISH_REPLAY" "programs:publish"
PROG_REQUIRED_TEMPLATE="$(echo "$PROG_PUBLISH" | jq -er '.program.required_template_id')"
PROG_REQUIRED_VERSION="$(echo "$PROG_PUBLISH" | jq -er '.program.required_template_version')"
[[ "$PROG_REQUIRED_TEMPLATE" == "$TPL" ]] || { echo "Expected required template $TPL, got $PROG_REQUIRED_TEMPLATE"; exit 1; }
[[ "$PROG_REQUIRED_VERSION" == "v1" ]] || { echo "Expected required template version v1, got $PROG_REQUIRED_VERSION"; exit 1; }

echo "== Tenant isolation hardening =="
PRINCIPAL_T2="$(curl_json POST "$BASE_IAL/principals" \
  '{"name":"Other Inc","jurisdiction":"US","timezone":"America/New_York"}')"
PRN_T2="$(echo "$PRINCIPAL_T2" | jq -er '.principal.principal_id')"
AGENT_T2="$(curl_json POST "$BASE_IAL/actors/agents" \
  "{\"principal_id\":\"$PRN_T2\",\"name\":\"OtherBot\",\"auth\":{\"mode\":\"HMAC\",\"scopes\":[\"cel.contracts:write\",\"cel.contracts:read\",\"exec.signatures:send\"]}}")"
AGENT_T2_TOKEN="$(echo "$AGENT_T2" | jq -er '.credentials.token')"
AGENT_T2_ID="$(echo "$AGENT_T2" | jq -er '.agent.actor_id')"
AGENT_T2_AUTH="Authorization: Bearer $AGENT_T2_TOKEN"

# Cross-tenant program read denied.
curl_json_expect_status 404 GET "$BASE_CEL/programs/terms_current" "" "$AGENT_T2_AUTH" >/dev/null

# Cross-tenant program publish/write denied by actor/principal mismatch.
T2_PUBLISH_BAD_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGENT_T2_ID\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"t2-pub-$RUN_ID\"},\"required_template_id\":\"$TPL\",\"required_template_version\":\"vX\"}"
curl_json_expect_status 403 POST "$BASE_CEL/programs/terms_current/publish" "$T2_PUBLISH_BAD_REQ" "$AGENT_T2_AUTH" >/dev/null

# Create an isolated terms_current program in tenant-2 for gate isolation checks.
T2_PROG_CREATE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN_T2\",\"actor_id\":\"$AGENT_T2_ID\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"t2-create-$RUN_ID\"},\"key\":\"terms_current\",\"mode\":\"STRICT_RECONSENT\"}"
curl_json POST "$BASE_CEL/programs" "$T2_PROG_CREATE_REQ" "$AGENT_T2_AUTH" >/dev/null
T2_PROG_PUBLISH_REQ="{\"actor_context\":{\"principal_id\":\"$PRN_T2\",\"actor_id\":\"$AGENT_T2_ID\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"t2-publish-$RUN_ID\"},\"required_template_id\":\"$TPL\",\"required_template_version\":\"v1\"}"
curl_json POST "$BASE_CEL/programs/terms_current/publish" "$T2_PROG_PUBLISH_REQ" "$AGENT_T2_AUTH" >/dev/null

echo "== Gate status read path =="
GATE_UNKNOWN="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=ext-gate-$RUN_ID" "" "$AGENT_AUTH")"
GATE_UNKNOWN_STATUS="$(echo "$GATE_UNKNOWN" | jq -er '.status')"
GATE_UNKNOWN_STEP="$(echo "$GATE_UNKNOWN" | jq -er '.next_step.type')"
[[ "$GATE_UNKNOWN_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED gate for unknown subject, got $GATE_UNKNOWN"; exit 1; }
[[ "$GATE_UNKNOWN_STEP" == "FILL_VARIABLES" ]] || { echo "Expected FILL_VARIABLES for unknown subject, got $GATE_UNKNOWN"; exit 1; }

GATE_ENROLL="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=ext-gate-$RUN_ID&actor_type=HUMAN" "" "$AGENT_AUTH")"
GATE_ENROLL_STATUS="$(echo "$GATE_ENROLL" | jq -er '.status')"
GATE_SUBJECT_ACTOR="$(echo "$GATE_ENROLL" | jq -er '.subject.actor_id')"
[[ "$GATE_ENROLL_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED after subject auto-enroll, got $GATE_ENROLL"; exit 1; }

GATE_CONTRACT_CREATE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$GATE_SUBJECT_ACTOR\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"gate-c-$RUN_ID\"},\"template_id\":\"$TPL\",\"counterparty\":{\"name\":\"Gate Vendor\",\"email\":\"gate@vendorx.com\"},\"initial_variables\":{\"effective_date\":\"2026-02-16\"}}"
GATE_CTR="$(curl_json POST "$BASE_CEL/contracts" "$GATE_CONTRACT_CREATE_REQ")"
GATE_CID="$(echo "$GATE_CTR" | jq -er '.contract.contract_id')"

GATE_SEND_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$GATE_SUBJECT_ACTOR\",\"actor_type\":\"HUMAN\"}}"
curl_json POST "$BASE_CEL/contracts/$GATE_CID:sendForSignature" "$GATE_SEND_REQ" "$AGENT_AUTH" >/dev/null
GATE_SIG="$(curl_json GET "$BASE_CEL/contracts/$GATE_CID/signature")"
GATE_ENV="$(echo "$GATE_SIG" | jq -er '.signature.envelope_id')"
post_signed_webhook \
  "{\"envelope_id\":\"$GATE_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke-gate\"}}" \
  "wh-gate-$RUN_ID" \
  >/dev/null

GATE_DONE="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=ext-gate-$RUN_ID" "" "$AGENT_AUTH")"
GATE_DONE_STATUS="$(echo "$GATE_DONE" | jq -er '.status')"
[[ "$GATE_DONE_STATUS" == "DONE" ]] || { echo "Expected DONE for effective subject contract, got $GATE_DONE"; exit 1; }

echo "== Gate resolve orchestrator =="
GATE_RESOLVE_REQ="{\"external_subject_id\":\"ext-resolve-$RUN_ID\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"gr1-$RUN_ID\",\"client_return_url\":\"https://app.example.com/return\"}"
GATE_RESOLVE_1="$(curl_json POST "$BASE_CEL/gates/terms_current/resolve" "$GATE_RESOLVE_REQ" "$AGENT_AUTH")"
GATE_RESOLVE_2="$(curl_json POST "$BASE_CEL/gates/terms_current/resolve" "$GATE_RESOLVE_REQ" "$AGENT_AUTH")"
assert_json_equal "$GATE_RESOLVE_1" "$GATE_RESOLVE_2" "gates:resolve"
GR_STATUS="$(echo "$GATE_RESOLVE_1" | jq -er '.status')"
GR_CONTINUE_URL="$(echo "$GATE_RESOLVE_1" | jq -er '.remediation.continue_url')"
GR_CONTRACT_ID="$(echo "$GATE_RESOLVE_1" | jq -er '.contract_id')"
[[ "$GR_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED from resolve before signature completion, got $GATE_RESOLVE_1"; exit 1; }
[[ "$GR_CONTINUE_URL" == https://* ]] || { echo "Expected provider continue_url, got $GR_CONTINUE_URL"; exit 1; }
[[ -n "$GR_CONTRACT_ID" ]] || { echo "Expected contract_id from resolve"; exit 1; }

GR_SIG="$(curl_json GET "$BASE_CEL/contracts/$GR_CONTRACT_ID/signature")"
GR_ENV="$(echo "$GR_SIG" | jq -er '.signature.envelope_id')"
post_signed_webhook \
  "{\"envelope_id\":\"$GR_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke-gate-resolve\"}}" \
  "wh-gate-resolve-$RUN_ID" \
  >/dev/null
GR_DONE="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=ext-resolve-$RUN_ID" "" "$AGENT_AUTH")"
GR_DONE_STATUS="$(echo "$GR_DONE" | jq -er '.status')"
[[ "$GR_DONE_STATUS" == "DONE" ]] || { echo "Expected DONE after gate resolve webhook completion, got $GR_DONE"; exit 1; }

echo "== Gate resolve concurrent dedupe =="
CON_SUBJECT="ext-concurrent-$RUN_ID"
CON_REQ_A="{\"external_subject_id\":\"$CON_SUBJECT\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"con-a-$RUN_ID\"}"
CON_REQ_B="{\"external_subject_id\":\"$CON_SUBJECT\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"con-b-$RUN_ID\"}"
CON_TMP_A="$(mktemp)"
CON_TMP_B="$(mktemp)"
curl -sS -X POST "$BASE_CEL/gates/terms_current/resolve" -H 'content-type: application/json' -H "$AGENT_AUTH" -d "$CON_REQ_A" >"$CON_TMP_A" &
PID_A=$!
curl -sS -X POST "$BASE_CEL/gates/terms_current/resolve" -H 'content-type: application/json' -H "$AGENT_AUTH" -d "$CON_REQ_B" >"$CON_TMP_B" &
PID_B=$!
wait "$PID_A"
wait "$PID_B"
CON_RES_A="$(cat "$CON_TMP_A")"
CON_RES_B="$(cat "$CON_TMP_B")"
rm -f "$CON_TMP_A" "$CON_TMP_B"

CON_STATUS_A="$(echo "$CON_RES_A" | jq -er '.status')"
CON_STATUS_B="$(echo "$CON_RES_B" | jq -er '.status')"
CON_CID_A="$(echo "$CON_RES_A" | jq -er '.contract_id')"
CON_CID_B="$(echo "$CON_RES_B" | jq -er '.contract_id')"
CON_URL_A="$(echo "$CON_RES_A" | jq -er '.remediation.continue_url')"
CON_URL_B="$(echo "$CON_RES_B" | jq -er '.remediation.continue_url')"
[[ "$CON_STATUS_A" == "BLOCKED" ]] || { echo "Expected BLOCKED for concurrent resolve A, got $CON_RES_A"; exit 1; }
[[ "$CON_STATUS_B" == "BLOCKED" ]] || { echo "Expected BLOCKED for concurrent resolve B, got $CON_RES_B"; exit 1; }
[[ "$CON_CID_A" == "$CON_CID_B" ]] || { echo "Expected same contract_id under concurrent resolve, got $CON_CID_A vs $CON_CID_B"; exit 1; }
[[ "$CON_URL_A" == "$CON_URL_B" ]] || { echo "Expected same continue_url under concurrent resolve, got $CON_URL_A vs $CON_URL_B"; exit 1; }

CON_SIG="$(curl_json GET "$BASE_CEL/contracts/$CON_CID_A/signature")"
CON_ENV="$(echo "$CON_SIG" | jq -er '.signature.envelope_id')"
[[ -n "$CON_ENV" ]] || { echo "Expected envelope for concurrent resolve contract"; exit 1; }

echo "== Platform integration flow + strict re-consent roll-forward =="
PLAT_SUBJECT="ext-platform-$RUN_ID"

# v1 required; status should be blocked before first resolve.
PLAT_STATUS_V1_1="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=$PLAT_SUBJECT" "" "$AGENT_AUTH")"
PLAT_STATUS_V1_1_STATUS="$(echo "$PLAT_STATUS_V1_1" | jq -er '.status')"
[[ "$PLAT_STATUS_V1_1_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED for fresh platform subject, got $PLAT_STATUS_V1_1"; exit 1; }

PLAT_RESOLVE_V1_REQ="{\"external_subject_id\":\"$PLAT_SUBJECT\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"plat-r1-$RUN_ID\"}"
PLAT_RESOLVE_V1="$(curl_json POST "$BASE_CEL/gates/terms_current/resolve" "$PLAT_RESOLVE_V1_REQ" "$AGENT_AUTH")"
PLAT_RESOLVE_V1_STATUS="$(echo "$PLAT_RESOLVE_V1" | jq -er '.status')"
PLAT_RESOLVE_V1_URL="$(echo "$PLAT_RESOLVE_V1" | jq -er '.remediation.continue_url')"
PLAT_V1_CONTRACT_ID="$(echo "$PLAT_RESOLVE_V1" | jq -er '.contract_id')"
[[ "$PLAT_RESOLVE_V1_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED while signature pending (v1), got $PLAT_RESOLVE_V1"; exit 1; }
[[ "$PLAT_RESOLVE_V1_URL" == https://* ]] || { echo "Expected continue_url for v1 resolve, got $PLAT_RESOLVE_V1_URL"; exit 1; }

PLAT_V1_SIG="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V1_CONTRACT_ID/signature")"
PLAT_V1_ENV="$(echo "$PLAT_V1_SIG" | jq -er '.signature.envelope_id')"
post_signed_webhook \
  "{\"envelope_id\":\"$PLAT_V1_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke-platform-v1\"}}" \
  "wh-platform-v1-$RUN_ID" \
  >/dev/null

PLAT_STATUS_V1_2="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=$PLAT_SUBJECT" "" "$AGENT_AUTH")"
PLAT_STATUS_V1_2_STATUS="$(echo "$PLAT_STATUS_V1_2" | jq -er '.status')"
[[ "$PLAT_STATUS_V1_2_STATUS" == "DONE" ]] || { echo "Expected DONE after v1 completion, got $PLAT_STATUS_V1_2"; exit 1; }

# Publish v2 for same program: strict re-consent should block again.
PROG_PUBLISH_V2_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"prog-publish-v2-$RUN_ID\"},\"required_template_id\":\"$TPL\",\"required_template_version\":\"v2\"}"
PROG_PUBLISH_V2="$(curl_json POST "$BASE_CEL/programs/terms_current/publish" "$PROG_PUBLISH_V2_REQ" "$AGENT_AUTH")"
PROG_PUBLISH_V2_VERSION="$(echo "$PROG_PUBLISH_V2" | jq -er '.program.required_template_version')"
[[ "$PROG_PUBLISH_V2_VERSION" == "v2" ]] || { echo "Expected required template version v2 after publish, got $PROG_PUBLISH_V2"; exit 1; }

PLAT_STATUS_V2_1="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=$PLAT_SUBJECT" "" "$AGENT_AUTH")"
PLAT_STATUS_V2_1_STATUS="$(echo "$PLAT_STATUS_V2_1" | jq -er '.status')"
[[ "$PLAT_STATUS_V2_1_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED after strict re-consent v2 publish, got $PLAT_STATUS_V2_1"; exit 1; }

PLAT_RESOLVE_V2_REQ="{\"external_subject_id\":\"$PLAT_SUBJECT\",\"idempotency_key\":\"plat-r2-$RUN_ID\"}"
PLAT_RESOLVE_V2="$(curl_json POST "$BASE_CEL/gates/terms_current/resolve" "$PLAT_RESOLVE_V2_REQ" "$AGENT_AUTH")"
PLAT_RESOLVE_V2_STATUS="$(echo "$PLAT_RESOLVE_V2" | jq -er '.status')"
PLAT_RESOLVE_V2_URL="$(echo "$PLAT_RESOLVE_V2" | jq -er '.remediation.continue_url')"
PLAT_V2_CONTRACT_ID="$(echo "$PLAT_RESOLVE_V2" | jq -er '.contract_id')"
[[ "$PLAT_RESOLVE_V2_STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED while signature pending (v2), got $PLAT_RESOLVE_V2"; exit 1; }
[[ "$PLAT_RESOLVE_V2_URL" == https://* ]] || { echo "Expected continue_url for v2 resolve, got $PLAT_RESOLVE_V2_URL"; exit 1; }
[[ "$PLAT_V1_CONTRACT_ID" != "$PLAT_V2_CONTRACT_ID" ]] || { echo "Expected distinct contracts for v1 and v2 strict re-consent"; exit 1; }

PLAT_V2_SIG="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/signature")"
PLAT_V2_ENV="$(echo "$PLAT_V2_SIG" | jq -er '.signature.envelope_id')"
post_signed_webhook \
  "{\"envelope_id\":\"$PLAT_V2_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke-platform-v2\"}}" \
  "wh-platform-v2-$RUN_ID" \
  >/dev/null

PLAT_STATUS_V2_2="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=$PLAT_SUBJECT" "" "$AGENT_AUTH")"
PLAT_STATUS_V2_2_STATUS="$(echo "$PLAT_STATUS_V2_2" | jq -er '.status')"
[[ "$PLAT_STATUS_V2_2_STATUS" == "DONE" ]] || { echo "Expected DONE after v2 completion, got $PLAT_STATUS_V2_2"; exit 1; }

# Same external subject queried from tenant-2 must not see tenant-1 DONE.
T2_PLAT_STATUS="$(curl_json GET "$BASE_CEL/gates/terms_current/status?external_subject_id=$PLAT_SUBJECT&actor_type=HUMAN" "" "$AGENT_T2_AUTH")"
T2_PLAT_STATUS_VAL="$(echo "$T2_PLAT_STATUS" | jq -er '.status')"
[[ "$T2_PLAT_STATUS_VAL" != "DONE" ]] || { echo "Expected tenant-2 status to not be DONE for tenant-1 subject, got $T2_PLAT_STATUS"; exit 1; }

echo "== Compliance evidence export =="
PLAT_EVIDENCE="$(curl_json GET "$BASE_CEL/gates/terms_current/evidence?external_subject_id=$PLAT_SUBJECT" "" "$AGENT_AUTH")"
PLAT_EVIDENCE_CONTRACT_ID="$(echo "$PLAT_EVIDENCE" | jq -er '.evidence.accepted.contract_id')"
PLAT_EVIDENCE_TEMPLATE_VERSION="$(echo "$PLAT_EVIDENCE" | jq -er '.evidence.accepted.template_version')"
PLAT_EVIDENCE_PACKET_HASH="$(echo "$PLAT_EVIDENCE" | jq -er '.evidence.accepted.packet_hash')"
PLAT_EVIDENCE_ENVELOPE_ID="$(echo "$PLAT_EVIDENCE" | jq -er '.evidence.accepted.signature_reference.envelope_id')"
[[ "$PLAT_EVIDENCE_CONTRACT_ID" == "$PLAT_V2_CONTRACT_ID" ]] || { echo "Expected evidence to reference latest effective v2 contract"; exit 1; }
[[ "$PLAT_EVIDENCE_TEMPLATE_VERSION" == "v2" ]] || { echo "Expected evidence template_version v2, got $PLAT_EVIDENCE_TEMPLATE_VERSION"; exit 1; }
[[ "$PLAT_EVIDENCE_PACKET_HASH" == sha256:* ]] || { echo "Expected packet hash in evidence, got $PLAT_EVIDENCE_PACKET_HASH"; exit 1; }
[[ -n "$PLAT_EVIDENCE_ENVELOPE_ID" ]] || { echo "Expected envelope reference in evidence"; exit 1; }

CTR_EVIDENCE="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/evidence" "" "$AGENT_AUTH")"
CTR_EVIDENCE_CID="$(echo "$CTR_EVIDENCE" | jq -er '.contract.contract_id')"
CTR_EVIDENCE_BUNDLE_VERSION="$(echo "$CTR_EVIDENCE" | jq -er '.bundle_version')"
CTR_EVIDENCE_BH="$(echo "$CTR_EVIDENCE" | jq -er '.hashes.bundle_hash')"
CTR_EVIDENCE_HAS_CONTRACT="$(echo "$CTR_EVIDENCE" | jq -er '[.manifest.artifacts[] | select(.artifact_type=="contract_record")] | length')"
CTR_EVIDENCE_HAS_RENDER="$(echo "$CTR_EVIDENCE" | jq -er '[.manifest.artifacts[] | select(.artifact_type=="render")] | length')"
CTR_EVIDENCE_HAS_WEBHOOKS="$(echo "$CTR_EVIDENCE" | jq -er '[.manifest.artifacts[] | select(.artifact_type=="webhook_receipts")] | length')"
CTR_EVIDENCE_WEBHOOKS_IS_ARRAY="$(echo "$CTR_EVIDENCE" | jq -er '.artifacts.webhook_receipts | type')"
CTR_EVIDENCE_HAS_ANCHORS="$(echo "$CTR_EVIDENCE" | jq -er '[.manifest.artifacts[] | select(.artifact_type=="anchors")] | length')"
CTR_EVIDENCE_ANCHORS_IS_ARRAY="$(echo "$CTR_EVIDENCE" | jq -er '.artifacts.anchors | type')"
[[ "$CTR_EVIDENCE_CID" == "$PLAT_V2_CONTRACT_ID" ]] || { echo "Expected contract evidence to reference requested contract"; exit 1; }
[[ "$CTR_EVIDENCE_BUNDLE_VERSION" == "evidence-v1" ]] || { echo "Expected evidence-v1 bundle, got $CTR_EVIDENCE_BUNDLE_VERSION"; exit 1; }
[[ "$CTR_EVIDENCE_BH" == sha256:* ]] || { echo "Expected bundle_hash in contract evidence"; exit 1; }
[[ "$CTR_EVIDENCE_HAS_CONTRACT" -ge 1 ]] || { echo "Expected contract_record artifact"; exit 1; }
[[ "$CTR_EVIDENCE_HAS_RENDER" -ge 1 ]] || { echo "Expected render artifact"; exit 1; }
[[ "$CTR_EVIDENCE_HAS_WEBHOOKS" -ge 1 ]] || { echo "Expected webhook_receipts artifact"; exit 1; }
[[ "$CTR_EVIDENCE_WEBHOOKS_IS_ARRAY" == "array" ]] || { echo "Expected webhook_receipts payload to be array"; exit 1; }
[[ "$CTR_EVIDENCE_HAS_ANCHORS" -ge 1 ]] || { echo "Expected anchors artifact"; exit 1; }
[[ "$CTR_EVIDENCE_ANCHORS_IS_ARRAY" == "array" ]] || { echo "Expected anchors payload to be array"; exit 1; }

echo "== Proof anchors =="
ANCHORS_LIST_BEFORE="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/anchors" "" "$AGENT_AUTH")"
ANCHORS_LIST_BEFORE_COUNT="$(echo "$ANCHORS_LIST_BEFORE" | jq -er '.anchors | length')"
ANCHOR_RFC3161_CREATE="$(curl_json_expect_status 200 POST "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/anchors" \
  '{"target":"bundle_hash","anchor_type":"rfc3161","request":{"tsa_url":"https://tsa.example.invalid","policy_oid":"1.2.3.4.5","ignored":"x"}}' \
  "$AGENT_AUTH" \
  "Idempotency-Key: anc-rfc3161-$RUN_ID")"
ANCHOR_RFC3161_STATUS="$(echo "$ANCHOR_RFC3161_CREATE" | jq -er '.anchor.status')"
ANCHOR_RFC3161_TYPE="$(echo "$ANCHOR_RFC3161_CREATE" | jq -er '.anchor.anchor_type')"
if [[ "$ANCHOR_RFC3161_STATUS" == "FAILED" ]]; then
  ANCHOR_RFC3161_ERROR="$(echo "$ANCHOR_RFC3161_CREATE" | jq -er '.anchor.proof.error_code')"
  [[ -n "$ANCHOR_RFC3161_ERROR" ]] || { echo "Expected deterministic error_code for failed rfc3161 anchor"; exit 1; }
elif [[ "$ANCHOR_RFC3161_STATUS" == "CONFIRMED" ]]; then
  ANCHOR_RFC3161_TOKEN="$(echo "$ANCHOR_RFC3161_CREATE" | jq -er '.anchor.proof.timestamp_token_b64')"
  [[ -n "$ANCHOR_RFC3161_TOKEN" ]] || { echo "Expected timestamp_token_b64 for confirmed rfc3161 anchor"; exit 1; }
else
  echo "Expected FAILED or CONFIRMED rfc3161 anchor, got $ANCHOR_RFC3161_CREATE"
  exit 1
fi
[[ "$ANCHOR_RFC3161_TYPE" == "rfc3161" ]] || { echo "Expected rfc3161 anchor type, got $ANCHOR_RFC3161_CREATE"; exit 1; }
ANCHORS_LIST_AFTER_RFC3161="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/anchors" "" "$AGENT_AUTH")"
ANCHORS_LIST_AFTER_RFC3161_COUNT="$(echo "$ANCHORS_LIST_AFTER_RFC3161" | jq -er '.anchors | length')"
[[ "$ANCHORS_LIST_AFTER_RFC3161_COUNT" -eq $((ANCHORS_LIST_BEFORE_COUNT + 1)) ]] || { echo "Expected one new rfc3161 anchor row"; exit 1; }

ANCHOR_CREATE="$(curl_json POST "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/anchors" \
  '{"target":"bundle_hash","anchor_type":"dev_stub","request":{"source":"smoke"}}' \
  "$AGENT_AUTH" \
  "Idempotency-Key: anc-$RUN_ID")"
ANCHOR_STATUS="$(echo "$ANCHOR_CREATE" | jq -er '.anchor.status')"
ANCHOR_DEV_STUB="$(echo "$ANCHOR_CREATE" | jq -er '.anchor.proof.dev_stub')"
[[ "$ANCHOR_STATUS" == "CONFIRMED" ]] || { echo "Expected confirmed dev stub anchor, got $ANCHOR_CREATE"; exit 1; }
[[ "$ANCHOR_DEV_STUB" == "true" ]] || { echo "Expected dev_stub proof marker in anchor response"; exit 1; }
ANCHORS_LIST="$(curl_json GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/anchors" "" "$AGENT_AUTH")"
ANCHORS_LIST_COUNT="$(echo "$ANCHORS_LIST" | jq -er '.anchors | length')"
[[ "$ANCHORS_LIST_COUNT" -ge 1 ]] || { echo "Expected at least one anchor in list response"; exit 1; }

# Cross-tenant evidence read denied.
curl_json_expect_status 404 GET "$BASE_CEL/contracts/$PLAT_V2_CONTRACT_ID/evidence" "" "$AGENT_T2_AUTH" >/dev/null

CREATE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"c1-$RUN_ID\"},\"template_id\":\"$TPL\",\"counterparty\":{\"name\":\"Vendor X\",\"email\":\"legal@vendorx.com\"},\"initial_variables\":{\"effective_date\":\"2026-02-16\"}}"
curl_json_expect_status 401 POST "$BASE_CEL/contracts" "$CREATE_REQ"
LOW_CREATE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT_LOW\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"c0-$RUN_ID\"},\"template_id\":\"$TPL\",\"counterparty\":{\"name\":\"Vendor X\",\"email\":\"legal@vendorx.com\"},\"initial_variables\":{\"effective_date\":\"2026-02-16\"}}"
curl_json_expect_status 403 POST "$BASE_CEL/contracts" "$LOW_CREATE_REQ" "$AGENT_LOW_AUTH"
CTR="$(curl_json POST "$BASE_CEL/contracts" "$CREATE_REQ" "$AGENT_AUTH")"
CTR_REPLAY="$(curl_json POST "$BASE_CEL/contracts" "$CREATE_REQ" "$AGENT_AUTH")"
assert_json_equal "$CTR" "$CTR_REPLAY" "contracts:create"
CID="$(echo "$CTR" | jq -er '.contract.contract_id')"
echo "contract_id=$CID"
printf "export CONTRACT_ID=%q\n" "$CID" >> /tmp/accords_env.sh

CHG_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\"},\"changeset\":{\"variables\":{},\"clauses\":[{\"op\":\"replace\",\"target\":\"clause.confidentiality\",\"value\":\"Mutual NDA\"}]},\"required_roles\":[\"LEGAL\"]}"
CHG_CREATE="$(curl_json POST "$BASE_CEL/contracts/$CID/changesets" "$CHG_REQ" "$AGENT_AUTH")"
CHG_ID="$(echo "$CHG_CREATE" | jq -er '.changeset.changeset_id')"
CHG_DECIDE_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\"},\"decision\":\"APPROVE\"}"
CHG_DECIDE="$(curl_json POST "$BASE_CEL/changesets/$CHG_ID:decide" "$CHG_DECIDE_REQ")"
CHG_STATUS="$(echo "$CHG_DECIDE" | jq -er '.status')"
[[ "$CHG_STATUS" == "APPROVED" ]] || { echo "Expected APPROVED changeset, got $CHG_DECIDE"; exit 1; }
CHG_APPLY_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\"}}"
CHG_APPLY="$(curl_json POST "$BASE_CEL/changesets/$CHG_ID:apply" "$CHG_APPLY_REQ" "$AGENT_AUTH")"
CHG_APPLY_STATUS="$(echo "$CHG_APPLY" | jq -er '.status')"
[[ "$CHG_APPLY_STATUS" == "APPLIED" ]] || { echo "Expected APPLIED changeset, got $CHG_APPLY"; exit 1; }

BULK1_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"v1-$RUN_ID\"},\"variables\":{\"party_address\":\"123 Main St\",\"price\":\"USD 120000.00\"}}"
BULK1="$(curl_json POST "$BASE_CEL/contracts/$CID/variables:bulkSet" "$BULK1_REQ" "$AGENT_AUTH")"
BULK1_REPLAY="$(curl_json POST "$BASE_CEL/contracts/$CID/variables:bulkSet" "$BULK1_REQ" "$AGENT_AUTH")"
assert_json_equal "$BULK1" "$BULK1_REPLAY" "variables:bulkSet(agent)"

A1_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a1-$RUN_ID\"}}"
curl_json_expect_status 401 POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" "$A1_REQ"
RES="$(curl_json POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" "$A1_REQ" "$AGENT_AUTH")"
RES_REPLAY="$(curl_json POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" "$A1_REQ" "$AGENT_AUTH")"
assert_json_equal "$RES" "$RES_REPLAY" "actions/SEND_FOR_SIGNATURE(a1)"
STATUS="$(echo "$RES" | jq -er '.status')"
[[ "$STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED, got $RES"; exit 1; }

curl_json POST "$BASE_CEL/contracts/$CID/variables:bulkSet" \
  "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"v2-$RUN_ID\"},\"variables\":{\"party_address\":\"123 Main St\"}}" \
  >/dev/null

RES2="$(curl_json POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a2-$RUN_ID\"}}" \
  "$AGENT_AUTH")"
NST="$(echo "$RES2" | jq -er '.next_step.type')"
[[ "$NST" == "REVIEW_VARIABLES" ]] || { echo "Expected REVIEW_VARIABLES, got $RES2"; exit 1; }

curl_json POST "$BASE_CEL/contracts/$CID/variables:review" \
  "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"vr1-$RUN_ID\"},\"decision\":\"APPROVE\",\"keys\":[\"price\"]}" \
  >/dev/null

RES3="$(curl_json POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a3-$RUN_ID\"}}" \
  "$AGENT_AUTH")"
NST2="$(echo "$RES3" | jq -er '.next_step.type')"
[[ "$NST2" == "APPROVE_ACTION" ]] || { echo "Expected APPROVE_ACTION, got $RES3"; exit 1; }
APRQ="$(echo "$RES3" | jq -er '.next_step.approval_request_id')"

SIGNED_PAYLOAD="$(jq -cn \
  --arg cid "$CID" \
  --arg aprq "$APRQ" \
  --arg nonce "n1-$RUN_ID" \
  '{contract_id:$cid,approval_request_id:$aprq,packet_hash:"sha256:dev",diff_hash:"sha256:dev",risk_hash:"sha256:dev",nonce:$nonce}')"
SIG_V1_ENVELOPE="$(gen_sig_v1_envelope "$SIGNED_PAYLOAD")"
AD_REQ="$(jq -cn \
  --arg prn "$PRN" \
  --arg act "$ACT_H" \
  --arg idem "ad1-$RUN_ID" \
  --argjson signed_payload "$SIGNED_PAYLOAD" \
  --argjson signature_envelope "$SIG_V1_ENVELOPE" \
  '{actor_context:{principal_id:$prn,actor_id:$act,actor_type:"HUMAN",idempotency_key:$idem},decision:"APPROVE",signed_payload:$signed_payload,signature_envelope:$signature_envelope}')"
WRONG_ROLE_AD_REQ="{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_WRONG\",\"actor_type\":\"HUMAN\"},\"decision\":\"APPROVE\",\"signed_payload\":{\"contract_id\":\"$CID\",\"approval_request_id\":\"$APRQ\",\"packet_hash\":\"sha256:dev\",\"diff_hash\":\"sha256:dev\",\"risk_hash\":\"sha256:dev\",\"nonce\":\"n-wrong-$RUN_ID\"},\"signature\":{\"type\":\"WEBAUTHN_ASSERTION\",\"assertion_response\":{}}}"
curl_json_expect_status 403 POST "$BASE_CEL/approvals/$APRQ:decide" "$WRONG_ROLE_AD_REQ"
AD1="$(curl_json POST "$BASE_CEL/approvals/$APRQ:decide" "$AD_REQ" "$HUMAN_AUTH")"
AD2="$(curl_json POST "$BASE_CEL/approvals/$APRQ:decide" "$AD_REQ" "$HUMAN_AUTH")"
assert_json_equal "$AD1" "$AD2" "approvals:decide"

RES4="$(curl_json POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a4-$RUN_ID\"}}" \
  "$AGENT_AUTH")"
STATUS4="$(echo "$RES4" | jq -er '.status')"
[[ "$STATUS4" == "DONE" ]] || { echo "Expected DONE, got $RES4"; exit 1; }

CTR_STATE="$(curl_json GET "$BASE_CEL/contracts/$CID")"
STATE="$(echo "$CTR_STATE" | jq -er '.contract.state')"
[[ "$STATE" == "SIGNATURE_SENT" ]] || { echo "Expected SIGNATURE_SENT, got $STATE"; exit 1; }

SIG="$(curl_json GET "$BASE_CEL/contracts/$CID/signature")"
SIG_STATUS="$(echo "$SIG" | jq -er '.signature.status')"
SIG_ENV="$(echo "$SIG" | jq -er '.signature.envelope_id')"
SIG_URL="$(echo "$SIG" | jq -er '.signature.signing_url')"
SIG_RECIPIENTS="$(echo "$SIG" | jq -er '.signature.recipients | length')"
[[ "$SIG_STATUS" == "SENT" ]] || { echo "Expected envelope status SENT, got $SIG_STATUS"; exit 1; }
[[ -n "$SIG_ENV" ]] || { echo "Expected non-empty envelope_id"; exit 1; }
[[ "$SIG_URL" == https://* ]] || { echo "Expected signing_url placeholder, got $SIG_URL"; exit 1; }
[[ "$SIG_RECIPIENTS" -ge 2 ]] || { echo "Expected at least 2 recipients, got $SIG_RECIPIENTS"; exit 1; }

BAD_WEBHOOK_BODY="{\"envelope_id\":\"$SIG_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke-invalid\"}}"
post_signed_webhook_expect_status 401 "$BAD_WEBHOOK_BODY" "wh-invalid-$RUN_ID" "sha256=deadbeef" >/dev/null
CTR_STILL_SIG_SENT="$(curl_json GET "$BASE_CEL/contracts/$CID")"
CTR_STILL_SIG_STATE="$(echo "$CTR_STILL_SIG_SENT" | jq -er '.contract.state')"
[[ "$CTR_STILL_SIG_STATE" == "SIGNATURE_SENT" ]] || { echo "Expected contract to remain SIGNATURE_SENT after invalid webhook, got $CTR_STILL_SIG_STATE"; exit 1; }

WEBHOOK_BODY="{\"envelope_id\":\"$SIG_ENV\",\"event_type\":\"envelope.completed\",\"payload\":{\"source\":\"smoke\"}}"
FIRST_WH="$(post_signed_webhook "$WEBHOOK_BODY" "wh-smoke-$RUN_ID")"
REPLAY_WH="$(post_signed_webhook "$WEBHOOK_BODY" "wh-smoke-$RUN_ID")"
REPLAY_FLAG="$(echo "$REPLAY_WH" | jq -er '.replay')"
[[ "$REPLAY_FLAG" == "true" ]] || { echo "Expected replay=true on duplicate webhook id, got $REPLAY_WH"; exit 1; }

CTR_EFFECTIVE="$(curl_json GET "$BASE_CEL/contracts/$CID")"
STATE2="$(echo "$CTR_EFFECTIVE" | jq -er '.contract.state')"
[[ "$STATE2" == "EFFECTIVE" ]] || { echo "Expected EFFECTIVE after webhook, got $STATE2"; exit 1; }

APPROVALS="$(curl_json GET "$BASE_CEL/contracts/$CID/approvals")"
APPROVAL_COUNT="$(echo "$APPROVALS" | jq -er '.approval_requests | length')"
[[ "$APPROVAL_COUNT" == "1" ]] || { echo "Expected 1 approval request, got $APPROVAL_COUNT"; exit 1; }
CID_EVIDENCE="$(curl_json GET "$BASE_CEL/contracts/$CID/evidence" "" "$AGENT_AUTH")"
SIG_V1_IN_EVIDENCE="$(echo "$CID_EVIDENCE" | jq -er --arg aprq "$APRQ" '[.artifacts.approval_decisions[] | select(.approval_request_id==$aprq) | .signature_object.signature_envelope.version == "sig-v1"] | any')"
[[ "$SIG_V1_IN_EVIDENCE" == "true" ]] || { echo "Expected sig-v1 signature envelope in evidence approval decision"; exit 1; }

EVENTS="$(curl_json GET "$BASE_CEL/contracts/$CID/events")"
CREATED_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="CREATED")] | length')"
VAR_SET_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="VARIABLE_SET")] | length')"
APRQ_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="APPROVAL_REQUESTED")] | length')"
APPROVED_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="APPROVED")] | length')"
SIGNED_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="SIGNATURE_SENT")] | length')"
EFFECTIVE_COUNT="$(echo "$EVENTS" | jq -er '[.events[] | select(.type=="EFFECTIVE")] | length')"
[[ "$CREATED_COUNT" == "1" ]] || { echo "Expected 1 CREATED event, got $CREATED_COUNT"; exit 1; }
[[ "$VAR_SET_COUNT" == "2" ]] || { echo "Expected 2 VARIABLE_SET events, got $VAR_SET_COUNT"; exit 1; }
[[ "$APRQ_COUNT" == "1" ]] || { echo "Expected 1 APPROVAL_REQUESTED event, got $APRQ_COUNT"; exit 1; }
[[ "$APPROVED_COUNT" == "1" ]] || { echo "Expected 1 APPROVED event, got $APPROVED_COUNT"; exit 1; }
[[ "$SIGNED_COUNT" == "1" ]] || { echo "Expected 1 SIGNATURE_SENT event, got $SIGNED_COUNT"; exit 1; }
[[ "$EFFECTIVE_COUNT" == "1" ]] || { echo "Expected 1 EFFECTIVE event, got $EFFECTIVE_COUNT"; exit 1; }

B1="$(curl_json GET "$BASE_CEL/contracts/$CID/evidence-bundle")"
B2="$(curl_json GET "$BASE_CEL/contracts/$CID/evidence-bundle")"
PH1="$(echo "$B1" | jq -er '.bundle.hashes.packet_hash')"
DH1="$(echo "$B1" | jq -er '.bundle.hashes.diff_hash')"
RH1="$(echo "$B1" | jq -er '.bundle.hashes.risk_hash')"
PH2="$(echo "$B2" | jq -er '.bundle.hashes.packet_hash')"
DH2="$(echo "$B2" | jq -er '.bundle.hashes.diff_hash')"
RH2="$(echo "$B2" | jq -er '.bundle.hashes.risk_hash')"
[[ "$PH1" == "$PH2" ]] || { echo "packet_hash unstable across runs"; exit 1; }
[[ "$DH1" == "$DH2" ]] || { echo "diff_hash unstable across runs"; exit 1; }
[[ "$RH1" == "$RH2" ]] || { echo "risk_hash unstable across runs"; exit 1; }
AD_COUNT="$(echo "$B1" | jq -er '.bundle.hash_inputs.packet_input.approval_decisions | length')"
[[ "$AD_COUNT" == "1" ]] || { echo "Expected 1 approval decision in hash inputs, got $AD_COUNT"; exit 1; }

CR1="$(curl_json GET "$BASE_CEL/contracts/$CID/render?format=text&locale=en-US" "" "$AGENT_AUTH")"
CR2="$(curl_json GET "$BASE_CEL/contracts/$CID/render?format=text&locale=en-US" "" "$AGENT_AUTH")"
CR_RENDERED1="$(echo "$CR1" | jq -er '.rendered')"
CR_RENDERED2="$(echo "$CR2" | jq -er '.rendered')"
CR_RH1="$(echo "$CR1" | jq -er '.render_hash')"
CR_RH2="$(echo "$CR2" | jq -er '.render_hash')"
CR_VH1="$(echo "$CR1" | jq -er '.variables_hash')"
CR_VH2="$(echo "$CR2" | jq -er '.variables_hash')"
CR_PH1="$(echo "$CR1" | jq -er '.packet_hash')"
CR_PH2="$(echo "$CR2" | jq -er '.packet_hash')"
[[ -n "$CR_RENDERED1" ]] || { echo "Expected non-empty canonical rendered text"; exit 1; }
[[ "$CR_RENDERED1" == "$CR_RENDERED2" ]] || { echo "canonical rendered output unstable across runs"; exit 1; }
[[ "$CR_RH1" == "$CR_RH2" ]] || { echo "render_hash unstable across runs"; exit 1; }
[[ "$CR_VH1" == "$CR_VH2" ]] || { echo "variables_hash unstable across runs"; exit 1; }
[[ "$CR_PH1" == "$CR_PH2" ]] || { echo "packet_hash unstable across runs for contract render"; exit 1; }

R1="$(curl_json POST "$BASE_CEL/contracts/$CID:render" "{}")"
R2="$(curl_json POST "$BASE_CEL/contracts/$CID:render" "{}")"
RP1="$(echo "$R1" | jq -er '.hashes.packet_hash')"
RD1="$(echo "$R1" | jq -er '.hashes.diff_hash')"
RR1="$(echo "$R1" | jq -er '.hashes.risk_hash')"
RP2="$(echo "$R2" | jq -er '.hashes.packet_hash')"
RD2="$(echo "$R2" | jq -er '.hashes.diff_hash')"
RR2="$(echo "$R2" | jq -er '.hashes.risk_hash')"
[[ "$RP1" == "$RP2" ]] || { echo "render packet_hash unstable across runs"; exit 1; }
[[ "$RD1" == "$RD2" ]] || { echo "render diff_hash unstable across runs"; exit 1; }
[[ "$RR1" == "$RR2" ]] || { echo "render risk_hash unstable across runs"; exit 1; }

if [[ "${SMOKE_PROOF_HTTP:-0}" == "1" ]]; then
  echo "== Proof endpoint HTTP integration =="
  CL_INTEGRATION=1 CL_BASE_URL="http://localhost:8082" CL_IAL_BASE_URL="http://localhost:8081" \
    go test ./services/cel/cmd/server -count=1 -run TestProofEndpointHTTPParityLive
fi

echo "== Slice 11 delegation e2e =="
CEL_URL="http://localhost:8082" \
IAL_URL="http://localhost:8081" \
SLICE11_FROM_SMOKE="1" \
PRINCIPAL_ID="$PRN" \
SETUP_AGENT_ACTOR_ID="$AGT" \
SETUP_AGENT_AUTH="$AGENT_AUTH" \
DELEGATOR_ACTOR_ID="$ACT_H" \
HUMAN_AUTH="$HUMAN_AUTH" \
DELEGATE_ACTOR_ID="$AGT_LOW" \
AGENT_AUTH="$AGENT_LOW_AUTH" \
CONTRACT_ID="$CID" \
TEMPLATE_ID="$TPL" \
bash scripts/test_slice11_delegation.sh

echo "Smoke test PASSED"
