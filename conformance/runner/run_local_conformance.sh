#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${BASE_URL:-${CL_BASE_URL:-http://localhost:8080}}"
IAL_BASE_URL="${IAL_BASE_URL:-${CL_IAL_BASE_URL:-http://localhost:8081}}"
OFFLINE_FIXTURE_DIR="$ROOT/conformance/fixtures/agent-commerce-offline"
OFFLINE_EVIDENCE_PATH="$OFFLINE_FIXTURE_DIR/evidence.json"
OFFLINE_PROOF_PATH="$OFFLINE_FIXTURE_DIR/settlement_proof.json"
CONFORMANCE_OUTPUT="${CONFORMANCE_OUTPUT:-text}"
if [[ "$CONFORMANCE_OUTPUT" != "text" && "$CONFORMANCE_OUTPUT" != "json" ]]; then
  CONFORMANCE_OUTPUT="text"
fi

PY_SDK_VENV="$ROOT/sdk/python/.venv"
PY_SDK_PYTHON="$PY_SDK_VENV/bin/python"
USE_PROVIDED_AGENT="false"
if [[ -n "${AGENT_TOKEN:-}" && -n "${AGENT_ACTOR_ID:-}" && -n "${PRINCIPAL_ID:-}" ]]; then
  USE_PROVIDED_AGENT="true"
fi

required_cases=(
  agent_id_v1_roundtrip.json
  settlement_proof_offline.json
  settlement_proof_make_offline.json
  rules_v1_require_settlement_paid_passes.json
  rules_v1_require_settlement_paid_fails.json
  rules_v1_require_amount_match_fails.json
  settlement_delegation_self_issued_pass.json
  settlement_delegation_missing_fail.json
  settlement_delegation_expired_fail.json
  settlement_delegation_amount_exceeded_fail.json
  settlement_delegation_root_issued_trust_pass.json
  well_known_protocol_capabilities.json
  well_known_protocol_capabilities_hosted_commerce_and_proof.json
  well_known_protocol_capabilities_deterministic.json
  gate_status_done.json
  gate_status_blocked.json
  gate_resolve_requires_idempotency.json
  error_model_401.json
  retry_429_then_success.json
  sig_v1_approval_happy_path.json
  sig_v2_approval_happy_path.json
  sig_v2_approval_bad_signature.json
  hosted_commerce_intent_roundtrip.json
  hosted_commerce_accept_roundtrip.json
  hosted_authorization_missing_delegation_intent.json
  hosted_authorization_self_issued_delegation_ok_intent.json
  hosted_authorization_root_issued_delegation_ok_intent.json
  delegation_revocation_blocks_intent.json
  delegation_revocation_untrusted_issuer_ignored.json
  delegation_revocation_root_issued_valid.json
  delegation_revocation_signature_invalid_ignored.json
  evidence_contains_anchors_and_receipts.json
  proof_export_roundtrip_hash_parity.json
  proof_export_offline_verify_bundle_good.json
  proof_bundle_v1_export_deterministic.json
  proof_bundle_v1_id_matches.json
  proof_bundle_v1_offline_verify_ok.json
  proof_bundle_v1_tamper_fails.json
  delegation_v1_p256_sign_verify.json
  mixed_signers_ed25519_p256_verify.json
  sig_v2_invalid_encoding_rejects.json
  evp_verify_bundle_good.json
)

RUN_STATUS="PASS"
FAILED_CASE=""
FAILURE_REASON=""
CASES_PASSED=0
CASES_FAILED=0
EXIT_CODE=0
CONFORMANCE_CONTRACT_ID="${CONFORMANCE_CONTRACT_ID:-}"
CONFORMANCE_EVIDENCE_JSON="${CONFORMANCE_EVIDENCE_JSON:-}"
CONFORMANCE_COMMERCE_INTENT_HASH="${CONFORMANCE_COMMERCE_INTENT_HASH:-}"
LAST_CASE_OUTPUT=""

log() {
  if [[ "$CONFORMANCE_OUTPUT" == "text" ]]; then
    echo "$@"
  fi
}

json_quote() {
  jq -Rn --arg s "$1" '$s'
}

cases_json_array() {
  local out="["
  local i
  for i in "${!required_cases[@]}"; do
    [[ "$i" -gt 0 ]] && out+=","
    out+="$(json_quote "${required_cases[$i]}")"
  done
  out+="]"
  printf '%s' "$out"
}

short_reason() {
  local raw="$1"
  local first
  first="$(printf '%s' "$raw" | sed -n '/./{p;q;}' | tr '\n' ' ' | tr '\r' ' ')"
  first="${first:0:220}"
  printf '%s' "$first"
}

emit_summary() {
  local ts git_commit cases_json
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  git_commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
  cases_json="$(cases_json_array)"

  printf '{"protocol":"contractlane","protocol_version":"v1","status":"%s","base_url":%s,"cases_passed":%d,"cases_failed":%d,"cases":%s,"failed_case":%s,"failure_reason":%s,"timestamp_utc":"%s","git_commit":%s}\n' \
    "$RUN_STATUS" \
    "$(json_quote "$BASE_URL")" \
    "$CASES_PASSED" \
    "$CASES_FAILED" \
    "$cases_json" \
    "$(json_quote "$FAILED_CASE")" \
    "$(json_quote "$FAILURE_REASON")" \
    "$ts" \
    "$(json_quote "$git_commit")"
}

on_exit() {
  emit_summary
}
trap on_exit EXIT

mark_failure() {
  local case_file="$1"
  local reason="$2"
  RUN_STATUS="FAIL"
  FAILED_CASE="$case_file"
  FAILURE_REASON="$reason"
  CASES_FAILED=1
  EXIT_CODE=1
}

run_case() {
  local case_file="$1"
  shift

  if [[ "$RUN_STATUS" == "FAIL" ]]; then
    return 1
  fi

  log "[case] ${case_file%.json}"

  local tmp_output output
  tmp_output="$(mktemp)"
  if "$@" >"$tmp_output" 2>&1; then
    output="$(cat "$tmp_output")"
    rm -f "$tmp_output"
    LAST_CASE_OUTPUT="$output"
    export LAST_CASE_OUTPUT
    if [[ "$CONFORMANCE_OUTPUT" == "text" && -n "$output" ]]; then
      printf '%s\n' "$output"
    fi
    CASES_PASSED=$((CASES_PASSED + 1))
    return 0
  fi

  output="$(cat "$tmp_output")"
  rm -f "$tmp_output"
  LAST_CASE_OUTPUT="$output"
  export LAST_CASE_OUTPUT
  mark_failure "$case_file" "$(short_reason "$output")"
  printf '%s\n' "$output" >&2
  return 1
}

run_case_batch() {
  local first_case="$1"
  local count="$2"
  shift 2

  if [[ "$RUN_STATUS" == "FAIL" ]]; then
    return 1
  fi

  log "[case-group] ${first_case} (+$((count - 1)) related)"

  local tmp_output output
  tmp_output="$(mktemp)"
  if "$@" >"$tmp_output" 2>&1; then
    output="$(cat "$tmp_output")"
    rm -f "$tmp_output"
    LAST_CASE_OUTPUT="$output"
    export LAST_CASE_OUTPUT
    if [[ "$CONFORMANCE_OUTPUT" == "text" && -n "$output" ]]; then
      printf '%s\n' "$output"
    fi
    CASES_PASSED=$((CASES_PASSED + count))
    return 0
  fi

  output="$(cat "$tmp_output")"
  rm -f "$tmp_output"
  LAST_CASE_OUTPUT="$output"
  export LAST_CASE_OUTPUT
  mark_failure "$first_case" "$(short_reason "$output")"
  printf '%s\n' "$output" >&2
  return 1
}

run_cmd() {
  if [[ "$CONFORMANCE_OUTPUT" == "json" ]]; then
    "$@" >/dev/null
  else
    "$@"
  fi
}

for c in "${required_cases[@]}"; do
  if [[ ! -f "$ROOT/conformance/cases/$c" ]]; then
    mark_failure "$c" "missing case file"
    break
  fi
  if ! jq -e . "$ROOT/conformance/cases/$c" >/dev/null; then
    mark_failure "$c" "invalid JSON case file"
    break
  fi
done

cd "$ROOT"

curl_json() {
  local method="$1"
  local url="$2"
  local data="${3-}"
  local auth_header="${4-}"
  local tmp status
  tmp="$(mktemp)"

  if [[ -n "$data" ]]; then
    if [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -H "$auth_header" -d "$data")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -d "$data")"
    fi
  else
    if [[ -n "$auth_header" ]]; then
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url" -H "$auth_header")"
    else
      status="$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$url")"
    fi
  fi

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "HTTP $status from $method $url" >&2
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

run_well_known_capabilities_case() {
  local cap
  cap="$(curl_json GET "$BASE_URL/cel/.well-known/contractlane")"
  echo "$cap" | jq -e '.protocol.versions | index("v1") != null' >/dev/null
  echo "$cap" | jq -e '.evidence.bundle_versions | index("evidence-v1") != null' >/dev/null
  echo "$cap" | jq -e '.signatures.envelopes | index("sig-v1") != null' >/dev/null
  echo "$cap" | jq -e '.signatures.envelopes | index("sig-v2") != null' >/dev/null
  echo "$cap" | jq -e '.signatures.algorithms | index("ed25519") != null' >/dev/null
  echo "$cap" | jq -e '.signatures.algorithms | index("es256") != null' >/dev/null
  echo "$cap" | jq -e '.evidence.always_present_artifacts | index("anchors") != null' >/dev/null
  echo "$cap" | jq -e '.evidence.always_present_artifacts | index("webhook_receipts") != null' >/dev/null
}

run_well_known_capabilities_hosted_commerce_and_proof_case() {
  local cap
  cap="$(curl_json GET "$BASE_URL/cel/.well-known/contractlane")"
  echo "$cap" | jq -e '.commerce.intent_v1.hosted == true' >/dev/null
  echo "$cap" | jq -e '.commerce.intent_v1.endpoint == "/commerce/intents"' >/dev/null
  echo "$cap" | jq -e '.commerce.accept_v1.hosted == true' >/dev/null
  echo "$cap" | jq -e '.commerce.accept_v1.endpoint == "/commerce/accepts"' >/dev/null
  echo "$cap" | jq -e '.proof_export.endpoint == "/cel/contracts/{id}/proof"' >/dev/null
  echo "$cap" | jq -e '.proof_export.formats | index("json") != null' >/dev/null
  echo "$cap" | jq -e '.commerce.settlement_attestations.server_derived | type == "boolean"' >/dev/null
  echo "$cap" | jq -e '.authorization.delegation_v1.server_enforced == true' >/dev/null
  echo "$cap" | jq -e '.authorization.delegation_v1.trust_agents_configurable == true' >/dev/null
}

run_well_known_capabilities_deterministic_case() {
  local cap1 cap2 can1 can2
  cap1="$(curl_json GET "$BASE_URL/cel/.well-known/contractlane")"
  cap2="$(curl_json GET "$BASE_URL/cel/.well-known/contractlane")"
  can1="$(printf '%s' "$cap1" | jq -cS .)"
  can2="$(printf '%s' "$cap2" | jq -cS .)"
  [[ "$can1" == "$can2" ]]
}

run_agent_id_offline_case() {
  local fixture expected got
  fixture="$ROOT/conformance/cases/agent_id_v1_roundtrip.json"
  expected="$(jq -er '.expected_agent_id' "$fixture")"
  got="$( (cd "$ROOT/sdk/go/contractlane" && go test ./... -count=1 -run TestAgentID_ConformanceVector >/dev/null) && echo "$expected" )"
  [[ "$got" == "$expected" ]]
}

run_settlement_proof_offline_case() {
  local fixture_dir
  fixture_dir="$OFFLINE_FIXTURE_DIR"
  test -f "$fixture_dir/evidence.json"
  test -f "$fixture_dir/settlement_proof.json"
  local out
  out="$(go run ./cmd/clctl proof verify --evidence "$fixture_dir/evidence.json" --proof "$fixture_dir/settlement_proof.json")"
  echo "$out" | tail -n 1 | jq -e '.status == "PASS"' >/dev/null
}

run_settlement_proof_make_offline_case() {
  local fixture_dir tmp_proof
  fixture_dir="$OFFLINE_FIXTURE_DIR"
  tmp_proof="/tmp/settlement_proof.gen.json"
  rm -f "$tmp_proof"

  go run ./cmd/clctl proof make \
    --evidence "$fixture_dir/evidence.json" \
    --out "$tmp_proof" \
    --intent-id "ci_a" \
    --contract-id "ctr_offline_reference" \
    --issued-at-utc "2026-02-18T00:00:00Z" >/dev/null

  go run ./cmd/clctl proof verify \
    --evidence "$fixture_dir/evidence.json" \
    --proof "$tmp_proof" >/dev/null

  diff -u "$tmp_proof" "$fixture_dir/settlement_proof.json" >/dev/null
}

run_rules_v1_require_settlement_paid_passes_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_RulesRequireSettlementPaidPasses) >/dev/null
}

run_rules_v1_require_settlement_paid_fails_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_RulesRequireSettlementPaidFails) >/dev/null
}

run_rules_v1_require_amount_match_fails_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_RulesRequireAmountMatchFails) >/dev/null
}

run_settlement_delegation_self_issued_case() {
  local fixture_dir
  fixture_dir="$OFFLINE_FIXTURE_DIR"
  go run ./cmd/clctl proof verify \
    --evidence "$fixture_dir/evidence.json" \
    --proof "$fixture_dir/settlement_proof.json" >/dev/null
}

run_settlement_delegation_missing_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_AuthorizationMissingDelegationFails) >/dev/null
}

run_settlement_delegation_expired_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_AuthorizationExpiredDelegationFails) >/dev/null
}

run_settlement_delegation_amount_exceeded_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_AuthorizationAmountExceededFails) >/dev/null
}

run_settlement_delegation_root_trust_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestVerifySettlementProofV1_AuthorizationRootIssuedNeedsTrust) >/dev/null
}

ensure_conformance_context() {
  export CONFORMANCE_CONTRACT_ID
  export CONFORMANCE_EVIDENCE_JSON
}

resolve_dev_identity() {
  if [[ "$USE_PROVIDED_AGENT" == "true" ]]; then
    return
  fi
  local bootstrap_out bootstrap_token bootstrap_principal bootstrap_actor
  bootstrap_out="$(BASE_IAL="$IAL_BASE_URL/ial" "$ROOT/scripts/dev_token.sh")"
  bootstrap_token="$(echo "$bootstrap_out" | awk -F= '/^export TOKEN=/{print $2}')"
  bootstrap_principal="$(echo "$bootstrap_out" | awk -F= '/^export PRINCIPAL_ID=/{print $2}')"
  bootstrap_actor="$(echo "$bootstrap_out" | awk -F= '/^export ACTOR_ID=/{print $2}')"

  PRINCIPAL_ID="${PRINCIPAL_ID:-$bootstrap_principal}"
  AGENT_TOKEN="${AGENT_TOKEN:-$bootstrap_token}"
  AGENT_ACTOR_ID="${AGENT_ACTOR_ID:-$bootstrap_actor}"

  if [[ -z "${PRINCIPAL_ID:-}" || -z "${AGENT_TOKEN:-}" || -z "${AGENT_ACTOR_ID:-}" ]]; then
    return 1
  fi
}

create_conformance_agent() {
  local agent_json resp
  agent_json="$(jq -cn \
    --arg principal "$PRINCIPAL_ID" \
    '{principal_id:$principal,name:"ConformanceAgent",auth:{mode:"HMAC",scopes:["cel.contracts:write","cel.contracts:read","cel.approvals:route","cel.approvals:decide","cel.gates:read","cel.gates:resolve","exec.signatures:send"]}}')"
  resp="$(curl_json POST "$IAL_BASE_URL/ial/actors/agents" "$agent_json")"
  AGENT_TOKEN="$(echo "$resp" | jq -er '.credentials.token')"
  AGENT_ACTOR_ID="$(echo "$resp" | jq -er '.agent.actor_id')"
}

create_human_session() {
  local email invite_resp invite_id enroll_resp human_actor ml_start ml_url ml_token ml_finish
  email="conformance+$(date +%s)@example.com"
  invite_resp="$(curl_json POST "$IAL_BASE_URL/ial/invites" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg email "$email" '{principal_id:$principal,invitee:{email:$email},requested_roles:["LEGAL"],expires_in_hours:72}')")"
  invite_id="$(echo "$invite_resp" | jq -er '.invite.invite_id')"

  enroll_resp="$(curl_json POST "$IAL_BASE_URL/ial/webauthn/register/finish" "$(jq -cn --arg token "dev:$invite_id" '{invite_token:$token,attestation_response:{}}')")"
  human_actor="$(echo "$enroll_resp" | jq -er '.actor.actor_id')"

  ml_start="$(curl_json POST "$IAL_BASE_URL/ial/auth/magic-link/start" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg email "$email" '{principal_id:$principal,email:$email,redirect_url:"https://example.local/return"}')")"
  ml_url="$(echo "$ml_start" | jq -er '.magic_link_url')"
  ml_token="$(echo "$ml_url" | sed -E 's/.*token=([^&]+).*/\1/')"
  ml_finish="$(curl_json POST "$IAL_BASE_URL/ial/auth/magic-link/finish" "$(jq -cn --arg token "$ml_token" '{token:$token}')")"

  HUMAN_TOKEN="$(echo "$ml_finish" | jq -er '.credentials.token')"
  HUMAN_ACTOR_ID="$human_actor"
}

run_sigv1_case() {
  local agent_auth human_auth contract_create contract_id route_resp aprq signed_payload envelope decide_req decide_resp decide_status

  agent_auth="Authorization: Bearer $AGENT_TOKEN"
  human_auth="Authorization: Bearer $HUMAN_TOKEN"

  curl_json POST "$BASE_URL/cel/dev/seed-template" "$(jq -cn --arg principal "$PRINCIPAL_ID" '{principal_id:$principal}')" "$agent_auth" >/dev/null

  contract_create="$(curl_json POST "$BASE_URL/cel/contracts" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" --arg idem "conf-create-$(date +%s)-$RANDOM" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT",idempotency_key:$idem},template_id:"tpl_nda_us_v1",counterparty:{name:"Conformance Co",email:"counterparty@example.com"},initial_variables:{}}')" "$agent_auth")"
  contract_id="$(echo "$contract_create" | jq -er '.contract.contract_id')"

  route_resp="$(curl_json POST "$BASE_URL/cel/contracts/$contract_id/approvals:route" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT"},action:"SEND_FOR_SIGNATURE",required_roles:["LEGAL"]}')" "$agent_auth")"
  aprq="$(echo "$route_resp" | jq -er '.approval_request.approval_request_id')"

  signed_payload="$(jq -cn --arg cid "$contract_id" --arg aprq "$aprq" --arg nonce "conf-nonce-$RANDOM" '{contract_id:$cid,approval_request_id:$aprq,packet_hash:"sha256:dev",diff_hash:"sha256:dev",risk_hash:"sha256:dev",nonce:$nonce}')"
  envelope="$(go run "$ROOT/conformance/runner/helpers/sigv1/main.go" "$signed_payload")"

  decide_req="$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$HUMAN_ACTOR_ID" --argjson payload "$signed_payload" --argjson env "$envelope" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"HUMAN",idempotency_key:"conf-decide-1"},decision:"APPROVE",signed_payload:$payload,signed_payload_hash:$env.payload_hash,signature_envelope:$env}')"
  decide_resp="$(curl_json POST "$BASE_URL/cel/approvals/$aprq:decide" "$decide_req" "$human_auth")"
  decide_status="$(echo "$decide_resp" | jq -er '.status')"
  [[ "$decide_status" == "APPROVED" ]]

  CONFORMANCE_CONTRACT_ID="$contract_id"
  export CONFORMANCE_CONTRACT_ID
  echo "{\"contract_id\":$(json_quote "$contract_id"),\"status\":\"APPROVED\"}"
}

run_sigv2_case() {
  local agent_auth human_auth contract_create contract_id route_resp aprq signed_payload envelope decide_req decide_resp decide_status

  agent_auth="Authorization: Bearer $AGENT_TOKEN"
  human_auth="Authorization: Bearer $HUMAN_TOKEN"

  curl_json POST "$BASE_URL/cel/dev/seed-template" "$(jq -cn --arg principal "$PRINCIPAL_ID" '{principal_id:$principal}')" "$agent_auth" >/dev/null

  contract_create="$(curl_json POST "$BASE_URL/cel/contracts" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" --arg idem "conf-create-sigv2-$(date +%s)-$RANDOM" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT",idempotency_key:$idem},template_id:"tpl_nda_us_v1",counterparty:{name:"Conformance Co",email:"counterparty@example.com"},initial_variables:{}}')" "$agent_auth")"
  contract_id="$(echo "$contract_create" | jq -er '.contract.contract_id')"

  route_resp="$(curl_json POST "$BASE_URL/cel/contracts/$contract_id/approvals:route" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT"},action:"SEND_FOR_SIGNATURE",required_roles:["LEGAL"]}')" "$agent_auth")"
  aprq="$(echo "$route_resp" | jq -er '.approval_request.approval_request_id')"

  signed_payload="$(jq -cn --arg cid "$contract_id" --arg aprq "$aprq" --arg nonce "conf-nonce-sigv2-$RANDOM" '{contract_id:$cid,approval_request_id:$aprq,packet_hash:"sha256:dev",diff_hash:"sha256:dev",risk_hash:"sha256:dev",nonce:$nonce}')"
  envelope="$(go run "$ROOT/conformance/runner/helpers/sigv2/main.go" "$signed_payload")"

  decide_req="$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$HUMAN_ACTOR_ID" --argjson payload "$signed_payload" --argjson env "$envelope" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"HUMAN",idempotency_key:"conf-decide-sigv2-1"},decision:"APPROVE",signed_payload:$payload,signed_payload_hash:$env.payload_hash,signature_envelope:$env}')"
  decide_resp="$(curl_json POST "$BASE_URL/cel/approvals/$aprq:decide" "$decide_req" "$human_auth")"
  decide_status="$(echo "$decide_resp" | jq -er '.status')"
  [[ "$decide_status" == "APPROVED" ]]
}

run_sigv2_bad_signature_case() {
  local agent_auth human_auth contract_create contract_id route_resp aprq signed_payload envelope bad_env decide_req tmp status body

  agent_auth="Authorization: Bearer $AGENT_TOKEN"
  human_auth="Authorization: Bearer $HUMAN_TOKEN"

  curl_json POST "$BASE_URL/cel/dev/seed-template" "$(jq -cn --arg principal "$PRINCIPAL_ID" '{principal_id:$principal}')" "$agent_auth" >/dev/null

  contract_create="$(curl_json POST "$BASE_URL/cel/contracts" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" --arg idem "conf-create-sigv2-bad-$(date +%s)-$RANDOM" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT",idempotency_key:$idem},template_id:"tpl_nda_us_v1",counterparty:{name:"Conformance Co",email:"counterparty@example.com"},initial_variables:{}}')" "$agent_auth")"
  contract_id="$(echo "$contract_create" | jq -er '.contract.contract_id')"

  route_resp="$(curl_json POST "$BASE_URL/cel/contracts/$contract_id/approvals:route" "$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$AGENT_ACTOR_ID" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"AGENT"},action:"SEND_FOR_SIGNATURE",required_roles:["LEGAL"]}')" "$agent_auth")"
  aprq="$(echo "$route_resp" | jq -er '.approval_request.approval_request_id')"

  signed_payload="$(jq -cn --arg cid "$contract_id" --arg aprq "$aprq" --arg nonce "conf-nonce-sigv2-bad-$RANDOM" '{contract_id:$cid,approval_request_id:$aprq,packet_hash:"sha256:dev",diff_hash:"sha256:dev",risk_hash:"sha256:dev",nonce:$nonce}')"
  envelope="$(go run "$ROOT/conformance/runner/helpers/sigv2/main.go" "$signed_payload")"
  bad_env="$(echo "$envelope" | jq '.signature = "not_base64url"')"

  decide_req="$(jq -cn --arg principal "$PRINCIPAL_ID" --arg actor "$HUMAN_ACTOR_ID" --argjson payload "$signed_payload" --argjson env "$bad_env" '{actor_context:{principal_id:$principal,actor_id:$actor,actor_type:"HUMAN",idempotency_key:"conf-decide-sigv2-bad-1"},decision:"APPROVE",signed_payload:$payload,signed_payload_hash:$env.payload_hash,signature_envelope:$env}')"

  tmp="$(mktemp)"
  status="$(curl -sS -o "$tmp" -w '%{http_code}' -X POST "$BASE_URL/cel/approvals/$aprq:decide" -H 'content-type: application/json' -H "$human_auth" -d "$decide_req")"
  body="$(cat "$tmp")"
  rm -f "$tmp"

  [[ "$status" == "403" ]]
  echo "$body" | jq -e '.error.code=="BAD_SIGNATURE"' >/dev/null
}

run_evidence_artifact_case() {
  local evidence_json
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi

  evidence_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/evidence?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"

  echo "$evidence_json" | jq -e '([.manifest.artifacts[] | select(.artifact_type=="anchors")] | length) >= 1' >/dev/null
  echo "$evidence_json" | jq -e '([.manifest.artifacts[] | select(.artifact_type=="webhook_receipts")] | length) >= 1' >/dev/null
  echo "$evidence_json" | jq -e '.artifacts.anchors | type == "array"' >/dev/null
  echo "$evidence_json" | jq -e '.artifacts.webhook_receipts | type == "array"' >/dev/null

  CONFORMANCE_EVIDENCE_JSON="$evidence_json"
  export CONFORMANCE_EVIDENCE_JSON
}

run_hosted_commerce_intent_roundtrip_case() {
  local agent_auth intent_payload envelope req resp intent_hash evidence_json
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  agent_auth="Authorization: Bearer $AGENT_TOKEN"
  intent_payload="$(jq -cn --arg cid "$CONFORMANCE_CONTRACT_ID" '{
    version:"commerce-intent-v1",
    intent_id:"ci_hosted_conf_1",
    contract_id:$cid,
    buyer_agent:"agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    seller_agent:"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
    items:[{sku:"sku_conf_1",qty:1,unit_price:{currency:"USD",amount:"26"}}],
    total:{currency:"USD",amount:"26"},
    expires_at:"2026-12-31T23:59:59Z",
    nonce:"Y29uZm9ybWFuY2VfaW50ZW50X25vbmNlX3Yx",
    metadata:{}
  }')"
  envelope="$(go run "$ROOT/conformance/runner/helpers/sigv1/main.go" "$intent_payload" "commerce-intent")"
  req="$(jq -cn --argjson intent "$intent_payload" --argjson sig "$envelope" '{intent:$intent,signature:$sig}')"
  resp="$(curl_json POST "$BASE_URL/commerce/intents" "$req" "$agent_auth")"
  intent_hash="$(echo "$resp" | jq -er '.intent_hash')"
  [[ "$(echo "$resp" | jq -er '.status')" == "ACCEPTED" ]]

  evidence_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/evidence?format=json" "" "$agent_auth")"
  echo "$evidence_json" | jq -e '([.manifest.artifacts[] | select(.artifact_type=="commerce_intents")] | length) >= 1' >/dev/null
  echo "$evidence_json" | jq -e --arg h "$intent_hash" '.artifacts.commerce_intents | any(.intent.intent_id=="ci_hosted_conf_1")' >/dev/null

  CONFORMANCE_COMMERCE_INTENT_HASH="$intent_hash"
  CONFORMANCE_EVIDENCE_JSON="$evidence_json"
  export CONFORMANCE_COMMERCE_INTENT_HASH
  export CONFORMANCE_EVIDENCE_JSON
}

run_hosted_commerce_accept_roundtrip_case() {
  local agent_auth accept_payload envelope req resp accept_hash evidence_json
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  if [[ -z "${CONFORMANCE_COMMERCE_INTENT_HASH:-}" ]]; then
    echo "missing conformance intent hash" >&2
    return 1
  fi
  agent_auth="Authorization: Bearer $AGENT_TOKEN"
  accept_payload="$(jq -cn --arg cid "$CONFORMANCE_CONTRACT_ID" --arg ih "$CONFORMANCE_COMMERCE_INTENT_HASH" '{
    version:"commerce-accept-v1",
    contract_id:$cid,
    intent_hash:$ih,
    accepted_at:"2026-12-31T23:59:59Z",
    nonce:"Y29uZm9ybWFuY2VfYWNjZXB0X25vbmNlX3Yx",
    metadata:{}
  }')"
  envelope="$(go run "$ROOT/conformance/runner/helpers/sigv1/main.go" "$accept_payload" "commerce-accept")"
  req="$(jq -cn --argjson accept "$accept_payload" --argjson sig "$envelope" '{accept:$accept,signature:$sig}')"
  resp="$(curl_json POST "$BASE_URL/commerce/accepts" "$req" "$agent_auth")"
  accept_hash="$(echo "$resp" | jq -er '.accept_hash')"
  [[ "$(echo "$resp" | jq -er '.status')" == "ACCEPTED" ]]

  evidence_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/evidence?format=json" "" "$agent_auth")"
  echo "$evidence_json" | jq -e '([.manifest.artifacts[] | select(.artifact_type=="commerce_intents")] | length) >= 1' >/dev/null
  echo "$evidence_json" | jq -e '([.manifest.artifacts[] | select(.artifact_type=="commerce_accepts")] | length) >= 1' >/dev/null
  echo "$evidence_json" | jq -e --arg ih "$CONFORMANCE_COMMERCE_INTENT_HASH" '.artifacts.commerce_accepts | any(.accept.intent_hash==$ih)' >/dev/null

  CONFORMANCE_EVIDENCE_JSON="$evidence_json"
  export CONFORMANCE_EVIDENCE_JSON
}

run_hosted_authorization_missing_delegation_intent_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_MissingDelegation >/dev/null
}

run_hosted_authorization_self_issued_delegation_ok_intent_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_SelfIssuedOK >/dev/null
}

run_hosted_authorization_root_issued_delegation_ok_intent_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_RootIssuedNeedsTrust >/dev/null
}

run_delegation_revocation_blocks_intent_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_DelegationRevoked >/dev/null
}

run_delegation_revocation_untrusted_issuer_ignored_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_RevocationUntrustedIssuerIgnored >/dev/null
}

run_delegation_revocation_root_issued_valid_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_RevocationRootIssuedWithTrust >/dev/null
}

run_delegation_revocation_signature_invalid_ignored_case() {
  GOCACHE=/tmp/go-build go test ./services/cel/cmd/server -count=1 -run TestEvaluateHostedCommerceAuthorization_RevocationInvalidSignatureIgnored >/dev/null
}

run_delegation_v1_p256_sign_verify_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestDelegationV1_SignAndVerifyES256) >/dev/null
}

run_mixed_signers_ed25519_p256_verify_case() {
  (cd "$ROOT/sdk/go/contractlane" && GOCACHE=/tmp/go-build go test ./... -count=1 -run TestMixedSignerVerification_Ed25519AndES256) >/dev/null
}

run_sigv2_invalid_encoding_rejects_case() {
  GOCACHE=/tmp/go-build go test ./pkg/signature -count=1 -run TestVerifyEnvelopeV2_InvalidEncodingCases >/dev/null
}

run_evp_case() {
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  if [[ -z "${CONFORMANCE_EVIDENCE_JSON:-}" ]]; then
    CONFORMANCE_EVIDENCE_JSON="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/evidence?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
    export CONFORMANCE_EVIDENCE_JSON
  fi
  if [[ -z "${CONFORMANCE_EVIDENCE_JSON:-}" ]]; then
    echo "missing conformance evidence JSON" >&2
    return 1
  fi
  printf '%s' "${CONFORMANCE_EVIDENCE_JSON:-}" | go run "$ROOT/conformance/runner/helpers/evpverify/main.go" >/dev/null
}

run_proof_export_roundtrip_hash_parity_case() {
  local evidence_json proof_json evidence_manifest proof_manifest evidence_bundle proof_bundle
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi

  evidence_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/evidence?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  proof_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"

  evidence_manifest="$(echo "$evidence_json" | jq -er '.hashes.manifest_hash')"
  proof_manifest="$(echo "$proof_json" | jq -er '.evidence.hashes.manifest_hash')"
  [[ "$evidence_manifest" == "$proof_manifest" ]]

  evidence_bundle="$(echo "$evidence_json" | jq -er '.hashes.bundle_hash')"
  proof_bundle="$(echo "$proof_json" | jq -er '.evidence.hashes.bundle_hash')"
  [[ "$evidence_bundle" == "$proof_bundle" ]]

  echo "$proof_json" | jq -e '.protocol == "contractlane" and .protocol_version == "v1"' >/dev/null
  echo "$proof_json" | jq -e '.requirements.authorization_required | type == "boolean"' >/dev/null
  echo "$proof_json" | jq -e '.requirements.required_scopes.commerce_intent == "commerce:intent:sign"' >/dev/null
  echo "$proof_json" | jq -e '.requirements.required_scopes.commerce_accept == "commerce:accept:sign"' >/dev/null
  echo "$proof_json" | jq -e '.requirements.settlement_required_status == "PAID"' >/dev/null
  echo "$proof_json" | jq -e 'has("generated_at") | not' >/dev/null
  echo "$proof_json" | jq -e 'has("request_id") | not' >/dev/null

  CONFORMANCE_EVIDENCE_JSON="$(echo "$proof_json" | jq -c '.evidence')"
  export CONFORMANCE_EVIDENCE_JSON
}

run_proof_export_offline_verify_bundle_good_case() {
  local proof_json proof_evidence
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi

  proof_json="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  proof_evidence="$(echo "$proof_json" | jq -c '.evidence')"
  if [[ -z "$proof_evidence" || "$proof_evidence" == "null" ]]; then
    echo "proof missing evidence object" >&2
    return 1
  fi
  printf '%s' "$proof_evidence" | go run "$ROOT/conformance/runner/helpers/evpverify/main.go" >/dev/null
}

run_proof_bundle_v1_export_deterministic_case() {
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  local r1 r2
  r1="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof-bundle?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  r2="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof-bundle?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  [[ "$(echo "$r1" | jq -cS .)" == "$(echo "$r2" | jq -cS .)" ]]
}

run_proof_bundle_v1_id_matches_case() {
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  local resp pid computed
  resp="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof-bundle?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  pid="$(echo "$resp" | jq -er '.proof_id')"
  computed="$(echo "$resp" | jq -c '.proof' | go run "$ROOT/conformance/runner/helpers/proofbundle/main.go" compute)"
  if [[ "${CONFORMANCE_DEBUG:-}" == "1" ]]; then
    echo "proof_bundle_debug server_proof_id=$pid"
    echo "proof_bundle_debug runner_proof_id=$computed"
    echo "$resp" | jq -c '.proof' | go run "$ROOT/conformance/runner/helpers/proofbundle/main.go" debug
  fi
  [[ "$pid" == "$computed" ]]
}

run_proof_bundle_v1_offline_verify_ok_case() {
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  local resp
  resp="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof-bundle?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  echo "$resp" | jq -c '.proof' | go run "$ROOT/conformance/runner/helpers/proofbundle/main.go" verify >/dev/null
}

run_proof_bundle_v1_tamper_fails_case() {
  ensure_conformance_context
  if [[ -z "${CONFORMANCE_CONTRACT_ID:-}" ]]; then
    echo "missing conformance contract id" >&2
    return 1
  fi
  local resp tampered
  resp="$(curl_json GET "$BASE_URL/cel/contracts/${CONFORMANCE_CONTRACT_ID}/proof-bundle?format=json" "" "Authorization: Bearer $AGENT_TOKEN")"
  tampered="$(echo "$resp" | jq -c '.proof | .bundle.contract.contract_id = "ctr_tampered"')"
  if echo "$tampered" | go run "$ROOT/conformance/runner/helpers/proofbundle/main.go" verify >/dev/null 2>&1; then
    echo "expected tampered proof bundle verification to fail" >&2
    return 1
  fi
}

run_sdk_conformance_suite() {
  cd "$ROOT/sdk/typescript"
  test -f package-lock.json
  run_cmd npm ci
  run_cmd npm run build
  if [[ "$CONFORMANCE_OUTPUT" == "json" ]]; then
    CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" npm test >/dev/null
  else
    CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" npm test
  fi

  if [[ ! -x "$PY_SDK_PYTHON" ]]; then
    python3 -m venv "$PY_SDK_VENV"
  fi
  PYTHONNOUSERSITE=1 "$PY_SDK_PYTHON" -m pip install --no-build-isolation -e "$ROOT/sdk/python[dev]" >/dev/null
  PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" "$PY_SDK_PYTHON" -m pytest "$ROOT/sdk/python/tests" -q -k conformance

  cd "$ROOT"
  (cd "$ROOT/sdk/go/contractlane" && CL_CONFORMANCE=1 CL_BASE_URL="$BASE_URL" CL_IAL_BASE_URL="$IAL_BASE_URL" go test ./... -count=1 -run Conformance)
}

export CL_BASE_URL="$BASE_URL"
export CL_IAL_BASE_URL="$IAL_BASE_URL"

run_case "agent_id_v1_roundtrip.json" run_agent_id_offline_case || true
run_case "settlement_proof_offline.json" run_settlement_proof_offline_case || true
run_case "settlement_proof_make_offline.json" run_settlement_proof_make_offline_case || true
run_case "rules_v1_require_settlement_paid_passes.json" run_rules_v1_require_settlement_paid_passes_case || true
run_case "rules_v1_require_settlement_paid_fails.json" run_rules_v1_require_settlement_paid_fails_case || true
run_case "rules_v1_require_amount_match_fails.json" run_rules_v1_require_amount_match_fails_case || true
run_case "settlement_delegation_self_issued_pass.json" run_settlement_delegation_self_issued_case || true
run_case "settlement_delegation_missing_fail.json" run_settlement_delegation_missing_case || true
run_case "settlement_delegation_expired_fail.json" run_settlement_delegation_expired_case || true
run_case "settlement_delegation_amount_exceeded_fail.json" run_settlement_delegation_amount_exceeded_case || true
run_case "settlement_delegation_root_issued_trust_pass.json" run_settlement_delegation_root_trust_case || true
run_case "well_known_protocol_capabilities.json" run_well_known_capabilities_case || true
run_case "well_known_protocol_capabilities_hosted_commerce_and_proof.json" run_well_known_capabilities_hosted_commerce_and_proof_case || true
run_case "well_known_protocol_capabilities_deterministic.json" run_well_known_capabilities_deterministic_case || true

if [[ "$RUN_STATUS" == "PASS" ]]; then
  if ! resolve_dev_identity; then
    mark_failure "sig_v1_approval_happy_path.json" "unable to resolve principal/agent identity"
  fi
fi

if [[ "$RUN_STATUS" == "PASS" ]]; then
  if [[ -z "${AGENT_TOKEN:-}" || -z "${AGENT_ACTOR_ID:-}" || -z "${PRINCIPAL_ID:-}" ]]; then
    mark_failure "sig_v1_approval_happy_path.json" "missing AGENT_TOKEN/AGENT_ACTOR_ID/PRINCIPAL_ID"
  fi
fi

if [[ "$RUN_STATUS" == "PASS" && "$USE_PROVIDED_AGENT" != "true" ]]; then
  if ! create_conformance_agent; then
    mark_failure "sig_v1_approval_happy_path.json" "failed to create conformance agent"
  fi
fi

if [[ "$RUN_STATUS" == "PASS" ]]; then
  if ! create_human_session; then
    mark_failure "sig_v1_approval_happy_path.json" "failed to create human session"
  fi
fi

run_case "sig_v1_approval_happy_path.json" run_sigv1_case || true
if [[ "$RUN_STATUS" == "PASS" ]]; then
  summary_json="$(printf '%s\n' "${LAST_CASE_OUTPUT:-}" | awk '/^\{/{line=$0} END{print line}')"
  if [[ -z "${summary_json:-}" ]]; then
    mark_failure "sig_v1_approval_happy_path.json" "missing summary JSON output from sig_v1_approval_happy_path"
  else
    parsed_contract_id="$(printf '%s' "$summary_json" | jq -r '.contract_id // empty' 2>/dev/null || true)"
    if [[ -z "${parsed_contract_id:-}" || "$parsed_contract_id" == "null" ]]; then
      mark_failure "sig_v1_approval_happy_path.json" "missing contract_id in sig_v1_approval_happy_path summary"
    elif [[ ! "$parsed_contract_id" =~ ^ctr_ ]]; then
      mark_failure "sig_v1_approval_happy_path.json" "invalid contract_id in sig_v1_approval_happy_path summary: expected ctr_*"
    else
      CONFORMANCE_CONTRACT_ID="$parsed_contract_id"
      export CONFORMANCE_CONTRACT_ID
    fi
  fi
fi
run_case "sig_v2_approval_happy_path.json" run_sigv2_case || true
run_case "sig_v2_approval_bad_signature.json" run_sigv2_bad_signature_case || true
run_case "hosted_commerce_intent_roundtrip.json" run_hosted_commerce_intent_roundtrip_case || true
run_case "hosted_commerce_accept_roundtrip.json" run_hosted_commerce_accept_roundtrip_case || true
run_case "hosted_authorization_missing_delegation_intent.json" run_hosted_authorization_missing_delegation_intent_case || true
run_case "hosted_authorization_self_issued_delegation_ok_intent.json" run_hosted_authorization_self_issued_delegation_ok_intent_case || true
run_case "hosted_authorization_root_issued_delegation_ok_intent.json" run_hosted_authorization_root_issued_delegation_ok_intent_case || true
run_case "delegation_revocation_blocks_intent.json" run_delegation_revocation_blocks_intent_case || true
run_case "delegation_revocation_untrusted_issuer_ignored.json" run_delegation_revocation_untrusted_issuer_ignored_case || true
run_case "delegation_revocation_root_issued_valid.json" run_delegation_revocation_root_issued_valid_case || true
run_case "delegation_revocation_signature_invalid_ignored.json" run_delegation_revocation_signature_invalid_ignored_case || true
run_case "evidence_contains_anchors_and_receipts.json" run_evidence_artifact_case || true
run_case "proof_export_roundtrip_hash_parity.json" run_proof_export_roundtrip_hash_parity_case || true
run_case "proof_export_offline_verify_bundle_good.json" run_proof_export_offline_verify_bundle_good_case || true
run_case "proof_bundle_v1_export_deterministic.json" run_proof_bundle_v1_export_deterministic_case || true
run_case "proof_bundle_v1_id_matches.json" run_proof_bundle_v1_id_matches_case || true
run_case "proof_bundle_v1_offline_verify_ok.json" run_proof_bundle_v1_offline_verify_ok_case || true
run_case "proof_bundle_v1_tamper_fails.json" run_proof_bundle_v1_tamper_fails_case || true
run_case "delegation_v1_p256_sign_verify.json" run_delegation_v1_p256_sign_verify_case || true
run_case "mixed_signers_ed25519_p256_verify.json" run_mixed_signers_ed25519_p256_verify_case || true
run_case "sig_v2_invalid_encoding_rejects.json" run_sigv2_invalid_encoding_rejects_case || true
run_case "evp_verify_bundle_good.json" run_evp_case || true

# Remaining five shared conformance cases are validated by SDK conformance suites.
run_case_batch "gate_status_done.json" 5 run_sdk_conformance_suite || true

if [[ "$RUN_STATUS" == "PASS" ]]; then
  log "local conformance passed"
else
  log "local conformance failed"
fi

exit "$EXIT_CODE"
