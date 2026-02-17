#!/usr/bin/env bash
set -euo pipefail

BASE_IAL="http://localhost:8081/ial"
BASE_CEL="http://localhost:8082/cel"

echo "== Health checks =="
curl -sf "http://localhost:8081/health" >/dev/null
curl -sf "http://localhost:8082/health" >/dev/null
curl -sf "http://localhost:8083/health" >/dev/null
echo "OK"

echo "== Create principal =="
PRINCIPAL=$(curl -sf -X POST "$BASE_IAL/principals" \
  -H 'content-type: application/json' \
  -d '{"name":"Acme Inc","jurisdiction":"US","timezone":"America/Los_Angeles"}')
PRN=$(echo "$PRINCIPAL" | python3 -c "import sys,json; print(json.load(sys.stdin)['principal']['principal_id'])")
echo "principal_id=$PRN"

echo "== Create agent =="
AGENT=$(curl -sf -X POST "$BASE_IAL/actors/agents" \
  -H 'content-type: application/json' \
  -d "{\"principal_id\":\"$PRN\",\"name\":\"DealBot\",\"auth\":{\"mode\":\"HMAC\",\"scopes\":[\"cel.contracts:write\"]}}")
AGT=$(echo "$AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent']['actor_id'])")
echo "agent_id=$AGT"

echo "== Invite human (dev stub enrollment) =="
# NOTE: IAL MVP handler only accepts principal_id, invitee.email, requested_roles, expires_in_hours
INVRESP=$(curl -sf -X POST "$BASE_IAL/invites" \
  -H 'content-type: application/json' \
  -d "{\"principal_id\":\"$PRN\",\"invitee\":{\"email\":\"sam@acme.com\"},\"requested_roles\":[\"LEGAL\"],\"expires_in_hours\":72}")
INV=$(echo "$INVRESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['invite']['invite_id'])")

ENR=$(curl -sf -X POST "$BASE_IAL/webauthn/register/finish" \
  -H 'content-type: application/json' \
  -d "{\"invite_token\":\"dev:$INV\",\"attestation_response\":{}}")
ACT_H=$(echo "$ENR" | python3 -c "import sys,json; print(json.load(sys.stdin)['actor']['actor_id'])")
echo "human_actor_id=$ACT_H"

echo "== Set policy profile =="
curl -sf -X PUT "$BASE_IAL/actors/$ACT_H/policy-profile" \
  -H 'content-type: application/json' \
  -d "{\"principal_id\":\"$PRN\",\"automation_level\":\"A2_FAST_LANE\",\"action_gates\":{\"SEND_FOR_SIGNATURE\":\"FORCE_HUMAN\"},\"variable_rules\":[{\"for_type\":\"MONEY\",\"policy\":\"AGENT_FILL_HUMAN_REVIEW\"},{\"for_key\":\"party_address\",\"policy\":\"HUMAN_REQUIRED\"}]}" \
  >/dev/null

echo "== Seed template (CEL dev endpoint) =="
curl -sf -X POST "$BASE_CEL/dev/seed-template" \
  -H 'content-type: application/json' \
  -d "{\"principal_id\":\"$PRN\"}" \
  >/dev/null

TPLS=$(curl -sf "$BASE_CEL/templates?contract_type=NDA&jurisdiction=US")
TPL=$(echo "$TPLS" | python3 -c "import sys,json; print(json.load(sys.stdin)['templates'][0]['template_id'])")
echo "template_id=$TPL"

curl -sf -X POST "$BASE_CEL/principals/$PRN/templates/$TPL/enable" \
  -H 'content-type: application/json' \
  -d "{\"enabled_by_actor_id\":\"$ACT_H\",\"override_gates\":{}}" \
  >/dev/null

CTR=$(curl -sf -X POST "$BASE_CEL/contracts" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"c1\"},\"template_id\":\"$TPL\",\"counterparty\":{\"name\":\"Vendor X\",\"email\":\"legal@vendorx.com\"},\"initial_variables\":{\"effective_date\":\"2026-02-16\"}}")
CID=$(echo "$CTR" | python3 -c "import sys,json; print(json.load(sys.stdin)['contract']['contract_id'])")
echo "contract_id=$CID"

curl -sf -X POST "$BASE_CEL/contracts/$CID/variables:bulkSet" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"v1\"},\"variables\":{\"party_address\":\"123 Main St\",\"price\":\"USD 120000.00\"}}" \
  >/dev/null

RES=$(curl -sf -X POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a1\"}}")
STATUS=$(echo "$RES" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
[[ "$STATUS" == "BLOCKED" ]] || { echo "Expected BLOCKED, got $RES"; exit 1; }

curl -sf -X POST "$BASE_CEL/contracts/$CID/variables:bulkSet" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"v2\"},\"variables\":{\"party_address\":\"123 Main St\"}}" \
  >/dev/null

RES2=$(curl -sf -X POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a2\"}}")
NST=$(echo "$RES2" | python3 -c "import sys,json; print(json.load(sys.stdin)['next_step']['type'])")
[[ "$NST" == "REVIEW_VARIABLES" ]] || { echo "Expected REVIEW_VARIABLES, got $RES2"; exit 1; }

curl -sf -X POST "$BASE_CEL/contracts/$CID/variables:review" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\",\"idempotency_key\":\"vr1\"},\"decision\":\"APPROVE\",\"keys\":[\"price\"]}" \
  >/dev/null

RES3=$(curl -sf -X POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a3\"}}")
NST2=$(echo "$RES3" | python3 -c "import sys,json; print(json.load(sys.stdin)['next_step']['type'])")
[[ "$NST2" == "APPROVE_ACTION" ]] || { echo "Expected APPROVE_ACTION, got $RES3"; exit 1; }
APRQ=$(echo "$RES3" | python3 -c "import sys,json; print(json.load(sys.stdin)['next_step']['approval_request_id'])")

curl -sf -X POST "$BASE_CEL/approvals/$APRQ:decide" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$ACT_H\",\"actor_type\":\"HUMAN\"},\"decision\":\"APPROVE\",\"signed_payload\":{\"contract_id\":\"$CID\",\"approval_request_id\":\"$APRQ\",\"packet_hash\":\"sha256:dev\",\"diff_hash\":\"sha256:dev\",\"risk_hash\":\"sha256:dev\",\"nonce\":\"n1\"},\"signature\":{\"type\":\"WEBAUTHN_ASSERTION\",\"assertion_response\":{}}}" \
  >/dev/null

RES4=$(curl -sf -X POST "$BASE_CEL/contracts/$CID/actions/SEND_FOR_SIGNATURE" \
  -H 'content-type: application/json' \
  -d "{\"actor_context\":{\"principal_id\":\"$PRN\",\"actor_id\":\"$AGT\",\"actor_type\":\"AGENT\",\"idempotency_key\":\"a4\"}}")
STATUS4=$(echo "$RES4" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
[[ "$STATUS4" == "DONE" ]] || { echo "Expected DONE, got $RES4"; exit 1; }

echo "Smoke test PASSED"
