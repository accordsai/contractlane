package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestProofEndpointHTTPParityLive(t *testing.T) {
	if os.Getenv("CL_INTEGRATION") != "1" {
		t.Skip("set CL_INTEGRATION=1 to run live integration")
	}

	baseURL := getenvOr("CL_BASE_URL", "http://localhost:8080")
	ialURL := getenvOr("CL_IAL_BASE_URL", "http://localhost:8081")

	principalResp := postJSONLive(t, ialURL+"/ial/principals", map[string]any{
		"name":         "CEL Proof Integration",
		"jurisdiction": "US",
		"timezone":     "UTC",
	})
	principalID := nestedString(t, principalResp, "principal", "principal_id")

	agentResp := postJSONLive(t, ialURL+"/ial/actors/agents", map[string]any{
		"principal_id": principalID,
		"name":         "CELProofAgent",
		"auth": map[string]any{
			"mode": "HMAC",
			"scopes": []string{
				"cel.contracts:write",
				"cel.contracts:read",
				"cel.approvals:route",
				"cel.approvals:decide",
				"cel.gates:read",
				"cel.gates:resolve",
				"exec.signatures:send",
			},
		},
	})
	agentID := nestedString(t, agentResp, "agent", "actor_id")
	token := nestedString(t, agentResp, "credentials", "token")
	auth := "Bearer " + token

	_ = postJSONAuthLive(t, baseURL+"/cel/dev/seed-template", auth, map[string]any{"principal_id": principalID})
	_ = postJSONAuthLive(t, baseURL+"/cel/programs", auth, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    principalID,
			"actor_id":        agentID,
			"actor_type":      "AGENT",
			"idempotency_key": "proof-live-program-" + time.Now().UTC().Format("20060102150405"),
		},
		"key":  "terms_current",
		"mode": "STRICT_RECONSENT",
	})
	_ = postJSONAuthLive(t, baseURL+"/cel/programs/terms_current/publish", auth, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    principalID,
			"actor_id":        agentID,
			"actor_type":      "AGENT",
			"idempotency_key": "proof-live-publish-" + time.Now().UTC().Format("20060102150405"),
		},
		"required_template_id":      "tpl_nda_us_v1",
		"required_template_version": "v1",
	})

	contractResp := postJSONAuthLive(t, baseURL+"/cel/contracts", auth, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    principalID,
			"actor_id":        agentID,
			"actor_type":      "AGENT",
			"idempotency_key": "proof-live-contract-" + time.Now().UTC().Format("20060102150405"),
		},
		"template_id": "tpl_nda_us_v1",
		"counterparty": map[string]any{
			"name":  "Counterparty",
			"email": "counterparty@example.com",
		},
		"initial_variables": map[string]any{},
	})
	contractID := nestedString(t, contractResp, "contract", "contract_id")

	evidence := getJSONAuthLive(t, baseURL+"/cel/contracts/"+contractID+"/evidence?format=json", auth)
	proof := getJSONAuthLive(t, baseURL+"/cel/contracts/"+contractID+"/proof?format=json", auth)

	if proof["protocol"] != "contractlane" {
		t.Fatalf("unexpected proof.protocol: %v", proof["protocol"])
	}
	if proof["protocol_version"] != "v1" {
		t.Fatalf("unexpected proof.protocol_version: %v", proof["protocol_version"])
	}
	if _, ok := proof["generated_at"]; ok {
		t.Fatalf("proof must not include top-level generated_at")
	}
	if _, ok := proof["request_id"]; ok {
		t.Fatalf("proof must not include top-level request_id")
	}

	proofEvidence, ok := proof["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("proof missing evidence object")
	}
	if !reflect.DeepEqual(proofEvidence, evidence) {
		t.Fatalf("proof evidence payload differs from evidence endpoint payload")
	}

	eHashes := nestedMap(t, evidence, "hashes")
	pHashes := nestedMap(t, proofEvidence, "hashes")
	if eHashes["manifest_hash"] != pHashes["manifest_hash"] {
		t.Fatalf("manifest hash mismatch: evidence=%v proof=%v", eHashes["manifest_hash"], pHashes["manifest_hash"])
	}
	if eHashes["bundle_hash"] != pHashes["bundle_hash"] {
		t.Fatalf("bundle hash mismatch: evidence=%v proof=%v", eHashes["bundle_hash"], pHashes["bundle_hash"])
	}

	req := nestedMap(t, proof, "requirements")
	if req["authorization_required"] == nil {
		t.Fatalf("proof.requirements.authorization_required missing")
	}
	scopes := nestedMap(t, req, "required_scopes")
	if scopes["commerce_intent"] != "commerce:intent:sign" {
		t.Fatalf("unexpected commerce_intent scope: %v", scopes["commerce_intent"])
	}
	if scopes["commerce_accept"] != "commerce:accept:sign" {
		t.Fatalf("unexpected commerce_accept scope: %v", scopes["commerce_accept"])
	}
}

func getenvOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func postJSONLive(t *testing.T, url string, body map[string]any) map[string]any {
	t.Helper()
	return postJSONAuthLive(t, url, "", body)
}

func postJSONAuthLive(t *testing.T, url, bearer string, body map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	return doRequestJSON(t, req)
}

func getJSONAuthLive(t *testing.T, url, bearer string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	return doRequestJSON(t, req)
}

func doRequestJSON(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	h := &http.Client{Timeout: 20 * time.Second}
	resp, err := h.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", req.Method, req.URL.String(), err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s => %d: %s", req.Method, req.URL.String(), resp.StatusCode, string(b))
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid json from %s: %v", req.URL.String(), err)
	}
	return out
}

func nestedMap(t *testing.T, m map[string]any, k string) map[string]any {
	t.Helper()
	v, ok := m[k].(map[string]any)
	if !ok {
		t.Fatalf("missing object key %q", k)
	}
	return v
}

func nestedString(t *testing.T, m map[string]any, k1, k2 string) string {
	t.Helper()
	o := nestedMap(t, m, k1)
	s, ok := o[k2].(string)
	if !ok || s == "" {
		t.Fatalf("missing string key %q.%q", k1, k2)
	}
	return s
}
