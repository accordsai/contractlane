package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestTemplateAdminLifecycleAndVisibilityLive(t *testing.T) {
	if os.Getenv("CL_INTEGRATION") != "1" {
		t.Skip("set CL_INTEGRATION=1 to run live integration")
	}
	adminToken := os.Getenv("CL_TEMPLATE_ADMIN_TOKEN")
	if adminToken == "" {
		t.Skip("set CL_TEMPLATE_ADMIN_TOKEN to run template admin live integration")
	}

	baseURL := getenvOr("CL_BASE_URL", "http://localhost:8080")
	ialURL := getenvOr("CL_IAL_BASE_URL", "http://localhost:8081")
	adminAuth := "Bearer " + adminToken

	pr1 := postJSONLive(t, ialURL+"/ial/principals", map[string]any{"name": "TemplateOwner", "jurisdiction": "US", "timezone": "UTC"})
	ownerPrincipal := nestedString(t, pr1, "principal", "principal_id")
	ownerAgent := postJSONLive(t, ialURL+"/ial/actors/agents", map[string]any{
		"principal_id": ownerPrincipal,
		"name":         "OwnerAgent",
		"auth": map[string]any{
			"mode":   "HMAC",
			"scopes": []string{"cel.contracts:write", "cel.contracts:read"},
		},
	})
	ownerActor := nestedString(t, ownerAgent, "agent", "actor_id")
	ownerAuth := "Bearer " + nestedString(t, ownerAgent, "credentials", "token")

	pr2 := postJSONLive(t, ialURL+"/ial/principals", map[string]any{"name": "TemplateOther", "jurisdiction": "US", "timezone": "UTC"})
	otherPrincipal := nestedString(t, pr2, "principal", "principal_id")
	otherAgent := postJSONLive(t, ialURL+"/ial/actors/agents", map[string]any{
		"principal_id": otherPrincipal,
		"name":         "OtherAgent",
		"auth": map[string]any{
			"mode":   "HMAC",
			"scopes": []string{"cel.contracts:write", "cel.contracts:read"},
		},
	})
	otherAuth := "Bearer " + nestedString(t, otherAgent, "credentials", "token")

	templateID := "tpl_private_live_" + time.Now().UTC().Format("20060102150405")
	createBody := map[string]any{
		"template_id":        templateID,
		"template_version":   "v1",
		"contract_type":      "NDA",
		"jurisdiction":       "US",
		"display_name":       "Private Template",
		"risk_tier":          "LOW",
		"visibility":         "PRIVATE",
		"owner_principal_id": ownerPrincipal,
		"template_gates":     map[string]any{"SEND_FOR_SIGNATURE": "DEFER"},
		"variables": []map[string]any{
			{
				"key":         "effective_date",
				"type":        "DATE",
				"required":    true,
				"sensitivity": "NONE",
				"set_policy":  "AGENT_ALLOWED",
				"constraints": map[string]any{},
			},
		},
	}
	resp1 := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates", adminAuth, createBody, map[string]string{"Idempotency-Key": "admin-create-live-1"})
	if resp1["status"] != "DRAFT" {
		t.Fatalf("expected DRAFT create status, got %v", resp1["status"])
	}
	respReplay := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates", adminAuth, createBody, map[string]string{"Idempotency-Key": "admin-create-live-1"})
	if fmt.Sprint(respReplay["template_id"]) != templateID {
		t.Fatalf("expected replay to return same template id")
	}

	cloneID := templateID + "_clone_v2"
	cloneResp := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates/"+templateID+":clone", adminAuth, map[string]any{
		"template_id":      cloneID,
		"template_version": "v2",
	}, map[string]string{"Idempotency-Key": "admin-clone-live-1"})
	if fmt.Sprint(cloneResp["template_id"]) != cloneID {
		t.Fatalf("expected clone template id %s, got %v", cloneID, cloneResp["template_id"])
	}
	if fmt.Sprint(cloneResp["status"]) != "DRAFT" {
		t.Fatalf("expected cloned template status DRAFT, got %v", cloneResp["status"])
	}
	cloneReplay := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates/"+templateID+":clone", adminAuth, map[string]any{
		"template_id":      cloneID,
		"template_version": "v2",
	}, map[string]string{"Idempotency-Key": "admin-clone-live-1"})
	if fmt.Sprint(cloneReplay["template_id"]) != cloneID {
		t.Fatalf("expected clone replay template id %s, got %v", cloneID, cloneReplay["template_id"])
	}

	_ = postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates/"+templateID+":publish", adminAuth, map[string]any{}, map[string]string{"Idempotency-Key": "admin-publish-live-1"})

	_ = postJSONAuthLive(t, baseURL+"/cel/principals/"+ownerPrincipal+"/templates/"+templateID+"/enable", ownerAuth, map[string]any{
		"enabled_by_actor_id": ownerActor,
		"override_gates":      map[string]any{},
	})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/cel/principals/"+otherPrincipal+"/templates/"+templateID+"/enable", bytes.NewReader(mustJSON(t, map[string]any{
		"enabled_by_actor_id": "",
		"override_gates":      map[string]any{},
	})))
	req.Header.Set("Authorization", otherAuth)
	req.Header.Set("Content-Type", "application/json")
	resp, body := doRequestRawLive(t, req)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 enabling private template for non-owner, got %d body=%s", resp.StatusCode, string(body))
	}

	contractOK := postJSONAuthLive(t, baseURL+"/cel/contracts", ownerAuth, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    ownerPrincipal,
			"actor_id":        ownerActor,
			"actor_type":      "AGENT",
			"idempotency_key": "tmpl-live-contract-owner",
		},
		"template_id": templateID,
		"counterparty": map[string]any{
			"name":  "Buyer",
			"email": "buyer@example.com",
		},
		"initial_variables": map[string]any{"effective_date": "2026-02-20"},
	})
	if nestedString(t, contractOK, "contract", "template_id") != templateID {
		t.Fatalf("unexpected template id on owner contract")
	}

	otherActor := nestedString(t, otherAgent, "agent", "actor_id")
	req2, _ := http.NewRequest(http.MethodPost, baseURL+"/cel/contracts", bytes.NewReader(mustJSON(t, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    otherPrincipal,
			"actor_id":        otherActor,
			"actor_type":      "AGENT",
			"idempotency_key": "tmpl-live-contract-other",
		},
		"template_id": templateID,
		"counterparty": map[string]any{
			"name":  "Buyer",
			"email": "buyer@example.com",
		},
		"initial_variables": map[string]any{"effective_date": "2026-02-20"},
	})))
	req2.Header.Set("Authorization", otherAuth)
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := doRequestRawLive(t, req2)
	if resp2.StatusCode != 404 {
		t.Fatalf("expected 404 creating contract with private template from non-owner, got %d", resp2.StatusCode)
	}

	shareResp := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates/"+templateID+"/shares", adminAuth, map[string]any{
		"principal_id": otherPrincipal,
	}, map[string]string{"Idempotency-Key": "admin-share-live-1"})
	if fmt.Sprint(shareResp["shared"]) != "true" {
		t.Fatalf("expected shared=true, got %v", shareResp["shared"])
	}
	shareReplay := postJSONAuthWithHeadersLive(t, baseURL+"/cel/admin/templates/"+templateID+"/shares", adminAuth, map[string]any{
		"principal_id": otherPrincipal,
	}, map[string]string{"Idempotency-Key": "admin-share-live-1"})
	if fmt.Sprint(shareReplay["principal_id"]) != otherPrincipal {
		t.Fatalf("expected share replay principal_id %s, got %v", otherPrincipal, shareReplay["principal_id"])
	}

	_ = postJSONAuthLive(t, baseURL+"/cel/principals/"+otherPrincipal+"/templates/"+templateID+"/enable", otherAuth, map[string]any{
		"enabled_by_actor_id": otherActor,
		"override_gates":      map[string]any{},
	})

	contractShared := postJSONAuthLive(t, baseURL+"/cel/contracts", otherAuth, map[string]any{
		"actor_context": map[string]any{
			"principal_id":    otherPrincipal,
			"actor_id":        otherActor,
			"actor_type":      "AGENT",
			"idempotency_key": "tmpl-live-contract-other-shared",
		},
		"template_id": templateID,
		"counterparty": map[string]any{
			"name":  "Buyer",
			"email": "buyer@example.com",
		},
		"initial_variables": map[string]any{"effective_date": "2026-02-20"},
	})
	if nestedString(t, contractShared, "contract", "template_id") != templateID {
		t.Fatalf("unexpected template id on shared contract")
	}
}

func TestTemplateAdminLintErrorShapeLive(t *testing.T) {
	if os.Getenv("CL_INTEGRATION") != "1" {
		t.Skip("set CL_INTEGRATION=1 to run live integration")
	}
	adminToken := os.Getenv("CL_TEMPLATE_ADMIN_TOKEN")
	if adminToken == "" {
		t.Skip("set CL_TEMPLATE_ADMIN_TOKEN to run template admin live integration")
	}
	baseURL := getenvOr("CL_BASE_URL", "http://localhost:8080")
	adminAuth := "Bearer " + adminToken

	templateID := "tpl_bad_live_" + time.Now().UTC().Format("20060102150405")
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/cel/admin/templates", bytes.NewReader(mustJSON(t, map[string]any{
		"template_id":      templateID,
		"template_version": "v1",
		"contract_type":    "NDA",
		"jurisdiction":     "US",
		"display_name":     "Bad Template",
		"risk_tier":        "LOW",
		"visibility":       "GLOBAL",
		"template_gates": map[string]any{
			"NOT_A_REAL_ACTION": "DEFER",
		},
		"variables": []map[string]any{
			{
				"key":         "Bad-Key",
				"type":        "DATE",
				"required":    true,
				"sensitivity": "NONE",
				"set_policy":  "AGENT_ALLOWED",
				"constraints": map[string]any{},
			},
		},
	})))
	req.Header.Set("Authorization", adminAuth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "admin-lint-live-1")

	resp, body := doRequestRawLive(t, req)
	if resp.StatusCode != 422 {
		t.Fatalf("expected 422, got %d body=%s", resp.StatusCode, string(body))
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid json body: %v", err)
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object: %v", parsed)
	}
	if fmt.Sprint(errObj["code"]) != "TEMPLATE_LINT_FAILED" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	details, ok := errObj["details"].([]any)
	if !ok || len(details) == 0 {
		t.Fatalf("expected non-empty error.details array")
	}
	foundPathCode := false
	for _, item := range details {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(m["path"]) == "variables[0].key" && fmt.Sprint(m["code"]) == "FORMAT_INVALID" {
			foundPathCode = true
			break
		}
	}
	if !foundPathCode {
		t.Fatalf("expected lint issue variables[0].key FORMAT_INVALID in details: %v", details)
	}
}

func postJSONAuthWithHeadersLive(t *testing.T, url, bearer string, body map[string]any, headers map[string]string) map[string]any {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequestJSON(t, req)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func doRequestRawLive(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	h := &http.Client{Timeout: 20 * time.Second}
	resp, err := h.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", req.Method, req.URL.String(), err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	body = buf.Bytes()
	return resp, body
}
