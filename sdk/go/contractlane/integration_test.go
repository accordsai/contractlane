package contractlane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type liveEnv struct {
	BaseURL string
	IALURL  string
	Token   string
}

func TestSDKIntegrationLive(t *testing.T) {
	if os.Getenv("CL_INTEGRATION") != "1" {
		t.Skip("set CL_INTEGRATION=1 to run live integration")
	}
	env := setupLiveEnv(t)
	client := NewClient(env.BaseURL, PrincipalAuth{Token: env.Token})

	gateKey := "terms_current"
	subject := "go-subject-" + NewIdempotencyKey()
	status, err := client.GateStatus(context.Background(), gateKey, subject)
	if err != nil {
		t.Fatalf("GateStatus: %v", err)
	}
	if status.Status != "DONE" && status.Status != "BLOCKED" {
		t.Fatalf("unexpected gate status %q", status.Status)
	}

	res, err := client.GateResolve(context.Background(), gateKey, subject, ResolveOptions{ActorType: "HUMAN", IdempotencyKey: NewIdempotencyKey()})
	if err != nil {
		t.Fatalf("GateResolve: %v", err)
	}
	if res.Status != "DONE" && res.Status != "BLOCKED" {
		t.Fatalf("unexpected resolve status %q", res.Status)
	}
	if res.Status == "BLOCKED" && res.NextStep == nil && res.Remediation == nil {
		t.Fatalf("blocked result missing next step/remediation")
	}
}

func TestConformanceLive(t *testing.T) {
	if os.Getenv("CL_CONFORMANCE") != "1" {
		t.Skip("set CL_CONFORMANCE=1 to run conformance live")
	}
	env := setupLiveEnv(t)
	client := NewClient(env.BaseURL, PrincipalAuth{Token: env.Token})

	gateKey := "terms_current"
	doneSubject := "go-conformance-done-" + NewIdempotencyKey()
	_, err := client.GateResolve(context.Background(), gateKey, doneSubject, ResolveOptions{ActorType: "HUMAN", IdempotencyKey: NewIdempotencyKey()})
	if err != nil {
		t.Fatalf("resolve precondition: %v", err)
	}
	blockedSubject := "go-conformance-blocked-" + NewIdempotencyKey()
	blocked, err := client.GateStatus(context.Background(), gateKey, blockedSubject)
	if err != nil {
		t.Fatalf("status blocked case: %v", err)
	}
	if blocked.Status != "BLOCKED" && blocked.Status != "DONE" {
		t.Fatalf("bad union status: %q", blocked.Status)
	}
}

func setupLiveEnv(t *testing.T) liveEnv {
	t.Helper()
	base := getenv("CL_BASE_URL", "http://localhost:8080")
	ial := getenv("CL_IAL_BASE_URL", "http://localhost:8081")

	principal := postJSON(t, ial+"/ial/principals", map[string]any{"name": "SDK Go", "jurisdiction": "US", "timezone": "UTC"})
	principalObj := principal["principal"].(map[string]any)
	principalID := principalObj["principal_id"].(string)

	agent := postJSON(t, ial+"/ial/actors/agents", map[string]any{
		"principal_id": principalID,
		"name":         "SDKGoAgent",
		"auth": map[string]any{
			"mode":   "HMAC",
			"scopes": []string{"cel.contracts:write", "exec.signatures:send"},
		},
	})
	agentObj := agent["agent"].(map[string]any)
	agentID := agentObj["actor_id"].(string)
	token := agent["credentials"].(map[string]any)["token"].(string)
	authHeader := "Bearer " + token

	_ = postJSON(t, base+"/cel/dev/seed-template", map[string]any{"principal_id": principalID})
	programKey := "terms_current"
	_ = postJSONAuth(t, base+"/cel/programs", authHeader, map[string]any{
		"actor_context": map[string]any{"principal_id": principalID, "actor_id": agentID, "actor_type": "AGENT", "idempotency_key": NewIdempotencyKey()},
		"key":           programKey,
		"mode":          "STRICT_RECONSENT",
	})
	_ = postJSONAuth(t, base+"/cel/programs/"+programKey+"/publish", authHeader, map[string]any{
		"actor_context":             map[string]any{"principal_id": principalID, "actor_id": agentID, "actor_type": "AGENT", "idempotency_key": NewIdempotencyKey()},
		"required_template_id":      "tpl_nda_us_v1",
		"required_template_version": "v1",
	})

	return liveEnv{BaseURL: base, IALURL: ial, Token: token}
}

func postJSON(t *testing.T, url string, body map[string]any) map[string]any {
	t.Helper()
	return postJSONAuth(t, url, "", body)
}

func postJSONAuth(t *testing.T, url, bearer string, body map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	h := &http.Client{Timeout: 15 * time.Second}
	resp, err := h.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s => %d: %s", url, resp.StatusCode, string(rb))
	}
	var out map[string]any
	if err := json.Unmarshal(rb, &out); err != nil {
		t.Fatalf("invalid json from %s: %v", url, err)
	}
	return out
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}
