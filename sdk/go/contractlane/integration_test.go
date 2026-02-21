package contractlane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/accordsai/contractlane/pkg/evp"
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

func TestContractEvidenceManifestHashRulesLive(t *testing.T) {
	if os.Getenv("CL_INTEGRATION") != "1" {
		t.Skip("set CL_INTEGRATION=1 to run live integration")
	}
	env := setupLiveEnv(t)
	client := NewClient(env.BaseURL, PrincipalAuth{Token: env.Token})

	subject := "go-evidence-" + NewIdempotencyKey()
	resolve, err := client.GateResolve(context.Background(), "terms_current", subject, ResolveOptions{
		ActorType:      "HUMAN",
		IdempotencyKey: NewIdempotencyKey(),
	})
	if err != nil {
		t.Fatalf("GateResolve: %v", err)
	}
	contractID, _ := resolve.Raw["contract_id"].(string)
	if contractID == "" {
		t.Fatalf("GateResolve missing contract_id in response: %#v", resolve.Raw)
	}

	evidence, err := client.GetContractEvidence(context.Background(), contractID, "json", nil, "none")
	if err != nil {
		t.Fatalf("GetContractEvidence: %v", err)
	}
	manifest, _ := evidence["manifest"].(map[string]any)
	if manifest == nil {
		t.Fatalf("missing manifest in evidence response")
	}
	canonicalization, _ := manifest["canonicalization"].(map[string]any)
	if canonicalization == nil {
		t.Fatalf("missing manifest.canonicalization")
	}
	if got := fmt.Sprint(canonicalization["manifest_hash_rule"]); got != "canonical_json_sorted_keys_v1" {
		t.Fatalf("unexpected manifest_hash_rule=%q", got)
	}
	if got := fmt.Sprint(canonicalization["bundle_hash_rule"]); got != "concat_artifact_hashes_v1" {
		t.Fatalf("unexpected bundle_hash_rule=%q", got)
	}
	descs, _ := manifest["artifacts"].([]any)
	if len(descs) == 0 {
		t.Fatalf("manifest.artifacts is empty")
	}
	foundDelegations := false
	foundWebhookReceipts := false
	foundAnchors := false
	for _, raw := range descs {
		d, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("artifact descriptor has invalid shape: %#v", raw)
		}
		if fmt.Sprint(d["artifact_type"]) == "delegation_records" {
			foundDelegations = true
		}
		if fmt.Sprint(d["artifact_type"]) == "webhook_receipts" {
			foundWebhookReceipts = true
		}
		if fmt.Sprint(d["artifact_type"]) == "anchors" {
			foundAnchors = true
		}
		hashOf := strings.TrimSpace(fmt.Sprint(d["hash_of"]))
		hashRule := strings.TrimSpace(fmt.Sprint(d["hash_rule"]))
		expected := strings.TrimSpace(fmt.Sprint(d["sha256"]))
		if hashOf == "" || hashRule == "" || expected == "" {
			t.Fatalf("artifact descriptor missing hash fields: %#v", d)
		}

		target, ok := jsonPathGet(evidence, hashOf)
		if !ok {
			t.Fatalf("hash_of path not found: %s", hashOf)
		}
		actual, err := computeHashByRule(hashRule, target)
		if err != nil {
			t.Fatalf("computeHashByRule(%s): %v", hashRule, err)
		}
		if actual != expected {
			t.Fatalf("hash mismatch for %s (%s): expected=%s actual=%s", fmt.Sprint(d["artifact_id"]), hashOf, expected, actual)
		}
	}
	if !foundDelegations {
		t.Fatalf("expected delegation_records artifact descriptor in evidence manifest")
	}
	if !foundWebhookReceipts {
		t.Fatalf("expected webhook_receipts artifact descriptor in evidence manifest")
	}
	if !foundAnchors {
		t.Fatalf("expected anchors artifact descriptor in evidence manifest")
	}
	webhookReceiptsRaw, ok := evidence["webhook_receipts"]
	if !ok {
		t.Fatalf("expected artifacts.webhook_receipts payload")
	}
	if _, ok := webhookReceiptsRaw.([]any); !ok {
		t.Fatalf("expected webhook_receipts payload to be array, got %T", webhookReceiptsRaw)
	}
	anchorsRaw, ok := evidence["anchors"]
	if !ok {
		t.Fatalf("expected artifacts.anchors payload")
	}
	if _, ok := anchorsRaw.([]any); !ok {
		t.Fatalf("expected anchors payload to be array, got %T", anchorsRaw)
	}
	rawEvidence, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	verifyResult, err := evp.VerifyBundleJSON(rawEvidence)
	if err != nil {
		t.Fatalf("VerifyBundleJSON error: %v", err)
	}
	if verifyResult.Status != evp.StatusVerified {
		t.Fatalf("expected verified evidence bundle, got %s details=%v", verifyResult.Status, verifyResult.Details)
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
			"scopes": []string{"cel.contracts:write", "cel.contracts:read", "exec.signatures:send"},
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

func jsonPathGet(root map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil, false
	}
	var cur any = root
	for _, p := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := obj[p]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func computeHashByRule(rule string, v any) (string, error) {
	switch rule {
	case "utf8_v1", "utf8":
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("utf8 rule expects string, got %T", v)
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:]), nil
	case "canonical_json_sorted_keys_v1", "canonical_json_sorted_keys":
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash_rule %q", rule)
	}
}
