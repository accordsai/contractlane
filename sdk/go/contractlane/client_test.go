package contractlane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGateResolveRequiresIdempotency(t *testing.T) {
	c := NewClient("http://example.com", PrincipalAuth{Token: "t"})
	_, err := c.GateResolve(context.Background(), "terms_current", "ext_1", ResolveOptions{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSDKConformanceCases(t *testing.T) {
	var attempt429 int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "sub_done":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "sub_blocked":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "BLOCKED", "next_step": map[string]any{"type": "SIGN", "continue_url": "https://example/sign"}})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "retry429":
			if attempt429 == 0 {
				attempt429++
				w.WriteHeader(429)
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": "RATE_LIMIT", "message": "try later"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "unauth":
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_code": "UNAUTHORIZED", "message": "bad token", "request_id": "req_1"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"})
	if _, err := c.GateStatus(context.Background(), "terms_current", "sub_done"); err != nil {
		t.Fatalf("done: %v", err)
	}
	blocked, err := c.GateStatus(context.Background(), "terms_current", "sub_blocked")
	if err != nil || blocked.Status != "BLOCKED" || blocked.NextStep == nil || blocked.NextStep.ContinueURL == "" {
		t.Fatalf("blocked mismatch err=%v blocked=%+v", err, blocked)
	}
	if _, err := c.GateStatus(context.Background(), "terms_current", "retry429"); err != nil {
		t.Fatalf("retry mismatch: %v", err)
	}
	if _, err := c.GateStatus(context.Background(), "terms_current", "unauth"); err == nil {
		t.Fatalf("expected 401 sdk error")
	}
}

func TestConformanceCasesExist(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	cases := []string{
		"conformance/cases/gate_status_done.json",
		"conformance/cases/gate_status_blocked.json",
		"conformance/cases/gate_resolve_requires_idempotency.json",
		"conformance/cases/error_model_401.json",
		"conformance/cases/retry_429_then_success.json",
	}
	for _, c := range cases {
		if strings.TrimSpace(c) == "" {
			t.Fatal("invalid case path")
		}
		if _, err := os.Stat(filepath.Join(root, c)); err != nil {
			t.Fatalf("missing conformance case %s: %v", c, err)
		}
	}
}
