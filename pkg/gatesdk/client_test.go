package gatesdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientStatusResolveEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/cel/gates/terms_current/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req_1", "gate_key": "terms_current", "status": "BLOCKED",
				"next_step": map[string]any{"type": "APPROVE_ACTION", "reason": "GATE_NOT_SATISFIED"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/cel/gates/terms_current/resolve":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req_2", "gate_key": "terms_current", "status": "BLOCKED",
				"contract_id": "ctr_1", "remediation": map[string]any{"continue_url": "https://sign.local/env_1"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/cel/gates/terms_current/evidence":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req_3",
				"evidence": map[string]any{
					"accepted": map[string]any{"contract_id": "ctr_1", "template_version": "v2"},
				},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	ctx := context.Background()

	st, err := c.Status(ctx, "terms_current", "ext_1", "")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if st.Status != "BLOCKED" {
		t.Fatalf("Status() status = %q", st.Status)
	}

	res, err := c.Resolve(ctx, "terms_current", ResolveRequest{
		ExternalSubjectID: "ext_1",
		ActorType:         "HUMAN",
		IdempotencyKey:    "k1",
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if res.ContractID != "ctr_1" {
		t.Fatalf("Resolve() contract_id = %q", res.ContractID)
	}

	ev, err := c.Evidence(ctx, "terms_current", "ext_1")
	if err != nil {
		t.Fatalf("Evidence() error: %v", err)
	}
	accepted, _ := ev.Evidence["accepted"].(map[string]any)
	if accepted["contract_id"] != "ctr_1" {
		t.Fatalf("Evidence() contract_id = %v", accepted["contract_id"])
	}
}
