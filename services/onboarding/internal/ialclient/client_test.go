package ialclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreatePrincipalAndAgent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/principals":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"principal":{"principal_id":"prn_123"}}`))
		case "/actors/agents":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"agent":{"actor_id":"act_123","principal_id":"prn_123"},"credentials":{"token":"agt_live_abc"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := New(ts.URL)
	p, err := c.CreatePrincipal("Acme", "US", "UTC")
	if err != nil {
		t.Fatalf("CreatePrincipal error: %v", err)
	}
	if p.PrincipalID != "prn_123" {
		t.Fatalf("unexpected principal id: %s", p.PrincipalID)
	}
	a, creds, err := c.CreateAgent("prn_123", "Bot", []string{"cel.contracts:write"})
	if err != nil {
		t.Fatalf("CreateAgent error: %v", err)
	}
	if a.ActorID != "act_123" {
		t.Fatalf("unexpected actor id: %s", a.ActorID)
	}
	if creds.Token != "agt_live_abc" {
		t.Fatalf("unexpected token: %s", creds.Token)
	}
}
