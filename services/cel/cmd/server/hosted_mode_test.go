package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestBuildCapabilitiesResponseReflectsFlags(t *testing.T) {
	cfg := hostedModeConfig{
		EnableHostedCommerce:                      false,
		EnableProofExport:                         false,
		EnableServerDerivedSettlementAttestations: false,
	}
	resp := buildCapabilitiesResponse(cfg)
	if resp.Commerce.IntentV1.Hosted {
		t.Fatalf("expected hosted commerce intent disabled")
	}
	if resp.Commerce.AcceptV1.Hosted {
		t.Fatalf("expected hosted commerce accept disabled")
	}
	if resp.Commerce.IntentV1.Endpoint != "" || resp.Commerce.AcceptV1.Endpoint != "" {
		t.Fatalf("expected empty commerce endpoints when disabled")
	}
	if resp.Authorization.DelegationV1.ServerEnforced {
		t.Fatalf("expected delegation server_enforced=false when hosted disabled")
	}
	if resp.ProofExport.Endpoint != "" || len(resp.ProofExport.Formats) != 0 {
		t.Fatalf("expected proof export disabled")
	}
}

func TestBuildCapabilitiesResponseDeterministic(t *testing.T) {
	cfg := hostedModeConfig{
		EnableHostedCommerce:                      true,
		EnableProofExport:                         true,
		EnableServerDerivedSettlementAttestations: false,
	}
	r1 := buildCapabilitiesResponse(cfg)
	r2 := buildCapabilitiesResponse(cfg)
	b1, _ := json.Marshal(r1)
	b2, _ := json.Marshal(r2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("expected deterministic capabilities payload")
	}
}

func TestWriteStandardErrorIncludesDelegationReason(t *testing.T) {
	rr := httptest.NewRecorder()
	writeStandardError(rr, http.StatusForbidden, "FORBIDDEN", "delegation authorization failed", "missing_delegation")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object")
	}
	if errObj["reason"] != "missing_delegation" {
		t.Fatalf("unexpected reason: %v", errObj["reason"])
	}
	if _, ok := body["request_id"]; !ok {
		t.Fatalf("expected request_id")
	}
}

func TestFixedWindowLimiterDeterministic(t *testing.T) {
	limiter := newFixedWindowLimiter(2, time.Minute)
	k := "k"
	now := time.Date(2026, 2, 19, 8, 0, 0, 0, time.UTC)
	if !limiter.AllowAt(k, now) {
		t.Fatalf("first should pass")
	}
	if !limiter.AllowAt(k, now.Add(10*time.Second)) {
		t.Fatalf("second should pass")
	}
	if limiter.AllowAt(k, now.Add(20*time.Second)) {
		t.Fatalf("third in same window should fail")
	}
	if !limiter.AllowAt(k, now.Add(61*time.Second)) {
		t.Fatalf("new window should pass")
	}
}

func TestReadJSONWithLimitTooLarge(t *testing.T) {
	large := `{"x":"` + strings.Repeat("a", 300) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/commerce/intents", strings.NewReader(large))
	rr := httptest.NewRecorder()
	var payload map[string]any
	if ok := readJSONWithLimit(rr, req, 64, &payload); ok {
		t.Fatalf("expected readJSONWithLimit to fail")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	errObj, _ := body["error"].(map[string]any)
	if !reflect.DeepEqual(errObj["code"], "PAYLOAD_TOO_LARGE") {
		t.Fatalf("unexpected code: %v", errObj["code"])
	}
}

func TestHostedRoutesDisabled_HTTP404Envelope(t *testing.T) {
	cfg := hostedModeConfig{
		EnableHostedCommerce: true,
	}
	limiter := newFixedWindowLimiter(0, time.Minute)
	r := chi.NewRouter()
	r.Post("/commerce/intents", func(w http.ResponseWriter, r *http.Request) {
		if !precheckHostedCommerceRequest(w, r, cfg, limiter) {
			return
		}
		writeStandardError(w, 500, "INTERNAL", "unexpected", "")
	})
	r.Post("/commerce/accepts", func(w http.ResponseWriter, r *http.Request) {
		if !precheckHostedCommerceRequest(w, r, cfg, limiter) {
			return
		}
		writeStandardError(w, 500, "INTERNAL", "unexpected", "")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	cfg.EnableHostedCommerce = false
	body := `{"intent":{},"signature":{}}`
	resp1 := mustDoJSONRequest(t, http.MethodPost, ts.URL+"/commerce/intents", body, "")
	assertErrorEnvelope(t, resp1, http.StatusNotFound, "NOT_FOUND")

	resp2 := mustDoJSONRequest(t, http.MethodPost, ts.URL+"/commerce/accepts", body, "")
	assertErrorEnvelope(t, resp2, http.StatusNotFound, "NOT_FOUND")
}

func TestProofRouteDisabled_HTTP404Envelope(t *testing.T) {
	cfg := hostedModeConfig{
		EnableProofExport: false,
	}
	limiter := newFixedWindowLimiter(0, time.Minute)
	r := chi.NewRouter()
	r.Get("/cel/contracts/{contract_id}/proof", func(w http.ResponseWriter, r *http.Request) {
		if !precheckProofExportRequest(w, r, cfg, limiter) {
			return
		}
		writeStandardError(w, 500, "INTERNAL", "unexpected", "")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp := mustDoJSONRequest(t, http.MethodGet, ts.URL+"/cel/contracts/ctr_test/proof?format=json", "", "")
	assertErrorEnvelope(t, resp, http.StatusNotFound, "NOT_FOUND")
}

func TestProofBundleRouteDisabled_HTTP404Envelope(t *testing.T) {
	cfg := hostedModeConfig{
		EnableProofBundleExport: false,
	}
	limiter := newFixedWindowLimiter(0, time.Minute)
	r := chi.NewRouter()
	r.Get("/cel/contracts/{contract_id}/proof-bundle", func(w http.ResponseWriter, r *http.Request) {
		if !precheckProofBundleExportRequest(w, r, cfg, limiter) {
			return
		}
		writeStandardError(w, 500, "INTERNAL", "unexpected", "")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp := mustDoJSONRequest(t, http.MethodGet, ts.URL+"/cel/contracts/ctr_test/proof-bundle?format=json", "", "")
	assertErrorEnvelope(t, resp, http.StatusNotFound, "NOT_FOUND")
}

func TestHostedRateLimit_HTTP429Deterministic(t *testing.T) {
	cfg := hostedModeConfig{
		EnableHostedCommerce: true,
	}
	limiter := newFixedWindowLimiter(1, time.Minute)
	fixedNow := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return fixedNow }

	r := chi.NewRouter()
	r.Post("/commerce/intents", func(w http.ResponseWriter, r *http.Request) {
		if !precheckHostedCommerceRequest(w, r, cfg, limiter) {
			return
		}
		// Keep first request deterministic and independent of DB/auth.
		writeStandardError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON", "")
	})
	ts := httptest.NewServer(r)
	defer ts.Close()

	auth := "Bearer test-token"
	resp1 := mustDoJSONRequest(t, http.MethodPost, ts.URL+"/commerce/intents", `{`, auth)
	assertErrorEnvelope(t, resp1, http.StatusBadRequest, "BAD_REQUEST")

	resp2 := mustDoJSONRequest(t, http.MethodPost, ts.URL+"/commerce/intents", `{`, auth)
	assertErrorEnvelope(t, resp2, http.StatusTooManyRequests, "RATE_LIMITED")
	errObj, _ := resp2.Body["error"].(map[string]any)
	if errObj["reason"] != "rate_limited" {
		t.Fatalf("unexpected rate-limit reason: %v", errObj["reason"])
	}
}

type httpJSONResponse struct {
	Status int
	Body   map[string]any
}

func mustDoJSONRequest(t *testing.T, method, url, body, auth string) httpJSONResponse {
	t.Helper()
	var reqBody *strings.Reader
	if body == "" {
		reqBody = strings.NewReader("")
	} else {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	var parsed map[string]any
	if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return httpJSONResponse{Status: res.StatusCode, Body: parsed}
}

func assertErrorEnvelope(t *testing.T, resp httpJSONResponse, wantStatus int, wantCode string) {
	t.Helper()
	if resp.Status != wantStatus {
		t.Fatalf("status mismatch: got=%d want=%d body=%v", resp.Status, wantStatus, resp.Body)
	}
	errObj, ok := resp.Body["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object: %v", resp.Body)
	}
	if errObj["code"] != wantCode {
		t.Fatalf("error.code mismatch: got=%v want=%s", errObj["code"], wantCode)
	}
	msg, ok := errObj["message"].(string)
	if !ok || strings.TrimSpace(msg) == "" {
		t.Fatalf("missing error.message: %v", errObj)
	}
	if _, ok := resp.Body["request_id"]; !ok {
		t.Fatalf("missing request_id: %v", resp.Body)
	}
}
