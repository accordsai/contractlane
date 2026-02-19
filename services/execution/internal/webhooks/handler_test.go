package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

type fakeReceiptStore struct {
	endpoint                     Endpoint
	inserted                     bool
	insertReceipt                Receipt
	existing                     Receipt
	insertCalls                  int
	getExistingCalls             int
	belongsToPrincipal           bool
	contractBelongsCalls         int
	lastContractBelongsID        string
	lastContractBelongsPrincipal string
	updateLinkageCalls           int
	lastUpdateReceiptID          string
	lastUpdateContractID         string
	lastUpdateLinkedAction       *string
}

func (f *fakeReceiptStore) GetEndpoint(ctx context.Context, provider, token string) (Endpoint, error) {
	if token != "tok_1" {
		return Endpoint{}, ErrEndpointNotFound
	}
	if provider != "internal" && provider != "stripe" {
		return Endpoint{}, ErrEndpointNotFound
	}
	return f.endpoint, nil
}

func (f *fakeReceiptStore) InsertReceipt(ctx context.Context, receipt Receipt) (bool, string, error) {
	f.insertCalls++
	f.insertReceipt = receipt
	if f.inserted {
		return true, "rcp_new", nil
	}
	return false, "", nil
}

func (f *fakeReceiptStore) GetReceiptByProviderEventID(ctx context.Context, principalID, provider, providerEventID string) (Receipt, error) {
	f.getExistingCalls++
	return f.existing, nil
}

func (f *fakeReceiptStore) ContractBelongsToPrincipal(ctx context.Context, contractID, principalID string) (bool, error) {
	f.contractBelongsCalls++
	f.lastContractBelongsID = contractID
	f.lastContractBelongsPrincipal = principalID
	return f.belongsToPrincipal, nil
}

func (f *fakeReceiptStore) UpdateReceiptLinkage(ctx context.Context, receiptID, contractID string, linkedAction *string) error {
	f.updateLinkageCalls++
	f.lastUpdateReceiptID = receiptID
	f.lastUpdateContractID = contractID
	f.lastUpdateLinkedAction = linkedAction
	return nil
}

func TestHandleIngress_ValidAndReplay(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "secret",
		},
		inserted:           true,
		belongsToPrincipal: true,
	}
	h := NewIngressHandler(store)

	contractID := "11111111-1111-4111-8111-111111111111"
	body := []byte(`{"contract_id":"` + contractID + `","linked_action":"SEND_FOR_SIGNATURE"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader(body))
	req.Header.Set("X-Signature", signHex("secret", body))
	req.Header.Set("X-Event-Id", "evt_1")
	req.Header.Set("X-Event-Type", "contract.completed")
	req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()
	h.HandleIngress(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.insertCalls != 1 {
		t.Fatalf("expected 1 insert call")
	}
	if !store.insertReceipt.SignatureValid || store.insertReceipt.ProcessingStatus != "VERIFIED" {
		t.Fatalf("expected verified receipt insert, got %+v", store.insertReceipt)
	}
	if store.updateLinkageCalls != 1 {
		t.Fatalf("expected linkage update call")
	}
	if store.lastUpdateContractID != contractID {
		t.Fatalf("expected linkage contract id %s got %s", contractID, store.lastUpdateContractID)
	}
	if store.lastUpdateLinkedAction == nil || *store.lastUpdateLinkedAction != "SEND_FOR_SIGNATURE" {
		t.Fatalf("expected linkage action SEND_FOR_SIGNATURE")
	}
}

func TestHandleIngress_MissingSignaturePersistsRejected(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "secret",
		},
		inserted: true,
	}
	h := NewIngressHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader([]byte(`{"x":1}`)))
	req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()
	h.HandleIngress(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.insertReceipt.SignatureValid {
		t.Fatalf("expected signature_valid false")
	}
	if store.insertReceipt.ProcessingStatus != "REJECTED" {
		t.Fatalf("expected REJECTED processing status")
	}
	if store.updateLinkageCalls != 0 {
		t.Fatalf("expected no linkage update for rejected signature")
	}
}

func TestHandleIngress_ReplayUsesExistingReceipt(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "secret",
		},
		inserted: false,
		existing: Receipt{
			ReceiptID:      "rcp_existing",
			RequestSHA256:  "abc",
			SignatureValid: false,
		},
	}
	h := NewIngressHandler(store)
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader(body))
	req.Header.Set("X-Signature", signHex("secret", body))
	req.Header.Set("X-Event-Id", "evt_1")
	req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()
	h.HandleIngress(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.getExistingCalls != 1 {
		t.Fatalf("expected existing receipt lookup")
	}
}

func TestHandleIngress_StripeValidPersistsVerifiedAndProviderEventID(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "whsec_test",
		},
		inserted: true,
	}
	h := NewIngressHandler(store)
	ts := time.Now().UTC().Unix()
	body := []byte(`{"id":"evt_stripe_1","type":"payment_intent.succeeded"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe/tok_1", bytesReader(body))
	req.Header.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1="+signStripeHex("whsec_test", ts, body))
	req = withChiParams(req, "provider", "stripe", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()

	h.HandleIngress(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !store.insertReceipt.SignatureValid || store.insertReceipt.ProcessingStatus != "VERIFIED" {
		t.Fatalf("expected verified receipt insert, got %+v", store.insertReceipt)
	}
	if store.insertReceipt.SignatureScheme != "stripe-v1" {
		t.Fatalf("expected stripe-v1 scheme, got %s", store.insertReceipt.SignatureScheme)
	}
	if store.insertReceipt.ProviderEventID == nil || *store.insertReceipt.ProviderEventID != "evt_stripe_1" {
		t.Fatalf("expected provider_event_id evt_stripe_1, got %+v", store.insertReceipt.ProviderEventID)
	}
}

func TestHandleIngress_StripeReplayUsesProviderEventIDDedupe(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "whsec_test",
		},
		inserted: false,
		existing: Receipt{
			ReceiptID:      "rcp_existing_stripe",
			RequestSHA256:  "stripe-req-sha",
			SignatureValid: true,
		},
	}
	h := NewIngressHandler(store)
	ts := time.Now().UTC().Unix()
	body := []byte(`{"id":"evt_stripe_2","type":"checkout.session.completed"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe/tok_1", bytesReader(body))
	req.Header.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1="+signStripeHex("whsec_test", ts, body))
	req = withChiParams(req, "provider", "stripe", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()

	h.HandleIngress(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.getExistingCalls != 1 {
		t.Fatalf("expected existing receipt lookup for replay")
	}
	if store.insertReceipt.ProviderEventID == nil || *store.insertReceipt.ProviderEventID != "evt_stripe_2" {
		t.Fatalf("expected parsed provider_event_id for dedupe key, got %+v", store.insertReceipt.ProviderEventID)
	}
}

func TestHandleIngress_LinkageNotAppliedCrossPrincipal(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "secret",
		},
		inserted:           true,
		belongsToPrincipal: false,
	}
	h := NewIngressHandler(store)
	contractID := "11111111-1111-4111-8111-111111111111"
	body := []byte(`{"metadata":{"contract_id":"` + contractID + `","linked_action":"NOOP"}}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader(body))
	req.Header.Set("X-Signature", signHex("secret", body))
	req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()
	h.HandleIngress(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if store.contractBelongsCalls != 1 {
		t.Fatalf("expected principal ownership check")
	}
	if store.updateLinkageCalls != 0 {
		t.Fatalf("expected no linkage update when contract principal mismatches")
	}
}

func TestHandleIngress_InvalidOrMissingContractID_NoLinkage(t *testing.T) {
	cases := []string{
		`{"ok":true}`,
		`{"contract_id":"not-a-uuid"}`,
		`{"metadata":{"contract_id":"still-not-uuid"}}`,
		`{"metadata":{"linked_action":"A"}}`,
		`not-json`,
	}
	for _, bodyStr := range cases {
		store := &fakeReceiptStore{
			endpoint: Endpoint{
				PrincipalID: "11111111-1111-1111-1111-111111111111",
				Secret:      "secret",
			},
			inserted:           true,
			belongsToPrincipal: true,
		}
		h := NewIngressHandler(store)
		body := []byte(bodyStr)
		req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader(body))
		req.Header.Set("X-Signature", signHex("secret", body))
		req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
		rr := httptest.NewRecorder()
		h.HandleIngress(rr, req)
		if rr.Code != 200 {
			t.Fatalf("body=%q expected 200, got %d body=%s", bodyStr, rr.Code, rr.Body.String())
		}
		if store.contractBelongsCalls != 0 {
			t.Fatalf("body=%q expected no contract ownership check", bodyStr)
		}
		if store.updateLinkageCalls != 0 {
			t.Fatalf("body=%q expected no linkage update", bodyStr)
		}
	}
}

func TestHandleIngress_PayloadTooLarge(t *testing.T) {
	store := &fakeReceiptStore{
		endpoint: Endpoint{
			PrincipalID: "11111111-1111-1111-1111-111111111111",
			Secret:      "secret",
		},
		inserted: true,
	}
	h := NewIngressHandler(store)
	body := make([]byte, maxWebhookBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/internal/tok_1", bytesReader(body))
	req = withChiParams(req, "provider", "internal", "endpoint_token", "tok_1")
	rr := httptest.NewRecorder()
	h.HandleIngress(rr, req)
	if rr.Code != 413 {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func withChiParams(req *http.Request, kv ...string) *http.Request {
	rc := chi.NewRouteContext()
	for i := 0; i+1 < len(kv); i += 2 {
		rc.URLParams.Add(kv[i], kv[i+1])
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
}

func signHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func signStripeHex(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	payload := []byte(strconv.FormatInt(ts, 10) + ".")
	payload = append(payload, body...)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
