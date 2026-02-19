package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestStripeV1Verifier_ValidSignature(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"id":"evt_123","type":"invoice.paid"}`)
	ts := int64(1_700_000_000)
	headers := http.Header{}
	headers.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1="+stripeSig(secret, ts, body))

	v := NewStripeV1VerifierWithTolerance("stripe", 300)
	got, err := v.Verify(headers, body, time.Unix(ts+2, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !got.Valid {
		t.Fatalf("expected valid signature")
	}
	if got.Scheme != "stripe-v1" {
		t.Fatalf("unexpected scheme: %s", got.Scheme)
	}
	if got.ProviderEventID != "evt_123" || got.EventType != "invoice.paid" {
		t.Fatalf("unexpected event metadata: %#v", got)
	}
}

func TestStripeV1Verifier_InvalidSignature(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"id":"evt_123","type":"invoice.paid"}`)
	ts := int64(1_700_000_000)
	headers := http.Header{}
	headers.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1=deadbeef")

	v := NewStripeV1VerifierWithTolerance("stripe", 300)
	got, err := v.Verify(headers, body, time.Unix(ts+1, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid signature")
	}
}

func TestStripeV1Verifier_MissingHeader(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"id":"evt_123","type":"invoice.paid"}`)
	headers := http.Header{}

	v := NewStripeV1VerifierWithTolerance("stripe", 300)
	got, err := v.Verify(headers, body, time.Unix(1_700_000_001, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid when header missing")
	}
}

func TestStripeV1Verifier_TimestampOutsideTolerance(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"id":"evt_123","type":"invoice.paid"}`)
	ts := int64(1_700_000_000)
	headers := http.Header{}
	headers.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1="+stripeSig(secret, ts, body))

	v := NewStripeV1VerifierWithTolerance("stripe", 300)
	got, err := v.Verify(headers, body, time.Unix(ts+301, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid due to skew outside tolerance")
	}
}

func TestStripeV1Verifier_JSONParsedOnlyAfterValidSignature(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{invalid-json`)
	ts := int64(1_700_000_000)
	headers := http.Header{}
	headers.Set("Stripe-Signature", "t="+strconv.FormatInt(ts, 10)+",v1="+stripeSig(secret, ts, body))

	v := NewStripeV1VerifierWithTolerance("stripe", 300)
	got, err := v.Verify(headers, body, time.Unix(ts+1, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !got.Valid {
		t.Fatalf("expected valid with matching signature even for invalid json")
	}
	if got.ProviderEventID != "" {
		t.Fatalf("expected empty ProviderEventID, got %q", got.ProviderEventID)
	}
	if got.EventType != "unknown" {
		t.Fatalf("expected unknown EventType, got %q", got.EventType)
	}
}

func stripeSig(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	payload := []byte(strconv.FormatInt(timestamp, 10) + ".")
	payload = append(payload, body...)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
