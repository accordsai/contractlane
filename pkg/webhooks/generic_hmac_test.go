package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

func TestGenericHMACVerifier_ValidSignature(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	headers := http.Header{}
	headers.Set("X-Signature", hex.EncodeToString(signHMAC(secret, body)))
	headers.Set("X-Event-Id", "evt_123")
	headers.Set("X-Event-Type", "contract.completed")

	v := NewGenericHMACVerifier("internal")
	got, err := v.Verify(headers, body, time.Unix(0, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !got.Valid {
		t.Fatalf("expected valid signature")
	}
	if got.Scheme != "generic-hmac-sha256/v1" {
		t.Fatalf("unexpected scheme: %s", got.Scheme)
	}
	if got.ProviderEventID != "evt_123" || got.EventType != "contract.completed" {
		t.Fatalf("unexpected event metadata: %#v", got)
	}
}

func TestGenericHMACVerifier_InvalidSignature(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	headers := http.Header{}
	headers.Set("X-Signature", hex.EncodeToString([]byte("wrong-sig")))

	v := NewGenericHMACVerifier("internal")
	got, err := v.Verify(headers, body, time.Unix(0, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid signature")
	}
}

func TestGenericHMACVerifier_MissingSignature(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	headers := http.Header{}

	v := NewGenericHMACVerifier("internal")
	got, err := v.Verify(headers, body, time.Unix(0, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid when signature header missing")
	}
	if present, _ := got.Details["signature_header_present"].(bool); present {
		t.Fatalf("expected signature_header_present=false")
	}
}

func TestGenericHMACVerifier_BadHex(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	headers := http.Header{}
	headers.Set("X-Signature", "zzzz")

	v := NewGenericHMACVerifier("internal")
	got, err := v.Verify(headers, body, time.Unix(0, 0), secret)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got.Valid {
		t.Fatalf("expected invalid for bad hex signature")
	}
	if decodable, _ := got.Details["signature_hex_decodable"].(bool); decodable {
		t.Fatalf("expected signature_hex_decodable=false")
	}
}

func TestGenericHMACVerifier_EmptySecretErrors(t *testing.T) {
	body := []byte(`{"ok":true}`)
	headers := http.Header{}
	headers.Set("X-Signature", "deadbeef")

	v := NewGenericHMACVerifier("internal")
	_, err := v.Verify(headers, body, time.Unix(0, 0), "")
	if err == nil {
		t.Fatalf("expected error for empty secret")
	}
}

func signHMAC(secret string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}
