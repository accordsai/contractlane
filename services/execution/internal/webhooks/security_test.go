package webhooks

import "testing"

func TestVerifySignature(t *testing.T) {
	secret := "test_secret"
	body := []byte(`{"envelope_id":"env_1","event_type":"envelope.completed"}`)
	sig := SignBody(secret, body)
	if !VerifySignature(secret, body, sig) {
		t.Fatalf("expected signature to verify")
	}
	if VerifySignature(secret, body, "sha256=deadbeef") {
		t.Fatalf("expected invalid signature")
	}
}

func TestPayloadHashDeterministic(t *testing.T) {
	body := []byte(`{"a":1}`)
	h1 := PayloadHash(body)
	h2 := PayloadHash(body)
	if h1 != h2 {
		t.Fatalf("expected deterministic hash")
	}
	if h1 == "" {
		t.Fatalf("expected non-empty hash")
	}
}
