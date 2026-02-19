package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"contractlane/pkg/evidencehash"
)

func TestVerifyEnvelopeV1_Ed25519HappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{
		"b": "two",
		"a": 1,
	}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		t.Fatalf("CanonicalSHA256: %v", err)
	}
	hashBytes, err := decodeLowerHex32(hashHex)
	if err != nil {
		t.Fatalf("decodeLowerHex32: %v", err)
	}
	sig := ed25519.Sign(priv, hashBytes)
	env := EnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}

	got, err := VerifyEnvelopeV1(payload, env)
	if err != nil {
		t.Fatalf("VerifyEnvelopeV1: %v", err)
	}
	if !got.IssuedAt.Equal(got.IssuedAt.UTC()) {
		t.Fatalf("expected UTC issuedAt")
	}
}

func TestVerifyEnvelopeV1_IssuedAtRequiredOrInvalid(t *testing.T) {
	payload := map[string]any{"a": 1}
	hashHex, _, _ := evidencehash.CanonicalSHA256(payload)
	env := EnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   "x",
		Signature:   "y",
		PayloadHash: hashHex,
		IssuedAt:    "",
	}
	_, err := VerifyEnvelopeV1(payload, env)
	if !errors.Is(err, ErrInvalidIssuedAt) {
		t.Fatalf("expected ErrInvalidIssuedAt for empty, got %v", err)
	}

	env.IssuedAt = "2026-02-18T12:00:00+00:00"
	_, err = VerifyEnvelopeV1(payload, env)
	if !errors.Is(err, ErrInvalidIssuedAt) {
		t.Fatalf("expected ErrInvalidIssuedAt for non-Z UTC format, got %v", err)
	}
}

func TestVerifyEnvelopeV1_PayloadHashMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := map[string]any{"a": 1}
	hashHex, _, _ := evidencehash.CanonicalSHA256(payload)
	hashBytes, _ := decodeLowerHex32(hashHex)
	sig := ed25519.Sign(priv, hashBytes)
	env := EnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	_, err := VerifyEnvelopeV1(payload, env)
	if !errors.Is(err, ErrPayloadHashMismatch) {
		t.Fatalf("expected ErrPayloadHashMismatch, got %v", err)
	}
}

func TestVerifyEnvelopeV1_UnsupportedAlgorithm(t *testing.T) {
	payload := map[string]any{"a": 1}
	hashHex, _, _ := evidencehash.CanonicalSHA256(payload)
	env := EnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "rsa-pss-sha256",
		PublicKey:   "x",
		Signature:   "y",
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	_, err := VerifyEnvelopeV1(payload, env)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}
