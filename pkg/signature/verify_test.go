package signature

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/accordsai/contractlane/pkg/evidencehash"
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

func TestVerifyEnvelopeV2_ES256HappyPathRaw64(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{"a": 1, "b": "two"}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		t.Fatalf("CanonicalSHA256: %v", err)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigRaw := make([]byte, 64)
	r.FillBytes(sigRaw[:32])
	s.FillBytes(sigRaw[32:])

	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	env := EnvelopeV2{
		Version:     "sig-v2",
		Algorithm:   "es256",
		PublicKey:   base64.RawURLEncoding.EncodeToString(pub),
		Signature:   base64.RawURLEncoding.EncodeToString(sigRaw),
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	got, err := VerifyEnvelopeV2(payload, env)
	if err != nil {
		t.Fatalf("VerifyEnvelopeV2: %v", err)
	}
	if !got.IssuedAt.Equal(got.IssuedAt.UTC()) {
		t.Fatalf("expected UTC issuedAt")
	}
}

func TestVerifyEnvelopeV2_ES256HappyPathDERCompatibility(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{"x": 1}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		t.Fatalf("CanonicalSHA256: %v", err)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, hashBytes)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
	env := EnvelopeV2{
		Version:     "sig-v2",
		Algorithm:   "es256",
		PublicKey:   base64.RawURLEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sigDER),
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, err := VerifyEnvelopeV2(payload, env); err != nil {
		t.Fatalf("VerifyEnvelopeV2 DER compatibility: %v", err)
	}
}

func TestVerifyEnvelope_DispatchV1AndV2(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{"a": 1}
	hashHex, _, _ := evidencehash.CanonicalSHA256(payload)
	hashBytes, _ := decodeLowerHex32(hashHex)
	sig := ed25519.Sign(priv, hashBytes)
	env := Envelope{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, err := VerifyEnvelope(payload, env); err != nil {
		t.Fatalf("VerifyEnvelope(v1): %v", err)
	}
}

func TestVerifyEnvelopeV2_InvalidEncodingCases(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := map[string]any{"a": 1}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		t.Fatalf("CanonicalSHA256: %v", err)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigRaw := make([]byte, 64)
	r.FillBytes(sigRaw[:32])
	s.FillBytes(sigRaw[32:])
	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)

	base := EnvelopeV2{
		Version:     "sig-v2",
		Algorithm:   "es256",
		PublicKey:   base64.RawURLEncoding.EncodeToString(pub),
		Signature:   base64.RawURLEncoding.EncodeToString(sigRaw),
		PayloadHash: hashHex,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}

	badAlgo := base
	badAlgo.Algorithm = "ed25519"
	if _, err := VerifyEnvelopeV2(payload, badAlgo); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm for bad algo, got %v", err)
	}

	badPub := base
	badPub.PublicKey = base64.RawURLEncoding.EncodeToString(pub[:64])
	if _, err := VerifyEnvelopeV2(payload, badPub); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("expected ErrInvalidEncoding for bad pub len, got %v", err)
	}

	offCurve := make([]byte, 65)
	offCurve[0] = 0x04
	offCurve[32] = 0x01
	offCurve[64] = 0x01
	badPoint := base
	badPoint.PublicKey = base64.RawURLEncoding.EncodeToString(offCurve)
	if _, err := VerifyEnvelopeV2(payload, badPoint); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("expected ErrInvalidEncoding for off-curve pub, got %v", err)
	}

	badSig := base
	badSig.Signature = base64.RawURLEncoding.EncodeToString(sigRaw[:63])
	if _, err := VerifyEnvelopeV2(payload, badSig); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("expected ErrInvalidEncoding for short signature, got %v", err)
	}
}
