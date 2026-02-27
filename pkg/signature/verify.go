package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/accordsai/contractlane/pkg/evidencehash"
)

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidIssuedAt      = errors.New("invalid issued_at")
	ErrPayloadHashMismatch  = errors.New("payload hash mismatch")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidEncoding      = errors.New("invalid encoding")
)

type VerifyResult struct {
	IssuedAt time.Time
}

func VerifyEnvelope(payload any, env Envelope) (VerifyResult, error) {
	version := strings.TrimSpace(env.Version)
	switch version {
	case "sig-v1":
		return VerifyEnvelopeV1(payload, EnvelopeV1(env))
	case "sig-v2":
		return VerifyEnvelopeV2(payload, EnvelopeV2(env))
	default:
		return VerifyResult{}, ErrUnsupportedAlgorithm
	}
}

func VerifyEnvelopeV1(payload any, env EnvelopeV1) (VerifyResult, error) {
	if strings.TrimSpace(env.Version) != "sig-v1" {
		return VerifyResult{}, ErrUnsupportedAlgorithm
	}
	if strings.TrimSpace(env.IssuedAt) == "" {
		return VerifyResult{}, ErrInvalidIssuedAt
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, env.IssuedAt)
	if err != nil {
		return VerifyResult{}, ErrInvalidIssuedAt
	}
	if !strings.HasSuffix(env.IssuedAt, "Z") || !issuedAt.Equal(issuedAt.UTC()) {
		return VerifyResult{}, ErrInvalidIssuedAt
	}

	expectedHashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return VerifyResult{}, err
	}
	expectedHashBytes, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return VerifyResult{}, ErrInvalidEncoding
	}
	payloadHashBytes, err := decodeLowerHex32(strings.TrimSpace(env.PayloadHash))
	if err != nil {
		return VerifyResult{}, err
	}
	if subtle.ConstantTimeCompare(expectedHashBytes, payloadHashBytes) != 1 {
		return VerifyResult{}, ErrPayloadHashMismatch
	}

	if strings.ToLower(strings.TrimSpace(env.Algorithm)) != "ed25519" {
		return VerifyResult{}, ErrUnsupportedAlgorithm
	}
	if err := verifyEd25519(payloadHashBytes, env.PublicKey, env.Signature); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{IssuedAt: issuedAt.UTC()}, nil
}

func VerifyEnvelopeV2(payload any, env EnvelopeV2) (VerifyResult, error) {
	if strings.TrimSpace(env.Version) != "sig-v2" {
		return VerifyResult{}, ErrUnsupportedAlgorithm
	}
	if strings.TrimSpace(env.IssuedAt) == "" {
		return VerifyResult{}, ErrInvalidIssuedAt
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, env.IssuedAt)
	if err != nil {
		return VerifyResult{}, ErrInvalidIssuedAt
	}
	if !strings.HasSuffix(env.IssuedAt, "Z") || !issuedAt.Equal(issuedAt.UTC()) {
		return VerifyResult{}, ErrInvalidIssuedAt
	}

	expectedHashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return VerifyResult{}, err
	}
	expectedHashBytes, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return VerifyResult{}, ErrInvalidEncoding
	}
	payloadHashBytes, err := decodeLowerHex32(strings.TrimSpace(env.PayloadHash))
	if err != nil {
		return VerifyResult{}, err
	}
	if subtle.ConstantTimeCompare(expectedHashBytes, payloadHashBytes) != 1 {
		return VerifyResult{}, ErrPayloadHashMismatch
	}

	if strings.ToLower(strings.TrimSpace(env.Algorithm)) != "es256" {
		return VerifyResult{}, ErrUnsupportedAlgorithm
	}
	if err := verifyES256(payloadHashBytes, env.PublicKey, env.Signature); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{IssuedAt: issuedAt.UTC()}, nil
}

func verifyEd25519(messageHash []byte, publicKeyB64, sigB64 string) error {
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return ErrInvalidEncoding
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return ErrInvalidEncoding
	}
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrInvalidEncoding
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), messageHash, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func verifyES256(messageHash []byte, publicKeyB64URL, signatureInput string) error {
	publicKey, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(publicKeyB64URL))
	if err != nil {
		return ErrInvalidEncoding
	}
	if len(publicKey) != 65 || publicKey[0] != 0x04 {
		return ErrInvalidEncoding
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])
	if !curve.IsOnCurve(x, y) {
		return ErrInvalidEncoding
	}
	pub := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	sigBytes, err := decodeSignatureBytesCompat(signatureInput)
	if err != nil {
		return ErrInvalidEncoding
	}
	r, s, err := parseES256Signature(sigBytes)
	if err != nil {
		return ErrInvalidEncoding
	}
	if !ecdsa.Verify(&pub, messageHash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

func decodeSignatureBytesCompat(in string) ([]byte, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return nil, ErrInvalidEncoding
	}
	// Canonical form: base64url without padding
	if bytes, err := decodeBase64URLNoPaddingStrict(s); err == nil {
		return bytes, nil
	}
	// Compatibility: std base64 with/without padding.
	std, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return std, nil
	}
	rawStd, err := base64.RawStdEncoding.DecodeString(s)
	if err == nil {
		return rawStd, nil
	}
	return nil, ErrInvalidEncoding
}

func decodeBase64URLNoPaddingStrict(in string) ([]byte, error) {
	s := strings.TrimSpace(in)
	if s == "" || strings.Contains(s, "=") {
		return nil, ErrInvalidEncoding
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, ErrInvalidEncoding
		}
	}
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	if base64.RawURLEncoding.EncodeToString(out) != s {
		return nil, ErrInvalidEncoding
	}
	return out, nil
}

func parseES256Signature(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if r.Sign() <= 0 || s.Sign() <= 0 {
			return nil, nil, ErrInvalidEncoding
		}
		return r, s, nil
	}
	var der struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(sig, &der)
	if err != nil || len(rest) != 0 || der.R == nil || der.S == nil {
		return nil, nil, ErrInvalidEncoding
	}
	if der.R.Sign() <= 0 || der.S.Sign() <= 0 {
		return nil, nil, ErrInvalidEncoding
	}
	return der.R, der.S, nil
}

func decodeLowerHex32(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidEncoding
	}
	if s != strings.ToLower(s) {
		return nil, ErrInvalidEncoding
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: payload_hash length", ErrInvalidEncoding)
	}
	return b, nil
}
