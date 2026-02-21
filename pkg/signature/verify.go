package signature

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

	switch strings.ToLower(strings.TrimSpace(env.Algorithm)) {
	case "ed25519":
		if err := verifyEd25519(payloadHashBytes, env.PublicKey, env.Signature); err != nil {
			return VerifyResult{}, err
		}
	case "secp256k1":
		return VerifyResult{}, ErrUnsupportedAlgorithm
	default:
		return VerifyResult{}, ErrUnsupportedAlgorithm
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
