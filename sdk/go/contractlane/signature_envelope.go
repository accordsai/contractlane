package contractlane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/accordsai/contractlane/pkg/evidencehash"
	signaturev1 "github.com/accordsai/contractlane/pkg/signature"
)

func SignSigV2ES256(payload any, priv *ecdsa.PrivateKey, issuedAt time.Time, context string) (env SignatureEnvelopeV2, err error) {
	payloadHashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	hashBytes, err := hex.DecodeString(payloadHashHex)
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	env, err = SignES256Prehashed(priv, hashBytes, issuedAt, context)
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	env.PayloadHash = payloadHashHex
	return env, nil
}

func SignES256Prehashed(priv *ecdsa.PrivateKey, hashBytes []byte, issuedAt time.Time, context string) (env SignatureEnvelopeV2, err error) {
	if priv == nil || priv.Curve == nil || priv.Curve.Params().Name != elliptic.P256().Params().Name {
		return SignatureEnvelopeV2{}, errors.New("p256 private key is required")
	}
	issuedAtUTC := issuedAt.UTC()
	if issuedAtUTC.IsZero() {
		return SignatureEnvelopeV2{}, errors.New("issued_at is required")
	}
	if len(hashBytes) != 32 {
		return SignatureEnvelopeV2{}, errors.New("payload_hash must decode to 32 bytes")
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashBytes)
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	sigRaw := make([]byte, 64)
	r.FillBytes(sigRaw[:32])
	s.FillBytes(sigRaw[32:])
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	env = SignatureEnvelopeV2{
		Version:     "sig-v2",
		Algorithm:   "es256",
		PublicKey:   base64.RawURLEncoding.EncodeToString(pub),
		Signature:   base64.RawURLEncoding.EncodeToString(sigRaw),
		PayloadHash: "",
		IssuedAt:    issuedAtUTC.Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(context) != "" {
		env.Context = strings.TrimSpace(context)
	}
	return env, nil
}

func VerifySignatureEnvelope(payload any, env SignatureEnvelope) (signaturev1.VerifyResult, error) {
	return signaturev1.VerifyEnvelope(payload, signaturev1.Envelope(env))
}

func AgentIDFromSignatureEnvelope(env SignatureEnvelope) (string, error) {
	switch strings.ToLower(strings.TrimSpace(env.Algorithm)) {
	case "ed25519":
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.PublicKey))
		if err != nil {
			return "", errors.New("invalid signature public_key encoding")
		}
		if len(pub) != ed25519.PublicKeySize {
			return "", errors.New("invalid signature public_key encoding")
		}
		return AgentIDFromEd25519PublicKey(pub)
	case "es256":
		pub, err := decodeBase64URLNoPadding(strings.TrimSpace(env.PublicKey), "signature public key")
		if err != nil {
			return "", err
		}
		return AgentIDFromP256PublicKey(pub)
	default:
		return "", errors.New("unsupported signature algorithm")
	}
}
