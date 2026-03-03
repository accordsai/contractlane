package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	ErrContextMismatch      = errors.New("context mismatch")
)

type VerifyResult struct {
	IssuedAt time.Time
}

type VerifyEnvelopeV3Options struct {
	ExpectedContext         string
	ExpectedChallengeBytes  []byte
	AllowedOrigins          []string
	ExpectedRPID            string
	ExpectedCredentialID    string
	CredentialPublicKeySec1 []byte
	RequireUserPresence     bool
	RequireUserVerification bool
	PreviousSignCount       uint32
}

type VerifyV3Result struct {
	IssuedAt  time.Time
	SignCount uint32
	Origin    string
}

type webAuthnClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
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

func ParseEnvelopeV3Strict(v any) (EnvelopeV3, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out EnvelopeV3
	if err := dec.Decode(&out); err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if dec.More() {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if strings.TrimSpace(out.Version) != "sig-v3" {
		return EnvelopeV3{}, ErrUnsupportedAlgorithm
	}
	if strings.TrimSpace(out.Algorithm) != "webauthn-es256" {
		return EnvelopeV3{}, ErrUnsupportedAlgorithm
	}
	if _, err := decodeLowerHex32(strings.TrimSpace(out.PayloadHash)); err != nil {
		return EnvelopeV3{}, err
	}
	if strings.TrimSpace(out.IssuedAt) == "" {
		return EnvelopeV3{}, ErrInvalidIssuedAt
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, out.IssuedAt)
	if err != nil {
		return EnvelopeV3{}, ErrInvalidIssuedAt
	}
	if !strings.HasSuffix(out.IssuedAt, "Z") || !issuedAt.Equal(issuedAt.UTC()) {
		return EnvelopeV3{}, ErrInvalidIssuedAt
	}
	if _, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(out.CredentialID)); err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if strings.TrimSpace(out.ChallengeID) == "" {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if _, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(out.ClientDataJSON)); err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if _, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(out.AuthenticatorData)); err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	if _, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(out.Signature)); err != nil {
		return EnvelopeV3{}, ErrInvalidEncoding
	}
	return out, nil
}

func VerifyEnvelopeV3(payload any, env EnvelopeV3, opts VerifyEnvelopeV3Options) (VerifyV3Result, error) {
	expectedHashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return VerifyV3Result{}, err
	}
	return VerifyEnvelopeV3WithExpectedHash(expectedHashHex, env, opts)
}

func VerifyEnvelopeV3WithExpectedHash(expectedPayloadHashHex string, env EnvelopeV3, opts VerifyEnvelopeV3Options) (VerifyV3Result, error) {
	normalized, err := ParseEnvelopeV3Strict(env)
	if err != nil {
		return VerifyV3Result{}, err
	}
	expectedBytes, err := decodeLowerHex32(strings.TrimSpace(expectedPayloadHashHex))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	envelopeBytes, err := decodeLowerHex32(strings.TrimSpace(normalized.PayloadHash))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	if subtle.ConstantTimeCompare(expectedBytes, envelopeBytes) != 1 {
		return VerifyV3Result{}, ErrPayloadHashMismatch
	}
	if strings.TrimSpace(opts.ExpectedContext) != "" && strings.TrimSpace(normalized.Context) != strings.TrimSpace(opts.ExpectedContext) {
		return VerifyV3Result{}, ErrContextMismatch
	}

	credIDBytes, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(normalized.CredentialID))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	if strings.TrimSpace(opts.ExpectedCredentialID) != "" {
		expectedCredIDBytes, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(opts.ExpectedCredentialID))
		if err != nil {
			return VerifyV3Result{}, ErrInvalidEncoding
		}
		if subtle.ConstantTimeCompare(expectedCredIDBytes, credIDBytes) != 1 {
			return VerifyV3Result{}, ErrInvalidSignature
		}
	}

	clientDataJSONBytes, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(normalized.ClientDataJSON))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	authDataBytes, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(normalized.AuthenticatorData))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	derSignature, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(normalized.Signature))
	if err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	if _, _, err := parseECDSADERStrict(derSignature); err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}

	var clientData webAuthnClientData
	if err := json.Unmarshal(clientDataJSONBytes, &clientData); err != nil {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	if strings.TrimSpace(clientData.Type) != "webauthn.get" {
		return VerifyV3Result{}, ErrInvalidSignature
	}
	if len(opts.ExpectedChallengeBytes) > 0 {
		chalFromClient, err := decodeBase64URLNoPaddingStrict(strings.TrimSpace(clientData.Challenge))
		if err != nil {
			return VerifyV3Result{}, ErrInvalidEncoding
		}
		if subtle.ConstantTimeCompare(opts.ExpectedChallengeBytes, chalFromClient) != 1 {
			return VerifyV3Result{}, ErrInvalidSignature
		}
	}
	if len(opts.AllowedOrigins) > 0 {
		originAllowed := false
		for _, allowed := range opts.AllowedOrigins {
			if strings.TrimSpace(clientData.Origin) == strings.TrimSpace(allowed) {
				originAllowed = true
				break
			}
		}
		if !originAllowed {
			return VerifyV3Result{}, ErrInvalidSignature
		}
	}
	signCount, err := parseAndValidateAuthenticatorData(authDataBytes, opts)
	if err != nil {
		return VerifyV3Result{}, err
	}
	if opts.PreviousSignCount > 0 && signCount > 0 && signCount <= opts.PreviousSignCount {
		return VerifyV3Result{}, ErrInvalidSignature
	}

	pubBytes := opts.CredentialPublicKeySec1
	if len(pubBytes) == 0 {
		return VerifyV3Result{}, ErrInvalidEncoding
	}
	pub, err := parseP256PublicKeySEC1(pubBytes)
	if err != nil {
		return VerifyV3Result{}, err
	}
	clientDataHash := sha256.Sum256(clientDataJSONBytes)
	verifyBytes := make([]byte, 0, len(authDataBytes)+len(clientDataHash))
	verifyBytes = append(verifyBytes, authDataBytes...)
	verifyBytes = append(verifyBytes, clientDataHash[:]...)
	verifyDigest := sha256.Sum256(verifyBytes)

	if !ecdsa.VerifyASN1(pub, verifyDigest[:], derSignature) {
		return VerifyV3Result{}, ErrInvalidSignature
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, normalized.IssuedAt)
	if err != nil {
		return VerifyV3Result{}, ErrInvalidIssuedAt
	}
	return VerifyV3Result{
		IssuedAt:  issuedAt.UTC(),
		SignCount: signCount,
		Origin:    strings.TrimSpace(clientData.Origin),
	}, nil
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

func parseP256PublicKeySEC1(publicKey []byte) (*ecdsa.PublicKey, error) {
	if len(publicKey) != 65 || publicKey[0] != 0x04 {
		return nil, ErrInvalidEncoding
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidEncoding
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseAndValidateAuthenticatorData(authData []byte, opts VerifyEnvelopeV3Options) (uint32, error) {
	if len(authData) < 37 {
		return 0, ErrInvalidEncoding
	}
	rpIDHash := authData[:32]
	flags := authData[32]
	signCount := binary.BigEndian.Uint32(authData[33:37])

	requireUP := true
	requireUV := true
	if !opts.RequireUserPresence {
		requireUP = false
	}
	if !opts.RequireUserVerification {
		requireUV = false
	}
	if requireUP && (flags&0x01) == 0 {
		return 0, ErrInvalidSignature
	}
	if requireUV && (flags&0x04) == 0 {
		return 0, ErrInvalidSignature
	}
	if strings.TrimSpace(opts.ExpectedRPID) != "" {
		rpHash := sha256.Sum256([]byte(strings.TrimSpace(opts.ExpectedRPID)))
		if subtle.ConstantTimeCompare(rpHash[:], rpIDHash) != 1 {
			return 0, ErrInvalidSignature
		}
	}
	return signCount, nil
}

func parseECDSADERStrict(sigDER []byte) (*big.Int, *big.Int, error) {
	var der struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(sigDER, &der)
	if err != nil || len(rest) != 0 || der.R == nil || der.S == nil {
		return nil, nil, ErrInvalidEncoding
	}
	if der.R.Sign() <= 0 || der.S.Sign() <= 0 {
		return nil, nil, ErrInvalidEncoding
	}
	return der.R, der.S, nil
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
