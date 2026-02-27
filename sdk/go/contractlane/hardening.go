package contractlane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/accordsai/contractlane/pkg/evidencehash"
)

type VerifyFailureCode string

const (
	VerifyCodeVerified          VerifyFailureCode = "VERIFIED"
	VerifyCodeMalformedInput    VerifyFailureCode = "MALFORMED_INPUT"
	VerifyCodeInvalidSchema     VerifyFailureCode = "INVALID_SCHEMA"
	VerifyCodeInvalidEvidence   VerifyFailureCode = "INVALID_EVIDENCE"
	VerifyCodeInvalidSignature  VerifyFailureCode = "INVALID_SIGNATURE"
	VerifyCodeAuthorizationFail VerifyFailureCode = "AUTHORIZATION_FAILED"
	VerifyCodeRulesFailed       VerifyFailureCode = "RULES_FAILED"
	VerifyCodeUnknown           VerifyFailureCode = "UNKNOWN_ERROR"
)

type VerifyReport struct {
	OK      bool              `json:"ok"`
	Code    VerifyFailureCode `json:"code"`
	ProofID string            `json:"proof_id,omitempty"`
	Message string            `json:"message,omitempty"`
}

func Canonicalize(v any) ([]byte, error) {
	_, b, err := evidencehash.CanonicalSHA256(v)
	return b, err
}

func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func CanonicalSHA256Hex(v any) (string, error) {
	return canonicalSha256Hex(v)
}

func ParseSigV1EnvelopeV1Strict(v any) (SignatureEnvelopeV1, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return SignatureEnvelopeV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out SignatureEnvelopeV1
	if err := dec.Decode(&out); err != nil {
		return SignatureEnvelopeV1{}, err
	}
	if dec.More() {
		return SignatureEnvelopeV1{}, errors.New("invalid trailing signature payload")
	}
	if out.Version != "sig-v1" {
		return SignatureEnvelopeV1{}, errors.New("version must be sig-v1")
	}
	if out.Algorithm != "ed25519" {
		return SignatureEnvelopeV1{}, errors.New("algorithm must be ed25519")
	}
	if len(out.PayloadHash) != 64 || strings.ToLower(out.PayloadHash) != out.PayloadHash {
		return SignatureEnvelopeV1{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	if _, err := hex.DecodeString(out.PayloadHash); err != nil {
		return SignatureEnvelopeV1{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	if err := validateRFC3339UTC(out.IssuedAt, "issued_at"); err != nil {
		return SignatureEnvelopeV1{}, err
	}
	return out, nil
}

func ParseSigV2EnvelopeV2Strict(v any) (SignatureEnvelopeV2, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out SignatureEnvelopeV2
	if err := dec.Decode(&out); err != nil {
		return SignatureEnvelopeV2{}, err
	}
	if dec.More() {
		return SignatureEnvelopeV2{}, errors.New("invalid trailing signature payload")
	}
	if out.Version != "sig-v2" {
		return SignatureEnvelopeV2{}, errors.New("version must be sig-v2")
	}
	if out.Algorithm != "es256" {
		return SignatureEnvelopeV2{}, errors.New("algorithm must be es256")
	}
	if len(out.PayloadHash) != 64 || strings.ToLower(out.PayloadHash) != out.PayloadHash {
		return SignatureEnvelopeV2{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	if _, err := hex.DecodeString(out.PayloadHash); err != nil {
		return SignatureEnvelopeV2{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	if err := validateRFC3339UTC(out.IssuedAt, "issued_at"); err != nil {
		return SignatureEnvelopeV2{}, err
	}
	if _, err := decodeBase64URLNoPadding(out.PublicKey, "signature public key"); err != nil {
		return SignatureEnvelopeV2{}, err
	}
	if _, err := decodeBase64URLNoPadding(out.Signature, "signature"); err != nil {
		// DER compatibility input is allowed at verifier boundaries, but strict parser
		// enforces canonical raw64 base64url encoding for new payloads.
		return SignatureEnvelopeV2{}, err
	}
	return out, nil
}

func NormalizeAmountV1(a CommerceAmountV1) (CommerceAmountV1, error) {
	minor, err := parseNormalizedAmountToMinor(a)
	if err != nil {
		return CommerceAmountV1{}, err
	}
	n, err := NormalizeMinorUnits(a.Currency, minor)
	if err != nil {
		return CommerceAmountV1{}, err
	}
	return CommerceAmountV1{Currency: n.Currency, Amount: n.Amount}, nil
}

func ParseAmountV1MinorUnits(a CommerceAmountV1) (int64, error) {
	return parseNormalizedAmountToMinor(a)
}

func ParseDelegationV1Strict(v any) (DelegationV1, error) {
	return parseDelegationStrict(v)
}

func NewCommerceIntentV1(intent CommerceIntentV1) (CommerceIntentV1, error) {
	if strings.TrimSpace(intent.Nonce) == "" {
		intent.Nonce = newNonceBase64URL(16)
	}
	if intent.Metadata == nil {
		intent.Metadata = map[string]any{}
	}
	return normalizeCommerceIntent(intent)
}

func NewCommerceAcceptV1(acc CommerceAcceptV1) (CommerceAcceptV1, error) {
	if strings.TrimSpace(acc.Nonce) == "" {
		acc.Nonce = newNonceBase64URL(16)
	}
	if acc.Metadata == nil {
		acc.Metadata = map[string]any{}
	}
	return normalizeCommerceAccept(acc)
}

func NewDelegationV1(d DelegationV1) (DelegationV1, error) {
	if strings.TrimSpace(d.Nonce) == "" {
		d.Nonce = newNonceBase64URL(16)
	}
	return normalizeDelegationV1(d)
}

func NewDelegationRevocationV1(r DelegationRevocationV1) (DelegationRevocationV1, error) {
	if strings.TrimSpace(r.Nonce) == "" {
		r.Nonce = newNonceBase64URL(16)
	}
	return normalizeDelegationRevocationV1(r)
}

func SigV1Sign(context string, payloadHashHex string, priv ed25519.PrivateKey, issuedAt time.Time, keyID string) (SignatureEnvelopeV1, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignatureEnvelopeV1{}, errors.New("ed25519 private key is required")
	}
	if len(payloadHashHex) != 64 || strings.ToLower(payloadHashHex) != payloadHashHex {
		return SignatureEnvelopeV1{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	msg, err := hex.DecodeString(payloadHashHex)
	if err != nil {
		return SignatureEnvelopeV1{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	env := SignatureEnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		PayloadHash: payloadHashHex,
		IssuedAt:    issuedAt.UTC().Format(time.RFC3339Nano),
		Context:     strings.TrimSpace(context),
	}
	if strings.TrimSpace(keyID) != "" {
		env.KeyID = strings.TrimSpace(keyID)
	}
	if err := validateRFC3339UTC(env.IssuedAt, "issued_at"); err != nil {
		return SignatureEnvelopeV1{}, err
	}
	return env, nil
}

func SigV2Sign(context string, payloadHashHex string, priv *ecdsa.PrivateKey, issuedAt time.Time, keyID string) (SignatureEnvelopeV2, error) {
	if len(payloadHashHex) != 64 || strings.ToLower(payloadHashHex) != payloadHashHex {
		return SignatureEnvelopeV2{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	hashBytes, err := hex.DecodeString(payloadHashHex)
	if err != nil {
		return SignatureEnvelopeV2{}, errors.New("payload_hash must be lowercase hex sha256")
	}
	env, err := SignES256Prehashed(priv, hashBytes, issuedAt, strings.TrimSpace(context))
	if err != nil {
		return SignatureEnvelopeV2{}, err
	}
	env.PayloadHash = payloadHashHex
	if strings.TrimSpace(keyID) != "" {
		env.KeyID = strings.TrimSpace(keyID)
	}
	return env, nil
}

func VerifyProofBundleV1Report(proof ProofBundleV1) VerifyReport {
	id, err := VerifyProofBundleV1(proof)
	if err == nil {
		return VerifyReport{OK: true, Code: VerifyCodeVerified, ProofID: id}
	}
	msg := err.Error()
	code := VerifyCodeUnknown
	switch {
	case strings.Contains(msg, "version must be proof-bundle-v1"), strings.Contains(msg, "protocol must be"), strings.Contains(msg, "bundle.contract.contract_id"):
		code = VerifyCodeInvalidSchema
	case strings.Contains(msg, "evidence verification failed"), strings.Contains(msg, "evidence missing"):
		code = VerifyCodeInvalidEvidence
	case strings.Contains(msg, "invalid signature"), strings.Contains(msg, "signature context mismatch"), strings.Contains(msg, "payload hash mismatch"):
		code = VerifyCodeInvalidSignature
	case strings.Contains(msg, "delegation_"):
		code = VerifyCodeAuthorizationFail
	case strings.Contains(msg, "rules_requirement_failed"):
		code = VerifyCodeRulesFailed
	default:
		code = VerifyCodeMalformedInput
	}
	return VerifyReport{OK: false, Code: code, Message: msg}
}

func newNonceBase64URL(n int) string {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// deterministic fallback for failure path; still valid base64url.
		return base64.RawURLEncoding.EncodeToString([]byte("contractlane_nonce_v1"))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
