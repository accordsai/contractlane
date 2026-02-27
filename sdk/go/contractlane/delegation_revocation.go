package contractlane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type DelegationRevocationV1 struct {
	Version      string `json:"version"`
	RevocationID string `json:"revocation_id"`
	DelegationID string `json:"delegation_id"`
	IssuerAgent  string `json:"issuer_agent"`
	Nonce        string `json:"nonce"`
	IssuedAt     string `json:"issued_at"`
	Reason       string `json:"reason,omitempty"`
}

type SignedDelegationRevocationV1 struct {
	Revocation      DelegationRevocationV1 `json:"revocation"`
	IssuerSignature SigEnvelope            `json:"issuer_signature"`
}

func ParseDelegationRevocationV1Strict(v any) (DelegationRevocationV1, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return DelegationRevocationV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out DelegationRevocationV1
	if err := dec.Decode(&out); err != nil {
		return DelegationRevocationV1{}, err
	}
	if dec.More() {
		return DelegationRevocationV1{}, errors.New("invalid trailing delegation revocation payload")
	}
	return normalizeDelegationRevocationV1(out)
}

func HashDelegationRevocationV1(payload DelegationRevocationV1) (string, error) {
	n, err := normalizeDelegationRevocationV1(payload)
	if err != nil {
		return "", err
	}
	return canonicalSha256Hex(delegationRevocationPayloadMap(n))
}

func SignDelegationRevocationV1(payload DelegationRevocationV1, priv ed25519.PrivateKey, issuedAt time.Time) (SigV1Envelope, error) {
	n, err := normalizeDelegationRevocationV1(payload)
	if err != nil {
		return SigV1Envelope{}, err
	}
	return SignSigV1Ed25519(delegationRevocationPayloadMap(n), priv, issuedAt, "delegation-revocation")
}

func SignDelegationRevocationV1ES256(payload DelegationRevocationV1, priv *ecdsa.PrivateKey, issuedAt time.Time) (SigV2Envelope, error) {
	n, err := normalizeDelegationRevocationV1(payload)
	if err != nil {
		return SigV2Envelope{}, err
	}
	return SignSigV2ES256(delegationRevocationPayloadMap(n), priv, issuedAt, "delegation-revocation")
}

func VerifyDelegationRevocationV1(payload DelegationRevocationV1, sig SigEnvelope) error {
	n, err := normalizeDelegationRevocationV1(payload)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sig.Context) != "delegation-revocation" {
		return errors.New("signature context mismatch")
	}
	hash, err := HashDelegationRevocationV1(n)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sig.PayloadHash) != hash {
		return errors.New("payload hash mismatch")
	}
	_, err = VerifySignatureEnvelope(delegationRevocationPayloadMap(n), sig)
	if err != nil {
		return err
	}
	issuerAgentID, err := AgentIDFromSignatureEnvelope(sig)
	if err != nil {
		return err
	}
	if issuerAgentID != n.IssuerAgent {
		return errors.New("signature public key does not match issuer_agent")
	}
	return nil
}

func ValidateDelegationRevocation(payload DelegationRevocationV1, signature SigEnvelope) (revocationHash string, parsedRevocation DelegationRevocationV1, issuerAgent string, err error) {
	n, err := normalizeDelegationRevocationV1(payload)
	if err != nil {
		return "", DelegationRevocationV1{}, "", err
	}
	if err := VerifyDelegationRevocationV1(n, signature); err != nil {
		return "", DelegationRevocationV1{}, "", err
	}
	hash, err := HashDelegationRevocationV1(n)
	if err != nil {
		return "", DelegationRevocationV1{}, "", err
	}
	return hash, n, n.IssuerAgent, nil
}

func parseDelegationRevocationStrict(v any) (DelegationRevocationV1, error) {
	return ParseDelegationRevocationV1Strict(v)
}

func normalizeDelegationRevocationV1(payload DelegationRevocationV1) (DelegationRevocationV1, error) {
	if payload.Version != "delegation-revocation-v1" {
		return DelegationRevocationV1{}, errors.New("version must be delegation-revocation-v1")
	}
	payload.RevocationID = strings.TrimSpace(payload.RevocationID)
	if payload.RevocationID == "" {
		return DelegationRevocationV1{}, errors.New("revocation_id is required")
	}
	payload.DelegationID = strings.TrimSpace(payload.DelegationID)
	if payload.DelegationID == "" {
		return DelegationRevocationV1{}, errors.New("delegation_id is required")
	}
	payload.IssuerAgent = strings.TrimSpace(payload.IssuerAgent)
	if !IsValidAgentID(payload.IssuerAgent) {
		return DelegationRevocationV1{}, errors.New("issuer_agent must be valid agent-id-v1")
	}
	if err := validateBase64URLNoPadding(payload.Nonce, "nonce"); err != nil {
		return DelegationRevocationV1{}, err
	}
	if err := validateRFC3339UTC(payload.IssuedAt, "issued_at"); err != nil {
		return DelegationRevocationV1{}, err
	}
	payload.Reason = strings.TrimSpace(payload.Reason)
	return payload, nil
}

func delegationRevocationPayloadMap(payload DelegationRevocationV1) map[string]any {
	out := map[string]any{
		"version":       payload.Version,
		"revocation_id": payload.RevocationID,
		"delegation_id": payload.DelegationID,
		"issuer_agent":  payload.IssuerAgent,
		"nonce":         payload.Nonce,
		"issued_at":     payload.IssuedAt,
	}
	if payload.Reason != "" {
		out["reason"] = payload.Reason
	}
	return out
}
