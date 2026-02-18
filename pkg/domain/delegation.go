package domain

import "time"

type DelegationRecord struct {
	DelegationID     string              `json:"delegation_id"`
	PrincipalID      string              `json:"principal_id"`
	DelegatorActorID string              `json:"delegator_actor_id"`
	DelegateActorID  string              `json:"delegate_actor_id"`
	Scope            DelegationScope     `json:"scope"`
	IssuedAt         time.Time           `json:"issued_at"`
	ExpiresAt        *time.Time          `json:"expires_at,omitempty"`
	RevokedAt        *time.Time          `json:"revoked_at,omitempty"`
	Signature        DelegationSignature `json:"signature"`
	CreatedAt        time.Time           `json:"created_at,omitempty"`
}

type DelegationScope struct {
	Actions      []string `json:"actions"`
	Templates    []string `json:"templates,omitempty"`
	MaxRiskLevel string   `json:"max_risk_level,omitempty"`
}

type DelegationSignature struct {
	SignedPayloadHash string `json:"signed_payload_hash"`
	SignatureBytes    string `json:"signature_bytes"`
	Algorithm         string `json:"algorithm"`
	KeyID             string `json:"key_id,omitempty"`
}
