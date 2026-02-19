package contractlane

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func fixedDelegationV1(t *testing.T) (DelegationV1, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	buyerSeed := bytesRepeat(21, 32)
	sellerSeed := bytesRepeat(22, 32)
	buyerPriv := ed25519.NewKeyFromSeed(buyerSeed)
	sellerPriv := ed25519.NewKeyFromSeed(sellerSeed)
	buyerAgent, err := AgentIDFromEd25519PublicKey(buyerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("buyer agent id: %v", err)
	}
	sellerAgent, err := AgentIDFromEd25519PublicKey(sellerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("seller agent id: %v", err)
	}
	maxUses := int64(5)
	p := DelegationV1{
		Version:      "delegation-v1",
		DelegationID: "del_01HZX9Y0H2J7F2S0P5R8M6T4YA",
		IssuerAgent:  buyerAgent,
		SubjectAgent: buyerAgent,
		Scopes: []string{
			DelegationScopeCommerceIntentSign,
			DelegationScopeCommerceAcceptSign,
		},
		Constraints: DelegationConstraintsV1{
			ContractID:        "ctr_offline_reference",
			CounterpartyAgent: sellerAgent,
			MaxAmount:         &CommerceAmountV1{Currency: "USD", Amount: "250"},
			ValidFrom:         "2026-01-01T00:00:00Z",
			ValidUntil:        "2026-12-31T23:59:59Z",
			MaxUses:           &maxUses,
		},
		Nonce:    "ZGVsZWdhdGlvbl9ub25jZV92MQ",
		IssuedAt: "2026-02-20T12:06:00Z",
	}
	return p, buyerPriv, sellerPriv
}

func TestDelegationHashKnownVector(t *testing.T) {
	d, _, _ := fixedDelegationV1(t)
	h, err := HashDelegationV1(d)
	if err != nil {
		t.Fatalf("HashDelegationV1: %v", err)
	}
	const expected = "75ef154464ecbfd012b7dc7e6fca65d81f10d6d56938cb085ec222f9790fb357"
	if h != expected {
		t.Fatalf("hash drift: got %s want %s", h, expected)
	}
}

func TestDelegationSignVerify(t *testing.T) {
	d, buyerPriv, _ := fixedDelegationV1(t)
	sig, err := SignDelegationV1(d, buyerPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationV1: %v", err)
	}
	if err := VerifyDelegationV1(d, sig); err != nil {
		t.Fatalf("VerifyDelegationV1: %v", err)
	}
	sig.Context = "wrong"
	if err := VerifyDelegationV1(d, sig); err == nil {
		t.Fatal("expected context mismatch")
	}
}

func TestDelegationConstraintEvaluation(t *testing.T) {
	d, _, _ := fixedDelegationV1(t)
	err := EvaluateDelegationConstraints(d.Constraints, DelegationEvalContext{
		ContractID:        "ctr_offline_reference",
		CounterpartyAgent: d.Constraints.CounterpartyAgent,
		IssuedAtUTC:       "2026-02-18T00:00:00Z",
		PaymentAmount:     &CommerceAmountV1{Currency: "USD", Amount: "26"},
	})
	if err != nil {
		t.Fatalf("EvaluateDelegationConstraints: %v", err)
	}

	// wrong contract
	err = EvaluateDelegationConstraints(d.Constraints, DelegationEvalContext{
		ContractID:        "ctr_other",
		CounterpartyAgent: d.Constraints.CounterpartyAgent,
		IssuedAtUTC:       "2026-02-18T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected contract mismatch")
	}
	// wrong counterparty
	err = EvaluateDelegationConstraints(d.Constraints, DelegationEvalContext{
		ContractID:        d.Constraints.ContractID,
		CounterpartyAgent: "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		IssuedAtUTC:       "2026-02-18T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected counterparty mismatch")
	}
	// expired
	err = EvaluateDelegationConstraints(d.Constraints, DelegationEvalContext{
		ContractID:        d.Constraints.ContractID,
		CounterpartyAgent: d.Constraints.CounterpartyAgent,
		IssuedAtUTC:       "2027-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected expiration failure")
	}
	// amount exceeded
	err = EvaluateDelegationConstraints(d.Constraints, DelegationEvalContext{
		ContractID:        d.Constraints.ContractID,
		CounterpartyAgent: d.Constraints.CounterpartyAgent,
		IssuedAtUTC:       "2026-02-18T00:00:00Z",
		PaymentAmount:     &CommerceAmountV1{Currency: "USD", Amount: "251"},
	})
	if err == nil {
		t.Fatal("expected amount exceeded failure")
	}
}

func TestDelegationClosedSchemaRejectsUnknownKeys(t *testing.T) {
	d, _, _ := fixedDelegationV1(t)
	raw := map[string]any{
		"version":       d.Version,
		"delegation_id": d.DelegationID,
		"issuer_agent":  d.IssuerAgent,
		"subject_agent": d.SubjectAgent,
		"scopes":        d.Scopes,
		"constraints": map[string]any{
			"contract_id":        d.Constraints.ContractID,
			"counterparty_agent": d.Constraints.CounterpartyAgent,
			"valid_from":         d.Constraints.ValidFrom,
			"valid_until":        d.Constraints.ValidUntil,
			"unknown_key":        true,
		},
		"nonce":     d.Nonce,
		"issued_at": d.IssuedAt,
	}
	if _, err := parseDelegationStrict(raw); err == nil {
		t.Fatal("expected unknown constraint key rejection")
	}
}
