package contractlane

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func TestValidateCommerceIntentSubmission_HashVectorAndContext(t *testing.T) {
	intent := fixedCommerceIntentV1()
	priv := ed25519.NewKeyFromSeed(bytesRepeat(7, ed25519.SeedSize))
	sig, err := SignCommerceIntentV1(intent, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1: %v", err)
	}

	got, err := validateCommerceIntentSubmission(intent, sig)
	if err != nil {
		t.Fatalf("validateCommerceIntentSubmission: %v", err)
	}
	const expected = "f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f"
	if got.IntentHash != expected {
		t.Fatalf("intent hash mismatch: got %s want %s", got.IntentHash, expected)
	}

	bad := sig
	bad.Context = "commerce-accept"
	if _, err := validateCommerceIntentSubmission(intent, bad); err == nil {
		t.Fatal("expected wrong context failure")
	}
}

func TestValidateCommerceAcceptSubmission_HashVectorAndContext(t *testing.T) {
	acc := fixedCommerceAcceptV1()
	priv := ed25519.NewKeyFromSeed(bytesRepeat(8, ed25519.SeedSize))
	sig, err := SignCommerceAcceptV1(acc, priv, time.Date(2026, 2, 20, 11, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceAcceptV1: %v", err)
	}

	got, err := validateCommerceAcceptSubmission(acc, sig)
	if err != nil {
		t.Fatalf("validateCommerceAcceptSubmission: %v", err)
	}
	const expected = "670a209431d7b80bc997fabf40a707952a6494af07ddf374d4efdd4532449e21"
	if got.AcceptHash != expected {
		t.Fatalf("accept hash mismatch: got %s want %s", got.AcceptHash, expected)
	}

	bad := sig
	bad.Context = "commerce-intent"
	if _, err := validateCommerceAcceptSubmission(acc, bad); err == nil {
		t.Fatal("expected wrong context failure")
	}
}

func TestEvaluateDelegationDecision_FailureReasons(t *testing.T) {
	artifacts := sampleOfflineArtifacts(t)
	delegationsTyped := artifacts["delegations"].([]SignedDelegationV1)
	delegations := toAnyDelegations(t, delegationsTyped)
	intent := artifacts["commerce_intents"].([]SignedCommerceIntentV1)[0].Intent

	base := delegationDecisionInput{
		RequiredScope:     DelegationScopeCommerceIntentSign,
		SigningAgent:      intent.BuyerAgent,
		CounterpartyAgent: intent.SellerAgent,
		ContractID:        intent.ContractID,
		IssuedAtUTC:       "2026-02-18T00:00:00Z",
		PaymentAmount:     &CommerceAmountV1{Currency: "USD", Amount: "26"},
		Delegations:       delegations,
	}
	if d := evaluateDelegationDecision(base); !d.OK {
		t.Fatalf("expected success, got %+v", d)
	}

	noDelegations := base
	noDelegations.Delegations = nil
	if d := evaluateDelegationDecision(noDelegations); d.FailureReason != DelegationFailureMissing {
		t.Fatalf("expected %s, got %+v", DelegationFailureMissing, d)
	}

	noScope := base
	noScope.RequiredScope = DelegationScopeCommerceAcceptSign
	if d := evaluateDelegationDecision(noScope); d.FailureReason != DelegationFailureScopeMissing {
		t.Fatalf("expected %s, got %+v", DelegationFailureScopeMissing, d)
	}

	untrustedRoot := cloneDecisionInput(base)
	rootDelegations := append([]SignedDelegationV1(nil), delegationsTyped...)
	{
		d := rootDelegations[0].Delegation
		issuerPriv := ed25519.NewKeyFromSeed(bytesRepeat(33, 32))
		issuerAgent, _ := AgentIDFromEd25519PublicKey(issuerPriv.Public().(ed25519.PublicKey))
		d.IssuerAgent = issuerAgent
		s, _ := SignDelegationV1(d, issuerPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
		rootDelegations[0] = SignedDelegationV1{Delegation: d, IssuerSignature: s}
	}
	untrustedRoot.Delegations = toAnyDelegations(t, rootDelegations)
	if d := evaluateDelegationDecision(untrustedRoot); d.FailureReason != DelegationFailureUntrustedIssuer {
		t.Fatalf("expected %s, got %+v", DelegationFailureUntrustedIssuer, d)
	}

	badSig := cloneDecisionInput(base)
	badSigDelegations := append([]SignedDelegationV1(nil), delegationsTyped...)
	bad := badSigDelegations[0].IssuerSignature
	bad.Signature = "AAAA"
	badSigDelegations[0].IssuerSignature = bad
	badSig.Delegations = toAnyDelegations(t, badSigDelegations)
	if d := evaluateDelegationDecision(badSig); d.FailureReason != DelegationFailureSignatureInvalid {
		t.Fatalf("expected %s, got %+v", DelegationFailureSignatureInvalid, d)
	}

	expired := cloneDecisionInput(base)
	expiredDelegations := append([]SignedDelegationV1(nil), delegationsTyped...)
	expiredDelegations[0].Delegation.Constraints.ValidFrom = "2026-01-01T00:00:00Z"
	expiredDelegations[0].Delegation.Constraints.ValidUntil = "2026-01-31T00:00:00Z"
	expiredDelegations[0].IssuerSignature, _ = SignDelegationV1(expiredDelegations[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(21, 32)), time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	expired.Delegations = toAnyDelegations(t, expiredDelegations)
	if d := evaluateDelegationDecision(expired); d.FailureReason != DelegationFailureExpired {
		t.Fatalf("expected %s, got %+v", DelegationFailureExpired, d)
	}

	amountExceeded := cloneDecisionInput(base)
	amountExceeded.PaymentAmount = &CommerceAmountV1{Currency: "USD", Amount: "251"}
	if d := evaluateDelegationDecision(amountExceeded); d.FailureReason != DelegationFailureAmountExceeded {
		t.Fatalf("expected %s, got %+v", DelegationFailureAmountExceeded, d)
	}

	revoked := cloneDecisionInput(base)
	revoked.Revocations = toAnyRevocations(t, []SignedDelegationRevocationV1{
		buildRevocationForDelegation(t, delegationsTyped[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(21, 32))),
	})
	if d := evaluateDelegationDecision(revoked); d.FailureReason != DelegationFailureRevoked {
		t.Fatalf("expected %s, got %+v", DelegationFailureRevoked, d)
	}

	untrustedRevocation := cloneDecisionInput(base)
	untrustedRevocation.Revocations = toAnyRevocations(t, []SignedDelegationRevocationV1{
		buildRevocationForDelegation(t, delegationsTyped[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(41, 32))),
	})
	if d := evaluateDelegationDecision(untrustedRevocation); !d.OK {
		t.Fatalf("expected untrusted revocation to be ignored, got %+v", d)
	}

	invalidSigRevocation := cloneDecisionInput(base)
	badRev := buildRevocationForDelegation(t, delegationsTyped[0].Delegation, ed25519.NewKeyFromSeed(bytesRepeat(21, 32)))
	badRev.IssuerSignature.Signature = "AAAA"
	invalidSigRevocation.Revocations = toAnyRevocations(t, []SignedDelegationRevocationV1{badRev})
	if d := evaluateDelegationDecision(invalidSigRevocation); !d.OK {
		t.Fatalf("expected invalid-signature revocation to be ignored, got %+v", d)
	}
}

func TestDeriveSettlementAttestations_HelperParity(t *testing.T) {
	receipts := []any{
		sampleStripeReceipt("evt_pi_succeeded_ci_a", "payment_intent.succeeded", "ctr_test_001", "ci_a", "d7504fd3c3a34f4f93fcc1ec1c375199b25bdaeaed58264af0581c56176284c0", 2600, "usd", "pi_ci_a"),
		sampleStripeReceipt("evt_pi_failed_ci_b", "payment_intent.payment_failed", "ctr_test_001", "ci_b", "8a31ddb90d269b7e52c085c3a81efd14ff50ac2bd07b390cc8714b15fe972931", 2600, "usd", "pi_ci_b"),
	}
	got1, err := deriveSettlementAttestations(receipts)
	if err != nil {
		t.Fatalf("deriveSettlementAttestations #1: %v", err)
	}
	got2, err := deriveSettlementAttestations(receipts)
	if err != nil {
		t.Fatalf("deriveSettlementAttestations #2: %v", err)
	}
	b1, _ := json.Marshal(got1)
	b2, _ := json.Marshal(got2)
	if string(b1) != string(b2) {
		t.Fatal("expected deterministic attestation derivation")
	}
}

func toAnySlice(t *testing.T, in any) []any {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal toAnySlice: %v", err)
	}
	var out []any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal toAnySlice: %v", err)
	}
	return out
}

func toAnyDelegations(t *testing.T, in []SignedDelegationV1) []any {
	return toAnySlice(t, in)
}

func toAnyRevocations(t *testing.T, in []SignedDelegationRevocationV1) []any {
	return toAnySlice(t, in)
}

func cloneDecisionInput(in delegationDecisionInput) delegationDecisionInput {
	out := in
	out.Delegations = append([]any(nil), in.Delegations...)
	out.Revocations = append([]any(nil), in.Revocations...)
	out.TrustAgents = append([]string(nil), in.TrustAgents...)
	if in.PaymentAmount != nil {
		p := *in.PaymentAmount
		out.PaymentAmount = &p
	}
	return out
}

func buildRevocationForDelegation(t *testing.T, d DelegationV1, issuerPriv ed25519.PrivateKey) SignedDelegationRevocationV1 {
	t.Helper()
	issuerAgent, err := AgentIDFromEd25519PublicKey(issuerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey: %v", err)
	}
	payload := DelegationRevocationV1{
		Version:      "delegation-revocation-v1",
		RevocationID: "rev_test_" + d.DelegationID,
		DelegationID: d.DelegationID,
		IssuerAgent:  issuerAgent,
		Nonce:        "cmV2b2NhdGlvbl9ub25jZQ",
		IssuedAt:     "2026-02-20T12:30:00Z",
	}
	sig, err := SignDelegationRevocationV1(payload, issuerPriv, time.Date(2026, 2, 20, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationRevocationV1: %v", err)
	}
	return SignedDelegationRevocationV1{
		Revocation:      payload,
		IssuerSignature: sig,
	}
}
