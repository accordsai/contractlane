package main

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	clsdk "contractlane/sdk/go/contractlane"
	"contractlane/services/cel/internal/store"
)

func TestEvaluateHostedCommerceAuthorization_MissingDelegation(t *testing.T) {
	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		"agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_test",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "10"},
		nil,
		nil,
		nil,
	)
	if ok {
		t.Fatal("expected authorization failure")
	}
	if reason != clsdk.DelegationFailureMissing {
		t.Fatalf("expected %s, got %s", clsdk.DelegationFailureMissing, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_SelfIssuedOK(t *testing.T) {
	delegations := []map[string]any{buildDelegationArtifactRow(t, 21, 21)}
	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		delegations[0]["delegation"].(map[string]any)["subject_agent"].(string),
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		delegations,
		nil,
		nil,
	)
	if !ok || reason != "" {
		t.Fatalf("expected self-issued delegation success, got ok=%v reason=%s", ok, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_RootIssuedNeedsTrust(t *testing.T) {
	row := buildDelegationArtifactRow(t, 21, 33)
	signing := row["delegation"].(map[string]any)["subject_agent"].(string)
	issuer := row["delegation"].(map[string]any)["issuer_agent"].(string)

	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		signing,
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{row},
		nil,
		nil,
	)
	if ok || reason != clsdk.DelegationFailureUntrustedIssuer {
		t.Fatalf("expected untrusted issuer failure, got ok=%v reason=%s", ok, reason)
	}

	ok, reason = evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		signing,
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{row},
		nil,
		[]string{issuer},
	)
	if !ok || reason != "" {
		t.Fatalf("expected trusted root-issued success, got ok=%v reason=%s", ok, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_DelegationRevoked(t *testing.T) {
	delegationRow := buildDelegationArtifactRow(t, 21, 21)
	delegation := delegationRow["delegation"].(map[string]any)
	issuerPriv := ed25519.NewKeyFromSeed(bytesRepeat(21, 32))
	revocationRow := buildRevocationArtifactRow(t, delegation["delegation_id"].(string), delegation["issuer_agent"].(string), issuerPriv)

	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		delegation["subject_agent"].(string),
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{delegationRow},
		[]map[string]any{revocationRow},
		nil,
	)
	if ok || reason != clsdk.DelegationFailureRevoked {
		t.Fatalf("expected %s, got ok=%v reason=%s", clsdk.DelegationFailureRevoked, ok, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_RevocationUntrustedIssuerIgnored(t *testing.T) {
	delegationRow := buildDelegationArtifactRow(t, 21, 21)
	delegation := delegationRow["delegation"].(map[string]any)
	revokerPriv := ed25519.NewKeyFromSeed(bytesRepeat(41, 32))
	revokerAgent, err := clsdk.AgentIDFromEd25519PublicKey(revokerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey: %v", err)
	}
	revocationRow := buildRevocationArtifactRow(t, delegation["delegation_id"].(string), revokerAgent, revokerPriv)

	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		delegation["subject_agent"].(string),
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{delegationRow},
		[]map[string]any{revocationRow},
		nil,
	)
	if !ok || reason != "" {
		t.Fatalf("expected untrusted revocation to be ignored, got ok=%v reason=%s", ok, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_RevocationInvalidSignatureIgnored(t *testing.T) {
	delegationRow := buildDelegationArtifactRow(t, 21, 21)
	delegation := delegationRow["delegation"].(map[string]any)
	issuerPriv := ed25519.NewKeyFromSeed(bytesRepeat(21, 32))
	revocationRow := buildRevocationArtifactRow(t, delegation["delegation_id"].(string), delegation["issuer_agent"].(string), issuerPriv)
	sig := revocationRow["issuer_signature"].(map[string]any)
	sig["signature"] = "AAAA"

	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		delegation["subject_agent"].(string),
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{delegationRow},
		[]map[string]any{revocationRow},
		nil,
	)
	if !ok || reason != "" {
		t.Fatalf("expected invalid-signature revocation to be ignored, got ok=%v reason=%s", ok, reason)
	}
}

func TestEvaluateHostedCommerceAuthorization_RevocationRootIssuedWithTrust(t *testing.T) {
	delegationRow := buildDelegationArtifactRow(t, 21, 33)
	delegation := delegationRow["delegation"].(map[string]any)
	rootPriv := ed25519.NewKeyFromSeed(bytesRepeat(33, 32))
	rootAgent := delegation["issuer_agent"].(string)
	revocationRow := buildRevocationArtifactRow(t, delegation["delegation_id"].(string), rootAgent, rootPriv)

	ok, reason := evaluateHostedCommerceAuthorization(
		true,
		clsdk.DelegationScopeCommerceIntentSign,
		delegation["subject_agent"].(string),
		"agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		"ctr_offline_reference",
		"2026-02-18T00:00:00Z",
		&clsdk.CommerceAmountV1{Currency: "USD", Amount: "26"},
		[]map[string]any{delegationRow},
		[]map[string]any{revocationRow},
		[]string{rootAgent},
	)
	if ok || reason != clsdk.DelegationFailureRevoked {
		t.Fatalf("expected %s, got ok=%v reason=%s", clsdk.DelegationFailureRevoked, ok, reason)
	}
}

func TestValidateCommerceIntentSubmissionRejectsWrongContext(t *testing.T) {
	intent := clsdk.CommerceIntentV1{
		Version:     "commerce-intent-v1",
		IntentID:    "ci_ctx_1",
		ContractID:  "ctr_ctx_1",
		BuyerAgent:  "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		SellerAgent: "agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
		Items: []clsdk.CommerceIntentItemV1{
			{SKU: "sku", Qty: 1, UnitPrice: clsdk.CommerceAmountV1{Currency: "USD", Amount: "1"}},
		},
		Total:     clsdk.CommerceAmountV1{Currency: "USD", Amount: "1"},
		ExpiresAt: "2026-02-20T12:00:00Z",
		Nonce:     "bm9uY2VfdjE",
		Metadata:  map[string]any{},
	}
	priv := ed25519.NewKeyFromSeed(bytesRepeat(7, 32))
	sig, err := clsdk.SignCommerceIntentV1(intent, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig.Context = "commerce-accept"
	if _, err := clsdk.ValidateCommerceIntentSubmission(intent, sig); err == nil {
		t.Fatal("expected wrong-context validation error")
	}
}

func TestEvaluateActionTransitionRulesV1_BlocksWhenPaidMissing(t *testing.T) {
	t.Setenv("CEL_RULES_V1_JSON", `{
		"version":"rules-v1",
		"rules":[
			{
				"rule_id":"rl_paid_effective",
				"when":{"contract_state_is":"SIGNATURE_SENT"},
				"then":{"permit_transition":{"from":"SIGNATURE_SENT","to":"EFFECTIVE","if":{"settlement_status_is":"PAID"}}}
			}
		]
	}`)
	c := store.Contract{ContractID: "ctr_rules_1", State: "SIGNATURE_SENT"}
	ok, _, fromState, toState, err := evaluateActionTransitionRulesV1(c, "EFFECTIVE", map[string]any{
		"settlement_attestations": []any{},
	}, nil)
	if err != nil {
		t.Fatalf("evaluateActionTransitionRulesV1: %v", err)
	}
	if ok {
		t.Fatal("expected transition to be blocked when PAID is missing")
	}
	if fromState != "SIGNATURE_SENT" || toState != "EFFECTIVE" {
		t.Fatalf("unexpected transition inference from=%s to=%s", fromState, toState)
	}
}

func TestEvaluateActionTransitionRulesV1_AllowsWhenPaidPresent(t *testing.T) {
	t.Setenv("CEL_RULES_V1_JSON", `{
		"version":"rules-v1",
		"rules":[
			{
				"rule_id":"rl_paid_effective",
				"when":{"contract_state_is":"SIGNATURE_SENT"},
				"then":{"permit_transition":{"from":"SIGNATURE_SENT","to":"EFFECTIVE","if":{"settlement_status_is":"PAID"}}}
			}
		]
	}`)
	c := store.Contract{ContractID: "ctr_rules_2", State: "SIGNATURE_SENT"}
	ok, _, _, _, err := evaluateActionTransitionRulesV1(c, "EFFECTIVE", map[string]any{
		"settlement_attestations": []any{
			map[string]any{"status": "PAID"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("evaluateActionTransitionRulesV1: %v", err)
	}
	if !ok {
		t.Fatal("expected transition to be permitted when PAID is present")
	}
}

func buildDelegationArtifactRow(t *testing.T, subjectSeedByte, issuerSeedByte byte) map[string]any {
	t.Helper()
	subjectPriv := ed25519.NewKeyFromSeed(bytesRepeat(subjectSeedByte, 32))
	issuerPriv := ed25519.NewKeyFromSeed(bytesRepeat(issuerSeedByte, 32))
	subjectAgent, err := clsdk.AgentIDFromEd25519PublicKey(subjectPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("subject agent: %v", err)
	}
	issuerAgent, err := clsdk.AgentIDFromEd25519PublicKey(issuerPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("issuer agent: %v", err)
	}
	maxUses := int64(5)
	payload := clsdk.DelegationV1{
		Version:      "delegation-v1",
		DelegationID: "del_test_" + string(rune('a'+subjectSeedByte%26)),
		IssuerAgent:  issuerAgent,
		SubjectAgent: subjectAgent,
		Scopes:       []string{clsdk.DelegationScopeCommerceIntentSign},
		Constraints: clsdk.DelegationConstraintsV1{
			ContractID:        "ctr_offline_reference",
			CounterpartyAgent: "*",
			MaxAmount:         &clsdk.CommerceAmountV1{Currency: "USD", Amount: "250"},
			ValidFrom:         "2026-01-01T00:00:00Z",
			ValidUntil:        "2026-12-31T23:59:59Z",
			MaxUses:           &maxUses,
		},
		Nonce:    "ZGVsZWdhdGlvbl9ub25jZV92MQ",
		IssuedAt: "2026-02-20T12:06:00Z",
	}
	sig, err := clsdk.SignDelegationV1(payload, issuerPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationV1: %v", err)
	}
	bd, _ := json.Marshal(payload)
	bs, _ := json.Marshal(sig)
	var delMap map[string]any
	var sigMap map[string]any
	_ = json.Unmarshal(bd, &delMap)
	_ = json.Unmarshal(bs, &sigMap)
	return map[string]any{
		"delegation":       delMap,
		"issuer_signature": sigMap,
	}
}

func buildRevocationArtifactRow(t *testing.T, delegationID, issuerAgent string, issuerPriv ed25519.PrivateKey) map[string]any {
	t.Helper()
	payload := clsdk.DelegationRevocationV1{
		Version:      "delegation-revocation-v1",
		RevocationID: "rev_test_" + delegationID,
		DelegationID: delegationID,
		IssuerAgent:  issuerAgent,
		Nonce:        "cmV2b2NhdGlvbl9ub25jZQ",
		IssuedAt:     "2026-02-20T12:30:00Z",
	}
	sig, err := clsdk.SignDelegationRevocationV1(payload, issuerPriv, time.Date(2026, 2, 20, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationRevocationV1: %v", err)
	}
	bp, _ := json.Marshal(payload)
	bs, _ := json.Marshal(sig)
	var p map[string]any
	var s map[string]any
	_ = json.Unmarshal(bp, &p)
	_ = json.Unmarshal(bs, &s)
	h, err := clsdk.HashDelegationRevocationV1(payload)
	if err != nil {
		t.Fatalf("HashDelegationRevocationV1: %v", err)
	}
	return map[string]any{
		"revocation_hash":  h,
		"revocation":       p,
		"issuer_signature": s,
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
