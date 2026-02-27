package contractlane

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestAgentID_P256V2RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	id, err := AgentIDFromP256PublicKey(pub)
	if err != nil {
		t.Fatalf("AgentIDFromP256PublicKey: %v", err)
	}
	algo, gotPub, err := ParseAgentID(id)
	if err != nil {
		t.Fatalf("ParseAgentID: %v", err)
	}
	if algo != "p256" {
		t.Fatalf("expected p256 algo, got %s", algo)
	}
	if string(gotPub) != string(pub) {
		t.Fatalf("public key mismatch")
	}
	if !IsValidAgentID(id) {
		t.Fatalf("expected IsValidAgentID true")
	}
}

func TestAgentID_P256V2RejectsMalformedPoint(t *testing.T) {
	invalid := make([]byte, 65)
	invalid[0] = 0x04
	invalid[32] = 0x01
	invalid[64] = 0x01
	if _, err := AgentIDFromP256PublicKey(invalid); err == nil {
		t.Fatalf("expected AgentIDFromP256PublicKey to reject off-curve key")
	}

	id := "agent:v2:pk:p256:" + base64.RawURLEncoding.EncodeToString(invalid)
	if _, _, err := ParseAgentID(id); err == nil {
		t.Fatalf("expected ParseAgentID to reject off-curve key")
	}
}

func TestCommerceIntentV1_SignAndVerifyES256(t *testing.T) {
	buyerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey buyer: %v", err)
	}
	sellerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey seller: %v", err)
	}
	buyerID, err := AgentIDFromP256PublicKey(elliptic.Marshal(elliptic.P256(), buyerPriv.PublicKey.X, buyerPriv.PublicKey.Y))
	if err != nil {
		t.Fatalf("buyer id: %v", err)
	}
	sellerID, err := AgentIDFromP256PublicKey(elliptic.Marshal(elliptic.P256(), sellerPriv.PublicKey.X, sellerPriv.PublicKey.Y))
	if err != nil {
		t.Fatalf("seller id: %v", err)
	}
	intent := fixedCommerceIntentV1()
	intent.BuyerAgent = buyerID
	intent.SellerAgent = sellerID
	sig, err := SignCommerceIntentV1ES256(intent, buyerPriv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1ES256: %v", err)
	}
	if sig.Version != "sig-v2" || sig.Algorithm != "es256" {
		t.Fatalf("unexpected sig envelope: %+v", sig)
	}
	if err := VerifyCommerceIntentV1(intent, sig); err != nil {
		t.Fatalf("VerifyCommerceIntentV1: %v", err)
	}
}

func TestDelegationV1_SignAndVerifyES256(t *testing.T) {
	subjectPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey subject: %v", err)
	}
	subjectID, err := AgentIDFromP256PublicKey(elliptic.Marshal(elliptic.P256(), subjectPriv.PublicKey.X, subjectPriv.PublicKey.Y))
	if err != nil {
		t.Fatalf("subject id: %v", err)
	}
	del := DelegationV1{
		Version:      "delegation-v1",
		DelegationID: "del_es256_01",
		IssuerAgent:  subjectID,
		SubjectAgent: subjectID,
		Scopes:       []string{DelegationScopeCommerceIntentSign},
		Constraints: DelegationConstraintsV1{
			ContractID:        "ctr_offline_reference",
			CounterpartyAgent: "*",
			ValidFrom:         "2026-01-01T00:00:00Z",
			ValidUntil:        "2026-12-31T23:59:59Z",
		},
		Nonce:    "ZGVsZWdhdGlvbl9ub25jZV92Mg",
		IssuedAt: "2026-02-20T12:06:00Z",
	}
	sig, err := SignDelegationV1ES256(del, subjectPriv, time.Date(2026, 2, 20, 12, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignDelegationV1ES256: %v", err)
	}
	if err := VerifyDelegationV1(del, sig); err != nil {
		t.Fatalf("VerifyDelegationV1: %v", err)
	}
}

func TestMixedSignerVerification_Ed25519AndES256(t *testing.T) {
	edSeed := make([]byte, 32)
	for i := range edSeed {
		edSeed[i] = 17
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	intent := fixedCommerceIntentV1()
	intentSig, err := SignCommerceIntentV1(intent, edPriv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1: %v", err)
	}
	if err := VerifyCommerceIntentV1(intent, intentSig); err != nil {
		t.Fatalf("VerifyCommerceIntentV1 ed25519: %v", err)
	}

	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey p256: %v", err)
	}
	accept := fixedCommerceAcceptV1()
	acceptSig, err := SignCommerceAcceptV1ES256(accept, p256Priv, time.Date(2026, 2, 20, 11, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceAcceptV1ES256: %v", err)
	}
	if err := VerifyCommerceAcceptV1(accept, acceptSig); err != nil {
		t.Fatalf("VerifyCommerceAcceptV1 es256: %v", err)
	}
}
