package contractlane

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func fixedCommerceIntentV1() CommerceIntentV1 {
	buyer := make([]byte, 32)
	seller := make([]byte, 32)
	for i := 0; i < 32; i++ {
		buyer[i] = byte(i)
		seller[i] = byte(32 + i)
	}
	buyerID, _ := AgentIDFromEd25519PublicKey(buyer)
	sellerID, _ := AgentIDFromEd25519PublicKey(seller)

	return CommerceIntentV1{
		Version:     "commerce-intent-v1",
		IntentID:    "ci_test_001",
		ContractID:  "ctr_test_001",
		BuyerAgent:  buyerID,
		SellerAgent: sellerID,
		Items: []CommerceIntentItemV1{
			{
				SKU: "sku_alpha",
				Qty: 2,
				UnitPrice: CommerceAmountV1{
					Currency: "USD",
					Amount:   "10.50",
				},
			},
			{
				SKU: "sku_beta",
				Qty: 1,
				UnitPrice: CommerceAmountV1{
					Currency: "USD",
					Amount:   "5.00",
				},
			},
		},
		Total: CommerceAmountV1{
			Currency: "USD",
			Amount:   "26.00",
		},
		ExpiresAt: "2026-02-20T12:00:00Z",
		Nonce:     "bm9uY2VfdjE",
		Metadata:  map[string]any{},
	}
}

func fixedCommerceAcceptV1() CommerceAcceptV1 {
	return CommerceAcceptV1{
		Version:    "commerce-accept-v1",
		ContractID: "ctr_test_001",
		IntentHash: "f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f",
		AcceptedAt: "2026-02-20T12:05:00Z",
		Nonce:      "YWNjZXB0X25vbmNlX3Yx",
		Metadata:   map[string]any{},
	}
}

func TestCommerceIntentV1_KnownVectorHash(t *testing.T) {
	got, err := HashCommerceIntentV1(fixedCommerceIntentV1())
	if err != nil {
		t.Fatalf("HashCommerceIntentV1: %v", err)
	}
	want := "f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f"
	if got != want {
		t.Fatalf("intent hash mismatch: want %s got %s", want, got)
	}
}

func TestCommerceAcceptV1_KnownVectorHash(t *testing.T) {
	got, err := HashCommerceAcceptV1(fixedCommerceAcceptV1())
	if err != nil {
		t.Fatalf("HashCommerceAcceptV1: %v", err)
	}
	want := "670a209431d7b80bc997fabf40a707952a6494af07ddf374d4efdd4532449e21"
	if got != want {
		t.Fatalf("accept hash mismatch: want %s got %s", want, got)
	}
}

func TestCommerceIntentV1_SignAndVerify(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 + i%31)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	intent := fixedCommerceIntentV1()

	sig, err := SignCommerceIntentV1(intent, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1: %v", err)
	}
	if sig.Context != "commerce-intent" {
		t.Fatalf("expected commerce-intent context, got %s", sig.Context)
	}
	if err := VerifyCommerceIntentV1(intent, sig); err != nil {
		t.Fatalf("VerifyCommerceIntentV1: %v", err)
	}
}

func TestCommerceAcceptV1_SignAndVerify(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(100 + i%29)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	acc := fixedCommerceAcceptV1()

	sig, err := SignCommerceAcceptV1(acc, priv, time.Date(2026, 2, 20, 11, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceAcceptV1: %v", err)
	}
	if sig.Context != "commerce-accept" {
		t.Fatalf("expected commerce-accept context, got %s", sig.Context)
	}
	if err := VerifyCommerceAcceptV1(acc, sig); err != nil {
		t.Fatalf("VerifyCommerceAcceptV1: %v", err)
	}
}

func TestCommerceVerify_RejectsWrongContextAndPayloadHash(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(7, ed25519.SeedSize))
	intent := fixedCommerceIntentV1()
	sig, err := SignCommerceIntentV1(intent, priv, time.Date(2026, 2, 20, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignCommerceIntentV1: %v", err)
	}

	badContext := sig
	badContext.Context = "commerce-accept"
	if err := VerifyCommerceIntentV1(intent, badContext); err == nil {
		t.Fatal("expected context mismatch failure")
	}

	badHash := sig
	badHash.PayloadHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyCommerceIntentV1(intent, badHash); err == nil {
		t.Fatal("expected payload hash mismatch failure")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
