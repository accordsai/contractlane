package contractlane

import (
	"strings"
	"testing"

	"contractlane/pkg/evidencehash"
)

func TestDeriveSettlementAttestationsFromReceipts_Deterministic(t *testing.T) {
	receipts := []any{
		sampleStripeReceipt("evt_pi_succeeded_ci_a", "payment_intent.succeeded", "ctr_test_001", "ci_a", "d7504fd3c3a34f4f93fcc1ec1c375199b25bdaeaed58264af0581c56176284c0", 2600, "usd", "pi_ci_a"),
		sampleStripeReceipt("evt_pi_failed_ci_b", "payment_intent.payment_failed", "ctr_test_001", "ci_b", "8a31ddb90d269b7e52c085c3a81efd14ff50ac2bd07b390cc8714b15fe972931", 2600, "usd", "pi_ci_b"),
	}

	a1, err := DeriveSettlementAttestationsFromReceipts(receipts)
	if err != nil {
		t.Fatalf("DeriveSettlementAttestationsFromReceipts #1: %v", err)
	}
	a2, err := DeriveSettlementAttestationsFromReceipts(receipts)
	if err != nil {
		t.Fatalf("DeriveSettlementAttestationsFromReceipts #2: %v", err)
	}
	if len(a1) != 2 || len(a2) != 2 {
		t.Fatalf("expected 2 attestations, got %d and %d", len(a1), len(a2))
	}
	if a1[0].ProviderEventID != "evt_pi_failed_ci_b" || a1[1].ProviderEventID != "evt_pi_succeeded_ci_a" {
		t.Fatalf("unexpected deterministic ordering: %+v", a1)
	}
	h1, _, err := evidencehash.CanonicalSHA256(a1)
	if err != nil {
		t.Fatalf("hash #1: %v", err)
	}
	h2, _, err := evidencehash.CanonicalSHA256(a2)
	if err != nil {
		t.Fatalf("hash #2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected stable hash, got %s vs %s", h1, h2)
	}
	const expectedHash = "b7b4e2a06edf31eb4f05480a141662eeac29d4b03d7a1c275d6d157ef1bfc382"
	if h1 != expectedHash {
		t.Fatalf("attestation hash drift: got %s want %s", h1, expectedHash)
	}
	if a1[1].Status != "PAID" {
		t.Fatalf("expected payment_intent.succeeded => PAID, got %s", a1[1].Status)
	}
	if a1[1].Amount.Amount != "26" {
		t.Fatalf("expected normalized amount 26, got %s", a1[1].Amount.Amount)
	}
}

func TestDeriveSettlementAttestationsFromReceipts_MissingMetadataSkipped(t *testing.T) {
	bad := sampleStripeReceipt("evt_missing_meta", "payment_intent.succeeded", "ctr_test_001", "ci_a", "d7504fd3c3a34f4f93fcc1ec1c375199b25bdaeaed58264af0581c56176284c0", 2600, "usd", "pi_missing")
	payload := bad["payload"].(map[string]any)
	obj := payload["data"].(map[string]any)["object"].(map[string]any)
	delete(obj, "metadata")

	att, err := DeriveSettlementAttestationsFromReceipts([]any{bad})
	if err != nil {
		t.Fatalf("DeriveSettlementAttestationsFromReceipts: %v", err)
	}
	if len(att) != 0 {
		t.Fatalf("expected no attestations when metadata missing, got %d", len(att))
	}
}

func TestNormalizeMinorUnits_KnownVectors(t *testing.T) {
	cases := []struct {
		currency string
		minor    int64
		want     string
	}{
		{"USD", 4900, "49"},
		{"USD", 4910, "49.1"},
		{"USD", 4901, "49.01"},
		{"JPY", 49, "49"},
		{"USD", 0, "0"},
	}
	for _, tc := range cases {
		got, err := NormalizeMinorUnits(tc.currency, tc.minor)
		if err != nil {
			t.Fatalf("NormalizeMinorUnits(%s,%d): %v", tc.currency, tc.minor, err)
		}
		if got.Currency != tc.currency || got.Amount != tc.want {
			t.Fatalf("NormalizeMinorUnits(%s,%d) = %s %s, want %s %s", tc.currency, tc.minor, got.Currency, got.Amount, tc.currency, tc.want)
		}
	}

	if _, err := NormalizeMinorUnits("XYZ", 10); err == nil || !strings.Contains(err.Error(), "unknown currency") {
		t.Fatalf("expected unknown currency error, got %v", err)
	}
	if _, err := NormalizeMinorUnits("USD", -1); err == nil {
		t.Fatal("expected negative minor units error")
	}
}
