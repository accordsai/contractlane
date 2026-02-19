package contractlane

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SettlementAttestationV1 struct {
	Version          string           `json:"version"`
	Provider         string           `json:"provider"`
	ProviderEventID  string           `json:"provider_event_id"`
	ProviderObjectID string           `json:"provider_object_id"`
	ContractID       string           `json:"contract_id"`
	IntentID         string           `json:"intent_id"`
	IntentHash       string           `json:"intent_hash"`
	Status           string           `json:"status"`
	Amount           CommerceAmountV1 `json:"amount"`
	OccurredAt       string           `json:"occurred_at"`
	DerivedFrom      struct {
		ReceiptRequestHash string `json:"receipt_request_hash"`
	} `json:"derived_from"`
}

type NormalizedAmount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

var isoMinorUnitExponentV1 = map[string]int{
	"USD": 2,
	"EUR": 2,
	"GBP": 2,
	"JPY": 0,
	"KRW": 0,
	"INR": 2,
	"CHF": 2,
	"CAD": 2,
	"AUD": 2,
}

var isoCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

func NormalizeMinorUnits(currency string, minor int64) (NormalizedAmount, error) {
	if minor < 0 {
		return NormalizedAmount{}, errors.New("minor units must be non-negative")
	}
	ccy := strings.ToUpper(strings.TrimSpace(currency))
	if !isoCurrencyPattern.MatchString(ccy) {
		return NormalizedAmount{}, errors.New("currency must be ISO4217 uppercase 3 letters")
	}
	exp, ok := isoMinorUnitExponentV1[ccy]
	if !ok {
		return NormalizedAmount{}, errors.New("unknown currency")
	}

	var amount string
	if exp == 0 {
		amount = strconv.FormatInt(minor, 10)
	} else {
		pow := int64(1)
		for i := 0; i < exp; i++ {
			if pow > (1<<62)/10 {
				return NormalizedAmount{}, errors.New("amount overflow")
			}
			pow *= 10
		}
		integerPart := minor / pow
		fractionPart := minor % pow
		fraction := fmt.Sprintf("%0*d", exp, fractionPart)
		amount = fmt.Sprintf("%d.%s", integerPart, fraction)
		amount = strings.TrimRight(amount, "0")
		amount = strings.TrimSuffix(amount, ".")
		if amount == "" {
			amount = "0"
		}
	}
	return NormalizedAmount{Currency: ccy, Amount: amount}, nil
}

func DeriveSettlementAttestationsFromReceipts(receipts any) ([]SettlementAttestationV1, error) {
	return deriveSettlementAttestations(receipts)
}

func extractReceiptPayload(receipt map[string]any) (map[string]any, bool) {
	if pm, ok := receipt["payload"].(map[string]any); ok {
		return pm, true
	}
	raw := strings.TrimSpace(fmt.Sprint(receipt["raw_body"]))
	if raw == "" {
		return nil, false
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, false
	}
	return payload, true
}

func deriveStripeAttestation(receipt map[string]any, evt map[string]any) (SettlementAttestationV1, bool) {
	eventType := strings.TrimSpace(fmt.Sprint(evt["type"]))
	status := mapStripeStatus(eventType)
	if status == "" {
		return SettlementAttestationV1{}, false
	}
	eventID := strings.TrimSpace(fmt.Sprint(evt["id"]))
	if eventID == "" {
		eventID = strings.TrimSpace(fmt.Sprint(receipt["provider_event_id"]))
	}
	if eventID == "" {
		return SettlementAttestationV1{}, false
	}
	createdSec, ok := int64Value(evt["created"])
	if !ok {
		return SettlementAttestationV1{}, false
	}
	occurredAt := time.Unix(createdSec, 0).UTC().Format(time.RFC3339)

	obj := nestedMap(evt, "data", "object")
	if obj == nil {
		return SettlementAttestationV1{}, false
	}
	objectID := strings.TrimSpace(fmt.Sprint(obj["id"]))
	if objectID == "" {
		return SettlementAttestationV1{}, false
	}
	metadata := nestedMap(obj, "metadata")
	if metadata == nil {
		return SettlementAttestationV1{}, false
	}
	contractID := strings.TrimSpace(fmt.Sprint(metadata["contract_id"]))
	intentID := strings.TrimSpace(fmt.Sprint(metadata["intent_id"]))
	intentHash := stripSHA256Prefix(fmt.Sprint(metadata["intent_hash"]))
	if contractID == "" || intentID == "" || intentHash == "" {
		return SettlementAttestationV1{}, false
	}
	if len(intentHash) != 64 {
		return SettlementAttestationV1{}, false
	}
	if _, err := hex.DecodeString(intentHash); err != nil {
		return SettlementAttestationV1{}, false
	}
	if intentHash != strings.ToLower(intentHash) {
		return SettlementAttestationV1{}, false
	}
	amountMinor := stripeMinorAmount(eventType, obj)
	if amountMinor < 0 {
		return SettlementAttestationV1{}, false
	}
	normalized, err := NormalizeMinorUnits(strings.TrimSpace(fmt.Sprint(obj["currency"])), amountMinor)
	if err != nil {
		return SettlementAttestationV1{}, false
	}
	requestHash := strings.TrimSpace(fmt.Sprint(receipt["request_sha256"]))
	if requestHash == "" {
		requestHash = strings.TrimSpace(fmt.Sprint(receipt["request_hash"]))
	}
	if requestHash == "" {
		return SettlementAttestationV1{}, false
	}
	att := SettlementAttestationV1{
		Version:          "settlement-attest-v1",
		Provider:         "stripe",
		ProviderEventID:  eventID,
		ProviderObjectID: objectID,
		ContractID:       contractID,
		IntentID:         intentID,
		IntentHash:       intentHash,
		Status:           status,
		Amount: CommerceAmountV1{
			Currency: normalized.Currency,
			Amount:   normalized.Amount,
		},
		OccurredAt: occurredAt,
	}
	att.DerivedFrom.ReceiptRequestHash = requestHash
	return att, true
}

func stripeMinorAmount(eventType string, obj map[string]any) int64 {
	if strings.HasPrefix(eventType, "payment_intent.") {
		if v, ok := int64Value(obj["amount_received"]); ok {
			return v
		}
	}
	if v, ok := int64Value(obj["amount"]); ok {
		return v
	}
	return -1
}

func mapStripeStatus(eventType string) string {
	switch eventType {
	case "payment_intent.succeeded":
		return "PAID"
	case "payment_intent.payment_failed", "payment_intent.canceled":
		return "FAILED"
	case "charge.refunded", "refund.created":
		return "REFUNDED"
	case "charge.dispute.created":
		return "DISPUTED"
	default:
		return ""
	}
}

func nestedMap(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func int64Value(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		return i, err == nil
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

func (s SettlementAttestationV1) validateForProof() error {
	if s.Version != "settlement-attest-v1" {
		return errors.New("invalid settlement attestation version")
	}
	if s.Status == "" {
		return errors.New("missing settlement attestation status")
	}
	if strings.TrimSpace(s.ContractID) == "" || strings.TrimSpace(s.IntentID) == "" || strings.TrimSpace(s.IntentHash) == "" {
		return errors.New("incomplete settlement attestation linkage")
	}
	return nil
}
