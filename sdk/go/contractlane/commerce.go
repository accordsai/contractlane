package contractlane

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"contractlane/pkg/evidencehash"
)

var base64URLNoPaddingPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type SigV1Envelope = SignatureEnvelopeV1

type CommerceAmountV1 struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

type CommerceIntentItemV1 struct {
	SKU       string           `json:"sku"`
	Qty       int              `json:"qty"`
	UnitPrice CommerceAmountV1 `json:"unit_price"`
}

type CommerceIntentV1 struct {
	Version     string                 `json:"version"`
	IntentID    string                 `json:"intent_id"`
	ContractID  string                 `json:"contract_id"`
	BuyerAgent  string                 `json:"buyer_agent"`
	SellerAgent string                 `json:"seller_agent"`
	Items       []CommerceIntentItemV1 `json:"items"`
	Total       CommerceAmountV1       `json:"total"`
	ExpiresAt   string                 `json:"expires_at"`
	Nonce       string                 `json:"nonce"`
	Metadata    map[string]any         `json:"metadata"`
}

type CommerceAcceptV1 struct {
	Version    string         `json:"version"`
	ContractID string         `json:"contract_id"`
	IntentHash string         `json:"intent_hash"`
	AcceptedAt string         `json:"accepted_at"`
	Nonce      string         `json:"nonce"`
	Metadata   map[string]any `json:"metadata"`
}

func HashCommerceIntentV1(intent CommerceIntentV1) (string, error) {
	n, err := normalizeCommerceIntent(intent)
	if err != nil {
		return "", err
	}
	h, _, err := evidencehash.CanonicalSHA256(commerceIntentPayload(n))
	return h, err
}

func SignCommerceIntentV1(intent CommerceIntentV1, priv ed25519.PrivateKey, issuedAt time.Time) (SigV1Envelope, error) {
	n, err := normalizeCommerceIntent(intent)
	if err != nil {
		return SigV1Envelope{}, err
	}
	return SignSigV1Ed25519(commerceIntentPayload(n), priv, issuedAt, "commerce-intent")
}

func VerifyCommerceIntentV1(intent CommerceIntentV1, sig SigV1Envelope) error {
	_, err := validateCommerceIntentSubmission(intent, sig)
	return err
}

func HashCommerceAcceptV1(acc CommerceAcceptV1) (string, error) {
	n, err := normalizeCommerceAccept(acc)
	if err != nil {
		return "", err
	}
	h, _, err := evidencehash.CanonicalSHA256(commerceAcceptPayload(n))
	return h, err
}

func SignCommerceAcceptV1(acc CommerceAcceptV1, priv ed25519.PrivateKey, issuedAt time.Time) (SigV1Envelope, error) {
	n, err := normalizeCommerceAccept(acc)
	if err != nil {
		return SigV1Envelope{}, err
	}
	return SignSigV1Ed25519(commerceAcceptPayload(n), priv, issuedAt, "commerce-accept")
}

func VerifyCommerceAcceptV1(acc CommerceAcceptV1, sig SigV1Envelope) error {
	_, err := validateCommerceAcceptSubmission(acc, sig)
	return err
}

func normalizeCommerceIntent(intent CommerceIntentV1) (CommerceIntentV1, error) {
	if intent.Version != "commerce-intent-v1" {
		return CommerceIntentV1{}, errors.New("invalid version")
	}
	if strings.TrimSpace(intent.IntentID) == "" || strings.TrimSpace(intent.ContractID) == "" {
		return CommerceIntentV1{}, errors.New("intent_id and contract_id are required")
	}
	if !IsValidAgentID(intent.BuyerAgent) || !IsValidAgentID(intent.SellerAgent) {
		return CommerceIntentV1{}, errors.New("buyer_agent and seller_agent must be valid agent-id-v1")
	}
	if len(intent.Items) == 0 {
		return CommerceIntentV1{}, errors.New("items are required")
	}
	for _, it := range intent.Items {
		if strings.TrimSpace(it.SKU) == "" {
			return CommerceIntentV1{}, errors.New("item sku is required")
		}
		if it.Qty < 1 {
			return CommerceIntentV1{}, errors.New("item qty must be >= 1")
		}
		if err := validateAmount(it.UnitPrice); err != nil {
			return CommerceIntentV1{}, err
		}
	}
	if err := validateAmount(intent.Total); err != nil {
		return CommerceIntentV1{}, err
	}
	if err := validateRFC3339UTC(intent.ExpiresAt, "expires_at"); err != nil {
		return CommerceIntentV1{}, err
	}
	if err := validateBase64URLNoPadding(intent.Nonce, "nonce"); err != nil {
		return CommerceIntentV1{}, err
	}
	if intent.Metadata == nil {
		intent.Metadata = map[string]any{}
	}
	return intent, nil
}

func normalizeCommerceAccept(acc CommerceAcceptV1) (CommerceAcceptV1, error) {
	if acc.Version != "commerce-accept-v1" {
		return CommerceAcceptV1{}, errors.New("invalid version")
	}
	if strings.TrimSpace(acc.ContractID) == "" {
		return CommerceAcceptV1{}, errors.New("contract_id is required")
	}
	if len(acc.IntentHash) != 64 {
		return CommerceAcceptV1{}, errors.New("intent_hash must be lowercase hex sha256")
	}
	if _, err := hex.DecodeString(acc.IntentHash); err != nil {
		return CommerceAcceptV1{}, errors.New("intent_hash must be lowercase hex sha256")
	}
	if acc.IntentHash != strings.ToLower(acc.IntentHash) {
		return CommerceAcceptV1{}, errors.New("intent_hash must be lowercase hex sha256")
	}
	if err := validateRFC3339UTC(acc.AcceptedAt, "accepted_at"); err != nil {
		return CommerceAcceptV1{}, err
	}
	if err := validateBase64URLNoPadding(acc.Nonce, "nonce"); err != nil {
		return CommerceAcceptV1{}, err
	}
	if acc.Metadata == nil {
		acc.Metadata = map[string]any{}
	}
	return acc, nil
}

func validateAmount(a CommerceAmountV1) error {
	if strings.TrimSpace(a.Currency) == "" || strings.TrimSpace(a.Amount) == "" {
		return errors.New("currency and amount are required")
	}
	return nil
}

func validateRFC3339UTC(v, field string) error {
	if !strings.HasSuffix(v, "Z") {
		return errors.New(field + " must be RFC3339 UTC")
	}
	if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
		return errors.New(field + " must be RFC3339 UTC")
	}
	return nil
}

func validateBase64URLNoPadding(v, field string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New(field + " is required")
	}
	if strings.Contains(v, "=") {
		return errors.New(field + " must be base64url without padding")
	}
	if !base64URLNoPaddingPattern.MatchString(v) {
		return errors.New(field + " must be base64url without padding")
	}
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		return errors.New(field + " must be base64url without padding")
	}
	return nil
}

func commerceIntentPayload(intent CommerceIntentV1) map[string]any {
	items := make([]any, 0, len(intent.Items))
	for _, it := range intent.Items {
		items = append(items, map[string]any{
			"sku": it.SKU,
			"qty": it.Qty,
			"unit_price": map[string]any{
				"currency": it.UnitPrice.Currency,
				"amount":   it.UnitPrice.Amount,
			},
		})
	}
	return map[string]any{
		"version":      intent.Version,
		"intent_id":    intent.IntentID,
		"contract_id":  intent.ContractID,
		"buyer_agent":  intent.BuyerAgent,
		"seller_agent": intent.SellerAgent,
		"items":        items,
		"total": map[string]any{
			"currency": intent.Total.Currency,
			"amount":   intent.Total.Amount,
		},
		"expires_at": intent.ExpiresAt,
		"nonce":      intent.Nonce,
		"metadata":   intent.Metadata,
	}
}

func commerceAcceptPayload(acc CommerceAcceptV1) map[string]any {
	return map[string]any{
		"version":     acc.Version,
		"contract_id": acc.ContractID,
		"intent_hash": acc.IntentHash,
		"accepted_at": acc.AcceptedAt,
		"nonce":       acc.Nonce,
		"metadata":    acc.Metadata,
	}
}
