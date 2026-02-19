package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrEndpointNotFound = errors.New("webhook endpoint not found")

type Store struct {
	DB *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{DB: db}
}

type Endpoint struct {
	PrincipalID string
	Secret      string
	RevokedAt   *time.Time
}

type Receipt struct {
	ReceiptID        string
	PrincipalID      string
	Provider         string
	EventType        string
	ProviderEventID  *string
	ReceivedAt       time.Time
	RequestMethod    string
	RequestPath      string
	RawBody          []byte
	RawBodySHA256    string
	HeadersCanonical any
	HeadersSHA256    string
	RequestSHA256    string
	SignatureValid   bool
	SignatureScheme  string
	SignatureDetails map[string]any
	LinkedContractID *string
	LinkedAction     *string
	ProcessingStatus string
	ProcessedAt      *time.Time
}

func (s *Store) GetEndpoint(ctx context.Context, provider, token string) (Endpoint, error) {
	var out Endpoint
	err := s.DB.QueryRow(ctx, `
SELECT principal_id::text, secret, revoked_at
FROM webhook_endpoints
WHERE provider=$1 AND endpoint_token=$2
`, provider, token).Scan(&out.PrincipalID, &out.Secret, &out.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Endpoint{}, ErrEndpointNotFound
		}
		return Endpoint{}, err
	}
	return out, nil
}

func (s *Store) InsertReceipt(ctx context.Context, receipt Receipt) (inserted bool, receiptID string, err error) {
	detailsJSON, err := json.Marshal(receipt.SignatureDetails)
	if err != nil {
		return false, "", err
	}
	headersJSON, err := json.Marshal(receipt.HeadersCanonical)
	if err != nil {
		return false, "", err
	}
	var providerEventID any
	if receipt.ProviderEventID != nil && strings.TrimSpace(*receipt.ProviderEventID) != "" {
		providerEventID = strings.TrimSpace(*receipt.ProviderEventID)
	}

	err = s.DB.QueryRow(ctx, `
INSERT INTO webhook_receipts_v2(
  principal_id,provider,event_type,provider_event_id,received_at,request_method,request_path,
  raw_body,raw_body_sha256,headers_canonical_json,headers_sha256,request_sha256,
  signature_valid,signature_scheme,signature_details,linked_contract_id,linked_action,processing_status,processed_at
)
VALUES(
  $1,$2,$3,$4,$5,$6,$7,
  $8,$9,$10::jsonb,$11,$12,
  $13,$14,$15::jsonb,$16,$17,$18,$19
)
ON CONFLICT (principal_id,provider,provider_event_id)
  WHERE provider_event_id IS NOT NULL
DO NOTHING
RETURNING receipt_id::text
`, receipt.PrincipalID, receipt.Provider, receipt.EventType, providerEventID, receipt.ReceivedAt.UTC(), receipt.RequestMethod, receipt.RequestPath,
		receipt.RawBody, receipt.RawBodySHA256, string(headersJSON), receipt.HeadersSHA256, receipt.RequestSHA256,
		receipt.SignatureValid, receipt.SignatureScheme, string(detailsJSON), receipt.LinkedContractID, receipt.LinkedAction, receipt.ProcessingStatus, receipt.ProcessedAt).Scan(&receiptID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, receiptID, nil
}

func (s *Store) GetReceiptByProviderEventID(ctx context.Context, principalID, provider, providerEventID string) (Receipt, error) {
	var out Receipt
	err := s.DB.QueryRow(ctx, `
SELECT receipt_id::text, request_sha256, signature_valid, event_type
FROM webhook_receipts_v2
WHERE principal_id=$1
  AND provider=$2
  AND provider_event_id=$3
`, principalID, provider, providerEventID).Scan(&out.ReceiptID, &out.RequestSHA256, &out.SignatureValid, &out.EventType)
	if err != nil {
		return Receipt{}, err
	}
	return out, nil
}

func (s *Store) ContractBelongsToPrincipal(ctx context.Context, contractID, principalID string) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM contracts
  WHERE contract_id=$1
    AND principal_id=$2
)
`, contractID, principalID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Store) UpdateReceiptLinkage(ctx context.Context, receiptID, contractID string, linkedAction *string) error {
	_, err := s.DB.Exec(ctx, `
UPDATE webhook_receipts_v2
SET linked_contract_id=COALESCE(linked_contract_id,$2::uuid),
    linked_action=CASE
      WHEN linked_action IS NULL AND $3 IS NOT NULL THEN $3
      ELSE linked_action
    END
WHERE receipt_id=$1::uuid
`, receiptID, contractID, linkedAction)
	return err
}
