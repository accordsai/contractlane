package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	pkgwebhooks "github.com/accordsai/contractlane/pkg/webhooks"

	"github.com/accordsai/contractlane/pkg/httpx"
	"github.com/go-chi/chi/v5"
)

const maxWebhookBodyBytes = 5 << 20 // 5MB

type verifierFactory func(provider string) pkgwebhooks.Verifier

type ReceiptStore interface {
	GetEndpoint(ctx context.Context, provider, token string) (Endpoint, error)
	InsertReceipt(ctx context.Context, receipt Receipt) (inserted bool, receiptID string, err error)
	GetReceiptByProviderEventID(ctx context.Context, principalID, provider, providerEventID string) (Receipt, error)
	ContractBelongsToPrincipal(ctx context.Context, contractID, principalID string) (bool, error)
	UpdateReceiptLinkage(ctx context.Context, receiptID, contractID string, linkedAction *string) error
}

type IngressHandler struct {
	store    ReceiptStore
	verifier verifierFactory
}

func NewIngressHandler(store ReceiptStore) *IngressHandler {
	return &IngressHandler{
		store: store,
		verifier: func(provider string) pkgwebhooks.Verifier {
			if strings.EqualFold(strings.TrimSpace(provider), "stripe") {
				return pkgwebhooks.NewStripeV1Verifier(provider)
			}
			return pkgwebhooks.NewGenericHMACVerifier(provider)
		},
	}
}

func (h *IngressHandler) HandleIngress(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	endpointToken := strings.TrimSpace(chi.URLParam(r, "endpoint_token"))
	endpoint, err := h.store.GetEndpoint(r.Context(), provider, endpointToken)
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			httpx.WriteError(w, 404, "NOT_FOUND", "webhook endpoint not found", nil)
			return
		}
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return
	}
	if endpoint.RevokedAt != nil {
		httpx.WriteError(w, 404, "NOT_FOUND", "webhook endpoint not found", nil)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			httpx.WriteError(w, 413, "PAYLOAD_TOO_LARGE", "payload exceeds 5MB limit", nil)
			return
		}
		httpx.WriteError(w, 400, "BAD_BODY", err.Error(), nil)
		return
	}

	headersCanonicalJSON, _, err := pkgwebhooks.CanonicalizeHeaders(r.Header)
	if err != nil {
		httpx.WriteError(w, 500, "CANONICALIZATION_ERROR", err.Error(), nil)
		return
	}
	rawBodySHA, headersSHA, requestSHA := pkgwebhooks.ComputeWebhookHashes(r.Method, r.URL.Path, headersCanonicalJSON, rawBody)

	receivedAt := time.Now().UTC()
	verifier := h.verifier(provider)
	result, err := verifier.Verify(r.Header, rawBody, receivedAt, endpoint.Secret)
	if err != nil {
		httpx.WriteError(w, 500, "VERIFIER_ERROR", err.Error(), nil)
		return
	}

	eventType := strings.TrimSpace(result.EventType)
	if eventType == "" {
		eventType = "unknown"
	}
	var providerEventID *string
	if v := strings.TrimSpace(result.ProviderEventID); v != "" {
		providerEventID = &v
	}
	processingStatus := "REJECTED"
	if result.Valid {
		processingStatus = "VERIFIED"
	}

	var headersCanonical any
	if err := json.Unmarshal(headersCanonicalJSON, &headersCanonical); err != nil {
		httpx.WriteError(w, 500, "CANONICALIZATION_ERROR", err.Error(), nil)
		return
	}

	receipt := Receipt{
		PrincipalID:      endpoint.PrincipalID,
		Provider:         provider,
		EventType:        eventType,
		ProviderEventID:  providerEventID,
		ReceivedAt:       receivedAt,
		RequestMethod:    r.Method,
		RequestPath:      r.URL.Path,
		RawBody:          rawBody,
		RawBodySHA256:    rawBodySHA,
		HeadersCanonical: headersCanonical,
		HeadersSHA256:    headersSHA,
		RequestSHA256:    requestSHA,
		SignatureValid:   result.Valid,
		SignatureScheme:  result.Scheme,
		SignatureDetails: result.Details,
		ProcessingStatus: processingStatus,
	}

	inserted, receiptID, err := h.store.InsertReceipt(r.Context(), receipt)
	if err != nil {
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return
	}
	if !inserted && providerEventID != nil {
		existing, err := h.store.GetReceiptByProviderEventID(r.Context(), endpoint.PrincipalID, provider, *providerEventID)
		if err != nil {
			httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
			return
		}
		receiptID = existing.ReceiptID
		requestSHA = existing.RequestSHA256
		result.Valid = existing.SignatureValid
	}

	if result.Valid {
		contractID, linkedAction := extractContractLinkage(rawBody)
		if contractID != "" {
			belongs, err := h.store.ContractBelongsToPrincipal(r.Context(), contractID, endpoint.PrincipalID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if belongs {
				if err := h.store.UpdateReceiptLinkage(r.Context(), receiptID, contractID, linkedAction); err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
			}
		}
	}

	httpx.WriteJSON(w, 200, map[string]any{
		"status":          "accepted",
		"receipt_id":      receiptID,
		"request_sha256":  requestSHA,
		"signature_valid": result.Valid,
	})
}

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func extractContractLinkage(rawBody []byte) (contractID string, linkedAction *string) {
	var payload map[string]any
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return "", nil
	}

	if v, ok := payload["linked_action"].(string); ok {
		s := strings.TrimSpace(v)
		if s != "" {
			linkedAction = &s
		}
	}

	if v, ok := payload["contract_id"].(string); ok {
		id := strings.TrimSpace(v)
		if isUUID(id) {
			return id, linkedAction
		}
	}

	metadata, _ := payload["metadata"].(map[string]any)
	if metadata != nil {
		if linkedAction == nil {
			if v, ok := metadata["linked_action"].(string); ok {
				s := strings.TrimSpace(v)
				if s != "" {
					linkedAction = &s
				}
			}
		}
		if v, ok := metadata["contract_id"].(string); ok {
			id := strings.TrimSpace(v)
			if isUUID(id) {
				return id, linkedAction
			}
		}
	}

	return "", linkedAction
}

func isUUID(v string) bool {
	return uuidRegex.MatchString(strings.TrimSpace(v))
}
