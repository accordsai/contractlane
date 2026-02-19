package webhooks

import (
	"net/http"
	"time"
)

type VerificationResult struct {
	Valid           bool           `json:"valid"`
	Scheme          string         `json:"scheme"`
	Details         map[string]any `json:"details"`
	ProviderEventID string         `json:"provider_event_id,omitempty"`
	EventType       string         `json:"event_type,omitempty"`
}

type Verifier interface {
	Provider() string
	Verify(headers http.Header, rawBody []byte, receivedAt time.Time, secret string) (VerificationResult, error)
}
