package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/accordsai/contractlane/pkg/authn"
	"github.com/accordsai/contractlane/pkg/db"
	"github.com/accordsai/contractlane/pkg/httpx"
	"github.com/accordsai/contractlane/services/execution/internal/webhooks"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func main() {
	pool := db.MustConnect()
	ingressStore := webhooks.NewStore(pool)
	ingressHandler := webhooks.NewIngressHandler(ingressStore)

	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8083"
	}

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	r.Post("/webhooks/{provider}/{endpoint_token}", ingressHandler.HandleIngress)

	r.Route("/exec", func(api chi.Router) {
		api.Post("/contracts/{contract_id}/sendForSignature", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				authn.LogAuthFailure(r.Context(), pool, "execution", "POST /exec/contracts/{contract_id}/sendForSignature", "", "", "UNAUTHORIZED", map[string]any{"required_scope": "exec.signatures:send"})
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			if !authn.HasScope(agent.Scopes, "exec.signatures:send") {
				authn.LogAuthFailure(r.Context(), pool, "execution", "POST /exec/contracts/{contract_id}/sendForSignature", agent.PrincipalID, agent.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": "exec.signatures:send"})
				httpx.WriteError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", map[string]any{"required_scope": "exec.signatures:send"})
				return
			}
			var req struct {
				ActorContext struct {
					PrincipalID string `json:"principal_id"`
					ActorID     string `json:"actor_id"`
					ActorType   string `json:"actor_type"`
				} `json:"actor_context"`
				TemplateID   string `json:"template_id"`
				Counterparty struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"counterparty"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			var existingProvider, existingEnvelopeID, existingStatus string
			var existingSigningURL *string
			var existingRecipients []byte
			err = pool.QueryRow(r.Context(), `
SELECT provider,envelope_id,status,signing_url,recipients
FROM signature_envelopes
WHERE contract_id=$1
`, contractID).Scan(&existingProvider, &existingEnvelopeID, &existingStatus, &existingSigningURL, &existingRecipients)
			if err == nil {
				var recipients any
				_ = json.Unmarshal(existingRecipients, &recipients)
				renderedDoc := "# Contract " + contractID + "\n\nTemplate: " + req.TemplateID + "\n\nCounterparty: " + req.Counterparty.Name + " <" + req.Counterparty.Email + ">\n"
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id":    httpx.NewRequestID(),
					"provider":      existingProvider,
					"envelope_id":   existingEnvelopeID,
					"status":        existingStatus,
					"signing_url":   existingSigningURL,
					"recipients":    recipients,
					"rendered_doc":  renderedDoc,
					"render_format": "markdown",
				})
				return
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			envelopeID := "env_" + uuid.NewString()
			signingURL := "https://sign.internal.local/envelopes/" + envelopeID
			recipients := []map[string]any{
				{"role": "COUNTERPARTY_SIGNER", "name": req.Counterparty.Name, "email": req.Counterparty.Email},
				{"role": "OUR_SIGNER", "name": "Principal Signer", "email": "signer@" + req.ActorContext.PrincipalID + ".local"},
			}
			renderedDoc := "# Contract " + contractID + "\n\nTemplate: " + req.TemplateID + "\n\nCounterparty: " + req.Counterparty.Name + " <" + req.Counterparty.Email + ">\n"

			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":    httpx.NewRequestID(),
				"provider":      "INTERNAL",
				"envelope_id":   envelopeID,
				"status":        "SENT",
				"signing_url":   signingURL,
				"recipients":    recipients,
				"rendered_doc":  renderedDoc,
				"render_format": "markdown",
			})
		})
		api.Post("/webhooks/esign/{provider}", func(w http.ResponseWriter, r *http.Request) {
			provider := chi.URLParam(r, "provider")
			secret := os.Getenv("EXEC_WEBHOOK_SECRET")
			if secret == "" {
				secret = "dev_webhook_secret"
			}
			eventID := strings.TrimSpace(r.Header.Get("X-Webhook-Id"))
			if eventID == "" {
				httpx.WriteError(w, 400, "MISSING_WEBHOOK_ID", "X-Webhook-Id header is required", nil)
				return
			}
			signatureHeader := strings.TrimSpace(r.Header.Get("X-Webhook-Signature"))
			if signatureHeader == "" {
				httpx.WriteError(w, 401, "INVALID_WEBHOOK_SIGNATURE", "X-Webhook-Signature header is required", nil)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				httpx.WriteError(w, 400, "BAD_BODY", err.Error(), nil)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			var req struct {
				EnvelopeID string         `json:"envelope_id"`
				EventType  string         `json:"event_type"`
				Status     string         `json:"status"`
				Payload    map[string]any `json:"payload"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			sigValid := webhooks.VerifySignature(secret, body, signatureHeader)
			payloadHash := webhooks.PayloadHash(body)
			rawPayload := []byte("{}")
			if len(body) > 0 {
				rawPayload = body
			}

			var replayCount int64
			err = pool.QueryRow(r.Context(), `
INSERT INTO webhook_receipts(provider,event_id,envelope_id,event_type,payload_hash,signature_valid,raw_payload,processing_result)
VALUES(upper($1),$2,$3,$4,$5,$6,$7::jsonb,CASE WHEN $6 THEN 'RECEIVED' ELSE 'INVALID_SIGNATURE' END)
ON CONFLICT (provider,event_id) DO UPDATE SET
  replay_count=webhook_receipts.replay_count+1,
  last_replayed_at=now(),
  processing_result='REPLAY_IGNORED'
RETURNING replay_count
`, provider, eventID, req.EnvelopeID, req.EventType, payloadHash, sigValid, string(rawPayload)).Scan(&replayCount)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if replayCount > 0 {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id":  httpx.NewRequestID(),
					"accepted":    true,
					"provider":    provider,
					"event_id":    eventID,
					"envelope_id": req.EnvelopeID,
					"replay":      true,
				})
				return
			}
			if !sigValid {
				httpx.WriteError(w, 401, "INVALID_WEBHOOK_SIGNATURE", "signature verification failed", nil)
				return
			}
			status := req.Status
			if status == "" {
				switch req.EventType {
				case "SIGNED_BY_US":
					status = "SIGNED_BY_US"
				case "SIGNED_BY_THEM":
					status = "SIGNED_BY_THEM"
				case "envelope.completed":
					status = "SIGNED_BY_THEM"
				default:
					status = "SENT"
				}
			}
			raw, _ := json.Marshal(map[string]any{
				"provider":   provider,
				"event_type": req.EventType,
				"payload":    req.Payload,
				"at":         time.Now().UTC().Format(time.RFC3339),
			})
			_, _ = pool.Exec(r.Context(), `
UPDATE signature_envelopes
SET status=$1,last_event_at=now(),raw_last_event=$2::jsonb,updated_at=now()
WHERE envelope_id=$3 AND provider=upper($4)
`, status, string(raw), req.EnvelopeID, provider)
			if req.EventType == "envelope.completed" {
				_, _ = pool.Exec(r.Context(), `
UPDATE contracts c
SET state='EFFECTIVE',updated_at=now()
FROM signature_envelopes se
WHERE se.contract_id=c.contract_id
  AND se.envelope_id=$1
  AND se.provider=upper($2)
  AND c.state<>'EFFECTIVE'
`, req.EnvelopeID, provider)
				_, _ = pool.Exec(r.Context(), `
INSERT INTO contract_events(contract_id,type,actor_id,payload)
SELECT c.contract_id,'EFFECTIVE','SYSTEM',$3::jsonb
FROM contracts c
JOIN signature_envelopes se ON se.contract_id=c.contract_id
WHERE se.envelope_id=$1
  AND se.provider=upper($2)
  AND c.state='EFFECTIVE'
  AND NOT EXISTS (
    SELECT 1 FROM contract_events ce
    WHERE ce.contract_id=c.contract_id AND ce.type='EFFECTIVE'
  )
`, req.EnvelopeID, provider, string(raw))
			}
			_, _ = pool.Exec(r.Context(), `
UPDATE webhook_receipts
SET processed_at=now(), processing_result='APPLIED'
WHERE provider=upper($1) AND event_id=$2
`, provider, eventID)

			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "accepted": true, "provider": provider, "event_id": eventID, "envelope_id": req.EnvelopeID, "status": status, "replay": false})
		})
	})

	http.ListenAndServe(":"+port, r)
}
