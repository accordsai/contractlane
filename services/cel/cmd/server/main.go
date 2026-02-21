package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	anchorrfc3161 "github.com/accordsai/contractlane/pkg/anchor/rfc3161"
	"github.com/accordsai/contractlane/pkg/authn"
	"github.com/accordsai/contractlane/pkg/canonhash"
	"github.com/accordsai/contractlane/pkg/db"
	"github.com/accordsai/contractlane/pkg/domain"
	"github.com/accordsai/contractlane/pkg/evidencehash"
	"github.com/accordsai/contractlane/pkg/httpx"
	signaturev1 "github.com/accordsai/contractlane/pkg/signature"
	clsdk "github.com/accordsai/contractlane/sdk/go/contractlane"
	"github.com/accordsai/contractlane/services/cel/internal/execclient"
	"github.com/accordsai/contractlane/services/cel/internal/ialclient"
	"github.com/accordsai/contractlane/services/cel/internal/idempotency"
	"github.com/accordsai/contractlane/services/cel/internal/render"
	"github.com/accordsai/contractlane/services/cel/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type actorContext struct {
	PrincipalID    string `json:"principal_id"`
	ActorID        string `json:"actor_id"`
	ActorType      string `json:"actor_type"`
	IdempotencyKey string `json:"idempotency_key"`
}

func main() {
	pool := db.MustConnect()
	st := store.New(pool)

	ialBase := os.Getenv("IAL_BASE_URL")
	if ialBase == "" {
		ialBase = "http://localhost:8081/ial"
	}
	ial := ialclient.New(ialBase)
	execBase := os.Getenv("EXEC_BASE_URL")
	if execBase == "" {
		execBase = "http://localhost:8083/exec"
	}
	exec := execclient.New(execBase)

	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8082"
	}

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	cfg := loadHostedModeConfig()
	commerceLimiter := newFixedWindowLimiter(cfg.HostedRateLimitPerMinute, time.Minute)
	proofLimiter := newFixedWindowLimiter(cfg.ProofRateLimitPerMinute, time.Minute)

	r.Route("/commerce", func(api chi.Router) {
		api.Post("/intents", func(w http.ResponseWriter, r *http.Request) {
			if !precheckHostedCommerceRequest(w, r, cfg, commerceLimiter) {
				return
			}
			const endpoint = "POST /commerce/intents"
			agent, ok := requireBearerAgentScope(r, w, pool, endpoint, "cel.contracts:write")
			if !ok {
				return
			}

			var req struct {
				Intent    clsdk.CommerceIntentV1 `json:"intent"`
				Signature clsdk.SigV1Envelope    `json:"signature"`
			}
			if ok := readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req); !ok {
				return
			}
			validated, err := clsdk.ValidateCommerceIntentSubmission(req.Intent, req.Signature)
			if err != nil {
				writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
				return
			}

			c, err := st.GetContract(r.Context(), validated.Intent.ContractID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 403, "FORBIDDEN", "contract principal mismatch", nil)
				return
			}

			if commerceAuthorizationRequired(c) {
				delegations, err := st.ListCommerceDelegationsForAuthorization(r.Context(), c.ContractID)
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				revocations, err := st.ListCommerceDelegationRevocationsForAuthorization(r.Context(), c.ContractID)
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				okAuth, reason := evaluateHostedCommerceAuthorization(
					true,
					clsdk.DelegationScopeCommerceIntentSign,
					validated.SigningAgent,
					validated.Intent.SellerAgent,
					c.ContractID,
					req.Signature.IssuedAt,
					&validated.Intent.Total,
					delegations,
					revocations,
					commerceTrustAgents(),
				)
				if !okAuth {
					log.Printf("commerce_intent_auth_failed contract_id=%s reason=%s", c.ContractID, reason)
					writeStandardError(w, 403, "FORBIDDEN", "delegation authorization failed", reason)
					return
				}
			}

			intentMap, sigMap, err := commerceIntentSubmissionMaps(validated.Intent, req.Signature)
			if err != nil {
				httpx.WriteError(w, 500, "INTERNAL_ERROR", err.Error(), nil)
				return
			}
			if err := st.UpsertCommerceIntentArtifact(r.Context(), c.ContractID, agent.ActorID, validated.IntentHash, map[string]any{
				"intent_hash":     validated.IntentHash,
				"signing_agent":   validated.SigningAgent,
				"intent":          intentMap,
				"buyer_signature": sigMap,
			}); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"contract_id": c.ContractID,
				"intent_hash": validated.IntentHash,
				"status":      "ACCEPTED",
			})
			log.Printf("commerce_intent_accepted contract_id=%s intent_hash=%s", c.ContractID, validated.IntentHash)
		})

		api.Post("/accepts", func(w http.ResponseWriter, r *http.Request) {
			if !precheckHostedCommerceRequest(w, r, cfg, commerceLimiter) {
				return
			}
			const endpoint = "POST /commerce/accepts"
			agent, ok := requireBearerAgentScope(r, w, pool, endpoint, "cel.contracts:write")
			if !ok {
				return
			}

			var req struct {
				Accept    clsdk.CommerceAcceptV1 `json:"accept"`
				Signature clsdk.SigV1Envelope    `json:"signature"`
			}
			if ok := readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req); !ok {
				return
			}
			validated, err := clsdk.ValidateCommerceAcceptSubmission(req.Accept, req.Signature)
			if err != nil {
				writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
				return
			}

			c, err := st.GetContract(r.Context(), validated.Accept.ContractID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 403, "FORBIDDEN", "contract principal mismatch", nil)
				return
			}

			okHash, err := st.CommerceIntentHashExists(r.Context(), c.ContractID, validated.Accept.IntentHash)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if !okHash {
				httpx.WriteError(w, 400, "BAD_REQUEST", "accept.intent_hash not found", nil)
				return
			}

			if commerceAuthorizationRequired(c) {
				delegations, err := st.ListCommerceDelegationsForAuthorization(r.Context(), c.ContractID)
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				revocations, err := st.ListCommerceDelegationRevocationsForAuthorization(r.Context(), c.ContractID)
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				okAuth, reason := evaluateHostedCommerceAuthorization(
					true,
					clsdk.DelegationScopeCommerceAcceptSign,
					validated.SigningAgent,
					"",
					c.ContractID,
					req.Signature.IssuedAt,
					nil,
					delegations,
					revocations,
					commerceTrustAgents(),
				)
				if !okAuth {
					log.Printf("commerce_accept_auth_failed contract_id=%s reason=%s", c.ContractID, reason)
					writeStandardError(w, 403, "FORBIDDEN", "delegation authorization failed", reason)
					return
				}
			}

			acceptMap, sigMap, err := commerceAcceptSubmissionMaps(validated.Accept, req.Signature)
			if err != nil {
				httpx.WriteError(w, 500, "INTERNAL_ERROR", err.Error(), nil)
				return
			}
			if err := st.UpsertCommerceAcceptArtifact(r.Context(), c.ContractID, agent.ActorID, validated.AcceptHash, map[string]any{
				"accept_hash":      validated.AcceptHash,
				"signing_agent":    validated.SigningAgent,
				"accept":           acceptMap,
				"seller_signature": sigMap,
			}); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"contract_id": c.ContractID,
				"accept_hash": validated.AcceptHash,
				"status":      "ACCEPTED",
			})
			log.Printf("commerce_accept_accepted contract_id=%s accept_hash=%s", c.ContractID, validated.AcceptHash)
		})
	})

	r.Route("/cel", func(api chi.Router) {
		api.Get("/.well-known/contractlane", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, buildCapabilitiesResponse(cfg))
		})
		registerTemplateAdminRoutes(api, st, pool, cfg)

		// DEV helper to seed a template for smoke tests
		api.Post("/dev/seed-template", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
			}
			_ = httpx.ReadJSON(r, &req)
			tplID, err := st.UpsertSeedTemplate(r.Context())
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "template_id": tplID})
		})

		api.Get("/templates", func(w http.ResponseWriter, r *http.Request) {
			ct := r.URL.Query().Get("contract_type")
			j := r.URL.Query().Get("jurisdiction")
			var principalID *string
			if authz := strings.TrimSpace(r.Header.Get("Authorization")); authz != "" {
				if agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, authz); err == nil {
					principalID = &agent.PrincipalID
				}
			}
			templates, err := st.ListTemplates(r.Context(), ct, j, principalID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "templates": templates})
		})

		api.Post("/principals/{principal_id}/templates/{template_id}/enable", func(w http.ResponseWriter, r *http.Request) {
			principalID := chi.URLParam(r, "principal_id")
			templateID := chi.URLParam(r, "template_id")
			var req struct {
				EnabledByActorID string            `json:"enabled_by_actor_id"`
				OverrideGates    map[string]string `json:"override_gates"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			tpl, err := st.GetTemplate(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			if strings.EqualFold(tpl.Visibility, "PRIVATE") {
				ownerOK := tpl.OwnerPrincipalID != nil && strings.TrimSpace(*tpl.OwnerPrincipalID) == principalID
				sharedOK := false
				if !ownerOK {
					if ok, err := st.IsTemplateSharedWithPrincipal(r.Context(), templateID, principalID); err == nil {
						sharedOK = ok
					}
				}
				if !ownerOK && !sharedOK {
					httpx.WriteError(w, 403, "FORBIDDEN", "template is private to owner principal", nil)
					return
				}
			}
			if err := st.EnableTemplate(r.Context(), principalID, templateID, req.EnabledByActorID, req.OverrideGates); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "enabled": true, "principal_id": principalID, "template_id": templateID})
		})

		api.Get("/templates/{template_id}/governance", func(w http.ResponseWriter, r *http.Request) {
			templateID := chi.URLParam(r, "template_id")
			tpl, err := st.GetTemplate(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			if strings.EqualFold(strings.TrimSpace(tpl.Visibility), "PRIVATE") {
				authz := strings.TrimSpace(r.Header.Get("Authorization"))
				if authz == "" {
					httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
					return
				}
				agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, authz)
				if err != nil {
					httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
					return
				}
				ownerOK := tpl.OwnerPrincipalID != nil && strings.TrimSpace(*tpl.OwnerPrincipalID) == agent.PrincipalID
				sharedOK := false
				if !ownerOK {
					if ok, err := st.IsTemplateSharedWithPrincipal(r.Context(), templateID, agent.PrincipalID); err == nil {
						sharedOK = ok
					}
				}
				if !ownerOK && !sharedOK {
					httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
					return
				}
			}
			gates, err := st.GetTemplateGates(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			vars, err := st.GetTemplateVars(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":      httpx.NewRequestID(),
				"template":        map[string]any{"template_id": templateID},
				"template_gates":  gates,
				"variables":       vars,
				"protected_slots": []string{},
			})
		})

		api.Post("/templates/{template_id}/versions/{version}/render", func(w http.ResponseWriter, r *http.Request) {
			templateID := chi.URLParam(r, "template_id")
			version := strings.TrimSpace(chi.URLParam(r, "version"))
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			if _, err := st.GetTemplateForPrincipalUse(r.Context(), agent.PrincipalID, templateID); err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			if enabled, err := st.IsTemplateEnabledForPrincipal(r.Context(), agent.PrincipalID, templateID); err == nil && !enabled {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			if expected := parseTemplateVersion(templateID); expected != "" && expected != version {
				httpx.WriteError(w, 404, "NOT_FOUND", "template version not found", nil)
				return
			}

			var req struct {
				Variables map[string]string `json:"variables"`
				Locale    string            `json:"locale"`
				Format    string            `json:"format"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.Variables == nil {
				req.Variables = map[string]string{}
			}
			format := normalizeRenderFormat(req.Format)
			if format == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "format must be text or html", nil)
				return
			}
			locale := normalizeLocale(req.Locale)

			tpl, err := st.GetTemplate(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			defs, err := st.GetTemplateVars(r.Context(), templateID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			templateText := render.BuildCanonicalTemplateText(render.TemplateSpec{
				TemplateID:      templateID,
				TemplateVersion: version,
				DisplayName:     tpl.DisplayName,
				Variables:       defs,
			})
			out, missing, err := render.Render(templateText, req.Variables, defs, format)
			if err != nil {
				httpx.WriteError(w, 500, "RENDER_FAILED", err.Error(), nil)
				return
			}
			if len(missing) > 0 {
				httpx.WriteError(w, 422, "MISSING_REQUIRED_VARIABLES", "missing required variables for render", map[string]any{"missing_keys": missing})
				return
			}
			varsHash, _, err := render.HashVariablesSnapshot(req.Variables)
			if err != nil {
				httpx.WriteError(w, 500, "RENDER_FAILED", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":          httpx.NewRequestID(),
				"template_id":         templateID,
				"template_version":    version,
				"format":              format,
				"locale":              locale,
				"rendered":            out,
				"render_hash":         render.HashRendered(out),
				"variables_hash":      varsHash,
				"determinism_version": render.DeterminismVersion,
			})
		})

		api.Post("/programs", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ActorContext actorContext `json:"actor_context"`
				Key          string       `json:"key"`
				Mode         string       `json:"mode"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.Key == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "key is required", nil)
				return
			}
			if req.Mode != "STRICT_RECONSENT" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "mode must be STRICT_RECONSENT", nil)
				return
			}
			if ok := requireAgentScope(r, w, pool, req.ActorContext, "POST /cel/programs", "cel.contracts:write"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, "POST /cel/programs"); replayed {
				return
			}
			p := store.ComplianceProgram{
				PrincipalID:      req.ActorContext.PrincipalID,
				ProgramKey:       req.Key,
				Mode:             req.Mode,
				CreatedByActorID: req.ActorContext.ActorID,
			}
			if err := st.CreateComplianceProgram(r.Context(), p); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			prog, err := st.GetComplianceProgram(r.Context(), req.ActorContext.PrincipalID, req.Key)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddComplianceProgramEvent(r.Context(), req.ActorContext.PrincipalID, req.Key, "COMPLIANCE_PROGRAM_CREATED", &req.ActorContext.ActorID, map[string]any{
				"mode": req.Mode,
			})
			resp := map[string]any{"request_id": httpx.NewRequestID(), "program": prog}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, "POST /cel/programs", 201, resp); !ok {
				return
			}
		})

		api.Get("/programs/{key}", func(w http.ResponseWriter, r *http.Request) {
			programKey := chi.URLParam(r, "key")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			prog, err := st.GetComplianceProgram(r.Context(), agent.PrincipalID, programKey)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "program": prog})
		})

		api.Post("/programs/{key}/publish", func(w http.ResponseWriter, r *http.Request) {
			programKey := chi.URLParam(r, "key")
			var req struct {
				ActorContext            actorContext `json:"actor_context"`
				RequiredTemplateID      string       `json:"required_template_id"`
				RequiredTemplateVersion string       `json:"required_template_version"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.RequiredTemplateID == "" || req.RequiredTemplateVersion == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "required_template_id and required_template_version are required", nil)
				return
			}
			endpoint := fmt.Sprintf("POST /cel/programs/%s/publish", programKey)
			if ok := requireAgentScope(r, w, pool, req.ActorContext, endpoint, "cel.contracts:write"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint); replayed {
				return
			}
			prog, err := st.GetComplianceProgram(r.Context(), req.ActorContext.PrincipalID, programKey)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if prog.Mode != "STRICT_RECONSENT" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "unsupported compliance mode", nil)
				return
			}
			if _, err := st.GetTemplate(r.Context(), req.RequiredTemplateID); err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "required template not found", nil)
				return
			}
			if err := st.PublishComplianceProgram(r.Context(), req.ActorContext.PrincipalID, programKey, req.RequiredTemplateID, req.RequiredTemplateVersion, req.ActorContext.ActorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddComplianceProgramEvent(r.Context(), req.ActorContext.PrincipalID, programKey, "COMPLIANCE_PROGRAM_PUBLISHED", &req.ActorContext.ActorID, map[string]any{
				"required_template_id":      req.RequiredTemplateID,
				"required_template_version": req.RequiredTemplateVersion,
			})
			updated, err := st.GetComplianceProgram(r.Context(), req.ActorContext.PrincipalID, programKey)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			resp := map[string]any{"request_id": httpx.NewRequestID(), "program": updated}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
				return
			}
		})

		api.Get("/gates/{gate_key}/status", func(w http.ResponseWriter, r *http.Request) {
			gateKey := chi.URLParam(r, "gate_key")
			externalSubjectID := strings.TrimSpace(r.URL.Query().Get("external_subject_id"))
			actorType := strings.TrimSpace(r.URL.Query().Get("actor_type"))

			if externalSubjectID == "" {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "MISSING_EXTERNAL_SUBJECT_ID",
				})
				return
			}

			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "UNAUTHORIZED",
				})
				return
			}
			principalID := agent.PrincipalID

			prog, err := st.GetComplianceProgram(r.Context(), principalID, gateKey)
			if err != nil {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "UNKNOWN_GATE_KEY",
				})
				return
			}
			if prog.Mode != "STRICT_RECONSENT" || prog.RequiredTemplateID == nil || prog.RequiredTemplateVersion == nil {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "PROGRAM_NOT_PUBLISHED",
				})
				return
			}

			var subject *ialclient.Subject
			if actorType == "" {
				s, err := ial.ResolveSubject(principalID, externalSubjectID, nil)
				if err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id": httpx.NewRequestID(),
						"gate_key":   gateKey,
						"status":     "BLOCKED",
						"next_step": map[string]any{
							"type":   "FILL_VARIABLES",
							"reason": "SUBJECT_ACTOR_TYPE_REQUIRED",
						},
						"remediation": map[string]any{
							"message":     "actor_type is required the first time for this external_subject_id",
							"required":    []string{"actor_type"},
							"resolve_url": fmt.Sprintf("/cel/gates/%s/resolve", gateKey),
						},
					})
					return
				}
				subject = s
			} else {
				s, err := ial.ResolveSubject(principalID, externalSubjectID, &actorType)
				if err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id": httpx.NewRequestID(),
						"gate_key":   gateKey,
						"status":     "REJECTED",
						"reason":     "SUBJECT_RESOLUTION_FAILED",
					})
					return
				}
				subject = s
			}

			ok, err := st.HasEffectiveContractForSubject(r.Context(), principalID, subject.ActorID, *prog.RequiredTemplateID, *prog.RequiredTemplateVersion)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if ok {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id":          httpx.NewRequestID(),
					"gate_key":            gateKey,
					"status":              "DONE",
					"external_subject_id": externalSubjectID,
					"subject":             subject,
					"required": map[string]any{
						"template_id":      *prog.RequiredTemplateID,
						"template_version": *prog.RequiredTemplateVersion,
					},
				})
				return
			}

			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":          httpx.NewRequestID(),
				"gate_key":            gateKey,
				"status":              "BLOCKED",
				"external_subject_id": externalSubjectID,
				"subject":             subject,
				"next_step": map[string]any{
					"type":   "APPROVE_ACTION",
					"reason": "GATE_NOT_SATISFIED",
				},
				"remediation": map[string]any{
					"resolve_url": fmt.Sprintf("/cel/gates/%s/resolve", gateKey),
				},
				"required": map[string]any{
					"template_id":      *prog.RequiredTemplateID,
					"template_version": *prog.RequiredTemplateVersion,
				},
			})
		})

		api.Post("/gates/{gate_key}/resolve", func(w http.ResponseWriter, r *http.Request) {
			gateKey := chi.URLParam(r, "gate_key")
			var req struct {
				ExternalSubjectID string  `json:"external_subject_id"`
				ActorType         *string `json:"actor_type"`
				IdempotencyKey    string  `json:"idempotency_key"`
				ClientReturnURL   string  `json:"client_return_url"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.ExternalSubjectID) == "" {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "MISSING_EXTERNAL_SUBJECT_ID",
				})
				return
			}
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "UNAUTHORIZED",
				})
				return
			}
			allowed, delegated, err := authn.HasScopeOrDelegation(r.Context(), pool, agent, "cel.contracts:write", authn.DelegationContext{
				Capability: "gate.resolve",
			})
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if !allowed {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "INSUFFICIENT_SCOPE",
				})
				return
			}
			if delegated {
				authn.LogAuthEvent(r.Context(), pool, "cel", "POST /cel/gates/{gate_key}/resolve", agent.PrincipalID, agent.ActorID, "DELEGATION_USED", map[string]any{
					"capability": "gate.resolve",
					"gate_key":   gateKey,
				})
			}
			actor := actorContext{
				PrincipalID:    agent.PrincipalID,
				ActorID:        agent.ActorID,
				ActorType:      "AGENT",
				IdempotencyKey: req.IdempotencyKey,
			}
			endpoint := fmt.Sprintf("POST /cel/gates/%s/resolve/%s", gateKey, strings.TrimSpace(req.ExternalSubjectID))
			if replayed := replayIdempotentResponse(r.Context(), st, w, actor, endpoint); replayed {
				return
			}
			prog, err := st.GetComplianceProgram(r.Context(), agent.PrincipalID, gateKey)
			if err != nil {
				resp := map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "UNKNOWN_GATE_KEY",
				}
				_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
				return
			}
			if prog.Mode != "STRICT_RECONSENT" || prog.RequiredTemplateID == nil || prog.RequiredTemplateVersion == nil {
				resp := map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "PROGRAM_NOT_PUBLISHED",
				}
				_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
				return
			}

			subject, err := ial.ResolveSubject(agent.PrincipalID, strings.TrimSpace(req.ExternalSubjectID), req.ActorType)
			if err != nil {
				if req.ActorType == nil || strings.TrimSpace(*req.ActorType) == "" {
					resp := map[string]any{
						"request_id":          httpx.NewRequestID(),
						"gate_key":            gateKey,
						"status":              "BLOCKED",
						"external_subject_id": strings.TrimSpace(req.ExternalSubjectID),
						"next_step": map[string]any{
							"type":   "FILL_VARIABLES",
							"reason": "SUBJECT_ACTOR_TYPE_REQUIRED",
						},
						"remediation": map[string]any{
							"message":  "actor_type is required the first time for this external_subject_id",
							"required": []string{"actor_type"},
						},
					}
					_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
					return
				}
				resp := map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "SUBJECT_RESOLUTION_FAILED",
				}
				_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
				return
			}

			done, err := st.HasEffectiveContractForSubject(r.Context(), agent.PrincipalID, subject.ActorID, *prog.RequiredTemplateID, *prog.RequiredTemplateVersion)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if done {
				resp := map[string]any{
					"request_id":          httpx.NewRequestID(),
					"gate_key":            gateKey,
					"status":              "DONE",
					"external_subject_id": strings.TrimSpace(req.ExternalSubjectID),
					"subject":             subject,
				}
				_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
				return
			}

			releaseLock, err := st.AcquireGateResolveLock(r.Context(), agent.PrincipalID, gateKey, strings.TrimSpace(req.ExternalSubjectID), *prog.RequiredTemplateVersion)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			defer releaseLock()

			// Re-check after lock in case another resolver completed the gate while we waited.
			done, err = st.HasEffectiveContractForSubject(r.Context(), agent.PrincipalID, subject.ActorID, *prog.RequiredTemplateID, *prog.RequiredTemplateVersion)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if done {
				resp := map[string]any{
					"request_id":          httpx.NewRequestID(),
					"gate_key":            gateKey,
					"status":              "DONE",
					"external_subject_id": strings.TrimSpace(req.ExternalSubjectID),
					"subject":             subject,
				}
				_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
				return
			}

			contractID, continueURL, err := ensureGateContractAndSignature(r.Context(), st, exec, gateKey, agent.PrincipalID, agent.ActorID, subject.ActorID, *prog.RequiredTemplateID, *prog.RequiredTemplateVersion, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 500, "ORCHESTRATION_ERROR", err.Error(), nil)
				return
			}
			resp := map[string]any{
				"request_id":          httpx.NewRequestID(),
				"gate_key":            gateKey,
				"status":              "BLOCKED",
				"external_subject_id": strings.TrimSpace(req.ExternalSubjectID),
				"contract_id":         contractID,
				"subject":             subject,
				"next_step": map[string]any{
					"type":   "APPROVE_ACTION",
					"reason": "SIGNATURE_REQUIRED",
				},
				"remediation": map[string]any{
					"continue_url":      continueURL,
					"client_return_url": req.ClientReturnURL,
				},
			}
			_ = saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, 200, resp)
		})

		api.Get("/gates/{gate_key}/evidence", func(w http.ResponseWriter, r *http.Request) {
			gateKey := chi.URLParam(r, "gate_key")
			externalSubjectID := strings.TrimSpace(r.URL.Query().Get("external_subject_id"))
			if externalSubjectID == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "external_subject_id is required", nil)
				return
			}
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			subject, err := ial.ResolveSubject(agent.PrincipalID, externalSubjectID, nil)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "subject mapping not found", nil)
				return
			}
			c, err := st.FindLatestEffectiveGateContractForSubject(r.Context(), agent.PrincipalID, gateKey, subject.ActorID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":          httpx.NewRequestID(),
						"gate_key":            gateKey,
						"external_subject_id": externalSubjectID,
						"status":              "BLOCKED",
						"next_step": map[string]any{
							"type":   "APPROVE_ACTION",
							"reason": "NO_EFFECTIVE_EVIDENCE",
						},
					})
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			evidence, err := buildContractEvidence(r.Context(), st, ial, c, gateKey, externalSubjectID, subject)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"evidence":   evidence,
			})
		})

		api.Get("/contracts/{contract_id}/evidence", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			format := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("format")))
			if format == "" {
				format = "json"
			}
			if format != "json" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "format must be json", nil)
				return
			}
			redact := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("redact")))
			if redact == "" {
				redact = "none"
			}
			if redact != "none" && redact != "pii" {
				httpx.WriteError(w, 422, "BAD_REDACT", "redact must be none or pii", nil)
				return
			}
			include, err := parseEvidenceIncludeFlags(r.URL.Query().Get("include"))
			if err != nil {
				httpx.WriteError(w, 422, "BAD_INCLUDE", err.Error(), nil)
				return
			}
			evidence, err := buildContractEvidenceBundle(r.Context(), st, ial, c, include, redact)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			evidence["request_id"] = httpx.NewRequestID()
			httpx.WriteJSON(w, 200, evidence)
		})

		api.Get("/contracts/{contract_id}/proof", func(w http.ResponseWriter, r *http.Request) {
			if !precheckProofExportRequest(w, r, cfg, proofLimiter) {
				return
			}
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				writeStandardError(w, 401, "UNAUTHORIZED", "agent authentication required", "")
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				writeStandardError(w, 404, "NOT_FOUND", "contract not found", "")
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				writeStandardError(w, 404, "NOT_FOUND", "contract not found", "")
				return
			}
			format := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("format")))
			if format == "" {
				format = "json"
			}
			if format != "json" {
				writeStandardError(w, 400, "BAD_REQUEST", "format must be json", "")
				return
			}
			redact := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("redact")))
			if redact == "" {
				redact = "none"
			}
			if redact != "none" && redact != "pii" {
				writeStandardError(w, 422, "BAD_REDACT", "redact must be none or pii", "")
				return
			}
			include, err := parseEvidenceIncludeFlags(r.URL.Query().Get("include"))
			if err != nil {
				writeStandardError(w, 422, "BAD_INCLUDE", err.Error(), "")
				return
			}
			evidence, err := buildContractEvidenceBundle(r.Context(), st, ial, c, include, redact)
			if err != nil {
				writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
				return
			}
			proof, err := clsdk.BuildContractProofBundle(
				contractSnapshotForProof(c),
				evidence,
				proofRequirementsForContract(c),
			)
			if err != nil {
				writeStandardError(w, 500, "INTERNAL_ERROR", err.Error(), "")
				return
			}
			httpx.WriteJSON(w, 200, proof)
			log.Printf("proof_exported contract_id=%s", c.ContractID)
		})

		api.Get("/contracts/{contract_id}/proof-bundle", func(w http.ResponseWriter, r *http.Request) {
			if !precheckProofBundleExportRequest(w, r, cfg, proofLimiter) {
				return
			}
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				writeStandardError(w, 401, "UNAUTHORIZED", "agent authentication required", "")
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				writeStandardError(w, 404, "NOT_FOUND", "contract not found", "")
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				writeStandardError(w, 404, "NOT_FOUND", "contract not found", "")
				return
			}
			format := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("format")))
			if format == "" {
				format = "json"
			}
			if format != "json" {
				writeStandardError(w, 400, "BAD_REQUEST", "format must be json", "")
				return
			}
			redact := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("redact")))
			if redact == "" {
				redact = "none"
			}
			if redact != "none" && redact != "pii" {
				writeStandardError(w, 422, "BAD_REDACT", "redact must be none or pii", "")
				return
			}
			include, err := parseEvidenceIncludeFlags(r.URL.Query().Get("include"))
			if err != nil {
				writeStandardError(w, 422, "BAD_INCLUDE", err.Error(), "")
				return
			}
			evidence, err := buildContractEvidenceBundle(r.Context(), st, ial, c, include, redact)
			if err != nil {
				writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
				return
			}
			proofBundle, err := clsdk.BuildProofBundleV1(
				contractExportForProofBundle(c),
				evidence,
				nil,
				buildCapabilitiesResponse(cfg),
			)
			if err != nil {
				writeStandardError(w, 500, "INTERNAL_ERROR", err.Error(), "")
				return
			}
			proofID, err := clsdk.ComputeProofID(proofBundle)
			if err != nil {
				writeStandardError(w, 500, "INTERNAL_ERROR", err.Error(), "")
				return
			}
			if os.Getenv("CONFORMANCE_DEBUG") == "1" {
				b, _ := json.Marshal(proofBundle)
				var generic any
				_ = json.Unmarshal(b, &generic)
				debugHash, debugBytes, debugErr := evidencehash.CanonicalSHA256(generic)
				if debugErr != nil {
					log.Printf("proof_bundle_debug compute_err=%v", debugErr)
				} else {
					log.Printf("proof_bundle_debug proof_id=%s canonical_sha=%s canonical_len=%d", proofID, debugHash, len(debugBytes))
				}
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"proof":    proofBundle,
				"proof_id": proofID,
			})
			log.Printf("proof_bundle_exported contract_id=%s proof_id=%s", c.ContractID, proofID)
		})

		api.Post("/contracts/{contract_id}/anchors", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			allowed, delegated, err := authn.HasScopeOrDelegation(r.Context(), pool, agent, "cel.contracts:write", authn.DelegationContext{})
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if !allowed {
				authn.LogAuthFailure(r.Context(), pool, "cel", "POST /cel/contracts/{contract_id}/anchors", agent.PrincipalID, agent.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": "cel.contracts:write"})
				httpx.WriteError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", map[string]any{"required_scope": "cel.contracts:write"})
				return
			}
			if delegated {
				authn.LogAuthEvent(r.Context(), pool, "cel", "POST /cel/contracts/{contract_id}/anchors", agent.PrincipalID, agent.ActorID, "DELEGATION_USED", map[string]any{"required_scope": "cel.contracts:write"})
			}
			idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if idempotencyKey == "" {
				httpx.WriteError(w, 400, "MISSING_IDEMPOTENCY_KEY", "Idempotency-Key header is required", nil)
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			var req struct {
				Target     string         `json:"target"`
				AnchorType string         `json:"anchor_type"`
				Request    map[string]any `json:"request"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			req.Target = strings.TrimSpace(strings.ToLower(req.Target))
			switch req.Target {
			case "bundle_hash", "manifest_hash":
			default:
				httpx.WriteError(w, 400, "BAD_REQUEST", "target must be bundle_hash or manifest_hash", nil)
				return
			}
			req.AnchorType = strings.TrimSpace(strings.ToLower(req.AnchorType))
			if req.AnchorType == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "anchor_type is required", nil)
				return
			}
			if req.Request == nil {
				req.Request = map[string]any{}
			}

			actor := actorContext{
				PrincipalID:    agent.PrincipalID,
				ActorID:        agent.ActorID,
				ActorType:      "AGENT",
				IdempotencyKey: idempotencyKey,
			}
			endpoint := fmt.Sprintf("POST /cel/contracts/%s/anchors", contractID)
			if replayed := replayIdempotentResponse(r.Context(), st, w, actor, endpoint); replayed {
				return
			}

			evidence, err := buildContractEvidenceBundle(r.Context(), st, ial, c, evidenceIncludeSet{
				render:     true,
				signatures: true,
				approvals:  true,
				events:     true,
				variables:  true,
			}, "none")
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			hashes, _ := evidence["hashes"].(map[string]any)
			targetHash := strings.TrimSpace(fmt.Sprint(hashes[req.Target]))
			if targetHash == "" {
				httpx.WriteError(w, 500, "ANCHOR_TARGET_HASH_MISSING", "failed to compute target hash", map[string]any{"target": req.Target})
				return
			}
			now := time.Now().UTC()
			if req.AnchorType != "dev_stub" && req.AnchorType != "rfc3161" {
				httpx.WriteError(w, 400, "UNSUPPORTED_ANCHOR_TYPE", "anchor_type not supported in this deployment", nil)
				return
			}
			status := "PENDING"
			var anchoredAt *time.Time
			proof := map[string]any{}
			requestPayload := map[string]any{}
			switch req.AnchorType {
			case "dev_stub":
				if strings.ToLower(strings.TrimSpace(os.Getenv("CEL_DEV_MODE"))) != "true" {
					httpx.WriteError(w, 400, "UNSUPPORTED_ANCHOR_TYPE", "dev_stub anchoring is only allowed in dev mode", nil)
					return
				}
				status = "CONFIRMED"
				anchoredAt = &now
				proof = map[string]any{
					"dev_stub":    true,
					"target":      req.Target,
					"target_hash": targetHash,
					"note":        "no external anchoring performed",
				}
				requestPayload = req.Request
			case "rfc3161":
				if req.Request != nil {
					if tsaURL, ok := req.Request["tsa_url"].(string); ok && strings.TrimSpace(tsaURL) != "" {
						requestPayload["tsa_url"] = strings.TrimSpace(tsaURL)
					}
					if policyOID, ok := req.Request["policy_oid"].(string); ok && strings.TrimSpace(policyOID) != "" {
						requestPayload["policy_oid"] = strings.TrimSpace(policyOID)
					}
				}
				status, proof, anchoredAt = performRFC3161Anchor(r.Context(), targetHash, requestPayload)
			}
			anchor, err := st.InsertAnchor(
				r.Context(),
				c.PrincipalID,
				c.ContractID,
				req.Target,
				targetHash,
				req.AnchorType,
				status,
				requestPayload,
				proof,
				anchoredAt,
			)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			resp := map[string]any{
				"request_id": httpx.NewRequestID(),
				"anchor": map[string]any{
					"anchor_id":   anchor.AnchorID,
					"target":      anchor.Target,
					"target_hash": anchor.TargetHash,
					"anchor_type": anchor.AnchorType,
					"status":      anchor.Status,
					"request":     anchor.Request,
					"proof":       anchor.Proof,
					"created_at":  anchor.CreatedAt.UTC().Format(time.RFC3339Nano),
					"anchored_at": "",
				},
			}
			if anchor.AnchoredAt != nil {
				respAnchor := resp["anchor"].(map[string]any)
				respAnchor["anchored_at"] = anchor.AnchoredAt.UTC().Format(time.RFC3339Nano)
			}
			responseStatus := 200
			if req.AnchorType == "dev_stub" {
				responseStatus = 201
			}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, actor, endpoint, responseStatus, resp); !ok {
				return
			}
		})

		api.Get("/contracts/{contract_id}/anchors", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			allowed, delegated, err := authn.HasScopeOrDelegation(r.Context(), pool, agent, "cel.contracts:read", authn.DelegationContext{})
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if !allowed {
				authn.LogAuthFailure(r.Context(), pool, "cel", "GET /cel/contracts/{contract_id}/anchors", agent.PrincipalID, agent.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": "cel.contracts:read"})
				httpx.WriteError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", map[string]any{"required_scope": "cel.contracts:read"})
				return
			}
			if delegated {
				authn.LogAuthEvent(r.Context(), pool, "cel", "GET /cel/contracts/{contract_id}/anchors", agent.PrincipalID, agent.ActorID, "DELEGATION_USED", map[string]any{"required_scope": "cel.contracts:read"})
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			anchors, err := st.ListAnchorsForContractEvidence(r.Context(), c.PrincipalID, c.ContractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"anchors":    anchors,
			})
		})

		api.Post("/contracts", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ActorContext     actorContext                 `json:"actor_context"`
				TemplateID       string                       `json:"template_id"`
				Counterparty     struct{ Name, Email string } `json:"counterparty"`
				InitialVariables map[string]string            `json:"initial_variables"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if ok := requireAgentScope(r, w, pool, req.ActorContext, "POST /cel/contracts", "cel.contracts:write"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, "POST /cel/contracts"); replayed {
				return
			}
			tpl, err := st.GetTemplateForPrincipalUse(r.Context(), req.ActorContext.PrincipalID, req.TemplateID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "template not found", nil)
				return
			}
			c := store.Contract{
				ContractID:        "ctr_" + uuid.NewString(),
				PrincipalID:       req.ActorContext.PrincipalID,
				TemplateID:        req.TemplateID,
				TemplateVersion:   ptr(strings.TrimSpace(tpl.TemplateVersion)),
				SubjectActorID:    ptr(req.ActorContext.ActorID),
				State:             "DRAFT_CREATED",
				RiskLevel:         "LOW",
				CounterpartyName:  req.Counterparty.Name,
				CounterpartyEmail: req.Counterparty.Email,
				CreatedBy:         req.ActorContext.ActorID,
				CreatedAt:         time.Now(),
			}
			if strings.TrimSpace(*c.TemplateVersion) == "" {
				c.TemplateVersion = ptr(parseTemplateVersion(req.TemplateID))
			}
			if err := st.CreateContract(r.Context(), c); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			// set initial vars (treated as agent values)
			defs, _ := st.GetTemplateVars(r.Context(), req.TemplateID)
			idGov := loadIdentityVarGov(ial, req.ActorContext.ActorID) // agent's identity rules not used; ok
			for k, v := range req.InitialVariables {
				def := findDef(defs, domain.VarKey(k))
				if def == nil {
					continue
				}
				canon, err := domain.ValidateAndCanonicalize(*def, v)
				if err != nil {
					httpx.WriteError(w, 400, "VAR_INVALID", err.Error(), nil)
					return
				}
				pol := domain.EffectiveVarSetPolicy(*def, idGov)
				src := domain.SourceAgent
				rev := domain.ReviewNotNeeded
				if pol == domain.VarAgentFillHumanReview {
					rev = domain.ReviewPending
				}
				if pol == domain.VarHumanRequired {
					rev = domain.ReviewPending
				}
				_ = st.SetVariable(r.Context(), c.ContractID, def.Key, canon, src, rev, req.ActorContext.ActorID)
			}
			_ = st.AddEvent(r.Context(), c.ContractID, "CREATED", req.ActorContext.ActorID, map[string]any{})
			resp := map[string]any{"request_id": httpx.NewRequestID(), "contract": c}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, "POST /cel/contracts", 201, resp); !ok {
				return
			}
		})

		api.Get("/contracts/{contract_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "contract_id")
			c, err := st.GetContract(r.Context(), id)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "contract": c})
		})

		api.Get("/contracts/{contract_id}/render", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "contract not found", nil)
				return
			}
			if c.PrincipalID != agent.PrincipalID {
				httpx.WriteError(w, 403, "FORBIDDEN", "contract belongs to a different principal", nil)
				return
			}
			if c.TemplateVersion == nil || strings.TrimSpace(*c.TemplateVersion) == "" {
				httpx.WriteError(w, 409, "TEMPLATE_VERSION_UNRESOLVABLE", "contract has no resolvable template version", nil)
				return
			}
			format := normalizeRenderFormat(r.URL.Query().Get("format"))
			if format == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "format must be text or html", nil)
				return
			}
			locale := normalizeLocale(r.URL.Query().Get("locale"))
			includeMeta := true
			if q := strings.TrimSpace(r.URL.Query().Get("include_meta")); q != "" {
				v, err := strconv.ParseBool(q)
				if err != nil {
					httpx.WriteError(w, 400, "BAD_REQUEST", "include_meta must be boolean", nil)
					return
				}
				includeMeta = v
			}

			tpl, err := st.GetTemplate(r.Context(), c.TemplateID)
			if err != nil {
				httpx.WriteError(w, 409, "TEMPLATE_VERSION_UNRESOLVABLE", "contract template not found", nil)
				return
			}
			defs, err := st.GetTemplateVars(r.Context(), c.TemplateID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			valuesSlice, err := st.GetVariables(r.Context(), c.ContractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			snapshot := map[string]string{}
			for _, v := range valuesSlice {
				snapshot[string(v.Key)] = v.Value
			}
			templateText := render.BuildCanonicalTemplateText(render.TemplateSpec{
				TemplateID:      c.TemplateID,
				TemplateVersion: *c.TemplateVersion,
				DisplayName:     tpl.DisplayName,
				Variables:       defs,
			})
			rendered, missing, err := render.Render(templateText, snapshot, defs, format)
			if err != nil {
				httpx.WriteError(w, 500, "RENDER_FAILED", err.Error(), nil)
				return
			}
			if len(missing) > 0 {
				httpx.WriteError(w, 422, "MISSING_REQUIRED_VARIABLES", "missing required variables for render", map[string]any{"missing_keys": missing})
				return
			}
			varsHash, _, err := render.HashVariablesSnapshot(snapshot)
			if err != nil {
				httpx.WriteError(w, 500, "RENDER_FAILED", err.Error(), nil)
				return
			}

			hashes, err := st.GetContractHashes(r.Context(), c.ContractID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					hashes, err = computeAndPersistContractHashes(r.Context(), st, ial, c.ContractID)
					if err != nil {
						httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
						return
					}
				} else {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
			}

			resp := map[string]any{
				"request_id":          httpx.NewRequestID(),
				"contract_id":         c.ContractID,
				"principal_id":        c.PrincipalID,
				"template_id":         c.TemplateID,
				"template_version":    *c.TemplateVersion,
				"contract_state":      c.State,
				"format":              format,
				"locale":              locale,
				"rendered":            rendered,
				"render_hash":         render.HashRendered(rendered),
				"packet_hash":         hashes["packet_hash"],
				"variables_hash":      varsHash,
				"generated_at":        time.Now().UTC().Format(time.RFC3339),
				"determinism_version": render.DeterminismVersion,
			}
			if includeMeta {
				resp["variables_snapshot"] = snapshot
			}
			httpx.WriteJSON(w, 200, resp)
		})

		api.Post("/contracts/{contract_id}/variables:bulkSet", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct {
				ActorContext actorContext      `json:"actor_context"`
				Variables    map[string]string `json:"variables"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			endpoint := fmt.Sprintf("POST /cel/contracts/%s/variables:bulkSet", contractID)
			if ok := requireAgentScope(r, w, pool, req.ActorContext, endpoint, "cel.contracts:write"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint); replayed {
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if c.State == "SIGNATURE_SENT" || c.State == "SIGNED_BY_US" || c.State == "SIGNED_BY_THEM" || c.State == "EFFECTIVE" || c.State == "ARCHIVED" {
				httpx.WriteError(w, 409, "VARIABLES_LOCKED", "variables cannot be changed after signature workflow initiated", nil)
				return
			}
			defs, err := st.GetTemplateVars(r.Context(), c.TemplateID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			// Resolve DEFER_TO_IDENTITY against the effective human approver profile.
			idGov := resolveIdentityVarGovForEvaluation(r.Context(), st, ial, req.ActorContext.PrincipalID, req.ActorContext.ActorType, req.ActorContext.ActorID)

			out := []map[string]any{}
			for k, v := range req.Variables {
				def := findDef(defs, domain.VarKey(k))
				if def == nil {
					continue
				}
				canon, err := domain.ValidateAndCanonicalize(*def, v)
				if err != nil {
					httpx.WriteError(w, 400, "VAR_INVALID", err.Error(), nil)
					return
				}
				pol := domain.EffectiveVarSetPolicy(*def, idGov)
				src := domain.SourceAgent
				if req.ActorContext.ActorType == "HUMAN" {
					src = domain.SourceHuman
				}
				rev := domain.ReviewNotNeeded
				switch pol {
				case domain.VarHumanRequired:
					if src == domain.SourceHuman {
						rev = domain.ReviewNotNeeded
					} else {
						rev = domain.ReviewPending
					}
				case domain.VarAgentFillHumanReview:
					if src == domain.SourceAgent {
						rev = domain.ReviewPending
					} else {
						rev = domain.ReviewNotNeeded
					}
				case domain.VarAgentAllowed:
					rev = domain.ReviewNotNeeded
				default:
					rev = domain.ReviewNotNeeded
				}
				if err := st.SetVariable(r.Context(), contractID, def.Key, canon, src, rev, req.ActorContext.ActorID); err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				out = append(out, map[string]any{"key": k, "value": canon, "source": src, "review_status": rev})
			}
			_ = st.AddEvent(r.Context(), contractID, "VARIABLE_SET", req.ActorContext.ActorID, map[string]any{"count": len(out)})
			resp := map[string]any{"request_id": httpx.NewRequestID(), "result": "OK", "variables": out}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
				return
			}
		})

		api.Get("/contracts/{contract_id}/variables", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			defs, _ := st.GetTemplateVars(r.Context(), c.TemplateID)
			vals, _ := st.GetVariables(r.Context(), contractID)

			// no actor context here; return computed gate status without identity rules (safe default agent allowed)
			idGov := domain.IdentityVariableGovernance{}
			gates := domain.EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, idGov, vals)

			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":  httpx.NewRequestID(),
				"definitions": defs,
				"values":      vals,
				"gate_status": map[string]any{
					"missing_required":   gates.MissingRequired,
					"needs_human_entry":  gates.NeedsHumanEntry,
					"needs_human_review": gates.NeedsHumanReview,
				},
			})
		})

		api.Post("/contracts/{contract_id}/variables:review", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct {
				ActorContext struct {
					PrincipalID    string `json:"principal_id"`
					ActorID        string `json:"actor_id"`
					ActorType      string `json:"actor_type"`
					IdempotencyKey string `json:"idempotency_key"`
				} `json:"actor_context"`
				Decision string   `json:"decision"`
				Keys     []string `json:"keys"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.ActorContext.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "HUMAN_ONLY", "only humans can review variables", nil)
				return
			}
			if err := st.ReviewVariables(r.Context(), contractID, req.Keys, req.Decision, req.ActorContext.ActorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddEvent(r.Context(), contractID, "VARIABLES_REVIEWED", req.ActorContext.ActorID, map[string]any{"decision": req.Decision, "count": len(req.Keys)})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "result": "OK", "updated": req.Keys})
		})

		api.Post("/contracts/{contract_id}/changesets", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct {
				ActorContext  actorContext   `json:"actor_context"`
				Changeset     map[string]any `json:"changeset"`
				RequiredRoles []string       `json:"required_roles"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if ok := requireAgentScope(r, w, pool, req.ActorContext, "POST /cel/contracts/{contract_id}/changesets", "cel.contracts:write"); !ok {
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if c.State == "SIGNATURE_SENT" || c.State == "SIGNED_BY_US" || c.State == "SIGNED_BY_THEM" || c.State == "EFFECTIVE" || c.State == "ARCHIVED" {
				httpx.WriteError(w, 409, "VARIABLES_LOCKED", "changesets cannot be applied after signature workflow initiated", nil)
				return
			}
			roles := req.RequiredRoles
			if len(roles) == 0 {
				roles = []string{"LEGAL"}
			}
			ch := store.Changeset{
				ChangesetID:       "chg_" + uuid.NewString(),
				ContractID:        contractID,
				Status:            "PENDING",
				Payload:           req.Changeset,
				RequiredRoles:     roles,
				ProposedByActorID: req.ActorContext.ActorID,
			}
			if err := st.CreateChangeset(r.Context(), ch); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddEvent(r.Context(), contractID, "CHANGESET_PROPOSED", req.ActorContext.ActorID, map[string]any{"changeset_id": ch.ChangesetID})
			httpx.WriteJSON(w, 201, map[string]any{"request_id": httpx.NewRequestID(), "changeset": ch})
		})

		api.Post("/changesets/{changeset_id}:decide", func(w http.ResponseWriter, r *http.Request) {
			changesetID := chi.URLParam(r, "changeset_id")
			var req struct {
				ActorContext actorContext `json:"actor_context"`
				Decision     string       `json:"decision"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.ActorContext.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "HUMAN_ONLY", "only humans can decide changesets", nil)
				return
			}
			ch, err := st.GetChangeset(r.Context(), changesetID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			humans, err := ial.ListActors(req.ActorContext.PrincipalID, "HUMAN")
			if err != nil {
				httpx.WriteError(w, 500, "IAL_ERROR", err.Error(), nil)
				return
			}
			allowed := false
			for _, h := range humans {
				if h.ActorID == req.ActorContext.ActorID && h.Status == "ACTIVE" && hasAnyRole(h.Roles, ch.RequiredRoles) {
					allowed = true
					break
				}
			}
			if !allowed {
				httpx.WriteError(w, 403, "WRONG_ROLE", "actor does not satisfy required changeset role", map[string]any{"required_roles": ch.RequiredRoles})
				return
			}
			if ch.Status != "PENDING" {
				httpx.WriteError(w, 409, "ALREADY_DECIDED", "changeset already decided", nil)
				return
			}
			next := "REJECTED"
			if req.Decision == "APPROVE" {
				next = "APPROVED"
			}
			if err := st.DecideChangeset(r.Context(), changesetID, next, req.ActorContext.ActorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddEvent(r.Context(), ch.ContractID, "CHANGESET_DECIDED", req.ActorContext.ActorID, map[string]any{"changeset_id": changesetID, "decision": next})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "changeset_id": changesetID, "status": next})
		})

		api.Post("/changesets/{changeset_id}:apply", func(w http.ResponseWriter, r *http.Request) {
			changesetID := chi.URLParam(r, "changeset_id")
			var req struct {
				ActorContext actorContext `json:"actor_context"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if ok := requireAgentScope(r, w, pool, req.ActorContext, "POST /cel/changesets/{changeset_id}:apply", "cel.contracts:write"); !ok {
				return
			}
			ch, err := st.GetChangeset(r.Context(), changesetID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if ch.Status != "APPROVED" {
				httpx.WriteError(w, 409, "NOT_APPROVED", "changeset must be approved before apply", nil)
				return
			}
			c, err := st.GetContract(r.Context(), ch.ContractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if c.State == "SIGNATURE_SENT" || c.State == "SIGNED_BY_US" || c.State == "SIGNED_BY_THEM" || c.State == "EFFECTIVE" || c.State == "ARCHIVED" {
				httpx.WriteError(w, 409, "VARIABLES_LOCKED", "changesets cannot be applied after signature workflow initiated", nil)
				return
			}
			varsRaw, _ := ch.Payload["variables"].(map[string]any)
			clausesRaw, _ := ch.Payload["clauses"].([]any)
			defs, err := st.GetTemplateVars(r.Context(), c.TemplateID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			idGov := resolveIdentityVarGovForEvaluation(r.Context(), st, ial, req.ActorContext.PrincipalID, req.ActorContext.ActorType, req.ActorContext.ActorID)
			applied := 0
			for k, vv := range varsRaw {
				def := findDef(defs, domain.VarKey(k))
				if def == nil {
					continue
				}
				raw, ok := vv.(string)
				if !ok {
					continue
				}
				canon, err := domain.ValidateAndCanonicalize(*def, raw)
				if err != nil {
					httpx.WriteError(w, 400, "VAR_INVALID", err.Error(), nil)
					return
				}
				pol := domain.EffectiveVarSetPolicy(*def, idGov)
				src := domain.SourceAgent
				if req.ActorContext.ActorType == "HUMAN" {
					src = domain.SourceHuman
				}
				rev := domain.ReviewNotNeeded
				switch pol {
				case domain.VarHumanRequired:
					if src == domain.SourceHuman {
						rev = domain.ReviewNotNeeded
					} else {
						rev = domain.ReviewPending
					}
				case domain.VarAgentFillHumanReview:
					if src == domain.SourceAgent {
						rev = domain.ReviewPending
					} else {
						rev = domain.ReviewNotNeeded
					}
				default:
					rev = domain.ReviewNotNeeded
				}
				if err := st.SetVariable(r.Context(), ch.ContractID, def.Key, canon, src, rev, req.ActorContext.ActorID); err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				applied++
			}
			if err := st.ApplyChangeset(r.Context(), changesetID, req.ActorContext.ActorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddEvent(r.Context(), ch.ContractID, "CHANGESET_APPLIED", req.ActorContext.ActorID, map[string]any{"changeset_id": changesetID, "variables_applied": applied, "clauses_count": len(clausesRaw)})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "changeset_id": changesetID, "status": "APPLIED", "variables_applied": applied})
		})

		api.Post("/contracts/{contract_id}/approvals:route", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct {
				ActorContext struct {
					PrincipalID string `json:"principal_id"`
					ActorID     string `json:"actor_id"`
					ActorType   string `json:"actor_type"`
				} `json:"actor_context"`
				Action        string   `json:"action"`
				RequiredRoles []string `json:"required_roles"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if ok := requireAgentScope(r, w, pool, actorContext{
				PrincipalID: req.ActorContext.PrincipalID,
				ActorID:     req.ActorContext.ActorID,
				ActorType:   req.ActorContext.ActorType,
			}, "POST /cel/contracts/{contract_id}/approvals:route", "cel.approvals:route"); !ok {
				return
			}
			aprq := "aprq_" + uuid.NewString()
			token := randomToken()
			tokenHash := hash(token)
			if err := st.CreateApprovalRequest(r.Context(), aprq, contractID, req.Action, tokenHash, req.RequiredRoles); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			_ = st.AddEvent(r.Context(), contractID, "APPROVAL_REQUESTED", req.ActorContext.ActorID, map[string]any{"approval_request_id": aprq, "action": req.Action})
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"approval_request": map[string]any{
					"approval_request_id": aprq, "contract_id": contractID, "action": req.Action, "status": "PENDING", "required_roles": req.RequiredRoles,
				},
				"review_urls": []map[string]any{
					{"actor_id": "TBD", "url": fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s?token=%s", contractID, token)},
				},
			})
		})

		api.Get("/contracts/{contract_id}/approvals", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			reqs, err := st.ListApprovalRequests(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "approval_requests": reqs})
		})

		api.Post("/approvals/{approval_request_id}:decide", func(w http.ResponseWriter, r *http.Request) {
			aprq := chi.URLParam(r, "approval_request_id")
			var req struct {
				ActorContext      actorContext           `json:"actor_context"`
				Decision          string                 `json:"decision"`
				SignedPayload     map[string]any         `json:"signed_payload"`
				SignedPayloadHash string                 `json:"signed_payload_hash"`
				Signature         map[string]any         `json:"signature"`
				SignatureEnvelope signaturev1.EnvelopeV1 `json:"signature_envelope"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			endpoint := fmt.Sprintf("POST /cel/approvals/%s:decide", aprq)
			if ok := requireAgentScope(r, w, pool, req.ActorContext, endpoint, "cel.approvals:decide"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint); replayed {
				return
			}
			if req.ActorContext.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "HUMAN_ONLY", "only humans can decide approvals", nil)
				return
			}
			signedPayloadHash, _, err := canonhash.SumObject(req.SignedPayload)
			if err != nil {
				httpx.WriteError(w, 500, "HASH_ERROR", err.Error(), nil)
				return
			}
			signedPayloadHashHex := strings.TrimPrefix(signedPayloadHash, "sha256:")
			if strings.TrimSpace(req.SignedPayloadHash) != "" {
				claimedHashHex := normalizeHexHash(req.SignedPayloadHash)
				if claimedHashHex == "" {
					httpx.WriteError(w, 403, "BAD_SIGNATURE", "signed_payload_hash must be lowercase hex sha256", nil)
					return
				}
				if subtle.ConstantTimeCompare([]byte(claimedHashHex), []byte(signedPayloadHashHex)) != 1 {
					httpx.WriteError(w, 403, "BAD_SIGNATURE", "signed_payload_hash mismatch", nil)
					return
				}
			}
			useSigV1Envelope := strings.TrimSpace(req.SignatureEnvelope.Version) != "" ||
				strings.TrimSpace(req.SignatureEnvelope.Algorithm) != "" ||
				strings.TrimSpace(req.SignatureEnvelope.Signature) != ""
			if useSigV1Envelope {
				if ctx := strings.TrimSpace(req.SignatureEnvelope.Context); ctx != "" && ctx != "contract-action" {
					httpx.WriteError(w, 403, "BAD_SIGNATURE", "signature envelope context must be contract-action", nil)
					return
				}
				if _, err := signaturev1.VerifyEnvelopeV1(req.SignedPayload, req.SignatureEnvelope); err != nil {
					httpx.WriteError(w, 403, "BAD_SIGNATURE", "signature envelope verification failed", map[string]any{"reason": err.Error()})
					return
				}
			} else {
				valid, err := ial.VerifySignature(req.ActorContext.PrincipalID, req.ActorContext.ActorID, r.Header.Get("Authorization"))
				if err != nil || !valid {
					httpx.WriteError(w, 403, "BAD_SIGNATURE", "signature verification failed", nil)
					return
				}
			}

			status, contractID, _, requiredRoles, err := st.GetApprovalRequest(r.Context(), aprq)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			if len(requiredRoles) == 0 {
				requiredRoles = []string{"LEGAL"}
			}
			allowed := false
			humans, err := ial.ListActors(req.ActorContext.PrincipalID, "HUMAN")
			if err == nil {
				for _, h := range humans {
					if h.ActorID == req.ActorContext.ActorID && h.Status == "ACTIVE" && hasAnyRole(h.Roles, requiredRoles) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				httpx.WriteError(w, 403, "WRONG_ROLE", "actor does not satisfy required approval role", map[string]any{"required_roles": requiredRoles})
				return
			}
			if status != "PENDING" {
				httpx.WriteError(w, 409, "ALREADY_DECIDED", "approval request already decided", nil)
				return
			}
			if req.Decision == "APPROVE" {
				artifacts, err := computeAndPersistContractHashes(r.Context(), st, ial, contractID)
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				signatureWithHashes := map[string]any{}
				for k, v := range req.Signature {
					signatureWithHashes[k] = v
				}
				if useSigV1Envelope {
					signatureWithHashes["signature_envelope"] = signatureEnvelopeToMap(req.SignatureEnvelope)
				}
				signatureWithHashes["hashes"] = map[string]any{
					"packet_hash": artifacts["packet_hash"],
					"diff_hash":   artifacts["diff_hash"],
					"risk_hash":   artifacts["risk_hash"],
				}
				signatureWithHashes["hash_inputs"] = map[string]any{
					"packet_input": artifacts["packet_input"],
					"diff_input":   artifacts["diff_input"],
					"risk_input":   artifacts["risk_input"],
				}
				if err := st.SaveApprovalDecision(r.Context(), aprq, req.ActorContext.ActorID, "APPROVE", req.SignedPayload, signedPayloadHash, signatureWithHashes); err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				_ = st.ApproveApprovalRequest(r.Context(), aprq)
				_ = st.AddEvent(r.Context(), contractID, "APPROVED", req.ActorContext.ActorID, map[string]any{"approval_request_id": aprq})
				resp := map[string]any{"request_id": httpx.NewRequestID(), "approval_request_id": aprq, "status": "APPROVED"}
				if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
					return
				}
				return
			}
			artifacts, err := computeAndPersistContractHashes(r.Context(), st, ial, contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			signatureWithHashes := map[string]any{}
			for k, v := range req.Signature {
				signatureWithHashes[k] = v
			}
			if useSigV1Envelope {
				signatureWithHashes["signature_envelope"] = signatureEnvelopeToMap(req.SignatureEnvelope)
			}
			signatureWithHashes["hashes"] = map[string]any{
				"packet_hash": artifacts["packet_hash"],
				"diff_hash":   artifacts["diff_hash"],
				"risk_hash":   artifacts["risk_hash"],
			}
			signatureWithHashes["hash_inputs"] = map[string]any{
				"packet_input": artifacts["packet_input"],
				"diff_input":   artifacts["diff_input"],
				"risk_input":   artifacts["risk_input"],
			}
			if err := st.SaveApprovalDecision(r.Context(), aprq, req.ActorContext.ActorID, "REJECT", req.SignedPayload, signedPayloadHash, signatureWithHashes); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			resp := map[string]any{"request_id": httpx.NewRequestID(), "approval_request_id": aprq, "status": "REJECTED"}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
				return
			}
		})

		api.Post("/contracts/{contract_id}:sendForSignature", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct {
				ActorContext struct {
					PrincipalID string `json:"principal_id"`
					ActorID     string `json:"actor_id"`
					ActorType   string `json:"actor_type"`
				} `json:"actor_context"`
			}
			_ = httpx.ReadJSON(r, &req)
			if ok := requireAgentScope(r, w, pool, actorContext{
				PrincipalID: req.ActorContext.PrincipalID,
				ActorID:     req.ActorContext.ActorID,
				ActorType:   req.ActorContext.ActorType,
			}, "POST /cel/contracts/{contract_id}:sendForSignature", "cel.contracts:write"); !ok {
				return
			}
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			exReq := execclient.SendForSignatureRequest{
				TemplateID: c.TemplateID,
			}
			exReq.ActorContext.PrincipalID = req.ActorContext.PrincipalID
			exReq.ActorContext.ActorID = req.ActorContext.ActorID
			exReq.ActorContext.ActorType = req.ActorContext.ActorType
			exReq.Counterparty.Name = c.CounterpartyName
			exReq.Counterparty.Email = c.CounterpartyEmail
			exResp, err := exec.SendForSignature(r.Context(), contractID, exReq, r.Header.Get("Authorization"))
			if err != nil {
				httpx.WriteError(w, 502, "EXECUTION_ERROR", err.Error(), nil)
				return
			}

			_ = st.TransitionState(r.Context(), contractID, "SIGNATURE_SENT")
			_ = st.UpsertEnvelope(r.Context(), contractID, exResp.Provider, exResp.EnvelopeID, exResp.Status, exResp.SigningURL, exResp.Recipients)
			_ = st.AddEvent(r.Context(), contractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": exResp.EnvelopeID, "provider": exResp.Provider})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "state": "SIGNATURE_SENT", "signature": map[string]any{"provider": exResp.Provider, "envelope_id": exResp.EnvelopeID, "status": exResp.Status}})
		})

		api.Get("/contracts/{contract_id}/signature", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			env, err := st.GetEnvelope(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "signature": env})
		})

		api.Get("/contracts/{contract_id}/events", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			evs, err := st.ListEvents(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "events": evs})
		})

		api.Get("/contracts/{contract_id}/evidence-bundle", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			evs, _ := st.ListEvents(r.Context(), contractID)
			hashes, err := computeAndPersistContractHashes(r.Context(), st, ial, contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"bundle": map[string]any{
					"bundle_id":        "bun_" + contractID,
					"bundle_root_hash": hashes["packet_hash"],
					"events":           evs,
					"hashes": map[string]any{
						"packet_hash": hashes["packet_hash"],
						"diff_hash":   hashes["diff_hash"],
						"risk_hash":   hashes["risk_hash"],
					},
					"hash_inputs": map[string]any{
						"packet_input": hashes["packet_input"],
						"diff_input":   hashes["diff_input"],
						"risk_input":   hashes["risk_input"],
					},
				},
			})
		})

		// Action endpoint (core)
		api.Post("/contracts/{contract_id}/actions/{action}", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			action := chi.URLParam(r, "action")

			var req struct {
				ActorContext actorContext `json:"actor_context"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			endpoint := fmt.Sprintf("POST /cel/contracts/%s/actions/%s", contractID, action)
			if ok := requireAgentScope(r, w, pool, req.ActorContext, endpoint, "cel.contracts:write"); !ok {
				return
			}
			if replayed := replayIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint); replayed {
				return
			}

			c, err := st.GetContract(r.Context(), contractID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			rulesArtifacts, err := buildRulesArtifactsFromContractEvents(r.Context(), st, contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			permitted, ruleID, fromState, toState, err := evaluateActionTransitionRulesV1(c, action, rulesArtifacts, commerceTrustAgents())
			if err != nil {
				writeStandardError(w, 500, "INTERNAL_ERROR", err.Error(), "")
				return
			}
			if !permitted {
				msg := "transition not permitted by rules-v1"
				if ruleID != "" && fromState != "" && toState != "" {
					msg = fmt.Sprintf("transition not permitted by rules-v1: rule_id=%s from=%s to=%s", ruleID, fromState, toState)
				}
				writeStandardError(w, 403, "FORBIDDEN", msg, "rules_transition_not_permitted")
				return
			}

			// 1) Variable gates first
			defs, _ := st.GetTemplateVars(r.Context(), c.TemplateID)
			vals, _ := st.GetVariables(r.Context(), contractID)

			// Resolve DEFER_TO_IDENTITY against the effective human approver profile.
			idGov := resolveIdentityVarGovForEvaluation(r.Context(), st, ial, req.ActorContext.PrincipalID, req.ActorContext.ActorType, req.ActorContext.ActorID)

			g := domain.EvaluateVariableGates(domain.ContractAction(action), defs, idGov, vals)
			if g.Blocked {
				nsType := "FILL_VARIABLES"
				vars := g.MissingRequired
				reason := g.Reason
				if len(g.NeedsHumanReview) > 0 {
					nsType = "REVIEW_VARIABLES"
					vars = g.NeedsHumanReview
					reason = "VARIABLES_REQUIRE_HUMAN_REVIEW"
				} else if len(g.NeedsHumanEntry) > 0 {
					nsType = "FILL_VARIABLES"
					vars = g.NeedsHumanEntry
					reason = "VARIABLES_REQUIRE_HUMAN_ENTRY"
				} else if len(g.MissingRequired) > 0 {
					nsType = "FILL_VARIABLES"
					reason = "MISSING_REQUIRED_VARIABLES"
				}
				resp := map[string]any{
					"request_id": httpx.NewRequestID(),
					"status":     "BLOCKED",
					"action":     action,
					"next_step": map[string]any{
						"type":           nsType,
						"reason":         reason,
						"variables":      vars,
						"required_roles": []string{"LEGAL"},
						"review_url":     fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s/variables?token=var_tok_dev", contractID),
					},
				}
				if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
					return
				}
				return
			}

			// 2) Action gate (template -> identity when DEFER).
			if action == "SEND_FOR_SIGNATURE" {
				templateGates, _ := st.GetTemplateGates(r.Context(), c.TemplateID)
				resolvedGate := resolveActionGateForEvaluation(r.Context(), st, ial, req.ActorContext.PrincipalID, req.ActorContext.ActorType, req.ActorContext.ActorID, action, templateGates[action])
				if resolvedGate == "ALLOW_AUTOMATION" {
					exReq := execclient.SendForSignatureRequest{
						TemplateID: c.TemplateID,
					}
					exReq.ActorContext.PrincipalID = req.ActorContext.PrincipalID
					exReq.ActorContext.ActorID = req.ActorContext.ActorID
					exReq.ActorContext.ActorType = req.ActorContext.ActorType
					exReq.Counterparty.Name = c.CounterpartyName
					exReq.Counterparty.Email = c.CounterpartyEmail
					exResp, err := exec.SendForSignature(r.Context(), contractID, exReq, r.Header.Get("Authorization"))
					if err != nil {
						httpx.WriteError(w, 502, "EXECUTION_ERROR", err.Error(), nil)
						return
					}
					_ = st.TransitionState(r.Context(), contractID, "SIGNATURE_SENT")
					_ = st.UpsertEnvelope(r.Context(), contractID, exResp.Provider, exResp.EnvelopeID, exResp.Status, exResp.SigningURL, exResp.Recipients)
					_ = st.AddEvent(r.Context(), contractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": exResp.EnvelopeID, "provider": exResp.Provider})
					resp := map[string]any{"request_id": httpx.NewRequestID(), "status": "DONE", "action": action, "state": "SIGNATURE_SENT"}
					if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
						return
					}
					return
				}

				// FORCE_HUMAN: require approval unless already approved.
				reqs, _ := st.ListApprovalRequests(r.Context(), contractID)
				approved := false
				for _, ar := range reqs {
					if ar["action"] == "SEND_FOR_SIGNATURE" && ar["status"] == "APPROVED" {
						approved = true
						break
					}
				}
				if !approved {
					aprq := "aprq_" + uuid.NewString()
					token := randomToken()
					tokenHash := hash(token)
					_ = st.CreateApprovalRequest(r.Context(), aprq, contractID, action, tokenHash, []string{"LEGAL"})
					_ = st.AddEvent(r.Context(), contractID, "APPROVAL_REQUESTED", req.ActorContext.ActorID, map[string]any{"approval_request_id": aprq, "action": action})
					resp := map[string]any{
						"request_id": httpx.NewRequestID(),
						"status":     "BLOCKED",
						"action":     action,
						"next_step": map[string]any{
							"type":                "APPROVE_ACTION",
							"reason":              "IDENTITY_GATE",
							"required_roles":      []string{"LEGAL"},
							"approval_request_id": aprq,
							"review_url":          fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s?token=%s", contractID, token),
						},
					}
					if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
						return
					}
					return
				}
				// Approved -> proceed to send-for-signature
				exReq := execclient.SendForSignatureRequest{
					TemplateID: c.TemplateID,
				}
				exReq.ActorContext.PrincipalID = req.ActorContext.PrincipalID
				exReq.ActorContext.ActorID = req.ActorContext.ActorID
				exReq.ActorContext.ActorType = req.ActorContext.ActorType
				exReq.Counterparty.Name = c.CounterpartyName
				exReq.Counterparty.Email = c.CounterpartyEmail
				exResp, err := exec.SendForSignature(r.Context(), contractID, exReq, r.Header.Get("Authorization"))
				if err != nil {
					httpx.WriteError(w, 502, "EXECUTION_ERROR", err.Error(), nil)
					return
				}
				_ = st.TransitionState(r.Context(), contractID, "SIGNATURE_SENT")
				_ = st.UpsertEnvelope(r.Context(), contractID, exResp.Provider, exResp.EnvelopeID, exResp.Status, exResp.SigningURL, exResp.Recipients)
				_ = st.AddEvent(r.Context(), contractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": exResp.EnvelopeID, "provider": exResp.Provider})
				resp := map[string]any{"request_id": httpx.NewRequestID(), "status": "DONE", "action": action, "state": "SIGNATURE_SENT"}
				if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
					return
				}
				return
			}

			// Other actions are stubs
			resp := map[string]any{"request_id": httpx.NewRequestID(), "status": "DONE", "action": action, "state": c.State}
			if ok := saveAndWriteIdempotentResponse(r.Context(), st, w, req.ActorContext, endpoint, 200, resp); !ok {
				return
			}
		})

		// Stubs validate/render
		api.Post("/contracts/{contract_id}:validate", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "risk_level": "LOW", "blocked": false, "required_roles": []string{}})
		})
		api.Post("/contracts/{contract_id}:render", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			hashes, err := computeAndPersistContractHashes(r.Context(), st, ial, contractID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"state":      "RENDERED",
				"artifacts":  []any{},
				"hashes": map[string]any{
					"packet_hash": hashes["packet_hash"],
					"diff_hash":   hashes["diff_hash"],
					"risk_hash":   hashes["risk_hash"],
				},
			})
		})
	})

	http.ListenAndServe(":"+port, r)
}

func findDef(defs []domain.VariableDefinition, key domain.VarKey) *domain.VariableDefinition {
	for i := range defs {
		if defs[i].Key == key {
			return &defs[i]
		}
	}
	return nil
}

func loadIdentityVarGov(ial *ialclient.Client, actorID string) domain.IdentityVariableGovernance {
	pp, err := ial.GetPolicyProfile(actorID)
	if err != nil || pp == nil {
		return domain.IdentityVariableGovernance{}
	}
	return policyProfileToVarGov(pp)
}

func resolveIdentityVarGovForEvaluation(ctx context.Context, st *store.Store, ial *ialclient.Client, principalID, callerType, callerActorID string) domain.IdentityVariableGovernance {
	pp := resolvePolicyProfileForEvaluation(ctx, st, ial, principalID, callerType, callerActorID)
	if pp == nil {
		return domain.IdentityVariableGovernance{}
	}
	return policyProfileToVarGov(pp)
}

func resolveActionGateForEvaluation(ctx context.Context, st *store.Store, ial *ialclient.Client, principalID, callerType, callerActorID, action, templateGate string) string {
	switch templateGate {
	case "ALLOW_AUTOMATION":
		return "ALLOW_AUTOMATION"
	case "FORCE_HUMAN":
		return "FORCE_HUMAN"
	case "DEFER":
		pp := resolvePolicyProfileForEvaluation(ctx, st, ial, principalID, callerType, callerActorID)
		if pp == nil {
			return "FORCE_HUMAN"
		}
		gate := pp.ActionGates[action]
		if gate == "ALLOW_AUTOMATION" {
			return "ALLOW_AUTOMATION"
		}
		return "FORCE_HUMAN"
	default:
		return "FORCE_HUMAN"
	}
}

func resolvePolicyProfileForEvaluation(ctx context.Context, st *store.Store, ial *ialclient.Client, principalID, callerType, callerActorID string) *ialclient.PolicyProfile {
	if callerType == "HUMAN" {
		pp, err := ial.GetPolicyProfile(callerActorID)
		if err == nil && pp != nil {
			return pp
		}
	}
	defaultActorID, defaultRole, err := st.GetPrincipalPolicyRouting(ctx, principalID)
	if err != nil {
		defaultRole = "LEGAL"
	}
	if defaultActorID != nil && *defaultActorID != "" {
		pp, err := ial.GetPolicyProfile(*defaultActorID)
		if err == nil && pp != nil {
			return pp
		}
	}
	approverActorID := resolveDefaultApproverActorID(ial, principalID, defaultRole)
	if approverActorID == "" {
		return nil
	}
	pp, err := ial.GetPolicyProfile(approverActorID)
	if err != nil || pp == nil {
		return nil
	}
	return pp
}

func resolveDefaultApproverActorID(ial *ialclient.Client, principalID, defaultRole string) string {
	if defaultRole == "" {
		defaultRole = "LEGAL"
	}
	actors, err := ial.ListActors(principalID, "HUMAN")
	if err != nil || len(actors) == 0 {
		return ""
	}
	for _, a := range actors {
		if a.Status == "ACTIVE" && hasRole(a.Roles, defaultRole) {
			return a.ActorID
		}
	}
	for _, a := range actors {
		if a.Status == "ACTIVE" {
			return a.ActorID
		}
	}
	return ""
}

func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func hasAnyRole(roles []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, rr := range required {
		if hasRole(roles, rr) {
			return true
		}
	}
	return false
}

func ptr[T any](v T) *T {
	return &v
}

func parseTemplateVersion(templateID string) string {
	s := strings.TrimSpace(templateID)
	if s == "" {
		return ""
	}
	idx := strings.LastIndex(s, "_")
	if idx == -1 || idx == len(s)-1 {
		return ""
	}
	v := s[idx+1:]
	if strings.HasPrefix(v, "v") {
		return v
	}
	return ""
}

func normalizeRenderFormat(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return "text"
	}
	if s == "text" || s == "html" {
		return s
	}
	return ""
}

func normalizeLocale(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return "en-US"
	}
	return s
}

func policyProfileToVarGov(pp *ialclient.PolicyProfile) domain.IdentityVariableGovernance {
	rules := []domain.IdentityVarRule{}
	for _, r := range pp.VariableRules {
		var pol string
		if p, ok := r["policy"].(string); ok {
			pol = p
		}
		varKeyAny, hasKey := r["for_key"]
		varTypeAny, hasType := r["for_type"]
		if hasKey {
			s, ok := varKeyAny.(string)
			if ok {
				k := domain.VarKey(s)
				rules = append(rules, domain.IdentityVarRule{ForKey: &k, Policy: domain.VarSetPolicy(pol)})
			}
		} else if hasType {
			s, ok := varTypeAny.(string)
			if ok {
				t := domain.VarType(s)
				rules = append(rules, domain.IdentityVarRule{ForType: &t, Policy: domain.VarSetPolicy(pol)})
			}
		}
	}
	return domain.IdentityVariableGovernance{Rules: rules}
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func replayIdempotentResponse(ctx context.Context, st *store.Store, w http.ResponseWriter, actor actorContext, endpoint string) bool {
	status, body, found, err := idempotency.Replay(ctx, st, idempotency.ActorContext{
		PrincipalID:    actor.PrincipalID,
		ActorID:        actor.ActorID,
		IdempotencyKey: actor.IdempotencyKey,
	}, endpoint)
	if err != nil {
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return true
	}
	if found {
		httpx.WriteJSON(w, status, body)
		return true
	}
	return false
}

func saveAndWriteIdempotentResponse(ctx context.Context, st *store.Store, w http.ResponseWriter, actor actorContext, endpoint string, status int, response map[string]any) bool {
	if err := idempotency.Save(ctx, st, idempotency.ActorContext{
		PrincipalID:    actor.PrincipalID,
		ActorID:        actor.ActorID,
		IdempotencyKey: actor.IdempotencyKey,
	}, endpoint, status, response); err != nil {
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return false
	}
	httpx.WriteJSON(w, status, response)
	return true
}

func buildContractEvidence(
	ctx context.Context,
	st *store.Store,
	ial *ialclient.Client,
	c store.Contract,
	gateKey, externalSubjectID string,
	subject *ialclient.Subject,
) (map[string]any, error) {
	hashes, err := st.GetContractHashes(ctx, c.ContractID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			hashes, err = computeAndPersistContractHashes(ctx, st, ial, c.ContractID)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	env, _ := st.GetEnvelope(ctx, c.ContractID)
	events, err := st.ListEvents(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	eventTypeCounts := map[string]int{}
	effectiveAt := ""
	lastEventAt := ""
	for _, e := range events {
		if typ, ok := e["type"].(string); ok {
			eventTypeCounts[typ]++
			if typ == "EFFECTIVE" {
				if at, ok := e["at"].(string); ok {
					effectiveAt = at
				}
			}
		}
		if at, ok := e["at"].(string); ok {
			lastEventAt = at
		}
	}
	acceptedBy := map[string]any{
		"mapped_actor_id":   "",
		"mapped_actor_type": "",
	}
	if subject != nil {
		acceptedBy["mapped_actor_id"] = subject.ActorID
		acceptedBy["mapped_actor_type"] = subject.ActorType
	}
	if externalSubjectID != "" {
		acceptedBy["external_subject_id"] = externalSubjectID
	}
	evidence := map[string]any{
		"gate_key": gateKey,
		"status":   c.State,
		"accepted": map[string]any{
			"when":                effectiveAt,
			"by":                  acceptedBy,
			"template_id":         c.TemplateID,
			"template_version":    c.TemplateVersion,
			"contract_id":         c.ContractID,
			"packet_hash":         hashes["packet_hash"],
			"diff_hash":           hashes["diff_hash"],
			"risk_hash":           hashes["risk_hash"],
			"signature_reference": env,
		},
		"event_trail_summary": map[string]any{
			"event_count":       len(events),
			"event_type_counts": eventTypeCounts,
			"last_event_at":     lastEventAt,
		},
		"references": map[string]any{
			"contract_evidence_url": fmt.Sprintf("/cel/contracts/%s/evidence", c.ContractID),
			"contract_events_url":   fmt.Sprintf("/cel/contracts/%s/events", c.ContractID),
			"evidence_bundle_url":   fmt.Sprintf("/cel/contracts/%s/evidence-bundle", c.ContractID),
		},
	}
	return evidence, nil
}

type evidenceIncludeSet struct {
	render     bool
	signatures bool
	approvals  bool
	events     bool
	variables  bool
}

func parseEvidenceIncludeFlags(raw string) (evidenceIncludeSet, error) {
	all := evidenceIncludeSet{render: true, signatures: true, approvals: true, events: true, variables: true}
	s := strings.TrimSpace(raw)
	if s == "" {
		return all, nil
	}
	out := evidenceIncludeSet{}
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(strings.ToLower(part))
		if p == "" {
			continue
		}
		switch p {
		case "render":
			out.render = true
		case "signatures":
			out.signatures = true
		case "approvals":
			out.approvals = true
		case "events":
			out.events = true
		case "variables":
			out.variables = true
		default:
			return evidenceIncludeSet{}, fmt.Errorf("invalid include flag: %s", p)
		}
	}
	return out, nil
}

func buildContractEvidenceBundle(
	ctx context.Context,
	st *store.Store,
	ial *ialclient.Client,
	c store.Contract,
	include evidenceIncludeSet,
	redact string,
) (map[string]any, error) {
	hashes, err := st.GetContractHashes(ctx, c.ContractID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			hashes, err = computeAndPersistContractHashes(ctx, st, ial, c.ContractID)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	contractRecord := map[string]any{
		"contract_id":         c.ContractID,
		"principal_id":        c.PrincipalID,
		"template_id":         c.TemplateID,
		"template_version":    c.TemplateVersion,
		"state":               c.State,
		"risk_level":          c.RiskLevel,
		"counterparty_name":   c.CounterpartyName,
		"counterparty_email":  c.CounterpartyEmail,
		"created_by_actor_id": c.CreatedBy,
		"created_at":          c.CreatedAt.UTC().Format(time.RFC3339),
	}
	if redact == "pii" {
		contractRecord["counterparty_email"] = "REDACTED"
	}

	tpl, err := st.GetTemplate(ctx, c.TemplateID)
	if err != nil {
		return nil, err
	}
	defs, err := st.GetTemplateVars(ctx, c.TemplateID)
	if err != nil {
		return nil, err
	}
	vars, err := st.GetVariables(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	varSnapshot := map[string]string{}
	for _, v := range vars {
		varSnapshot[string(v.Key)] = v.Value
	}
	variablesHash, _, err := render.HashVariablesSnapshot(varSnapshot)
	if err != nil {
		return nil, err
	}

	templateVersion := ""
	if c.TemplateVersion != nil {
		templateVersion = *c.TemplateVersion
	}
	templateText := render.BuildCanonicalTemplateText(render.TemplateSpec{
		TemplateID:      c.TemplateID,
		TemplateVersion: templateVersion,
		DisplayName:     tpl.DisplayName,
		Variables:       defs,
	})
	renderedText, missing, err := render.Render(templateText, varSnapshot, defs, "text")
	if err != nil {
		return nil, err
	}
	renderArtifact := map[string]any{
		"format":              "text",
		"locale":              "en-US",
		"rendered":            renderedText,
		"render_hash":         render.HashRendered(renderedText),
		"determinism_version": render.DeterminismVersion,
	}
	if len(missing) > 0 {
		renderArtifact["rendered"] = ""
		renderArtifact["render_hash"] = render.HashRendered("")
		renderArtifact["missing_required_keys"] = missing
	}

	artifacts := map[string]any{
		"contract_record": contractRecord,
	}
	if include.variables {
		artifacts["variables_snapshot"] = map[string]any{
			"variables":      varSnapshot,
			"variables_hash": variablesHash,
		}
	}
	if include.render {
		artifacts["render"] = renderArtifact
	}
	if include.approvals {
		reqs, err := st.ListApprovalRequestsForEvidence(ctx, c.ContractID)
		if err != nil {
			return nil, err
		}
		decisions, err := st.ListApprovalDecisionsForEvidence(ctx, c.ContractID)
		if err != nil {
			return nil, err
		}
		artifacts["approval_requests"] = reqs
		artifacts["approval_decisions"] = decisions
	}
	if include.signatures {
		envs, err := st.ListSignatureEnvelopesForEvidence(ctx, c.ContractID)
		if err != nil {
			return nil, err
		}
		artifacts["signature_envelopes"] = envs
	}
	if include.events {
		evs, err := st.ListEvents(ctx, c.ContractID)
		if err != nil {
			return nil, err
		}
		artifacts["contract_events"] = evs
	}
	commerceIntents, err := st.ListCommerceIntentsForEvidence(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	if len(commerceIntents) > 0 {
		artifacts["commerce_intents"] = commerceIntents
	}
	commerceAccepts, err := st.ListCommerceAcceptsForEvidence(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	if len(commerceAccepts) > 0 {
		artifacts["commerce_accepts"] = commerceAccepts
	}
	idem, err := st.ListIdempotencyRecordsForContract(ctx, c.PrincipalID, c.ContractID)
	if err != nil {
		return nil, err
	}
	artifacts["idempotency"] = idem
	delegations, err := st.ListActiveDelegationsForEvidence(ctx, c.PrincipalID)
	if err != nil {
		return nil, err
	}
	artifacts["delegation_records"] = delegations
	revocationRows, err := st.ListCommerceDelegationRevocationsForAuthorization(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	artifacts["delegation_revocations"] = normalizeDelegationRevocationsForEvidence(revocationRows)
	webhookReceipts, err := st.ListVerifiedWebhookReceiptsForContractEvidence(ctx, c.PrincipalID, c.ContractID)
	if err != nil {
		return nil, err
	}
	artifacts["webhook_receipts"] = webhookReceipts
	anchors, err := st.ListAnchorsForContractEvidence(ctx, c.PrincipalID, c.ContractID)
	if err != nil {
		return nil, err
	}
	artifacts["anchors"] = anchors

	artifactList := make([]map[string]any, 0, len(artifacts))
	for artifactType, payload := range artifacts {
		hash, b, err := canonicalSHA256(payload)
		if err != nil {
			return nil, err
		}
		contentType := "application/json"
		if artifactType == "render" {
			contentType = "text/plain; charset=utf-8"
			rendered := fmt.Sprint(renderArtifact["rendered"])
			hash = render.HashRendered(rendered)
			b = []byte(rendered)
			_ = b
		}
		hashOf, hashRule := artifactHashSpec(artifactType)
		artifactList = append(artifactList, map[string]any{
			"artifact_type": artifactType,
			"artifact_id":   artifactIDForType(artifactType, c.ContractID),
			"sha256":        hash,
			"content_type":  contentType,
			"hash_of":       hashOf,
			"hash_rule":     hashRule,
		})
	}
	sort.Slice(artifactList, func(i, j int) bool {
		ti := fmt.Sprint(artifactList[i]["artifact_type"])
		tj := fmt.Sprint(artifactList[j]["artifact_type"])
		if ti != tj {
			return ti < tj
		}
		return fmt.Sprint(artifactList[i]["artifact_id"]) < fmt.Sprint(artifactList[j]["artifact_id"])
	})
	if err := validateEvidenceManifestCoverage(artifacts, artifactList); err != nil {
		return nil, err
	}

	manifest := map[string]any{
		"canonicalization": map[string]any{
			"json":               "JCS-like sorted keys",
			"newlines":           "\\n",
			"encoding":           "utf-8",
			"bundle_v":           "evidence-v1",
			"manifest_hash_rule": "canonical_json_sorted_keys_v1",
			"bundle_hash_rule":   "concat_artifact_hashes_v1",
		},
		"artifacts": artifactList,
	}
	manifestHash, _, err := evidencehash.CanonicalSHA256(manifest)
	if err != nil {
		return nil, err
	}
	bundleHash := evidencehash.ComputeBundleHashFromManifest("evidence-v1", c.ContractID, fmt.Sprint(hashes["packet_hash"]), artifactList)

	return map[string]any{
		"bundle_version": "evidence-v1",
		"generated_at":   c.CreatedAt.UTC().Format(time.RFC3339),
		"principal_id":   c.PrincipalID,
		"contract": map[string]any{
			"contract_id":         c.ContractID,
			"state":               c.State,
			"template_id":         c.TemplateID,
			"template_version":    c.TemplateVersion,
			"packet_hash":         hashes["packet_hash"],
			"diff_hash":           hashes["diff_hash"],
			"risk_hash":           hashes["risk_hash"],
			"variables_hash":      variablesHash,
			"determinism_version": "evidence-v1",
		},
		"hashes": map[string]any{
			"bundle_hash":   "sha256:" + bundleHash,
			"manifest_hash": "sha256:" + manifestHash,
		},
		"manifest":  manifest,
		"artifacts": artifacts,
	}, nil
}

func artifactIDForType(artifactType, contractID string) string {
	switch artifactType {
	case "contract_record":
		return "contract:" + contractID
	case "render":
		return "render:text"
	case "variables_snapshot":
		return "variables:snapshot"
	case "approval_requests":
		return "approvals:requests"
	case "approval_decisions":
		return "approvals:decisions"
	case "signature_envelopes":
		return "signatures:envelopes"
	case "contract_events":
		return "events:contract"
	case "idempotency":
		return "idempotency:records"
	case "commerce_intents":
		return "commerce_intents.json"
	case "commerce_accepts":
		return "commerce_accepts.json"
	case "delegation_records":
		return "delegations:active"
	case "delegation_revocations":
		return "delegation_revocations.json"
	case "webhook_receipts":
		return "webhook_receipts.json"
	case "anchors":
		return "anchors.json"
	default:
		return artifactType
	}
}

func artifactHashSpec(artifactType string) (hashOf, hashRule string) {
	switch artifactType {
	case "render":
		return "artifacts.render.rendered", "utf8_v1"
	default:
		return "artifacts." + artifactType, "canonical_json_sorted_keys_v1"
	}
}

func validateEvidenceManifestCoverage(artifacts map[string]any, artifactList []map[string]any) error {
	covered := make(map[string]struct{}, len(artifactList))
	for _, descriptor := range artifactList {
		artifactType := strings.TrimSpace(fmt.Sprint(descriptor["artifact_type"]))
		if artifactType == "" {
			return errors.New("artifact descriptor missing artifact_type")
		}
		if _, ok := artifacts[artifactType]; !ok {
			return fmt.Errorf("artifact descriptor references unknown artifact_type: %s", artifactType)
		}
		if _, exists := covered[artifactType]; exists {
			return fmt.Errorf("duplicate artifact descriptor for artifact_type: %s", artifactType)
		}
		hashOf := strings.TrimSpace(fmt.Sprint(descriptor["hash_of"]))
		hashRule := strings.TrimSpace(fmt.Sprint(descriptor["hash_rule"]))
		if hashOf == "" || hashRule == "" {
			return fmt.Errorf("artifact descriptor missing hash metadata for artifact_type: %s", artifactType)
		}
		expectedHashOf, expectedHashRule := artifactHashSpec(artifactType)
		if hashOf != expectedHashOf || hashRule != expectedHashRule {
			return fmt.Errorf("artifact descriptor hash metadata mismatch for artifact_type: %s", artifactType)
		}
		covered[artifactType] = struct{}{}
	}
	for artifactType := range artifacts {
		if _, ok := covered[artifactType]; !ok {
			return fmt.Errorf("artifact missing manifest descriptor: %s", artifactType)
		}
	}
	return nil
}

func computeBundleHashFromManifest(bundleVersion, contractID, packetHash string, artifacts []map[string]any) string {
	return evidencehash.ComputeBundleHashFromManifest(bundleVersion, contractID, packetHash, artifacts)
}

func canonicalSHA256(v any) (hexHash string, bytes []byte, err error) {
	return evidencehash.CanonicalSHA256(v)
}

func ensureGateContractAndSignature(
	ctx context.Context,
	st *store.Store,
	exec *execclient.Client,
	gateKey, principalID, callerActorID, subjectActorID, templateID, templateVersion, authHeader string,
) (string, string, error) {
	c, err := st.FindLatestGateContractForSubjectVersion(ctx, principalID, gateKey, subjectActorID, templateID, templateVersion)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
		c = store.Contract{
			ContractID:      "ctr_" + uuid.NewString(),
			PrincipalID:     principalID,
			TemplateID:      templateID,
			TemplateVersion: ptr(templateVersion),
			SubjectActorID:  ptr(subjectActorID),
			GateKey:         ptr(gateKey),
			State:           "DRAFT_CREATED",
			RiskLevel:       "LOW",
			CreatedBy:       callerActorID,
			CreatedAt:       time.Now(),
		}
		if err := st.CreateContract(ctx, c); err != nil {
			// Handle concurrent create-once race by re-reading.
			if !strings.Contains(strings.ToLower(err.Error()), "duplicate") && !strings.Contains(strings.ToLower(err.Error()), "unique") {
				return "", "", err
			}
			c, err = st.FindLatestGateContractForSubjectVersion(ctx, principalID, gateKey, subjectActorID, templateID, templateVersion)
			if err != nil {
				return "", "", err
			}
		} else {
			_ = st.AddEvent(ctx, c.ContractID, "CREATED", callerActorID, map[string]any{"gate_key": gateKey})
		}
	}

	if c.State == "EFFECTIVE" {
		return c.ContractID, "", nil
	}
	if c.State == "SIGNATURE_SENT" || c.State == "SIGNED_BY_US" || c.State == "SIGNED_BY_THEM" {
		env, err := st.GetEnvelope(ctx, c.ContractID)
		if err == nil {
			if u, ok := env["signing_url"].(*string); ok && u != nil {
				return c.ContractID, *u, nil
			}
		}
	}

	exReq := execclient.SendForSignatureRequest{TemplateID: c.TemplateID}
	exReq.ActorContext.PrincipalID = principalID
	exReq.ActorContext.ActorID = callerActorID
	exReq.ActorContext.ActorType = "AGENT"
	exReq.Counterparty.Name = c.CounterpartyName
	exReq.Counterparty.Email = c.CounterpartyEmail
	exResp, err := exec.SendForSignature(ctx, c.ContractID, exReq, authHeader)
	if err != nil {
		return "", "", err
	}
	if err := st.TransitionState(ctx, c.ContractID, "SIGNATURE_SENT"); err != nil {
		return "", "", err
	}
	if err := st.UpsertEnvelope(ctx, c.ContractID, exResp.Provider, exResp.EnvelopeID, exResp.Status, exResp.SigningURL, exResp.Recipients); err != nil {
		return "", "", err
	}
	_ = st.AddEvent(ctx, c.ContractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": exResp.EnvelopeID, "provider": exResp.Provider, "gate_key": gateKey})
	return c.ContractID, exResp.SigningURL, nil
}

func computeAndPersistContractHashes(ctx context.Context, st *store.Store, ial *ialclient.Client, contractID string) (map[string]any, error) {
	c, err := st.GetContract(ctx, contractID)
	if err != nil {
		return nil, err
	}
	t, err := st.GetTemplate(ctx, c.TemplateID)
	if err != nil {
		return nil, err
	}
	tpl := map[string]any{
		"template_id":   t.TemplateID,
		"contract_type": t.ContractType,
		"jurisdiction":  t.Jurisdiction,
		"display_name":  t.DisplayName,
		"risk_tier":     t.RiskTier,
	}
	tplVars, err := st.GetTemplateVars(ctx, c.TemplateID)
	if err != nil {
		return nil, err
	}
	gates, err := st.GetTemplateGates(ctx, c.TemplateID)
	if err != nil {
		return nil, err
	}
	vars, err := st.GetVariables(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	approvals, err := st.ListApprovalRequestsForHash(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	approvalDecisions, err := st.ListApprovalDecisionsForHash(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	events, err := st.ListEventsForHash(ctx, c.ContractID)
	if err != nil {
		return nil, err
	}
	for i := range events {
		events[i]["payload"] = normalizeEventPayload(events[i]["payload"])
	}

	idGov := resolveIdentityVarGovForEvaluation(ctx, st, ial, c.PrincipalID, "AGENT", c.CreatedBy)
	effectiveVarPolicies := make([]map[string]any, 0, len(tplVars))
	templateVars := make([]map[string]any, 0, len(tplVars))
	for _, v := range tplVars {
		templateVars = append(templateVars, map[string]any{
			"key":         string(v.Key),
			"type":        string(v.Type),
			"required":    v.Required,
			"sensitivity": string(v.Sensitivity),
			"set_policy":  string(v.SetPolicy),
		})
		effectiveVarPolicies = append(effectiveVarPolicies, map[string]any{
			"key":              string(v.Key),
			"template_policy":  string(v.SetPolicy),
			"effective_policy": string(domain.EffectiveVarSetPolicy(v, idGov)),
		})
	}
	sort.Slice(templateVars, func(i, j int) bool { return fmt.Sprint(templateVars[i]["key"]) < fmt.Sprint(templateVars[j]["key"]) })
	sort.Slice(effectiveVarPolicies, func(i, j int) bool {
		return fmt.Sprint(effectiveVarPolicies[i]["key"]) < fmt.Sprint(effectiveVarPolicies[j]["key"])
	})

	contractVars := make([]map[string]any, 0, len(vars))
	for _, v := range vars {
		contractVars = append(contractVars, map[string]any{
			"key":           string(v.Key),
			"value":         v.Value,
			"source":        string(v.Source),
			"review_status": string(v.ReviewStatus),
		})
	}
	sort.Slice(contractVars, func(i, j int) bool { return fmt.Sprint(contractVars[i]["key"]) < fmt.Sprint(contractVars[j]["key"]) })

	resolvedActionGate := resolveActionGateForEvaluation(ctx, st, ial, c.PrincipalID, "AGENT", c.CreatedBy, "SEND_FOR_SIGNATURE", gates["SEND_FOR_SIGNATURE"])
	packetInput := map[string]any{
		"template_snapshot": map[string]any{
			"template":       tpl,
			"template_gates": gates,
			"variables":      templateVars,
		},
		"governance": map[string]any{
			"resolved_action_gates": map[string]any{
				"SEND_FOR_SIGNATURE": resolvedActionGate,
			},
			"resolved_variable_policies": effectiveVarPolicies,
		},
		"variables":          contractVars,
		"approvals":          approvals,
		"approval_decisions": approvalDecisions,
		"event_log":          events,
	}
	diffInput := map[string]any{
		"state":     c.State,
		"approvals": approvals,
		"variables": contractVars,
	}
	riskInput := map[string]any{
		"risk_level": c.RiskLevel,
		"state":      c.State,
		"approvals":  approvals,
	}
	packetHash, _, err := canonhash.SumObject(packetInput)
	if err != nil {
		return nil, err
	}
	diffHash, _, err := canonhash.SumObject(diffInput)
	if err != nil {
		return nil, err
	}
	riskHash, _, err := canonhash.SumObject(riskInput)
	if err != nil {
		return nil, err
	}
	if err := st.SaveContractHashes(ctx, c.ContractID, packetInput, diffInput, riskInput, packetHash, diffHash, riskHash); err != nil {
		return nil, err
	}
	return map[string]any{
		"packet_hash":  packetHash,
		"diff_hash":    diffHash,
		"risk_hash":    riskHash,
		"packet_input": packetInput,
		"diff_input":   diffInput,
		"risk_input":   riskInput,
	}, nil
}

func normalizeEventPayload(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			if k == "approval_request_id" || k == "envelope_id" || k == "request_id" || k == "token" {
				continue
			}
			out[k] = normalizeEventPayload(vv)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, vv := range x {
			out = append(out, normalizeEventPayload(vv))
		}
		return out
	default:
		return v
	}
}

func performRFC3161Anchor(ctx context.Context, targetHash string, requestPayload map[string]any) (status string, proof map[string]any, anchoredAt *time.Time) {
	now := time.Now().UTC()
	status = "FAILED"
	proof = map[string]any{}

	tsaURL := ""
	if raw, ok := requestPayload["tsa_url"].(string); ok {
		tsaURL = strings.TrimSpace(raw)
	}
	if tsaURL == "" {
		tsaURL = strings.TrimSpace(os.Getenv("RFC3161_TSA_URL"))
	}
	if tsaURL == "" {
		proof["error_code"] = "TSA_URL_REQUIRED"
		return status, proof, nil
	}
	if !isAllowedTSAURL(tsaURL, os.Getenv("RFC3161_TSA_ALLOWLIST")) {
		proof["error_code"] = "TSA_URL_NOT_ALLOWED"
		return status, proof, nil
	}

	policyOID := ""
	if raw, ok := requestPayload["policy_oid"].(string); ok {
		policyOID = strings.TrimSpace(raw)
	}
	reqDER, err := anchorrfc3161.BuildTimeStampRequestFromHashHex(targetHash, policyOID)
	if err != nil {
		proof["error_code"] = "INVALID_TARGET_HASH"
		return status, proof, nil
	}
	client := anchorrfc3161.NewClient(nil)
	tokenBytes, contentType, err := client.RequestTimestampToken(ctx, tsaURL, reqDER)
	if err != nil {
		errCode := "TSA_REQUEST_FAILED"
		if strings.HasPrefix(err.Error(), "tsa_http_status_") {
			errCode = "TSA_HTTP_STATUS"
		} else if err.Error() == "tsa_empty_response" {
			errCode = "TSA_EMPTY_RESPONSE"
		}
		proof["error_code"] = errCode
		return status, proof, nil
	}

	status = "CONFIRMED"
	anchoredAt = &now
	proof["rfc3161"] = true
	proof["target_hash"] = targetHash
	proof["timestamp_token_b64"] = base64.StdEncoding.EncodeToString(tokenBytes)
	if contentType != "" {
		proof["content_type"] = contentType
	}
	return status, proof, anchoredAt
}

func isAllowedTSAURL(url, allowlistRaw string) bool {
	allowlistRaw = strings.TrimSpace(allowlistRaw)
	if allowlistRaw == "" {
		return true
	}
	for _, p := range strings.Split(allowlistRaw, ",") {
		if strings.TrimSpace(p) == url {
			return true
		}
	}
	return false
}

func normalizeHexHash(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	s = strings.TrimPrefix(s, "sha256:")
	if s == "" {
		return ""
	}
	if s != strings.ToLower(s) {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return ""
	}
	return s
}

func signatureEnvelopeToMap(env signaturev1.EnvelopeV1) map[string]any {
	out := map[string]any{
		"version":      env.Version,
		"algorithm":    env.Algorithm,
		"public_key":   env.PublicKey,
		"signature":    env.Signature,
		"payload_hash": env.PayloadHash,
		"issued_at":    env.IssuedAt,
	}
	if strings.TrimSpace(env.KeyID) != "" {
		out["key_id"] = env.KeyID
	}
	if strings.TrimSpace(env.Context) != "" {
		out["context"] = env.Context
	}
	return out
}

func requireAgentScope(r *http.Request, w http.ResponseWriter, pool *pgxpool.Pool, actor actorContext, endpoint, requiredScope string) bool {
	if actor.ActorType != "AGENT" {
		return true
	}
	agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
	if err != nil {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, actor.PrincipalID, actor.ActorID, "UNAUTHORIZED", map[string]any{"required_scope": requiredScope})
		httpx.WriteError(w, 401, "UNAUTHORIZED", "agent authentication required", nil)
		return false
	}
	if agent.ActorID != actor.ActorID || agent.PrincipalID != actor.PrincipalID {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, actor.PrincipalID, actor.ActorID, "ACTOR_MISMATCH", map[string]any{"required_scope": requiredScope})
		httpx.WriteError(w, 403, "FORBIDDEN", "token actor does not match actor_context", nil)
		return false
	}
	dctx, hasDelegationContext, err := delegationContextForEndpoint(r.Context(), pool, endpoint, actor.PrincipalID)
	if err != nil {
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return false
	}
	allowed, delegated, err := authn.HasScopeOrDelegation(r.Context(), pool, agent, requiredScope, dctx)
	if err != nil {
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return false
	}
	if !allowed {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, actor.PrincipalID, actor.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": requiredScope})
		httpx.WriteError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", map[string]any{"required_scope": requiredScope})
		return false
	}
	if delegated {
		details := map[string]any{
			"required_scope": requiredScope,
			"capability":     dctx.Capability,
		}
		if hasDelegationContext {
			details["template_id"] = dctx.TemplateID
			details["risk_level"] = dctx.RiskLevel
		}
		authn.LogAuthEvent(r.Context(), pool, "cel", endpoint, actor.PrincipalID, actor.ActorID, "DELEGATION_USED", details)
	}
	return true
}

func requireBearerAgentScope(r *http.Request, w http.ResponseWriter, pool *pgxpool.Pool, endpoint, requiredScope string) (*authn.AgentIdentity, bool) {
	agent, err := authn.AuthenticateAgentBearer(r.Context(), pool, r.Header.Get("Authorization"))
	if err != nil {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, "", "", "UNAUTHORIZED", map[string]any{"required_scope": requiredScope})
		writeStandardError(w, 401, "UNAUTHORIZED", "agent authentication required", "")
		return nil, false
	}
	allowed, delegated, err := authn.HasScopeOrDelegation(r.Context(), pool, agent, requiredScope, authn.DelegationContext{})
	if err != nil {
		writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
		return nil, false
	}
	if !allowed {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, agent.PrincipalID, agent.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": requiredScope})
		writeStandardError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", "")
		return nil, false
	}
	if delegated {
		authn.LogAuthEvent(r.Context(), pool, "cel", endpoint, agent.PrincipalID, agent.ActorID, "DELEGATION_USED", map[string]any{"required_scope": requiredScope})
	}
	return agent, true
}

func commerceAuthorizationRequired(c store.Contract) bool {
	return strings.EqualFold(strings.TrimSpace(c.RiskLevel), "HIGH")
}

func contractSnapshotForProof(c store.Contract) map[string]any {
	return map[string]any{
		"contract_id":      c.ContractID,
		"state":            c.State,
		"template_id":      c.TemplateID,
		"template_version": c.TemplateVersion,
	}
}

func contractExportForProofBundle(c store.Contract) clsdk.ContractExportV1 {
	out := clsdk.ContractExportV1{
		ContractID:  c.ContractID,
		PrincipalID: c.PrincipalID,
		TemplateID:  c.TemplateID,
		State:       c.State,
		RiskLevel:   c.RiskLevel,
	}
	if c.TemplateVersion != nil {
		out.TemplateVersion = *c.TemplateVersion
	}
	if c.GateKey != nil {
		out.GateKey = *c.GateKey
	}
	return out
}

func proofRequirementsForContract(c store.Contract) map[string]any {
	return map[string]any{
		"authorization_required": commerceAuthorizationRequired(c),
		"required_scopes": map[string]any{
			"commerce_intent": clsdk.DelegationScopeCommerceIntentSign,
			"commerce_accept": clsdk.DelegationScopeCommerceAcceptSign,
		},
		"settlement_required_status": "PAID",
	}
}

func commerceTrustAgents() []string {
	raw := strings.TrimSpace(os.Getenv("COMMERCE_TRUST_AGENTS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func evaluateHostedCommerceAuthorization(
	required bool,
	scope, signingAgent, counterpartyAgent, contractID, issuedAtUTC string,
	amount *clsdk.CommerceAmountV1,
	delegations []map[string]any,
	revocations []map[string]any,
	trustAgents []string,
) (bool, string) {
	if !required {
		return true, ""
	}
	decision := clsdk.EvaluateDelegationDecision(clsdk.DelegationDecisionInput{
		RequiredScope:     scope,
		SigningAgent:      signingAgent,
		CounterpartyAgent: counterpartyAgent,
		ContractID:        contractID,
		IssuedAtUTC:       issuedAtUTC,
		PaymentAmount:     amount,
		Delegations:       toAnySliceMaps(delegations),
		Revocations:       toAnySliceMaps(revocations),
		TrustAgents:       trustAgents,
	})
	if decision.OK {
		return true, ""
	}
	return false, decision.FailureReason
}

func toAnySliceMaps(xs []map[string]any) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func normalizeDelegationRevocationsForEvidence(rows []map[string]any) []map[string]any {
	if len(rows) == 0 {
		return []map[string]any{}
	}
	type revRow struct {
		hash string
		row  map[string]any
	}
	byHash := map[string]revRow{}
	for _, row := range rows {
		revAny, ok := row["revocation"]
		if !ok {
			continue
		}
		rev, err := clsdk.ParseDelegationRevocationV1Strict(revAny)
		if err != nil {
			continue
		}
		h, err := clsdk.HashDelegationRevocationV1(rev)
		if err != nil {
			continue
		}
		if _, exists := byHash[h]; exists {
			continue
		}
		sigMap, _ := row["issuer_signature"].(map[string]any)
		out := map[string]any{
			"revocation_hash": h,
			"revocation": map[string]any{
				"version":       rev.Version,
				"revocation_id": rev.RevocationID,
				"delegation_id": rev.DelegationID,
				"issuer_agent":  rev.IssuerAgent,
				"nonce":         rev.Nonce,
				"issued_at":     rev.IssuedAt,
			},
			"issuer_signature": sigMap,
		}
		if strings.TrimSpace(rev.Reason) != "" {
			out["revocation"].(map[string]any)["reason"] = rev.Reason
		}
		byHash[h] = revRow{hash: h, row: out}
	}
	if len(byHash) == 0 {
		return []map[string]any{}
	}
	hashes := make([]string, 0, len(byHash))
	for h := range byHash {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	out := make([]map[string]any, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, byHash[h].row)
	}
	return out
}

func contractRulesV1FromEnv() (*clsdk.RulesV1, error) {
	raw := strings.TrimSpace(os.Getenv("CEL_RULES_V1_JSON"))
	if raw == "" {
		return nil, nil
	}
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("invalid CEL_RULES_V1_JSON: %w", err)
	}
	rules, err := clsdk.ParseRulesV1Strict(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid CEL_RULES_V1_JSON: %w", err)
	}
	return &rules, nil
}

func buildRulesArtifactsFromContractEvents(ctx context.Context, st *store.Store, contractID string) (map[string]any, error) {
	events, err := st.ListEvents(ctx, contractID)
	if err != nil {
		return nil, err
	}
	settlement := make([]any, 0)
	for _, ev := range events {
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(ev["type"])), "SETTLEMENT_ATTESTATION") {
			continue
		}
		switch payload := ev["payload"].(type) {
		case map[string]any:
			settlement = append(settlement, payload)
		case []any:
			for _, item := range payload {
				if m, ok := item.(map[string]any); ok {
					settlement = append(settlement, m)
				}
			}
		}
	}
	return map[string]any{
		"settlement_attestations": settlement,
	}, nil
}

func evaluateActionTransitionRulesV1(c store.Contract, action string, artifacts map[string]any, trustAgents []string) (permitted bool, ruleID, fromState, toState string, err error) {
	rules, err := contractRulesV1FromEnv()
	if err != nil {
		return false, "", "", "", err
	}
	if rules == nil {
		return true, "", "", "", nil
	}
	fromState, toState, ok := inferActionTransition(c.State, action)
	if !ok {
		return true, "", "", "", nil
	}
	res, err := clsdk.EvaluateRulesV1(*rules, clsdk.RulesEvaluationInput{
		ContractID:     c.ContractID,
		ContractState:  c.State,
		TransitionFrom: fromState,
		TransitionTo:   toState,
		Artifacts:      artifacts,
		TrustAgents:    trustAgents,
	})
	if err != nil {
		return false, "", fromState, toState, err
	}
	for _, rr := range res.RuleResults {
		for _, eff := range rr.Effects {
			if eff.Type != "permit_transition" {
				continue
			}
			if strings.TrimSpace(eff.From) != fromState || strings.TrimSpace(eff.To) != toState {
				continue
			}
			if eff.Permitted != nil && !*eff.Permitted {
				return false, rr.RuleID, fromState, toState, nil
			}
		}
	}
	return true, "", fromState, toState, nil
}

func inferActionTransition(currentState, action string) (fromState, toState string, ok bool) {
	fromState = strings.TrimSpace(currentState)
	act := strings.ToUpper(strings.TrimSpace(action))
	if fromState == "" || act == "" {
		return "", "", false
	}
	if act == "SEND_FOR_SIGNATURE" {
		return fromState, "SIGNATURE_SENT", true
	}
	switch act {
	case "DRAFT_CREATED", "POLICY_VALIDATED", "RENDERED", "READY_TO_SIGN", "SIGNATURE_SENT", "SIGNED_BY_US", "SIGNED_BY_THEM", "EFFECTIVE", "ARCHIVED":
		return fromState, act, true
	default:
		return "", "", false
	}
}

func commerceIntentSubmissionMaps(intent clsdk.CommerceIntentV1, sig clsdk.SigV1Envelope) (map[string]any, map[string]any, error) {
	intentB, err := json.Marshal(intent)
	if err != nil {
		return nil, nil, err
	}
	sigB, err := json.Marshal(sig)
	if err != nil {
		return nil, nil, err
	}
	var intentMap map[string]any
	var sigMap map[string]any
	if err := json.Unmarshal(intentB, &intentMap); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(sigB, &sigMap); err != nil {
		return nil, nil, err
	}
	return intentMap, sigMap, nil
}

func commerceAcceptSubmissionMaps(acc clsdk.CommerceAcceptV1, sig clsdk.SigV1Envelope) (map[string]any, map[string]any, error) {
	accB, err := json.Marshal(acc)
	if err != nil {
		return nil, nil, err
	}
	sigB, err := json.Marshal(sig)
	if err != nil {
		return nil, nil, err
	}
	var accMap map[string]any
	var sigMap map[string]any
	if err := json.Unmarshal(accB, &accMap); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(sigB, &sigMap); err != nil {
		return nil, nil, err
	}
	return accMap, sigMap, nil
}

func delegationContextForEndpoint(ctx context.Context, pool *pgxpool.Pool, endpoint, principalID string) (authn.DelegationContext, bool, error) {
	parts := strings.Split(endpoint, "/")
	// Expected endpoint shape: POST /cel/contracts/{contract_id}/actions/{action}
	if len(parts) >= 6 && parts[1] == "cel" && parts[2] == "contracts" && parts[4] == "actions" {
		contractID := strings.TrimSpace(parts[3])
		var templateID string
		var riskLevel string
		err := pool.QueryRow(ctx, `
SELECT template_id,risk_level
FROM contracts
WHERE contract_id=$1 AND principal_id=$2
`, contractID, principalID).Scan(&templateID, &riskLevel)
		if err == nil {
			return authn.DelegationContext{
				Capability: "contract.execute",
				TemplateID: templateID,
				RiskLevel:  riskLevel,
			}, true, nil
		}
		// Treat missing contract metadata as no delegation context.
		return authn.DelegationContext{}, false, nil
	}
	return authn.DelegationContext{}, false, nil
}
