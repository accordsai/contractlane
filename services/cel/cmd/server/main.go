package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"contractlane/pkg/authn"
	"contractlane/pkg/canonhash"
	"contractlane/pkg/db"
	"contractlane/pkg/domain"
	"contractlane/pkg/httpx"
	"contractlane/services/cel/internal/execclient"
	"contractlane/services/cel/internal/ialclient"
	"contractlane/services/cel/internal/idempotency"
	"contractlane/services/cel/internal/store"

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

	r.Route("/cel", func(api chi.Router) {

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
			templates, err := st.ListTemplates(r.Context(), ct, j)
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
			if err := st.EnableTemplate(r.Context(), principalID, templateID, req.EnabledByActorID, req.OverrideGates); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "enabled": true, "principal_id": principalID, "template_id": templateID})
		})

		api.Get("/templates/{template_id}/governance", func(w http.ResponseWriter, r *http.Request) {
			templateID := chi.URLParam(r, "template_id")
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
			if !authn.HasScope(agent.Scopes, "cel.contracts:write") {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"gate_key":   gateKey,
					"status":     "REJECTED",
					"reason":     "INSUFFICIENT_SCOPE",
				})
				return
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
			externalSubjectID := ""
			var subject *ialclient.Subject
			if c.SubjectActorID != nil && *c.SubjectActorID != "" {
				// Best-effort reverse lookup through gate endpoint semantics is not supported; return mapped actor only.
				subject = &ialclient.Subject{
					PrincipalID: c.PrincipalID,
					ActorID:     *c.SubjectActorID,
				}
			}
			gateKey := ""
			if c.GateKey != nil {
				gateKey = *c.GateKey
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
			c := store.Contract{
				ContractID:        "ctr_" + uuid.NewString(),
				PrincipalID:       req.ActorContext.PrincipalID,
				TemplateID:        req.TemplateID,
				TemplateVersion:   ptr(parseTemplateVersion(req.TemplateID)),
				SubjectActorID:    ptr(req.ActorContext.ActorID),
				State:             "DRAFT_CREATED",
				RiskLevel:         "LOW",
				CounterpartyName:  req.Counterparty.Name,
				CounterpartyEmail: req.Counterparty.Email,
				CreatedBy:         req.ActorContext.ActorID,
				CreatedAt:         time.Now(),
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
				ActorContext  actorContext   `json:"actor_context"`
				Decision      string         `json:"decision"`
				SignedPayload map[string]any `json:"signed_payload"`
				Signature     map[string]any `json:"signature"`
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
			valid, err := ial.VerifySignature(req.ActorContext.PrincipalID, req.ActorContext.ActorID, r.Header.Get("Authorization"))
			if err != nil || !valid {
				httpx.WriteError(w, 403, "BAD_SIGNATURE", "signature verification failed", nil)
				return
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
				signedPayloadHash, _, err := canonhash.SumObject(req.SignedPayload)
				if err != nil {
					httpx.WriteError(w, 500, "HASH_ERROR", err.Error(), nil)
					return
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
			signedPayloadHash, _, err := canonhash.SumObject(req.SignedPayload)
			if err != nil {
				httpx.WriteError(w, 500, "HASH_ERROR", err.Error(), nil)
				return
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
	if !authn.HasScope(agent.Scopes, requiredScope) {
		authn.LogAuthFailure(r.Context(), pool, "cel", endpoint, actor.PrincipalID, actor.ActorID, "INSUFFICIENT_SCOPE", map[string]any{"required_scope": requiredScope})
		httpx.WriteError(w, 403, "INSUFFICIENT_SCOPE", "agent lacks required scope", map[string]any{"required_scope": requiredScope})
		return false
	}
	return true
}
