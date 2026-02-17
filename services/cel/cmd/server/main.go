package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"contractlane/pkg/db"
	"contractlane/pkg/domain"
	"contractlane/pkg/httpx"
	"contractlane/services/cel/internal/ialclient"
	"contractlane/services/cel/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func main() {
	pool := db.MustConnect()
	st := store.New(pool)

	ialBase := os.Getenv("IAL_BASE_URL")
	if ialBase == "" { ialBase = "http://localhost:8081/ial" }
	ial := ialclient.New(ialBase)

	port := os.Getenv("SERVICE_PORT")
	if port == "" { port = "8082" }

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	r.Route("/cel", func(api chi.Router) {

		// DEV helper to seed a template for smoke tests
		api.Post("/dev/seed-template", func(w http.ResponseWriter, r *http.Request) {
			var req struct{ PrincipalID string `json:"principal_id"` }
			_ = httpx.ReadJSON(r, &req)
			tplID, err := st.UpsertSeedTemplate(r.Context())
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "template_id": tplID})
		})

		api.Get("/templates", func(w http.ResponseWriter, r *http.Request) {
			ct := r.URL.Query().Get("contract_type")
			j := r.URL.Query().Get("jurisdiction")
			templates, err := st.ListTemplates(r.Context(), ct, j)
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "templates": templates})
		})

		api.Post("/principals/{principal_id}/templates/{template_id}/enable", func(w http.ResponseWriter, r *http.Request) {
			principalID := chi.URLParam(r, "principal_id")
			templateID := chi.URLParam(r, "template_id")
			var req struct {
				EnabledByActorID string `json:"enabled_by_actor_id"`
				OverrideGates map[string]string `json:"override_gates"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			if err := st.EnableTemplate(r.Context(), principalID, templateID, req.EnabledByActorID, req.OverrideGates); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "enabled": true, "principal_id": principalID, "template_id": templateID})
		})

		api.Get("/templates/{template_id}/governance", func(w http.ResponseWriter, r *http.Request) {
			templateID := chi.URLParam(r, "template_id")
			gates, err := st.GetTemplateGates(r.Context(), templateID)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			vars, err := st.GetTemplateVars(r.Context(), templateID)
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"template": map[string]any{"template_id": templateID},
				"template_gates": gates,
				"variables": vars,
				"protected_slots": []string{},
			})
		})

		api.Post("/contracts", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
					IdempotencyKey string `json:"idempotency_key"`
				} `json:"actor_context"`
				TemplateID string `json:"template_id"`
				Counterparty struct{ Name, Email string } `json:"counterparty"`
				InitialVariables map[string]string `json:"initial_variables"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			c := store.Contract{
				ContractID: "ctr_" + uuid.NewString(),
				PrincipalID: req.ActorContext.PrincipalID,
				TemplateID: req.TemplateID,
				State: "DRAFT_CREATED",
				RiskLevel: "LOW",
				CounterpartyName: req.Counterparty.Name,
				CounterpartyEmail: req.Counterparty.Email,
				CreatedBy: req.ActorContext.ActorID,
				CreatedAt: time.Now(),
			}
			if err := st.CreateContract(r.Context(), c); err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			// set initial vars (treated as agent values)
			defs, _ := st.GetTemplateVars(r.Context(), req.TemplateID)
			idGov := loadIdentityVarGov(ial, req.ActorContext.ActorID) // agent's identity rules not used; ok
			for k, v := range req.InitialVariables {
				def := findDef(defs, domain.VarKey(k))
				if def == nil { continue }
				canon, err := domain.ValidateAndCanonicalize(*def, v)
				if err != nil { httpx.WriteError(w, 400, "VAR_INVALID", err.Error(), nil); return }
				pol := domain.EffectiveVarSetPolicy(*def, idGov)
				src := domain.SourceAgent
				rev := domain.ReviewNotNeeded
				if pol == domain.VarAgentFillHumanReview { rev = domain.ReviewPending }
				if pol == domain.VarHumanRequired { rev = domain.ReviewPending }
				_ = st.SetVariable(r.Context(), c.ContractID, def.Key, canon, src, rev, req.ActorContext.ActorID)
			}
			_ = st.AddEvent(r.Context(), c.ContractID, "CREATED", req.ActorContext.ActorID, map[string]any{})
			httpx.WriteJSON(w, 201, map[string]any{"request_id": httpx.NewRequestID(), "contract": c})
		})

		api.Get("/contracts/{contract_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "contract_id")
			c, err := st.GetContract(r.Context(), id)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "contract": c})
		})

		api.Post("/contracts/{contract_id}/variables:bulkSet", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
					IdempotencyKey string `json:"idempotency_key"`
				} `json:"actor_context"`
				Variables map[string]string `json:"variables"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			if c.State == "SIGNATURE_SENT" || c.State == "SIGNED_BY_US" || c.State == "SIGNED_BY_THEM" || c.State == "EFFECTIVE" || c.State == "ARCHIVED" {
				httpx.WriteError(w, 409, "VARIABLES_LOCKED", "variables cannot be changed after signature workflow initiated", nil); return
			}
			defs, err := st.GetTemplateVars(r.Context(), c.TemplateID)
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			// identity governance for HUMAN actor: use their rules
			idGov := loadIdentityVarGov(ial, req.ActorContext.ActorID)

			out := []map[string]any{}
			for k, v := range req.Variables {
				def := findDef(defs, domain.VarKey(k))
				if def == nil { continue }
				canon, err := domain.ValidateAndCanonicalize(*def, v)
				if err != nil { httpx.WriteError(w, 400, "VAR_INVALID", err.Error(), nil); return }
				pol := domain.EffectiveVarSetPolicy(*def, idGov)
				src := domain.SourceAgent
				if req.ActorContext.ActorType == "HUMAN" { src = domain.SourceHuman }
				rev := domain.ReviewNotNeeded
				switch pol {
				case domain.VarHumanRequired:
					if src == domain.SourceHuman { rev = domain.ReviewNotNeeded } else { rev = domain.ReviewPending }
				case domain.VarAgentFillHumanReview:
					if src == domain.SourceAgent { rev = domain.ReviewPending } else { rev = domain.ReviewNotNeeded }
				case domain.VarAgentAllowed:
					rev = domain.ReviewNotNeeded
				default:
					rev = domain.ReviewNotNeeded
				}
				if err := st.SetVariable(r.Context(), contractID, def.Key, canon, src, rev, req.ActorContext.ActorID); err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
				}
				out = append(out, map[string]any{"key": k, "value": canon, "source": src, "review_status": rev})
			}
			_ = st.AddEvent(r.Context(), contractID, "VARIABLE_SET", req.ActorContext.ActorID, map[string]any{"count": len(out)})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "result":"OK", "variables": out})
		})

		api.Get("/contracts/{contract_id}/variables", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			c, err := st.GetContract(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			defs, _ := st.GetTemplateVars(r.Context(), c.TemplateID)
			vals, _ := st.GetVariables(r.Context(), contractID)

			// no actor context here; return computed gate status without identity rules (safe default agent allowed)
			idGov := domain.IdentityVariableGovernance{}
			gates := domain.EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, idGov, vals)

			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"definitions": defs,
				"values": vals,
				"gate_status": map[string]any{
					"missing_required": gates.MissingRequired,
					"needs_human_entry": gates.NeedsHumanEntry,
					"needs_human_review": gates.NeedsHumanReview,
				},
			})
		})

		api.Post("/contracts/{contract_id}/variables:review", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
					IdempotencyKey string `json:"idempotency_key"`
				} `json:"actor_context"`
				Decision string `json:"decision"`
				Keys []string `json:"keys"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			if req.ActorContext.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "HUMAN_ONLY", "only humans can review variables", nil); return
			}
			if err := st.ReviewVariables(r.Context(), contractID, req.Keys, req.Decision, req.ActorContext.ActorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			_ = st.AddEvent(r.Context(), contractID, "VARIABLES_REVIEWED", req.ActorContext.ActorID, map[string]any{"decision": req.Decision, "count": len(req.Keys)})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "result":"OK", "updated": req.Keys})
		})

		api.Post("/contracts/{contract_id}/approvals:route", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
				} `json:"actor_context"`
				Action string `json:"action"`
				RequiredRoles []string `json:"required_roles"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			aprq := "aprq_" + uuid.NewString()
			token := randomToken()
			tokenHash := hash(token)
			if err := st.CreateApprovalRequest(r.Context(), aprq, contractID, req.Action, tokenHash, req.RequiredRoles); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			_ = st.AddEvent(r.Context(), contractID, "APPROVAL_REQUESTED", req.ActorContext.ActorID, map[string]any{"approval_request_id": aprq, "action": req.Action})
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"approval_request": map[string]any{
					"approval_request_id": aprq, "contract_id": contractID, "action": req.Action, "status":"PENDING", "required_roles": req.RequiredRoles,
				},
				"review_urls": []map[string]any{
					{"actor_id": "TBD", "url": fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s?token=%s", contractID, token)},
				},
			})
		})

		api.Get("/contracts/{contract_id}/approvals", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			reqs, err := st.ListApprovalRequests(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "approval_requests": reqs})
		})

		api.Post("/approvals/{approval_request_id}:decide", func(w http.ResponseWriter, r *http.Request) {
			aprq := chi.URLParam(r, "approval_request_id")
			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
				} `json:"actor_context"`
				Decision string `json:"decision"`
				SignedPayload map[string]any `json:"signed_payload"`
				Signature map[string]any `json:"signature"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }
			if req.ActorContext.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "HUMAN_ONLY", "only humans can decide approvals", nil); return
			}
			valid, err := ial.VerifySignature(req.ActorContext.PrincipalID, req.ActorContext.ActorID)
			if err != nil || !valid {
				httpx.WriteError(w, 403, "BAD_SIGNATURE", "signature verification failed", nil); return
			}
			status, contractID, _, _, err := st.GetApprovalRequest(r.Context(), aprq)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			if status != "PENDING" {
				httpx.WriteError(w, 409, "ALREADY_DECIDED", "approval request already decided", nil); return
			}
			if req.Decision == "APPROVE" {
				_ = st.ApproveApprovalRequest(r.Context(), aprq)
				_ = st.AddEvent(r.Context(), contractID, "APPROVED", req.ActorContext.ActorID, map[string]any{"approval_request_id": aprq})
				httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "approval_request_id": aprq, "status":"APPROVED"})
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "approval_request_id": aprq, "status":"REJECTED"})
		})

		api.Post("/contracts/{contract_id}:sendForSignature", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
				} `json:"actor_context"`
			}
			_ = httpx.ReadJSON(r, &req)
			// Stub: mark SIGNATURE_SENT and create envelope
			_ = st.TransitionState(r.Context(), contractID, "SIGNATURE_SENT")
			env := "env_" + uuid.NewString()
			_ = st.UpsertEnvelope(r.Context(), contractID, "INTERNAL", env, "SENT")
			_ = st.AddEvent(r.Context(), contractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": env})
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "state":"SIGNATURE_SENT", "signature": map[string]any{"provider":"INTERNAL","envelope_id":env,"status":"SENT"}})
		})

		api.Get("/contracts/{contract_id}/signature", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			env, err := st.GetEnvelope(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "signature": env})
		})

		api.Get("/contracts/{contract_id}/events", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			evs, err := st.ListEvents(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return }
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "events": evs})
		})

		api.Get("/contracts/{contract_id}/evidence-bundle", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			evs, _ := st.ListEvents(r.Context(), contractID)
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"bundle": map[string]any{
					"bundle_id": "bun_" + uuid.NewString(),
					"bundle_root_hash": "sha256:dev",
					"events": evs,
				},
			})
		})

		// Action endpoint (core)
		api.Post("/contracts/{contract_id}/actions/{action}", func(w http.ResponseWriter, r *http.Request) {
			contractID := chi.URLParam(r, "contract_id")
			action := chi.URLParam(r, "action")

			var req struct{
				ActorContext struct{
					PrincipalID string `json:"principal_id"`
					ActorID string `json:"actor_id"`
					ActorType string `json:"actor_type"`
					IdempotencyKey string `json:"idempotency_key"`
				} `json:"actor_context"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil { httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return }

			c, err := st.GetContract(r.Context(), contractID)
			if err != nil { httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return }

			// 1) Variable gates first
			defs, _ := st.GetTemplateVars(r.Context(), c.TemplateID)
			vals, _ := st.GetVariables(r.Context(), contractID)

			// identity var gov from *human* actor if available; for agent calls, assume empty.
			idGov := domain.IdentityVariableGovernance{}
			if req.ActorContext.ActorType == "HUMAN" {
				idGov = loadIdentityVarGov(ial, req.ActorContext.ActorID)
			}

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
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"status": "BLOCKED",
					"action": action,
					"next_step": map[string]any{
						"type": nsType,
						"reason": reason,
						"variables": vars,
						"required_roles": []string{"LEGAL"},
						"review_url": fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s/variables?token=var_tok_dev", contractID),
					},
				})
				return
			}

			// 2) Action gate (template->identity). For MVP, enforce identity gate FORCE_HUMAN for SEND_FOR_SIGNATURE.
			if action == "SEND_FOR_SIGNATURE" {
				// Get a single "LEGAL" actor policy (we use caller's policy profile if caller is human; else require approval).
				// In MVP smoke test: policy profile on ACT_H will be FORCE_HUMAN.
				// So: always require approval unless an approval_request is already approved.
				// Create approval request on-demand.
				// Check if there is any approved request for this contract+action (simplified: check latest request status).
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
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id": httpx.NewRequestID(),
						"status": "BLOCKED",
						"action": action,
						"next_step": map[string]any{
							"type": "APPROVE_ACTION",
							"reason": "IDENTITY_GATE",
							"required_roles": []string{"LEGAL"},
							"approval_request_id": aprq,
							"review_url": fmt.Sprintf("https://app.yourdomain.com/review/contracts/%s?token=%s", contractID, token),
						},
					})
					return
				}
				// Approved -> proceed to send-for-signature
				_ = st.TransitionState(r.Context(), contractID, "SIGNATURE_SENT")
				env := "env_" + uuid.NewString()
				_ = st.UpsertEnvelope(r.Context(), contractID, "INTERNAL", env, "SENT")
				_ = st.AddEvent(r.Context(), contractID, "SIGNATURE_SENT", "SYSTEM", map[string]any{"envelope_id": env})
				httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "status":"DONE", "action": action, "state":"SIGNATURE_SENT"})
				return
			}

			// Other actions are stubs
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "status":"DONE", "action": action, "state": c.State})
		})

		// Stubs validate/render
		api.Post("/contracts/{contract_id}:validate", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "risk_level":"LOW", "blocked": false, "required_roles": []string{}})
		})
		api.Post("/contracts/{contract_id}:render", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "state":"RENDERED", "artifacts": []any{}, "hashes": map[string]string{"packet_hash":"sha256:dev","diff_hash":"sha256:dev","risk_hash":"sha256:dev"}})
		})
	})

	http.ListenAndServe(":"+port, r)
}

func findDef(defs []domain.VariableDefinition, key domain.VarKey) *domain.VariableDefinition {
	for i := range defs {
		if defs[i].Key == key { return &defs[i] }
	}
	return nil
}

func loadIdentityVarGov(ial *ialclient.Client, actorID string) domain.IdentityVariableGovernance {
	pp, err := ial.GetPolicyProfile(actorID)
	if err != nil || pp == nil { return domain.IdentityVariableGovernance{} }
	rules := []domain.IdentityVarRule{}
	for _, r := range pp.VariableRules {
		var pol string
		if p, ok := r["policy"].(string); ok { pol = p }
		varKeyAny, hasKey := r["for_key"]
		varTypeAny, hasType := r["for_type"]
		if hasKey {
			s, ok := varKeyAny.(string); if ok {
				k := domain.VarKey(s)
				rules = append(rules, domain.IdentityVarRule{ForKey: &k, Policy: domain.VarSetPolicy(pol)})
			}
		} else if hasType {
			s, ok := varTypeAny.(string); if ok {
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
