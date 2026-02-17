package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"contractlane/pkg/db"
	"contractlane/pkg/httpx"
	"contractlane/services/ial/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func main() {
	pool := db.MustConnect()
	st := store.New(pool)

	port := os.Getenv("SERVICE_PORT")
	if port == "" { port = "8081" }

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	r.Route("/ial", func(api chi.Router) {

		api.Post("/principals", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name string `json:"name"`
				Jurisdiction string `json:"jurisdiction"`
				Timezone string `json:"timezone"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return
			}
			p := store.Principal{
				PrincipalID: "prn_" + uuid.NewString(),
				Name: req.Name, Jurisdiction: req.Jurisdiction, Timezone: req.Timezone,
				CreatedAt: time.Now(),
			}
			if err := st.CreatePrincipal(r.Context(), p); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 201, map[string]any{"request_id": httpx.NewRequestID(), "principal": p})
		})

		api.Get("/principals/{principal_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "principal_id")
			p, err := st.GetPrincipal(r.Context(), id)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "principal": p})
		})

		api.Post("/actors/agents", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
				Name string `json:"name"`
				Auth struct {
					Mode string `json:"mode"`
					Scopes []string `json:"scopes"`
				} `json:"auth"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return
			}
			token := randomToken()
			tokenHash := store.HashToken("agt_live_" + token)
			name := req.Name
			a := store.Actor{
				ActorID: "act_" + uuid.NewString(),
				PrincipalID: req.PrincipalID,
				ActorType: "AGENT",
				Status: "ACTIVE",
				Name: &name,
				Roles: req.Auth.Scopes,
				CreatedAt: time.Now(),
			}
			if err := st.CreateAgent(r.Context(), a, tokenHash, req.Auth.Scopes); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"agent": map[string]any{
					"actor_id": a.ActorID,
					"principal_id": a.PrincipalID,
					"actor_type": "AGENT",
					"name": req.Name,
					"scopes": req.Auth.Scopes,
					"created_at": a.CreatedAt,
				},
				"credentials": map[string]any{
					"token": "agt_live_" + token,
					"token_hint": "store once; not retrievable again",
				},
			})
		})

		api.Get("/actors", func(w http.ResponseWriter, r *http.Request) {
			principalID := r.URL.Query().Get("principal_id")
			typ := r.URL.Query().Get("type")
			var typPtr *string
			if typ != "" { typPtr = &typ }
			actors, err := st.ListActors(r.Context(), principalID, typPtr)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "actors": actors})
		})

		api.Post("/invites", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
				Invitee struct{ Email string `json:"email"` } `json:"invitee"`
				RequestedRoles []string `json:"requested_roles"`
				ExpiresInHours int `json:"expires_in_hours"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return
			}
			id := "inv_" + uuid.NewString()
			token := "inv_tok_" + randomToken()
			tokenHash := store.HashToken(token)
			expiresAt := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
			inv := store.Invite{
				InviteID: id, PrincipalID: req.PrincipalID, Email: req.Invitee.Email,
				RequestedRoles: req.RequestedRoles, Status: "PENDING", ExpiresAt: expiresAt,
			}
			if err := st.CreateInvite(r.Context(), inv, tokenHash); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"invite": inv,
				"enrollment_url": "https://app.yourdomain.com/enroll?token=" + token,
			})
		})

		api.Get("/invites/{invite_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "invite_id")
			inv, _, err := st.GetInvite(r.Context(), id)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "invite": inv})
		})

		api.Post("/webauthn/register/start", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "webauthn": map[string]any{"publicKey": map[string]any{}}})
		})

		// Dev stub enrollment: invite_token "dev:<invite_id>".
		api.Post("/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				InviteToken string `json:"invite_token"`
				AttestationResponse any `json:"attestation_response"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return
			}
			if len(req.InviteToken) < 5 || req.InviteToken[:4] != "dev:" {
				httpx.WriteError(w, 400, "BAD_TOKEN", "headless MVP supports invite_token dev:<invite_id>", nil); return
			}
			inviteID := req.InviteToken[4:]
			inv, _, err := st.GetInvite(r.Context(), inviteID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return
			}
			actorID := "act_" + uuid.NewString()
			email := inv.Email
			a := store.Actor{
				ActorID: actorID, PrincipalID: inv.PrincipalID, ActorType: "HUMAN", Status: "ACTIVE",
				Email: &email, Roles: inv.RequestedRoles, CreatedAt: time.Now(),
			}
			if err := st.CreateHuman(r.Context(), a); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			if err := st.CompleteInvite(r.Context(), inviteID, actorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "actor": a})
		})

		// Stub signature verification
		api.Post("/verify-signature", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "valid": true, "actor_status": "ACTIVE"})
		})

		api.Put("/actors/{actor_id}/policy-profile", func(w http.ResponseWriter, r *http.Request) {
			actorID := chi.URLParam(r, "actor_id")
			var req struct {
				PrincipalID string `json:"principal_id"`
				AutomationLevel string `json:"automation_level"`
				ActionGates map[string]string `json:"action_gates"`
				VariableRules []map[string]any `json:"variable_rules"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil); return
			}
			ag, _ := json.Marshal(req.ActionGates)
			vr, _ := json.Marshal(req.VariableRules)
			if err := st.UpsertPolicyProfile(r.Context(), actorID, req.PrincipalID, req.AutomationLevel, ag, vr); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil); return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"policy_profile": map[string]any{
					"actor_id": actorID,
					"automation_level": req.AutomationLevel,
					"action_gates": req.ActionGates,
					"variable_rules": req.VariableRules,
				},
			})
		})

		api.Get("/actors/{actor_id}/policy-profile", func(w http.ResponseWriter, r *http.Request) {
			actorID := chi.URLParam(r, "actor_id")
			principalID, level, ag, vr, err := st.GetPolicyProfile(r.Context(), actorID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil); return
			}
			var agObj any
			var vrObj any
			_ = json.Unmarshal(ag, &agObj)
			_ = json.Unmarshal(vr, &vrObj)
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"policy_profile": map[string]any{
					"actor_id": actorID,
					"principal_id": principalID,
					"automation_level": level,
					"action_gates": agObj,
					"variable_rules": vrObj,
				},
			})
		})
	})

	http.ListenAndServe(":"+port, r)
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
