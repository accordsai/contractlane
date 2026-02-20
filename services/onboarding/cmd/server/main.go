package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"contractlane/pkg/db"
	"contractlane/pkg/httpx"
	"contractlane/services/onboarding/internal/ialclient"
	"contractlane/services/onboarding/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func main() {
	pool := db.MustConnect()
	st := store.New(pool)

	port := strings.TrimSpace(os.Getenv("SERVICE_PORT"))
	if port == "" {
		port = "8084"
	}
	ialBase := strings.TrimSpace(os.Getenv("IAL_BASE_URL"))
	if ialBase == "" {
		ialBase = "http://localhost:8081/ial"
	}
	bootstrapToken := strings.TrimSpace(os.Getenv("ONBOARDING_BOOTSTRAP_TOKEN"))

	ial := ialclient.New(ialBase)

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	r.Route("/onboarding/v1", func(api chi.Router) {
		api.Post("/orgs", func(w http.ResponseWriter, r *http.Request) {
			if !requireBootstrapToken(w, r, bootstrapToken) {
				return
			}
			var req struct {
				Name       string `json:"name"`
				AdminEmail string `json:"admin_email"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.AdminEmail) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "name and admin_email are required", nil)
				return
			}

			org := store.Org{OrgID: "org_" + uuid.NewString(), Name: strings.TrimSpace(req.Name)}
			usr := store.User{UserID: "usr_" + uuid.NewString(), Email: strings.ToLower(strings.TrimSpace(req.AdminEmail))}
			if !handleIdempotentMutation(r, w, st, "global", usr.UserID, "POST /onboarding/v1/orgs", func() (int, map[string]any, error) {
				effectiveUser, err := st.CreateOrgWithOwner(r.Context(), org, usr)
				if err != nil {
					return 500, nil, err
				}
				b, _ := json.Marshal(map[string]any{"org_id": org.OrgID, "owner_user_id": effectiveUser.UserID})
				_ = st.RecordAuditEvent(r.Context(), org.OrgID, "", effectiveUser.UserID, "ORG_CREATED", b)
				return 201, map[string]any{
					"request_id": httpx.NewRequestID(),
					"org":        org,
					"owner":      effectiveUser,
				}, nil
			}) {
				return
			}
		})

		api.Post("/orgs/{org_id}/projects", func(w http.ResponseWriter, r *http.Request) {
			if !requireBootstrapToken(w, r, bootstrapToken) {
				return
			}
			orgID := chi.URLParam(r, "org_id")
			if err := st.EnsureOrgExists(r.Context(), orgID); err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "org not found", nil)
				return
			}
			var req struct {
				Name         string `json:"name"`
				Jurisdiction string `json:"jurisdiction"`
				Timezone     string `json:"timezone"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.Name) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "name is required", nil)
				return
			}
			if strings.TrimSpace(req.Jurisdiction) == "" {
				req.Jurisdiction = "US"
			}
			if strings.TrimSpace(req.Timezone) == "" {
				req.Timezone = "UTC"
			}

			endpoint := "POST /onboarding/v1/orgs/{org_id}/projects"
			if !handleIdempotentMutation(r, w, st, orgID, "system", endpoint, func() (int, map[string]any, error) {
				principal, err := ial.CreatePrincipal(strings.TrimSpace(req.Name), strings.TrimSpace(req.Jurisdiction), strings.TrimSpace(req.Timezone))
				if err != nil {
					return 502, nil, err
				}
				p := store.Project{
					ProjectID:   "prj_" + uuid.NewString(),
					OrgID:       orgID,
					PrincipalID: principal.PrincipalID,
					Name:        strings.TrimSpace(req.Name),
				}
				if err := st.CreateProject(r.Context(), p); err != nil {
					return 500, nil, err
				}
				b, _ := json.Marshal(map[string]any{"org_id": orgID, "project_id": p.ProjectID, "principal_id": p.PrincipalID})
				_ = st.RecordAuditEvent(r.Context(), orgID, p.ProjectID, "", "PROJECT_CREATED", b)
				return 201, map[string]any{"request_id": httpx.NewRequestID(), "project": p}, nil
			}) {
				return
			}
		})

		api.Post("/projects/{project_id}/agents", func(w http.ResponseWriter, r *http.Request) {
			if !requireBootstrapToken(w, r, bootstrapToken) {
				return
			}
			projectID := chi.URLParam(r, "project_id")
			project, err := st.GetProject(r.Context(), projectID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "project not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			var req struct {
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.Name) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "name is required", nil)
				return
			}
			if len(req.Scopes) == 0 {
				req.Scopes = []string{"cel.contracts:write"}
			}

			endpoint := "POST /onboarding/v1/projects/{project_id}/agents"
			if !handleIdempotentMutation(r, w, st, project.OrgID, "system", endpoint, func() (int, map[string]any, error) {
				agent, creds, err := ial.CreateAgent(project.PrincipalID, strings.TrimSpace(req.Name), req.Scopes)
				if err != nil {
					return 502, nil, err
				}
				credential := store.Credential{
					CredentialID: "cred_" + uuid.NewString(),
					ProjectID:    project.ProjectID,
					PrincipalID:  project.PrincipalID,
					ActorID:      agent.ActorID,
					TokenHash:    store.HashToken(creds.Token),
					Scopes:       req.Scopes,
					Status:       "ACTIVE",
				}
				if err := st.CreateCredential(r.Context(), credential); err != nil {
					return 500, nil, err
				}
				b, _ := json.Marshal(map[string]any{"project_id": project.ProjectID, "actor_id": agent.ActorID, "credential_id": credential.CredentialID})
				_ = st.RecordAuditEvent(r.Context(), project.OrgID, project.ProjectID, agent.ActorID, "AGENT_CREDENTIAL_ISSUED", b)

				return 201, map[string]any{
					"request_id": httpx.NewRequestID(),
					"agent": map[string]any{
						"actor_id":     agent.ActorID,
						"principal_id": agent.PrincipalID,
						"name":         strings.TrimSpace(req.Name),
						"scopes":       req.Scopes,
					},
					"credential": map[string]any{
						"credential_id": credential.CredentialID,
						"status":        credential.Status,
						"token":         creds.Token,
						"token_hint":    "store once; not retrievable again",
					},
				}, nil
			}) {
				return
			}
		})
	})

	http.ListenAndServe(":"+port, r)
}

func requireBootstrapToken(w http.ResponseWriter, r *http.Request, configured string) bool {
	if configured == "" {
		return true
	}
	tok, ok := parseBearer(r.Header.Get("Authorization"))
	if !ok || tok != configured {
		httpx.WriteError(w, 401, "UNAUTHORIZED", "onboarding bearer token required", nil)
		return false
	}
	return true
}

func parseBearer(authorization string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.TrimSpace(authorization), prefix) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	if tok == "" {
		return "", false
	}
	return tok, true
}

func handleIdempotentMutation(r *http.Request, w http.ResponseWriter, st *store.Store, scopeID, actorID, endpoint string, run func() (int, map[string]any, error)) bool {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key != "" {
		rec, err := st.GetIdempotencyRecord(r.Context(), scopeID, actorID, key, endpoint)
		if err != nil {
			httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
			return false
		}
		if rec != nil {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(rec.ResponseStatus)
			_, _ = w.Write(rec.ResponseBody)
			return false
		}
	}

	status, body, err := run()
	if err != nil {
		if status == 502 {
			httpx.WriteError(w, 502, "IAL_ERROR", err.Error(), nil)
			return false
		}
		httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
		return false
	}

	if key != "" {
		buf := bytes.Buffer{}
		_ = json.NewEncoder(&buf).Encode(body)
		_ = st.SaveIdempotencyRecord(r.Context(), store.IdempotencyRecord{
			ScopeID:        scopeID,
			ActorID:        actorID,
			IdempotencyKey: key,
			Endpoint:       endpoint,
			ResponseStatus: status,
			ResponseBody:   bytes.TrimSpace(buf.Bytes()),
		})
	}
	httpx.WriteJSON(w, status, body)
	return true
}
