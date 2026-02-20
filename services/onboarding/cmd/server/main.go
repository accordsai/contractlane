package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
	signupTTL := envIntDefault("ONBOARDING_SIGNUP_TTL_MINUTES", 15)
	maxAttempts := envIntDefault("ONBOARDING_SIGNUP_MAX_ATTEMPTS", 5)
	devExposeCode := strings.EqualFold(strings.TrimSpace(os.Getenv("ONBOARDING_PUBLIC_SIGNUP_DEV_MODE")), "true")
	publicCfg := loadPublicSignupConfig()

	ial := ialclient.New(ialBase)
	startIPLimiter := newFixedWindowLimiter(publicCfg.StartIPRatePerMinute, time.Minute)
	startEmailLimiter := newFixedWindowLimiter(publicCfg.StartEmailRatePerHour, time.Hour)
	verifyIPLimiter := newFixedWindowLimiter(publicCfg.VerifyIPRatePerMinute, time.Minute)
	completeIPLimiter := newFixedWindowLimiter(publicCfg.CompleteIPRatePerMinute, time.Minute)

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

	r.Route("/public/v1/signup", func(api chi.Router) {
		api.Post("/start", func(w http.ResponseWriter, r *http.Request) {
			if !enforceSignupChallenge(w, r, publicCfg) {
				return
			}
			clientIP := clientIPFromRequest(r)
			if !enforceRateLimit(w, startIPLimiter, "start_ip:"+clientIP) {
				return
			}
			var req struct {
				Email   string `json:"email"`
				OrgName string `json:"org_name"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			email := strings.ToLower(strings.TrimSpace(req.Email))
			orgName := strings.TrimSpace(req.OrgName)
			if email == "" || orgName == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "email and org_name are required", nil)
				return
			}
			if !isSaneEmail(email) {
				httpx.WriteError(w, 400, "BAD_REQUEST", "email is invalid", nil)
				return
			}
			if !isAllowedSignupEmail(email, publicCfg) {
				httpx.WriteError(w, 403, "EMAIL_NOT_ALLOWED", "email domain is not allowed", nil)
				return
			}
			if !enforceRateLimit(w, startEmailLimiter, "start_email:"+email) {
				return
			}
			code := randomVerificationCode()
			sess := store.SignupSession{
				SessionID:            "sgs_" + uuid.NewString(),
				Email:                email,
				OrgName:              orgName,
				Status:               "PENDING",
				VerificationCodeHash: store.HashToken(code),
				ExpiresAt:            time.Now().UTC().Add(time.Duration(signupTTL) * time.Minute),
			}
			if err := st.CreateSignupSession(r.Context(), sess); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			resp := map[string]any{
				"request_id": httpx.NewRequestID(),
				"signup_session": map[string]any{
					"session_id": sess.SessionID,
					"status":     sess.Status,
					"expires_at": sess.ExpiresAt,
				},
				"challenge": map[string]any{
					"type":      "EMAIL_OTP",
					"channel":   "email",
					"recipient": maskEmail(email),
				},
			}
			// Phase A stub to make integration testable before real delivery is wired.
			if devExposeCode {
				resp["challenge"] = map[string]any{
					"type":              "EMAIL_OTP",
					"channel":           "email",
					"recipient":         maskEmail(email),
					"verification_code": code,
				}
			}
			httpx.WriteJSON(w, 201, resp)
		})

		api.Post("/verify", func(w http.ResponseWriter, r *http.Request) {
			if !enforceSignupChallenge(w, r, publicCfg) {
				return
			}
			clientIP := clientIPFromRequest(r)
			if !enforceRateLimit(w, verifyIPLimiter, "verify_ip:"+clientIP) {
				return
			}
			var req struct {
				SessionID        string `json:"session_id"`
				VerificationCode string `json:"verification_code"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.SessionID) == "" || strings.TrimSpace(req.VerificationCode) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "session_id and verification_code are required", nil)
				return
			}
			sess, err := st.VerifySignupSession(r.Context(), strings.TrimSpace(req.SessionID), strings.TrimSpace(req.VerificationCode), time.Now().UTC(), maxAttempts)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "signup session not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if sess.Status == "VERIFIED" {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"signup_session": map[string]any{
						"session_id":  sess.SessionID,
						"status":      sess.Status,
						"verified_at": sess.VerifiedAt,
						"expires_at":  sess.ExpiresAt,
					},
				})
				return
			}
			if sess.Status == "EXPIRED" {
				httpx.WriteError(w, 410, "SIGNUP_SESSION_EXPIRED", "signup session expired", nil)
				return
			}
			httpx.WriteError(w, 401, "INVALID_VERIFICATION_CODE", "verification code is invalid", map[string]any{
				"attempts": sess.VerificationAttempts,
			})
		})

		api.Get("/{session_id}", func(w http.ResponseWriter, r *http.Request) {
			sessionID := strings.TrimSpace(chi.URLParam(r, "session_id"))
			sess, err := st.GetSignupSession(r.Context(), sessionID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "signup session not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			status := sess.Status
			if status != "VERIFIED" && time.Now().UTC().After(sess.ExpiresAt.UTC()) {
				status = "EXPIRED"
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"signup_session": map[string]any{
					"session_id":            sess.SessionID,
					"email":                 sess.Email,
					"org_name":              sess.OrgName,
					"status":                status,
					"verification_attempts": sess.VerificationAttempts,
					"created_at":            sess.CreatedAt,
					"verified_at":           sess.VerifiedAt,
					"completed_at":          sess.CompletedAt,
					"expires_at":            sess.ExpiresAt,
				},
			})
		})

		api.Post("/complete", func(w http.ResponseWriter, r *http.Request) {
			if !enforceSignupChallenge(w, r, publicCfg) {
				return
			}
			clientIP := clientIPFromRequest(r)
			if !enforceRateLimit(w, completeIPLimiter, "complete_ip:"+clientIP) {
				return
			}
			var req struct {
				SessionID    string   `json:"session_id"`
				Jurisdiction string   `json:"jurisdiction"`
				Timezone     string   `json:"timezone"`
				ProjectName  string   `json:"project_name"`
				AgentName    string   `json:"agent_name"`
				Scopes       []string `json:"scopes"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			sessionID := strings.TrimSpace(req.SessionID)
			if sessionID == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "session_id is required", nil)
				return
			}
			sess, err := st.GetSignupSession(r.Context(), sessionID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteError(w, 404, "NOT_FOUND", "signup session not found", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			if prov, err := st.GetSignupProvision(r.Context(), sessionID); err == nil {
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id": httpx.NewRequestID(),
					"status":     "ALREADY_COMPLETED",
					"provisioning": map[string]any{
						"session_id":    prov.SessionID,
						"org_id":        prov.OrgID,
						"project_id":    prov.ProjectID,
						"principal_id":  prov.PrincipalID,
						"actor_id":      prov.ActorID,
						"credential_id": prov.CredentialID,
					},
				})
				return
			} else if !errors.Is(err, pgx.ErrNoRows) {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			if time.Now().UTC().After(sess.ExpiresAt.UTC()) {
				httpx.WriteError(w, 410, "SIGNUP_SESSION_EXPIRED", "signup session expired", nil)
				return
			}
			if sess.Status != "VERIFIED" {
				httpx.WriteError(w, 409, "SIGNUP_SESSION_NOT_VERIFIED", "signup session must be VERIFIED before completion", nil)
				return
			}

			jurisdiction := strings.TrimSpace(req.Jurisdiction)
			if jurisdiction == "" {
				jurisdiction = "US"
			}
			timezone := strings.TrimSpace(req.Timezone)
			if timezone == "" {
				timezone = "UTC"
			}
			projectName := strings.TrimSpace(req.ProjectName)
			if projectName == "" {
				projectName = "Default Project"
			}
			agentName := strings.TrimSpace(req.AgentName)
			if agentName == "" {
				agentName = "Default Agent"
			}
			if len(req.Scopes) == 0 {
				req.Scopes = []string{"cel.contracts:write"}
			}

			org := store.Org{
				OrgID: "org_" + uuid.NewString(),
				Name:  sess.OrgName,
			}
			user := store.User{
				UserID: "usr_" + uuid.NewString(),
				Email:  sess.Email,
			}
			owner, err := st.CreateOrgWithOwner(r.Context(), org, user)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			principal, err := ial.CreatePrincipal(sess.OrgName, jurisdiction, timezone)
			if err != nil {
				httpx.WriteError(w, 502, "IAL_ERROR", err.Error(), nil)
				return
			}
			project := store.Project{
				ProjectID:   "prj_" + uuid.NewString(),
				OrgID:       org.OrgID,
				PrincipalID: principal.PrincipalID,
				Name:        projectName,
			}
			if err := st.CreateProject(r.Context(), project); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			agent, creds, err := ial.CreateAgent(project.PrincipalID, agentName, req.Scopes)
			if err != nil {
				httpx.WriteError(w, 502, "IAL_ERROR", err.Error(), nil)
				return
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
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			provision := store.SignupProvision{
				SessionID:    sess.SessionID,
				OrgID:        org.OrgID,
				ProjectID:    project.ProjectID,
				PrincipalID:  project.PrincipalID,
				ActorID:      agent.ActorID,
				CredentialID: credential.CredentialID,
			}
			if err := st.CreateSignupProvision(r.Context(), provision); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if err := st.MarkSignupSessionCompleted(r.Context(), sess.SessionID, time.Now().UTC()); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			auditPayload, _ := json.Marshal(map[string]any{
				"session_id":    sess.SessionID,
				"org_id":        org.OrgID,
				"project_id":    project.ProjectID,
				"principal_id":  project.PrincipalID,
				"actor_id":      agent.ActorID,
				"credential_id": credential.CredentialID,
			})
			_ = st.RecordAuditEvent(r.Context(), org.OrgID, project.ProjectID, agent.ActorID, "SIGNUP_COMPLETED", auditPayload)

			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"status":     "COMPLETED",
				"owner":      owner,
				"org":        org,
				"project":    project,
				"agent": map[string]any{
					"actor_id":     agent.ActorID,
					"principal_id": agent.PrincipalID,
					"name":         agentName,
					"scopes":       req.Scopes,
				},
				"credential": map[string]any{
					"credential_id": credential.CredentialID,
					"status":        credential.Status,
					"token":         creds.Token,
					"token_hint":    "store once; not retrievable again",
				},
			})
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

func envIntDefault(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v <= 0 {
		return def
	}
	return v
}

func randomVerificationCode() string {
	// 6-digit numeric OTP derived from secure random bytes.
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "000000"
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return fmt.Sprintf("%06d", n%1000000)
}

func maskEmail(email string) string {
	e := strings.TrimSpace(strings.ToLower(email))
	parts := strings.Split(e, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "***"
	}
	local := parts[0]
	domain := parts[1]
	if len(local) <= 2 {
		return local[:1] + "***@" + domain
	}
	return local[:2] + "***@" + domain
}

type publicSignupConfig struct {
	ChallengeToken          string
	StartIPRatePerMinute    int
	StartEmailRatePerHour   int
	VerifyIPRatePerMinute   int
	CompleteIPRatePerMinute int
	AllowedEmailDomains     map[string]struct{}
	DeniedEmailDomains      map[string]struct{}
}

func loadPublicSignupConfig() publicSignupConfig {
	return publicSignupConfig{
		ChallengeToken:          strings.TrimSpace(os.Getenv("ONBOARDING_PUBLIC_SIGNUP_CHALLENGE_TOKEN")),
		StartIPRatePerMinute:    envIntDefault("ONBOARDING_PUBLIC_SIGNUP_START_IP_RATE_PER_MINUTE", 20),
		StartEmailRatePerHour:   envIntDefault("ONBOARDING_PUBLIC_SIGNUP_START_EMAIL_RATE_PER_HOUR", 5),
		VerifyIPRatePerMinute:   envIntDefault("ONBOARDING_PUBLIC_SIGNUP_VERIFY_IP_RATE_PER_MINUTE", 60),
		CompleteIPRatePerMinute: envIntDefault("ONBOARDING_PUBLIC_SIGNUP_COMPLETE_IP_RATE_PER_MINUTE", 10),
		AllowedEmailDomains:     csvSet(strings.TrimSpace(os.Getenv("ONBOARDING_PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS"))),
		DeniedEmailDomains:      csvSet(strings.TrimSpace(os.Getenv("ONBOARDING_PUBLIC_SIGNUP_DENIED_EMAIL_DOMAINS"))),
	}
}

func csvSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func isSaneEmail(email string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return false
	}
	local := strings.TrimSpace(parts[0])
	domain := strings.TrimSpace(parts[1])
	return local != "" && domain != "" && strings.Contains(domain, ".")
}

func isAllowedSignupEmail(email string, cfg publicSignupConfig) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.TrimSpace(parts[1])
	if domain == "" {
		return false
	}
	if len(cfg.AllowedEmailDomains) > 0 {
		if _, ok := cfg.AllowedEmailDomains[domain]; !ok {
			return false
		}
	}
	if _, blocked := cfg.DeniedEmailDomains[domain]; blocked {
		return false
	}
	return true
}

func enforceSignupChallenge(w http.ResponseWriter, r *http.Request, cfg publicSignupConfig) bool {
	if cfg.ChallengeToken == "" {
		return true
	}
	token := strings.TrimSpace(r.Header.Get("X-Signup-Challenge"))
	if token == "" || token != cfg.ChallengeToken {
		httpx.WriteError(w, 401, "CHALLENGE_REQUIRED", "signup challenge token required", nil)
		return false
	}
	return true
}

type fixedWindowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	byKey  map[string]windowState
}

type windowState struct {
	start time.Time
	count int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:  limit,
		window: window,
		byKey:  map[string]windowState{},
	}
}

func enforceRateLimit(w http.ResponseWriter, limiter *fixedWindowLimiter, key string) bool {
	if limiter == nil || limiter.limit <= 0 {
		return true
	}
	if limiter.Allow(strings.TrimSpace(key), time.Now().UTC()) {
		return true
	}
	httpx.WriteError(w, 429, "RATE_LIMITED", "rate limit exceeded", nil)
	return false
}

func (l *fixedWindowLimiter) Allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	if key == "" {
		key = "anonymous"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.byKey[key]
	if cur.start.IsZero() || now.Sub(cur.start) >= l.window {
		l.byKey[key] = windowState{start: now, count: 1}
		return true
	}
	if cur.count >= l.limit {
		return false
	}
	cur.count++
	l.byKey[key] = cur
	return true
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			v := strings.TrimSpace(parts[0])
			if v != "" {
				return v
			}
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(r.RemoteAddr) == "" {
		return "unknown"
	}
	return strings.TrimSpace(r.RemoteAddr)
}
