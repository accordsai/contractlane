package main

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/accordsai/contractlane/pkg/db"
	"github.com/accordsai/contractlane/pkg/domain"
	"github.com/accordsai/contractlane/pkg/evidencehash"
	"github.com/accordsai/contractlane/pkg/httpx"
	"github.com/accordsai/contractlane/pkg/signature"
	"github.com/accordsai/contractlane/services/ial/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type webAuthnConfig struct {
	Enabled        bool
	RPID           string
	RPName         string
	AllowedOrigins []string
	ChallengeTTL   time.Duration
}

func loadWebAuthnConfig() webAuthnConfig {
	enabled := envBoolDefault("ENABLE_SIG_V3_WEBAUTHN", true)
	rpID := strings.TrimSpace(os.Getenv("IAL_WEBAUTHN_RP_ID"))
	if rpID == "" {
		rpID = "localhost"
	}
	rpName := strings.TrimSpace(os.Getenv("IAL_WEBAUTHN_RP_NAME"))
	if rpName == "" {
		rpName = "Contract Lane"
	}
	originsRaw := strings.TrimSpace(os.Getenv("IAL_WEBAUTHN_ALLOWED_ORIGINS"))
	if originsRaw == "" {
		originsRaw = "http://localhost:3000,http://localhost,https://localhost"
	}
	origins := []string{}
	for _, part := range strings.Split(originsRaw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			origins = append(origins, p)
		}
	}
	ttlSeconds := envIntDefault("IAL_WEBAUTHN_CHALLENGE_TTL_SECONDS", 300)
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	return webAuthnConfig{
		Enabled:        enabled,
		RPID:           rpID,
		RPName:         rpName,
		AllowedOrigins: origins,
		ChallengeTTL:   time.Duration(ttlSeconds) * time.Second,
	}
}

func main() {
	pool := db.MustConnect()
	st := store.New(pool)
	waCfg := loadWebAuthnConfig()

	port := os.Getenv("SERVICE_PORT")
	if port == "" {
		port = "8081"
	}

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	r.Route("/ial", func(api chi.Router) {
		api.Post("/dev/bootstrap", func(w http.ResponseWriter, r *http.Request) {
			if strings.ToLower(strings.TrimSpace(os.Getenv("IAL_DEV_BOOTSTRAP"))) != "true" {
				httpx.WriteError(w, 404, "NOT_FOUND", "dev bootstrap disabled", nil)
				return
			}
			devPrincipalInput := strings.TrimSpace(os.Getenv("IAL_DEV_PRINCIPAL_ID"))
			if devPrincipalInput == "" {
				devPrincipalInput = "prn_dev_local"
			}
			principalID := devPrincipalInput
			if _, err := uuid.Parse(principalID); err != nil {
				// Keep dev bootstrap deterministic while ensuring DB rows use UUID-compatible principal IDs.
				principalID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("contractlane/dev/principal/"+devPrincipalInput)).String()
			}
			principalName := strings.TrimSpace(os.Getenv("IAL_DEV_PRINCIPAL_NAME"))
			if principalName == "" {
				principalName = "Dev Principal"
			}
			principalJurisdiction := strings.TrimSpace(os.Getenv("IAL_DEV_PRINCIPAL_JURISDICTION"))
			if principalJurisdiction == "" {
				principalJurisdiction = "US"
			}
			principalTimezone := strings.TrimSpace(os.Getenv("IAL_DEV_PRINCIPAL_TIMEZONE"))
			if principalTimezone == "" {
				principalTimezone = "UTC"
			}
			agentID := strings.TrimSpace(os.Getenv("IAL_DEV_AGENT_ID"))
			if agentID == "" {
				agentID = "act_dev_local"
			}
			agentName := strings.TrimSpace(os.Getenv("IAL_DEV_AGENT_NAME"))
			if agentName == "" {
				agentName = "Dev Agent"
			}
			token := strings.TrimSpace(os.Getenv("IAL_DEV_TOKEN"))
			if token == "" {
				token = "agt_live_dev_local_token"
			}
			scopes := []string{
				"cel.contracts:write",
				"cel.approvals:decide",
				"cel.approvals:route",
				"cel.gates:read",
				"cel.gates:resolve",
				"exec.signatures:send",
			}

			p := store.Principal{
				PrincipalID:  principalID,
				Name:         principalName,
				Jurisdiction: principalJurisdiction,
				Timezone:     principalTimezone,
			}
			if err := st.UpsertPrincipal(r.Context(), p); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			a := store.Actor{
				ActorID:     agentID,
				PrincipalID: principalID,
				ActorType:   "AGENT",
				Status:      "ACTIVE",
				Name:        &agentName,
				Roles:       scopes,
			}
			if err := st.UpsertAgent(r.Context(), a, store.HashToken(token), scopes); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			termsTemplateID := strings.TrimSpace(os.Getenv("IAL_DEV_TERMS_TEMPLATE_ID"))
			termsTemplateVersion := strings.TrimSpace(os.Getenv("IAL_DEV_TERMS_TEMPLATE_VERSION"))

			if termsTemplateID == "" {
				ref, err := st.FindDevTermsTemplate(r.Context())
				if err != nil {
					httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
					return
				}
				if ref != nil {
					termsTemplateID = ref.TemplateID
				}
			}
			if termsTemplateID == "" {
				termsTemplateID = "tpl_terms_v1"
			}
			if termsTemplateVersion == "" {
				termsTemplateVersion = parseTemplateVersion(termsTemplateID)
				if termsTemplateVersion == "" {
					termsTemplateVersion = "v1"
				}
			}
			if err := st.UpsertTemplateAndGovernance(r.Context(), termsTemplateID, "TERMS", "Terms and Conditions (Dev)"); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if err := st.UpsertComplianceProgramPublished(r.Context(), principalID, "terms_current", "STRICT_RECONSENT", termsTemplateID, termsTemplateVersion, agentID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}

			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"principal": map[string]any{
					"principal_id":    principalID,
					"principal_alias": devPrincipalInput,
					"name":            principalName,
					"jurisdiction":    principalJurisdiction,
					"timezone":        principalTimezone,
				},
				"agent": map[string]any{
					"actor_id":     agentID,
					"principal_id": principalID,
					"actor_type":   "AGENT",
					"name":         agentName,
					"scopes":       scopes,
				},
				"compliance_program": map[string]any{
					"program_key":                "terms_current",
					"mode":                       "STRICT_RECONSENT",
					"required_template_id":       termsTemplateID,
					"required_template_version":  termsTemplateVersion,
					"bootstrap_principal_id":     principalID,
					"bootstrap_principal_alias":  devPrincipalInput,
					"bootstrap_created_by_actor": agentID,
				},
				"credentials": map[string]any{
					"token":      token,
					"token_hint": "dev bootstrap token",
				},
			})
		})

		api.Post("/principals", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name         string `json:"name"`
				Jurisdiction string `json:"jurisdiction"`
				Timezone     string `json:"timezone"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			p := store.Principal{
				PrincipalID: "prn_" + uuid.NewString(),
				Name:        req.Name, Jurisdiction: req.Jurisdiction, Timezone: req.Timezone,
				CreatedAt: time.Now(),
			}
			if err := st.CreatePrincipal(r.Context(), p); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 201, map[string]any{"request_id": httpx.NewRequestID(), "principal": p})
		})

		api.Get("/principals/{principal_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "principal_id")
			p, err := st.GetPrincipal(r.Context(), id)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "principal": p})
		})

		api.Post("/actors/agents", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
				Name        string `json:"name"`
				Auth        struct {
					Mode   string   `json:"mode"`
					Scopes []string `json:"scopes"`
				} `json:"auth"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			token := randomToken()
			tokenHash := store.HashToken("agt_live_" + token)
			name := req.Name
			a := store.Actor{
				ActorID:     "act_" + uuid.NewString(),
				PrincipalID: req.PrincipalID,
				ActorType:   "AGENT",
				Status:      "ACTIVE",
				Name:        &name,
				Roles:       req.Auth.Scopes,
				CreatedAt:   time.Now(),
			}
			if err := st.CreateAgent(r.Context(), a, tokenHash, req.Auth.Scopes); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id": httpx.NewRequestID(),
				"agent": map[string]any{
					"actor_id":     a.ActorID,
					"principal_id": a.PrincipalID,
					"actor_type":   "AGENT",
					"name":         req.Name,
					"scopes":       req.Auth.Scopes,
					"created_at":   a.CreatedAt,
				},
				"credentials": map[string]any{
					"token":      "agt_live_" + token,
					"token_hint": "store once; not retrievable again",
				},
			})
		})

		api.Get("/actors", func(w http.ResponseWriter, r *http.Request) {
			principalID := r.URL.Query().Get("principal_id")
			typ := r.URL.Query().Get("type")
			var typPtr *string
			if typ != "" {
				typPtr = &typ
			}
			actors, err := st.ListActors(r.Context(), principalID, typPtr)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "actors": actors})
		})

		api.Post("/subjects:resolve", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID       string  `json:"principal_id"`
				ExternalSubjectID string  `json:"external_subject_id"`
				ActorTypeIfNeeded *string `json:"actor_type_if_needed"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.PrincipalID == "" || req.ExternalSubjectID == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "principal_id and external_subject_id are required", nil)
				return
			}
			subj, err := st.ResolveOrCreateSubject(r.Context(), req.PrincipalID, req.ExternalSubjectID, req.ActorTypeIfNeeded)
			if err != nil {
				if err == store.ErrActorTypeRequired {
					httpx.WriteError(w, 400, "NEEDS_ACTOR_TYPE", "actor_type_if_needed is required when no mapping exists", nil)
					return
				}
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"subject":    subj,
			})
		})

		api.Post("/invites", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
				Invitee     struct {
					Email string `json:"email"`
				} `json:"invitee"`
				RequestedRoles []string `json:"requested_roles"`
				ExpiresInHours int      `json:"expires_in_hours"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
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
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id":     httpx.NewRequestID(),
				"invite":         inv,
				"enrollment_url": "https://app.yourdomain.com/enroll?token=" + token,
			})
		})

		api.Get("/invites/{invite_id}", func(w http.ResponseWriter, r *http.Request) {
			id := chi.URLParam(r, "invite_id")
			inv, _, err := st.GetInvite(r.Context(), id)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "invite": inv})
		})

		api.Post("/webauthn/register/start", func(w http.ResponseWriter, r *http.Request) {
			// Legacy stub endpoint preserved for backward compatibility.
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "webauthn": map[string]any{"publicKey": map[string]any{}}})
		})

		// Dev stub enrollment: invite_token "dev:<invite_id>".
		api.Post("/webauthn/register/finish", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				InviteToken         string `json:"invite_token"`
				AttestationResponse any    `json:"attestation_response"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if len(req.InviteToken) < 5 || req.InviteToken[:4] != "dev:" {
				httpx.WriteError(w, 400, "BAD_TOKEN", "headless MVP supports invite_token dev:<invite_id>", nil)
				return
			}
			inviteID := req.InviteToken[4:]
			inv, _, err := st.GetInvite(r.Context(), inviteID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			actorID := "act_" + uuid.NewString()
			email := inv.Email
			a := store.Actor{
				ActorID: actorID, PrincipalID: inv.PrincipalID, ActorType: "HUMAN", Status: "ACTIVE",
				Email: &email, Roles: inv.RequestedRoles, CreatedAt: time.Now(),
			}
			if err := st.CreateHuman(r.Context(), a); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if err := st.CompleteInvite(r.Context(), inviteID, actorID); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "actor": a})
		})

		api.Post("/webauthn/credentials/register/start", func(w http.ResponseWriter, r *http.Request) {
			if !waCfg.Enabled {
				httpx.WriteError(w, 404, "NOT_FOUND", "webauthn is disabled", nil)
				return
			}
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "human bearer token required", nil)
				return
			}
			_, principalID, actorID, expiresAt, err := st.GetHumanAuthSession(r.Context(), store.HashToken(token))
			if err != nil || !expiresAt.After(time.Now().UTC()) {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid or expired session", nil)
				return
			}
			actor, err := st.GetActor(r.Context(), actorID)
			if err != nil || actor.PrincipalID != principalID || actor.ActorType != "HUMAN" || actor.Status != "ACTIVE" {
				httpx.WriteError(w, 403, "FORBIDDEN", "actor not eligible for webauthn registration", nil)
				return
			}
			registrationID := "wch_" + uuid.NewString()
			challengeBytes := randomBytes(32)
			expiresAtChallenge := time.Now().UTC().Add(waCfg.ChallengeTTL)
			ch := store.WebAuthnChallenge{
				ChallengeID:    registrationID,
				ChallengeType:  "REGISTRATION",
				PrincipalID:    principalID,
				ActorID:        actorID,
				Context:        "webauthn.register",
				ChallengeBytes: challengeBytes,
				ExpiresAt:      expiresAtChallenge,
			}
			if err := st.CreateWebAuthnChallenge(r.Context(), ch); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			userName := actorID
			if actor.Email != nil && strings.TrimSpace(*actor.Email) != "" {
				userName = strings.ToLower(strings.TrimSpace(*actor.Email))
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":      httpx.NewRequestID(),
				"registration_id": registrationID,
				"webauthn": map[string]any{
					"publicKey": map[string]any{
						"challenge": base64.RawURLEncoding.EncodeToString(challengeBytes),
						"rp": map[string]any{
							"id":   waCfg.RPID,
							"name": waCfg.RPName,
						},
						"user": map[string]any{
							"id":          base64.RawURLEncoding.EncodeToString([]byte(actorID)),
							"name":        userName,
							"displayName": userName,
						},
						"pubKeyCredParams": []map[string]any{
							{"type": "public-key", "alg": -7},
						},
						"timeout":                int(waCfg.ChallengeTTL / time.Millisecond),
						"attestation":            "none",
						"authenticatorSelection": map[string]any{"userVerification": "required"},
					},
				},
			})
		})

		api.Post("/webauthn/credentials/register/finish", func(w http.ResponseWriter, r *http.Request) {
			if !waCfg.Enabled {
				httpx.WriteError(w, 404, "NOT_FOUND", "webauthn is disabled", nil)
				return
			}
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "human bearer token required", nil)
				return
			}
			_, principalID, actorID, expiresAt, err := st.GetHumanAuthSession(r.Context(), store.HashToken(token))
			if err != nil || !expiresAt.After(time.Now().UTC()) {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid or expired session", nil)
				return
			}
			var req struct {
				RegistrationID string   `json:"registration_id"`
				CredentialID   string   `json:"credential_id"`
				PublicKey      string   `json:"public_key"`
				ClientDataJSON string   `json:"client_data_json"`
				Transports     []string `json:"transports"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.RegistrationID) == "" || strings.TrimSpace(req.CredentialID) == "" || strings.TrimSpace(req.PublicKey) == "" || strings.TrimSpace(req.ClientDataJSON) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "registration_id, credential_id, public_key, and client_data_json are required", nil)
				return
			}
			ch, err := st.ConsumeWebAuthnChallenge(r.Context(), strings.TrimSpace(req.RegistrationID), principalID, actorID, "REGISTRATION")
			if err != nil {
				httpx.WriteError(w, 400, "INVALID_CHALLENGE", err.Error(), nil)
				return
			}
			clientDataJSONBytes, err := decodeBase64URLNoPaddingStrict(req.ClientDataJSON)
			if err != nil {
				httpx.WriteError(w, 400, "BAD_REQUEST", "client_data_json must be base64url without padding", nil)
				return
			}
			clientData, err := parseWebAuthnClientData(clientDataJSONBytes)
			if err != nil {
				httpx.WriteError(w, 400, "BAD_REQUEST", "invalid client_data_json", nil)
				return
			}
			if strings.TrimSpace(clientData.Type) != "webauthn.create" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "client_data_json.type must be webauthn.create", nil)
				return
			}
			if !challengeMatches(clientData.Challenge, ch.ChallengeBytes) {
				httpx.WriteError(w, 400, "BAD_REQUEST", "registration challenge mismatch", nil)
				return
			}
			if !originAllowed(clientData.Origin, waCfg.AllowedOrigins) {
				httpx.WriteError(w, 400, "BAD_REQUEST", "origin not allowed", nil)
				return
			}

			credIDBytes, err := decodeBase64URLNoPaddingStrict(req.CredentialID)
			if err != nil {
				httpx.WriteError(w, 400, "BAD_REQUEST", "credential_id must be base64url without padding", nil)
				return
			}
			pubKeyBytes, err := decodeBase64URLNoPaddingStrict(req.PublicKey)
			if err != nil {
				httpx.WriteError(w, 400, "BAD_REQUEST", "public_key must be base64url without padding", nil)
				return
			}
			if err := validateP256SEC1PublicKey(pubKeyBytes); err != nil {
				httpx.WriteError(w, 400, "BAD_REQUEST", "public_key must be P-256 SEC1 uncompressed", nil)
				return
			}
			if err := st.UpsertWebAuthnCredential(r.Context(), store.WebAuthnCredential{
				CredentialID: base64.RawURLEncoding.EncodeToString(credIDBytes),
				ActorID:      actorID,
				PublicKey:    pubKeyBytes,
				SignCount:    0,
				RPID:         waCfg.RPID,
				Transports:   req.Transports,
			}); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":    httpx.NewRequestID(),
				"credential_id": base64.RawURLEncoding.EncodeToString(credIDBytes),
				"status":        "REGISTERED",
				"actor_id":      actorID,
				"principal_id":  principalID,
			})
		})

		api.Post("/webauthn/assertions/start", func(w http.ResponseWriter, r *http.Request) {
			if !waCfg.Enabled {
				httpx.WriteError(w, 404, "NOT_FOUND", "webauthn is disabled", nil)
				return
			}
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "human bearer token required", nil)
				return
			}
			_, principalID, actorID, expiresAt, err := st.GetHumanAuthSession(r.Context(), store.HashToken(token))
			if err != nil || !expiresAt.After(time.Now().UTC()) {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid or expired session", nil)
				return
			}
			var req struct {
				ApprovalRequestID string `json:"approval_request_id"`
				PayloadHash       string `json:"payload_hash"`
				Context           string `json:"context"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			req.Context = strings.TrimSpace(req.Context)
			if req.Context == "" {
				req.Context = "contract-action"
			}
			payloadHashHex := normalizeHashHex(strings.TrimSpace(req.PayloadHash))
			if payloadHashHex == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "payload_hash must be lowercase hex sha256", nil)
				return
			}
			creds, err := st.ListActiveWebAuthnCredentialsByActor(r.Context(), principalID, actorID, waCfg.RPID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			if len(creds) == 0 {
				httpx.WriteError(w, 400, "BAD_REQUEST", "no active webauthn credentials for actor", nil)
				return
			}
			challengeID := "wch_" + uuid.NewString()
			challengeBytes := randomBytes(32)
			payloadHashWithPrefix := "sha256:" + payloadHashHex
			challenge := store.WebAuthnChallenge{
				ChallengeID:       challengeID,
				ChallengeType:     "ASSERTION",
				PrincipalID:       principalID,
				ActorID:           actorID,
				ApprovalRequestID: stringPtr(strings.TrimSpace(req.ApprovalRequestID)),
				PayloadHash:       &payloadHashWithPrefix,
				Context:           req.Context,
				ChallengeBytes:    challengeBytes,
				ExpiresAt:         time.Now().UTC().Add(waCfg.ChallengeTTL),
			}
			if err := st.CreateWebAuthnChallenge(r.Context(), challenge); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			allow := make([]map[string]any, 0, len(creds))
			for _, c := range creds {
				allow = append(allow, map[string]any{
					"type": "public-key",
					"id":   c.CredentialID,
				})
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":   httpx.NewRequestID(),
				"challenge_id": challengeID,
				"webauthn": map[string]any{
					"publicKey": map[string]any{
						"challenge":        base64.RawURLEncoding.EncodeToString(challengeBytes),
						"rpId":             waCfg.RPID,
						"allowCredentials": allow,
						"userVerification": "required",
						"timeout":          int(waCfg.ChallengeTTL / time.Millisecond),
					},
				},
			})
		})

		api.Post("/auth/magic-link/start", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID string `json:"principal_id"`
				Email       string `json:"email"`
				RedirectURL string `json:"redirect_url"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if req.PrincipalID == "" || strings.TrimSpace(req.Email) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "principal_id and email are required", nil)
				return
			}
			actor, err := st.FindActiveHumanByEmail(r.Context(), req.PrincipalID, req.Email)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "active human actor not found for email", nil)
				return
			}
			rawToken := "mlt_live_" + randomToken()
			tokenID := "mlt_" + uuid.NewString()
			expiresAt := time.Now().UTC().Add(15 * time.Minute)
			if err := st.CreateMagicLinkToken(r.Context(), tokenID, req.PrincipalID, actor.ActorID, strings.ToLower(strings.TrimSpace(req.Email)), store.HashToken(rawToken), expiresAt); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			magicURL := "https://app.yourdomain.com/auth/magic-link?token=" + rawToken
			if strings.TrimSpace(req.RedirectURL) != "" {
				magicURL += "&redirect_url=" + req.RedirectURL
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"challenge": map[string]any{
					"token_id":   tokenID,
					"expires_at": expiresAt,
				},
				"delivery": map[string]any{
					"channel": "email",
					"to":      strings.ToLower(strings.TrimSpace(req.Email)),
				},
				"magic_link_url": magicURL,
			})
		})

		api.Post("/auth/magic-link/finish", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Token string `json:"token"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.Token) == "" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "token is required", nil)
				return
			}
			principalID, actorID, _, err := st.ConsumeMagicLinkToken(r.Context(), store.HashToken(strings.TrimSpace(req.Token)))
			if err != nil {
				httpx.WriteError(w, 401, "INVALID_TOKEN", err.Error(), nil)
				return
			}
			sessionToken := "hum_live_" + randomToken()
			sessionID := "hse_" + uuid.NewString()
			expiresAt := time.Now().UTC().Add(8 * time.Hour)
			if err := st.CreateHumanAuthSession(r.Context(), sessionID, principalID, actorID, store.HashToken(sessionToken), expiresAt); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			actor, err := st.GetActor(r.Context(), actorID)
			if err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"actor":      actor,
				"session": map[string]any{
					"session_id":  sessionID,
					"auth_method": "MAGIC_LINK",
					"expires_at":  expiresAt,
				},
				"credentials": map[string]any{
					"token":      sessionToken,
					"token_hint": "store once; not retrievable again",
				},
			})
		})

		api.Get("/auth/me", func(w http.ResponseWriter, r *http.Request) {
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "human bearer token required", nil)
				return
			}
			sessionID, principalID, actorID, expiresAt, err := st.GetHumanAuthSession(r.Context(), store.HashToken(token))
			if err != nil || !expiresAt.After(time.Now().UTC()) {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid or expired session", nil)
				return
			}
			actor, err := st.GetActor(r.Context(), actorID)
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid session actor", nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"session": map[string]any{
					"session_id":   sessionID,
					"principal_id": principalID,
					"actor_id":     actorID,
					"expires_at":   expiresAt,
					"auth_method":  "MAGIC_LINK",
				},
				"actor": actor,
			})
		})

		api.Post("/delegations", func(w http.ResponseWriter, r *http.Request) {
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "bearer token required", nil)
				return
			}
			caller, err := st.ResolveBearerIdentity(r.Context(), token)
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid bearer token", nil)
				return
			}

			var req struct {
				PrincipalID      string                     `json:"principal_id"`
				DelegatorActorID string                     `json:"delegator_actor_id"`
				DelegateActorID  string                     `json:"delegate_actor_id"`
				Scope            domain.DelegationScope     `json:"scope"`
				ExpiresAt        *string                    `json:"expires_at"`
				Signature        domain.DelegationSignature `json:"signature"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			if strings.TrimSpace(req.PrincipalID) != "" && req.PrincipalID != caller.PrincipalID {
				httpx.WriteError(w, 403, "FORBIDDEN", "principal mismatch", nil)
				return
			}
			if caller.ActorID != req.DelegatorActorID {
				httpx.WriteError(w, 403, "FORBIDDEN", "delegator must match authenticated actor", nil)
				return
			}
			delegator, err := st.GetActor(r.Context(), req.DelegatorActorID)
			if err != nil || delegator.PrincipalID != caller.PrincipalID || delegator.ActorType != "HUMAN" {
				httpx.WriteError(w, 403, "FORBIDDEN", "delegator must be active human in principal", nil)
				return
			}
			delegate, err := st.GetActor(r.Context(), req.DelegateActorID)
			if err != nil || delegate.PrincipalID != caller.PrincipalID || delegate.ActorType != "AGENT" {
				httpx.WriteError(w, 400, "BAD_REQUEST", "delegate_actor_id must be an AGENT in principal", nil)
				return
			}
			if err := validateDelegationScope(req.Scope); err != nil {
				httpx.WriteError(w, 422, "INVALID_SCOPE", err.Error(), nil)
				return
			}
			var expiresAt *time.Time
			if req.ExpiresAt != nil && strings.TrimSpace(*req.ExpiresAt) != "" {
				tm, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.ExpiresAt))
				if err != nil {
					httpx.WriteError(w, 422, "INVALID_EXPIRES_AT", "expires_at must be RFC3339", nil)
					return
				}
				u := tm.UTC()
				expiresAt = &u
			}
			issuedAt := time.Now().UTC()
			payload := buildDelegationCreatePayload(caller.PrincipalID, req.DelegatorActorID, req.DelegateActorID, req.Scope, expiresAt)
			if err := verifyDelegationSignature(payload, req.Signature); err != nil {
				httpx.WriteError(w, 401, "INVALID_SIGNATURE", err.Error(), nil)
				return
			}
			rec := domain.DelegationRecord{
				DelegationID:     "dlg_" + uuid.NewString(),
				PrincipalID:      caller.PrincipalID,
				DelegatorActorID: req.DelegatorActorID,
				DelegateActorID:  req.DelegateActorID,
				Scope:            req.Scope,
				IssuedAt:         issuedAt,
				ExpiresAt:        expiresAt,
				Signature:        req.Signature,
			}
			if err := st.CreateDelegation(r.Context(), rec); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 201, map[string]any{
				"request_id":    httpx.NewRequestID(),
				"delegation_id": rec.DelegationID,
				"status":        "CREATED",
			})
		})

		api.Post("/delegations/{delegation_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
			token, ok := parseBearer(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "bearer token required", nil)
				return
			}
			caller, err := st.ResolveBearerIdentity(r.Context(), token)
			if err != nil {
				httpx.WriteError(w, 401, "UNAUTHORIZED", "invalid bearer token", nil)
				return
			}
			delegationID := chi.URLParam(r, "delegation_id")
			rec, err := st.GetDelegation(r.Context(), delegationID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", "delegation not found", nil)
				return
			}
			if rec.PrincipalID != caller.PrincipalID {
				httpx.WriteError(w, 403, "FORBIDDEN", "principal mismatch", nil)
				return
			}
			if rec.DelegatorActorID != caller.ActorID {
				httpx.WriteError(w, 403, "FORBIDDEN", "only delegator can revoke", nil)
				return
			}
			var req struct {
				RevokedAt *string                    `json:"revoked_at"`
				Signature domain.DelegationSignature `json:"signature"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			revokedAt := time.Now().UTC()
			if req.RevokedAt != nil && strings.TrimSpace(*req.RevokedAt) != "" {
				tm, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.RevokedAt))
				if err != nil {
					httpx.WriteError(w, 422, "INVALID_REVOKED_AT", "revoked_at must be RFC3339", nil)
					return
				}
				revokedAt = tm.UTC()
			}
			payload := buildDelegationRevokePayload(rec.PrincipalID, rec.DelegationID, rec.DelegatorActorID, rec.DelegateActorID, revokedAt)
			if err := verifyDelegationSignature(payload, req.Signature); err != nil {
				httpx.WriteError(w, 401, "INVALID_SIGNATURE", err.Error(), nil)
				return
			}
			if err := st.RevokeDelegation(r.Context(), delegationID, revokedAt); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":    httpx.NewRequestID(),
				"delegation_id": delegationID,
				"status":        "REVOKED",
			})
		})

		// Signature verification backed by real human session when provided.
		api.Post("/verify-signature", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				PrincipalID       string         `json:"principal_id"`
				ActorID           string         `json:"actor_id"`
				SignatureType     string         `json:"signature_type"`
				PayloadHash       string         `json:"payload_hash"`
				Context           string         `json:"context"`
				SignatureEnvelope map[string]any `json:"signature_envelope"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			actor, err := st.GetActor(r.Context(), req.ActorID)
			if err != nil || actor.PrincipalID != req.PrincipalID {
				httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "valid": false, "actor_status": "UNKNOWN", "reason": "unknown_actor"})
				return
			}
			if strings.TrimSpace(req.SignatureType) == "" && req.SignatureEnvelope != nil {
				if strings.TrimSpace(fmt.Sprint(req.SignatureEnvelope["version"])) == "sig-v3" {
					req.SignatureType = "sig-v3-webauthn"
				}
			}
			if strings.EqualFold(strings.TrimSpace(req.SignatureType), "sig-v3-webauthn") {
				if !waCfg.Enabled {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "sig_v3_disabled",
					})
					return
				}
				if req.SignatureEnvelope == nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "missing_signature_envelope",
					})
					return
				}
				envV3, err := signature.ParseEnvelopeV3Strict(req.SignatureEnvelope)
				if err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "invalid_sig_v3_envelope",
					})
					return
				}
				credentialID := strings.TrimSpace(envV3.CredentialID)
				cred, err := st.GetWebAuthnCredential(r.Context(), req.PrincipalID, req.ActorID, credentialID)
				if err != nil || cred.RevokedAt != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "credential_not_found",
					})
					return
				}
				ch, err := st.ConsumeWebAuthnChallenge(r.Context(), strings.TrimSpace(envV3.ChallengeID), req.PrincipalID, req.ActorID, "ASSERTION")
				if err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "invalid_or_used_challenge",
					})
					return
				}
				expectedHash := normalizeHashHex(strings.TrimSpace(req.PayloadHash))
				if expectedHash == "" && ch.PayloadHash != nil {
					expectedHash = normalizeHashHex(strings.TrimPrefix(strings.TrimSpace(*ch.PayloadHash), "sha256:"))
				}
				if expectedHash == "" {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "missing_payload_hash",
					})
					return
				}
				expectedContext := strings.TrimSpace(ch.Context)
				if expectedContext == "" {
					expectedContext = "contract-action"
				}
				verifyResult, err := signature.VerifyEnvelopeV3WithExpectedHash(expectedHash, envV3, signature.VerifyEnvelopeV3Options{
					ExpectedContext:         expectedContext,
					ExpectedChallengeBytes:  ch.ChallengeBytes,
					AllowedOrigins:          waCfg.AllowedOrigins,
					ExpectedRPID:            waCfg.RPID,
					ExpectedCredentialID:    credentialID,
					CredentialPublicKeySec1: cred.PublicKey,
					RequireUserPresence:     true,
					RequireUserVerification: true,
					PreviousSignCount:       uint32(maxInt64(cred.SignCount, 0)),
				})
				if err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "signature_verification_failed",
					})
					return
				}
				if err := st.UpdateWebAuthnCredentialUsage(r.Context(), cred.CredentialID, int64(verifyResult.SignCount), time.Now().UTC()); err != nil {
					httpx.WriteJSON(w, 200, map[string]any{
						"request_id":   httpx.NewRequestID(),
						"valid":        false,
						"actor_status": actor.Status,
						"reason":       "credential_update_failed",
					})
					return
				}
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id":   httpx.NewRequestID(),
					"valid":        actor.Status == "ACTIVE" && actor.ActorType == "HUMAN",
					"actor_status": actor.Status,
					"auth_method":  "WEBAUTHN_SIG_V3",
					"reason":       "verified",
				})
				return
			}
			token, hasBearer := parseBearer(r.Header.Get("Authorization"))
			if hasBearer {
				sessionID, principalID, actorID, expiresAt, err := st.GetHumanAuthSession(r.Context(), store.HashToken(token))
				if err != nil || !expiresAt.After(time.Now().UTC()) || principalID != req.PrincipalID || actorID != req.ActorID {
					httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "valid": false, "actor_status": actor.Status, "reason": "invalid_session"})
					return
				}
				httpx.WriteJSON(w, 200, map[string]any{
					"request_id":   httpx.NewRequestID(),
					"valid":        actor.Status == "ACTIVE" && actor.ActorType == "HUMAN",
					"actor_status": actor.Status,
					"session_id":   sessionID,
					"auth_method":  "MAGIC_LINK",
					"reason":       "verified",
				})
				return
			}
			allowDevBypass := strings.ToLower(strings.TrimSpace(os.Getenv("IAL_ALLOW_DEV_SIGNATURE_BYPASS"))) != "false"
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id":   httpx.NewRequestID(),
				"valid":        allowDevBypass && actor.Status == "ACTIVE" && actor.ActorType == "HUMAN",
				"actor_status": actor.Status,
				"auth_method":  "DEV_BYPASS",
				"reason":       "dev_bypass",
			})
		})

		api.Put("/actors/{actor_id}/policy-profile", func(w http.ResponseWriter, r *http.Request) {
			actorID := chi.URLParam(r, "actor_id")
			var req struct {
				PrincipalID     string            `json:"principal_id"`
				AutomationLevel string            `json:"automation_level"`
				ActionGates     map[string]string `json:"action_gates"`
				VariableRules   []map[string]any  `json:"variable_rules"`
			}
			if err := httpx.ReadJSON(r, &req); err != nil {
				httpx.WriteError(w, 400, "BAD_JSON", err.Error(), nil)
				return
			}
			ag, _ := json.Marshal(req.ActionGates)
			vr, _ := json.Marshal(req.VariableRules)
			if err := st.UpsertPolicyProfile(r.Context(), actorID, req.PrincipalID, req.AutomationLevel, ag, vr); err != nil {
				httpx.WriteError(w, 500, "DB_ERROR", err.Error(), nil)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"policy_profile": map[string]any{
					"actor_id":         actorID,
					"automation_level": req.AutomationLevel,
					"action_gates":     req.ActionGates,
					"variable_rules":   req.VariableRules,
				},
			})
		})

		api.Get("/actors/{actor_id}/policy-profile", func(w http.ResponseWriter, r *http.Request) {
			actorID := chi.URLParam(r, "actor_id")
			principalID, level, ag, vr, err := st.GetPolicyProfile(r.Context(), actorID)
			if err != nil {
				httpx.WriteError(w, 404, "NOT_FOUND", err.Error(), nil)
				return
			}
			var agObj any
			var vrObj any
			_ = json.Unmarshal(ag, &agObj)
			_ = json.Unmarshal(vr, &vrObj)
			httpx.WriteJSON(w, 200, map[string]any{
				"request_id": httpx.NewRequestID(),
				"policy_profile": map[string]any{
					"actor_id":         actorID,
					"principal_id":     principalID,
					"automation_level": level,
					"action_gates":     agObj,
					"variable_rules":   vrObj,
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

func parseBearer(authorization string) (string, bool) {
	if strings.TrimSpace(authorization) == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	if tok == "" {
		return "", false
	}
	return tok, true
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

func validateDelegationScope(scope domain.DelegationScope) error {
	if len(scope.Actions) == 0 {
		return fmt.Errorf("scope.actions must not be empty")
	}
	allowed := map[string]struct{}{
		"contract.execute": {},
		"gate.resolve":     {},
	}
	for _, action := range scope.Actions {
		if _, ok := allowed[action]; !ok {
			return fmt.Errorf("unsupported scope action: %s", action)
		}
	}
	switch strings.TrimSpace(scope.MaxRiskLevel) {
	case "", "LOW", "MEDIUM", "HIGH":
	default:
		return fmt.Errorf("scope.max_risk_level must be LOW, MEDIUM, HIGH, or empty")
	}
	return nil
}

func verifyDelegationSignature(payload map[string]any, sig domain.DelegationSignature) error {
	if strings.TrimSpace(sig.Algorithm) == "" || strings.TrimSpace(sig.SignedPayloadHash) == "" || strings.TrimSpace(sig.SignatureBytes) == "" {
		return fmt.Errorf("signature.algorithm, signature.signed_payload_hash, and signature.signature_bytes are required")
	}
	if sig.Algorithm != "HMAC-SHA256" {
		return fmt.Errorf("unsupported delegation signature algorithm")
	}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return err
	}
	expectedPayloadHash := "sha256:" + hashHex
	if sig.SignedPayloadHash != expectedPayloadHash {
		return fmt.Errorf("signed_payload_hash mismatch")
	}
	secret := strings.TrimSpace(os.Getenv("IAL_DELEGATION_HMAC_SECRET"))
	if secret == "" {
		secret = "dev_delegation_secret"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(sig.SignedPayloadHash))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(sig.SignatureBytes)) {
		return fmt.Errorf("invalid delegation signature")
	}
	return nil
}

func buildDelegationCreatePayload(principalID, delegatorActorID, delegateActorID string, scope domain.DelegationScope, expiresAt *time.Time) map[string]any {
	scopePayload := map[string]any{
		"actions":        scope.Actions,
		"templates":      scope.Templates,
		"max_risk_level": scope.MaxRiskLevel,
	}
	payload := map[string]any{
		"principal_id":       principalID,
		"delegator_actor_id": delegatorActorID,
		"delegate_actor_id":  delegateActorID,
		"scope":              scopePayload,
		"expires_at":         nil,
		"delegation_version": "delegation-v1",
	}
	if expiresAt != nil {
		payload["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	return payload
}

func buildDelegationRevokePayload(principalID, delegationID, delegatorActorID, delegateActorID string, revokedAt time.Time) map[string]any {
	return map[string]any{
		"principal_id":       principalID,
		"delegation_id":      delegationID,
		"delegator_actor_id": delegatorActorID,
		"delegate_actor_id":  delegateActorID,
		"revoked_at":         revokedAt.UTC().Format(time.RFC3339),
		"delegation_version": "delegation-v1",
	}
}

func envBoolDefault(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
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
	return v
}

func randomBytes(n int) []byte {
	if n <= 0 {
		n = 32
	}
	out := make([]byte, n)
	_, _ = rand.Read(out)
	return out
}

func decodeBase64URLNoPaddingStrict(in string) ([]byte, error) {
	s := strings.TrimSpace(in)
	if s == "" || strings.Contains(s, "=") {
		return nil, fmt.Errorf("invalid base64url value")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, fmt.Errorf("invalid base64url value")
		}
	}
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(out) != s {
		return nil, fmt.Errorf("invalid base64url value")
	}
	return out, nil
}

func validateP256SEC1PublicKey(pub []byte) error {
	if len(pub) != 65 || pub[0] != 0x04 {
		return fmt.Errorf("invalid public key encoding")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("invalid public key point")
	}
	return nil
}

func normalizeHashHex(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func parseWebAuthnClientData(raw []byte) (signatureClientData, error) {
	var out signatureClientData
	if err := json.Unmarshal(raw, &out); err != nil {
		return signatureClientData{}, err
	}
	if strings.TrimSpace(out.Type) == "" || strings.TrimSpace(out.Challenge) == "" || strings.TrimSpace(out.Origin) == "" {
		return signatureClientData{}, fmt.Errorf("missing fields")
	}
	return out, nil
}

type signatureClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func challengeMatches(clientChallengeB64URL string, expected []byte) bool {
	got, err := decodeBase64URLNoPaddingStrict(clientChallengeB64URL)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}

func originAllowed(origin string, allowed []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}
	for _, a := range allowed {
		if origin == strings.TrimSpace(a) {
			return true
		}
	}
	return false
}

func stringPtr(v string) *string {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil
	}
	return &s
}

func maxInt64(v, min int64) int64 {
	if v < min {
		return min
	}
	return v
}
