package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"contractlane/pkg/domain"
	"contractlane/pkg/httpx"
	"contractlane/services/cel/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	templateVarKeyRe       = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	templateVersionRe      = regexp.MustCompile(`^v[0-9]+$`)
	templateMoneyValueRe   = regexp.MustCompile(`^[A-Z]{3}\s+-?[0-9]+(\.[0-9]{1,2})?$`)
	templateAllowedActions = map[string]struct{}{
		"SEND_FOR_SIGNATURE": {},
		"DRAFT_CREATED":      {},
		"POLICY_VALIDATED":   {},
		"RENDERED":           {},
		"READY_TO_SIGN":      {},
		"SIGNATURE_SENT":     {},
		"SIGNED_BY_US":       {},
		"SIGNED_BY_THEM":     {},
		"EFFECTIVE":          {},
		"ARCHIVED":           {},
	}
	templateAllowedGateValues = map[string]struct{}{
		"FORCE_HUMAN":      {},
		"ALLOW_AUTOMATION": {},
		"DEFER":            {},
	}
	templateAllowedConstraintKeysByType = map[string]map[string]struct{}{
		string(domain.VarInt): {
			"allowed_values": {},
			"min_int":        {},
			"max_int":        {},
		},
		string(domain.VarMoney): {
			"allowed_values": {},
			"min_money":      {},
			"max_money":      {},
		},
		string(domain.VarString): {
			"allowed_values": {},
		},
		string(domain.VarDate): {
			"allowed_values": {},
		},
		string(domain.VarDuration): {
			"allowed_values": {},
		},
		string(domain.VarAddress): {
			"allowed_values": {},
		},
	}
)

type templateAdminUpsertRequest struct {
	TemplateID      string                        `json:"template_id"`
	TemplateVersion string                        `json:"template_version"`
	ContractType    string                        `json:"contract_type"`
	Jurisdiction    string                        `json:"jurisdiction"`
	DisplayName     string                        `json:"display_name"`
	RiskTier        string                        `json:"risk_tier"`
	Visibility      string                        `json:"visibility"`
	OwnerPrincipal  *string                       `json:"owner_principal_id"`
	Metadata        map[string]any                `json:"metadata"`
	TemplateGates   map[string]string             `json:"template_gates"`
	ProtectedSlots  []string                      `json:"protected_slots"`
	ProhibitedSlots []string                      `json:"prohibited_slots"`
	Variables       []store.TemplateVariableInput `json:"variables"`
}

type templateAdminCloneRequest struct {
	TemplateID      string         `json:"template_id"`
	TemplateVersion string         `json:"template_version,omitempty"`
	DisplayName     *string        `json:"display_name,omitempty"`
	Visibility      *string        `json:"visibility,omitempty"`
	OwnerPrincipal  *string        `json:"owner_principal_id,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type templateAdminShareRequest struct {
	PrincipalID string `json:"principal_id"`
}

type TemplateLintIssue struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type TemplateLintError struct {
	Issues []TemplateLintIssue
}

var requireBearerAgentScopeFn = requireBearerAgentScope

func (e *TemplateLintError) add(path, code, message string) {
	e.Issues = append(e.Issues, TemplateLintIssue{
		Path:    strings.TrimSpace(path),
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	})
}

func (e *TemplateLintError) hasIssues() bool { return len(e.Issues) > 0 }

func (e *TemplateLintError) sort() {
	sort.Slice(e.Issues, func(i, j int) bool {
		if e.Issues[i].Path != e.Issues[j].Path {
			return e.Issues[i].Path < e.Issues[j].Path
		}
		if e.Issues[i].Code != e.Issues[j].Code {
			return e.Issues[i].Code < e.Issues[j].Code
		}
		return e.Issues[i].Message < e.Issues[j].Message
	})
}

func (e *TemplateLintError) Error() string {
	if len(e.Issues) == 0 {
		return "template validation failed"
	}
	first := e.Issues[0]
	return fmt.Sprintf("template validation failed at %s: %s", first.Path, first.Message)
}

func registerTemplateAdminRoutes(api chi.Router, st *store.Store, pool *pgxpool.Pool, cfg hostedModeConfig) {
	api.Get("/admin/templates", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		filter := store.TemplateAdminListFilter{
			Status:           strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("status"))),
			Visibility:       strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("visibility"))),
			OwnerPrincipalID: strings.TrimSpace(r.URL.Query().Get("owner_principal_id")),
			ContractType:     strings.TrimSpace(r.URL.Query().Get("contract_type")),
			Jurisdiction:     strings.TrimSpace(r.URL.Query().Get("jurisdiction")),
		}
		templates, err := st.ListAdminTemplates(r.Context(), filter)
		if err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{
			"request_id": httpx.NewRequestID(),
			"admin":      adminSubject,
			"templates":  templates,
		})
	})

	api.Get("/admin/templates/{template_id}", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		tpl, gates, vars, protectedSlots, prohibitedSlots, err := st.GetTemplateWithGovernance(r.Context(), templateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{
			"request_id":       httpx.NewRequestID(),
			"admin":            adminSubject,
			"template":         tpl,
			"template_gates":   gates,
			"variables":        vars,
			"protected_slots":  protectedSlots,
			"prohibited_slots": prohibitedSlots,
		})
	})

	api.Post("/admin/templates", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		endpoint := "POST /cel/admin/templates"
		if replayed, idemKey := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			_ = idemKey
			return
		}

		var req templateAdminUpsertRequest
		if !readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req) {
			return
		}
		if err := validateTemplateAdminRequest(req, true); err != nil {
			var lintErr *TemplateLintError
			if errors.As(err, &lintErr) {
				writeTemplateLintError(w, lintErr)
				return
			}
			writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
			return
		}
		in := mapTemplateAdminUpsert(req)
		in.Status = "DRAFT"
		if err := st.CreateAdminTemplate(r.Context(), in); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), in.TemplateID, "CREATE", adminSubject, nil, in.OwnerPrincipalID, map[string]any{
			"visibility": in.Visibility,
			"status":     in.Status,
		})
		resp := map[string]any{
			"request_id":  httpx.NewRequestID(),
			"template_id": in.TemplateID,
			"status":      "DRAFT",
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 201, resp)
	})

	api.Put("/admin/templates/{template_id}", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		endpoint := fmt.Sprintf("PUT /cel/admin/templates/%s", templateID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}

		var req templateAdminUpsertRequest
		if !readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req) {
			return
		}
		req.TemplateID = templateID
		if err := validateTemplateAdminRequest(req, false); err != nil {
			var lintErr *TemplateLintError
			if errors.As(err, &lintErr) {
				writeTemplateLintError(w, lintErr)
				return
			}
			writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
			return
		}
		current, err := st.GetTemplate(r.Context(), templateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		if strings.EqualFold(strings.TrimSpace(current.Status), "ARCHIVED") {
			writeStandardError(w, 409, "CONFLICT", "archived template cannot be updated", "")
			return
		}
		in := mapTemplateAdminUpsert(req)
		in.Status = current.Status
		if err := st.UpdateAdminTemplate(r.Context(), in); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), in.TemplateID, "UPDATE", adminSubject, nil, in.OwnerPrincipalID, map[string]any{
			"visibility": in.Visibility,
		})
		resp := map[string]any{
			"request_id":  httpx.NewRequestID(),
			"template_id": in.TemplateID,
			"updated":     true,
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 200, resp)
	})

	api.Post("/admin/templates/{template_id}:publish", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		endpoint := fmt.Sprintf("POST /cel/admin/templates/%s:publish", templateID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}
		tpl, gates, vars, _, _, err := st.GetTemplateWithGovernance(r.Context(), templateID)
		if err != nil {
			writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
			return
		}
		if err := validateTemplatePublishReady(tpl, gates, vars); err != nil {
			var lintErr *TemplateLintError
			if errors.As(err, &lintErr) {
				writeTemplateLintError(w, lintErr)
				return
			}
			writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
			return
		}
		if err := st.PublishTemplate(r.Context(), templateID, nil); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), templateID, "PUBLISH", adminSubject, nil, nil, nil)
		resp := map[string]any{
			"request_id":  httpx.NewRequestID(),
			"template_id": templateID,
			"status":      "PUBLISHED",
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 200, resp)
	})

	api.Post("/admin/templates/{template_id}:archive", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		endpoint := fmt.Sprintf("POST /cel/admin/templates/%s:archive", templateID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}
		if _, err := st.GetTemplate(r.Context(), templateID); err != nil {
			writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
			return
		}
		if err := st.ArchiveTemplate(r.Context(), templateID, nil); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), templateID, "ARCHIVE", adminSubject, nil, nil, nil)
		resp := map[string]any{
			"request_id":  httpx.NewRequestID(),
			"template_id": templateID,
			"status":      "ARCHIVED",
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 200, resp)
	})

	api.Post("/admin/templates/{template_id}:clone", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		sourceTemplateID := chi.URLParam(r, "template_id")
		endpoint := fmt.Sprintf("POST /cel/admin/templates/%s:clone", sourceTemplateID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}

		sourceTpl, err := st.GetTemplate(r.Context(), sourceTemplateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}

		var req templateAdminCloneRequest
		if !readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req) {
			return
		}
		in, err := validateTemplateCloneRequest(sourceTpl, sourceTemplateID, req)
		if err != nil {
			var lintErr *TemplateLintError
			if errors.As(err, &lintErr) {
				writeTemplateLintError(w, lintErr)
				return
			}
			writeStandardError(w, 400, "BAD_REQUEST", err.Error(), "")
			return
		}

		if err := st.CloneAdminTemplate(r.Context(), sourceTemplateID, in); err != nil {
			errText := strings.ToLower(strings.TrimSpace(err.Error()))
			if strings.Contains(errText, "duplicate key") || strings.Contains(errText, "unique") {
				writeStandardError(w, 409, "CONFLICT", "target template already exists", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), in.TargetTemplateID, "CLONE", adminSubject, nil, in.OwnerPrincipalID, map[string]any{
			"source_template_id": sourceTemplateID,
			"visibility":         in.Visibility,
		})
		resp := map[string]any{
			"request_id":         httpx.NewRequestID(),
			"template_id":        in.TargetTemplateID,
			"template_version":   in.TargetTemplateVersion,
			"status":             "DRAFT",
			"source_template_id": sourceTemplateID,
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 201, resp)
	})

	api.Get("/admin/templates/{template_id}/shares", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		tpl, err := st.GetTemplate(r.Context(), templateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		shares, err := st.ListTemplateShares(r.Context(), templateID)
		if err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{
			"request_id":  httpx.NewRequestID(),
			"admin":       adminSubject,
			"template_id": templateID,
			"visibility":  tpl.Visibility,
			"shares":      shares,
		})
	})

	api.Post("/admin/templates/{template_id}/shares", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		endpoint := fmt.Sprintf("POST /cel/admin/templates/%s/shares", templateID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}
		tpl, err := st.GetTemplate(r.Context(), templateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		if !strings.EqualFold(strings.TrimSpace(tpl.Visibility), "PRIVATE") {
			writeStandardError(w, 409, "CONFLICT", "template sharing is only valid for PRIVATE templates", "")
			return
		}
		var req templateAdminShareRequest
		if !readJSONWithLimit(w, r, cfg.HostedMaxBodyBytes, &req) {
			return
		}
		principalID := strings.TrimSpace(req.PrincipalID)
		if principalID == "" {
			writeStandardError(w, 400, "BAD_REQUEST", "principal_id is required", "")
			return
		}
		if tpl.OwnerPrincipalID != nil && strings.TrimSpace(*tpl.OwnerPrincipalID) == principalID {
			writeStandardError(w, 409, "CONFLICT", "owner principal is implicitly shared", "")
			return
		}
		if err := st.ShareTemplateWithPrincipal(r.Context(), templateID, principalID, adminSubject); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), templateID, "SHARE_ADD", adminSubject, nil, &principalID, nil)
		resp := map[string]any{
			"request_id":   httpx.NewRequestID(),
			"template_id":  templateID,
			"principal_id": principalID,
			"shared":       true,
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 200, resp)
	})

	api.Delete("/admin/templates/{template_id}/shares/{principal_id}", func(w http.ResponseWriter, r *http.Request) {
		adminSubject, ok := requireTemplateAdmin(r, w, pool, cfg)
		if !ok {
			return
		}
		templateID := chi.URLParam(r, "template_id")
		principalID := strings.TrimSpace(chi.URLParam(r, "principal_id"))
		endpoint := fmt.Sprintf("DELETE /cel/admin/templates/%s/shares/%s", templateID, principalID)
		if replayed, _ := replayTemplateAdminIdempotency(r, w, st, adminSubject, endpoint); replayed {
			return
		}
		tpl, err := st.GetTemplate(r.Context(), templateID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeStandardError(w, 404, "NOT_FOUND", "template not found", "")
				return
			}
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		if tpl.OwnerPrincipalID != nil && strings.TrimSpace(*tpl.OwnerPrincipalID) == principalID {
			writeStandardError(w, 409, "CONFLICT", "cannot remove owner principal share", "")
			return
		}
		if err := st.UnshareTemplateWithPrincipal(r.Context(), templateID, principalID); err != nil {
			writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
			return
		}
		_ = st.AddTemplateAdminAuditEvent(r.Context(), templateID, "SHARE_REMOVE", adminSubject, nil, &principalID, nil)
		resp := map[string]any{
			"request_id":   httpx.NewRequestID(),
			"template_id":  templateID,
			"principal_id": principalID,
			"shared":       false,
		}
		saveTemplateAdminIdempotencyAndWrite(r, w, st, adminSubject, endpoint, 200, resp)
	})
}

func requireTemplateAdmin(r *http.Request, w http.ResponseWriter, pool *pgxpool.Pool, cfg hostedModeConfig) (string, bool) {
	if !cfg.EnableTemplateAdminAPI {
		writeStandardError(w, 404, "NOT_FOUND", "not found", "")
		return "", false
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.TemplateAdminAuthMode))
	if mode == "" {
		mode = "bootstrap"
	}
	switch mode {
	case "bootstrap":
		token := strings.TrimSpace(cfg.TemplateAdminBootstrapToken)
		if token == "" {
			writeStandardError(w, 503, "ADMIN_DISABLED", "template admin is not configured", "")
			return "", false
		}
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
			writeStandardError(w, 401, "UNAUTHORIZED", "admin authentication required", "")
			return "", false
		}
		got := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if got != token {
			writeStandardError(w, 403, "FORBIDDEN", "invalid admin credentials", "")
			return "", false
		}
		return "bootstrap", true
	case "agent_scope":
		requiredScope := strings.TrimSpace(cfg.TemplateAdminRequiredScope)
		if requiredScope == "" {
			requiredScope = "cel.admin:templates"
		}
		agent, ok := requireBearerAgentScopeFn(r, w, pool, "TEMPLATE_ADMIN", requiredScope)
		if !ok || agent == nil {
			return "", false
		}
		return fmt.Sprintf("agent:%s/%s", agent.PrincipalID, agent.ActorID), true
	default:
		writeStandardError(w, 503, "ADMIN_DISABLED", "template admin auth mode is not configured", "")
		return "", false
	}
}

func replayTemplateAdminIdempotency(r *http.Request, w http.ResponseWriter, st *store.Store, adminSubject, endpoint string) (bool, string) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeStandardError(w, 400, "MISSING_IDEMPOTENCY_KEY", "Idempotency-Key header is required", "")
		return true, ""
	}
	status, body, found, err := st.GetTemplateAdminIdempotency(r.Context(), adminSubject, key, endpoint)
	if err != nil {
		writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
		return true, key
	}
	if found {
		httpx.WriteJSON(w, status, body)
		return true, key
	}
	return false, key
}

func saveTemplateAdminIdempotencyAndWrite(r *http.Request, w http.ResponseWriter, st *store.Store, adminSubject, endpoint string, status int, response map[string]any) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := st.SaveTemplateAdminIdempotency(r.Context(), adminSubject, key, endpoint, status, response); err != nil {
		writeStandardError(w, 500, "DB_ERROR", err.Error(), "")
		return
	}
	httpx.WriteJSON(w, status, response)
}

func validateTemplateAdminRequest(req templateAdminUpsertRequest, isCreate bool) error {
	lint := &TemplateLintError{}
	if isCreate && strings.TrimSpace(req.TemplateID) == "" {
		lint.add("template_id", "REQUIRED", "template_id is required")
	}
	if strings.TrimSpace(req.ContractType) == "" {
		lint.add("contract_type", "REQUIRED", "contract_type is required")
	}
	if strings.TrimSpace(req.Jurisdiction) == "" {
		lint.add("jurisdiction", "REQUIRED", "jurisdiction is required")
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		lint.add("display_name", "REQUIRED", "display_name is required")
	}
	risk := strings.ToUpper(strings.TrimSpace(req.RiskTier))
	switch risk {
	case "LOW", "MEDIUM", "HIGH":
	default:
		lint.add("risk_tier", "ENUM_INVALID", "risk_tier must be LOW|MEDIUM|HIGH")
	}
	vis := strings.ToUpper(strings.TrimSpace(req.Visibility))
	if vis == "" {
		vis = "GLOBAL"
	}
	switch vis {
	case "GLOBAL", "PRIVATE":
	default:
		lint.add("visibility", "ENUM_INVALID", "visibility must be GLOBAL|PRIVATE")
	}
	if vis == "PRIVATE" && (req.OwnerPrincipal == nil || strings.TrimSpace(*req.OwnerPrincipal) == "") {
		lint.add("owner_principal_id", "REQUIRED", "owner_principal_id is required for PRIVATE visibility")
	}
	if strings.TrimSpace(req.TemplateVersion) == "" {
		lint.add("template_version", "REQUIRED", "template_version is required")
	}
	if !templateVersionRe.MatchString(strings.TrimSpace(req.TemplateVersion)) {
		lint.add("template_version", "FORMAT_INVALID", "template_version must match v<integer>")
	}
	if expected := parseTemplateVersion(req.TemplateID); expected != "" && expected != strings.TrimSpace(req.TemplateVersion) {
		lint.add("template_id", "VERSION_MISMATCH", fmt.Sprintf("template_id version suffix (%s) must match template_version (%s)", expected, strings.TrimSpace(req.TemplateVersion)))
	}
	if len(req.Variables) == 0 {
		lint.add("variables", "REQUIRED", "variables must be non-empty")
	}
	if len(req.Variables) > 200 {
		lint.add("variables", "LIMIT_EXCEEDED", "variables count exceeds limit (200)")
	}
	if len(req.TemplateGates) > 64 {
		lint.add("template_gates", "LIMIT_EXCEEDED", "template_gates count exceeds limit (64)")
	}
	lintTemplateGates(req.TemplateGates, lint)
	lintTemplateVariables(req.Variables, lint)
	lintTemplateSlots(req.ProtectedSlots, req.ProhibitedSlots, req.Variables, lint)
	if len(req.Metadata) > 0 {
		b, _ := json.Marshal(req.Metadata)
		if len(b) > 8192 {
			lint.add("metadata", "LIMIT_EXCEEDED", "metadata exceeds size limit (8192 bytes)")
		}
	}
	if lint.hasIssues() {
		lint.sort()
		return lint
	}
	return nil
}

func validateTemplatePublishReady(tpl store.Template, gates map[string]string, vars []domain.VariableDefinition) error {
	lint := &TemplateLintError{}
	if strings.EqualFold(strings.TrimSpace(tpl.Status), "ARCHIVED") {
		lint.add("status", "STATE_INVALID", "archived template cannot be published")
	}
	if len(vars) == 0 {
		lint.add("variables", "REQUIRED", "published template must define at least one variable")
	}
	sendGate := ""
	for action, gate := range gates {
		if strings.EqualFold(strings.TrimSpace(action), "SEND_FOR_SIGNATURE") {
			sendGate = strings.ToUpper(strings.TrimSpace(gate))
			break
		}
	}
	if sendGate == "" {
		lint.add("template_gates.SEND_FOR_SIGNATURE", "REQUIRED", "published template must define SEND_FOR_SIGNATURE gate")
	} else if _, ok := templateAllowedGateValues[sendGate]; !ok {
		lint.add("template_gates.SEND_FOR_SIGNATURE", "GATE_INVALID", fmt.Sprintf("template_gates[SEND_FOR_SIGNATURE] has invalid gate value: %s", sendGate))
	}

	for i, v := range vars {
		if len(v.Constraints.AllowedValues) == 0 {
			continue
		}
		seen := map[string]struct{}{}
		for j, raw := range v.Constraints.AllowedValues {
			path := fmt.Sprintf("variables[%d].constraints.allowed_values[%d]", i, j)
			base := v
			base.Constraints.AllowedValues = nil
			canonical, err := domain.ValidateAndCanonicalize(base, raw)
			if err != nil {
				lint.add(path, "VALUE_INVALID", fmt.Sprintf("allowed_values entry is invalid for variable %s: %v", v.Key, err))
				continue
			}
			if canonical != raw {
				lint.add(path, "VALUE_NON_CANONICAL", fmt.Sprintf("allowed_values entry for variable %s must be canonical: %q", v.Key, canonical))
				continue
			}
			if _, dup := seen[canonical]; dup {
				lint.add(path, "DUPLICATE", fmt.Sprintf("duplicate allowed_values entry for variable %s: %s", v.Key, canonical))
				continue
			}
			seen[canonical] = struct{}{}
		}
	}
	if lint.hasIssues() {
		lint.sort()
		return lint
	}
	return nil
}

func validateTemplateCloneRequest(sourceTpl store.Template, sourceTemplateID string, req templateAdminCloneRequest) (store.TemplateAdminCloneInput, error) {
	lint := &TemplateLintError{}
	targetID := strings.TrimSpace(req.TemplateID)
	if targetID == "" {
		lint.add("template_id", "REQUIRED", "template_id is required")
	} else if targetID == sourceTemplateID {
		lint.add("template_id", "CONFLICT", "template_id must differ from source template_id")
	}

	version := strings.TrimSpace(req.TemplateVersion)
	if version == "" {
		if parsed := parseTemplateVersion(targetID); parsed != "" {
			version = parsed
		} else if strings.HasPrefix(strings.TrimSpace(sourceTpl.TemplateVersion), "v") {
			n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(sourceTpl.TemplateVersion), "v"))
			if err == nil && n >= 0 {
				version = fmt.Sprintf("v%d", n+1)
			}
		}
	}
	if version == "" {
		lint.add("template_version", "REQUIRED", "template_version is required when it cannot be inferred")
	} else if !templateVersionRe.MatchString(version) {
		lint.add("template_version", "FORMAT_INVALID", "template_version must match v<integer>")
	}
	if expected := parseTemplateVersion(targetID); expected != "" && expected != version {
		lint.add("template_id", "VERSION_MISMATCH", fmt.Sprintf("template_id version suffix (%s) must match template_version (%s)", expected, version))
	}

	var visibility *string
	if req.Visibility != nil {
		v := strings.ToUpper(strings.TrimSpace(*req.Visibility))
		switch v {
		case "GLOBAL", "PRIVATE":
			visibility = &v
		default:
			lint.add("visibility", "ENUM_INVALID", "visibility must be GLOBAL|PRIVATE")
		}
	}
	owner := req.OwnerPrincipal
	effectiveVisibility := strings.ToUpper(strings.TrimSpace(sourceTpl.Visibility))
	if visibility != nil {
		effectiveVisibility = *visibility
	}
	if effectiveVisibility == "PRIVATE" {
		if owner == nil {
			owner = sourceTpl.OwnerPrincipalID
		}
		if owner == nil || strings.TrimSpace(*owner) == "" {
			lint.add("owner_principal_id", "REQUIRED", "owner_principal_id is required for PRIVATE visibility")
		}
	}

	if lint.hasIssues() {
		lint.sort()
		return store.TemplateAdminCloneInput{}, lint
	}
	return store.TemplateAdminCloneInput{
		TargetTemplateID:      targetID,
		TargetTemplateVersion: version,
		DisplayName:           req.DisplayName,
		Visibility:            visibility,
		OwnerPrincipalID:      owner,
		Metadata:              req.Metadata,
	}, nil
}

func lintTemplateGates(gates map[string]string, lint *TemplateLintError) {
	keys := make([]string, 0, len(gates))
	for action := range gates {
		keys = append(keys, action)
	}
	sort.Strings(keys)
	for _, actionKey := range keys {
		action := strings.TrimSpace(strings.ToUpper(actionKey))
		gate := strings.TrimSpace(strings.ToUpper(gates[actionKey]))
		if _, ok := templateAllowedActions[action]; !ok {
			lint.add("template_gates."+action, "ACTION_UNSUPPORTED", fmt.Sprintf("template_gates contains unsupported action: %s", action))
		}
		if _, ok := templateAllowedGateValues[gate]; !ok {
			lint.add("template_gates."+action, "GATE_INVALID", fmt.Sprintf("template_gates[%s] has invalid gate value: %s", action, gate))
		}
	}
}

func lintTemplateVariables(vars []store.TemplateVariableInput, lint *TemplateLintError) {
	seen := map[string]struct{}{}
	for i, v := range vars {
		key := strings.TrimSpace(v.Key)
		path := fmt.Sprintf("variables[%d]", i)
		if !templateVarKeyRe.MatchString(key) {
			lint.add(path+".key", "FORMAT_INVALID", fmt.Sprintf("invalid variable key format: %s", key))
		}
		if _, dup := seen[key]; dup {
			lint.add(path+".key", "DUPLICATE", fmt.Sprintf("duplicate variable key: %s", key))
		}
		seen[key] = struct{}{}

		typ := strings.TrimSpace(strings.ToUpper(v.Type))
		if _, ok := templateAllowedConstraintKeysByType[typ]; !ok {
			lint.add(path+".type", "ENUM_INVALID", fmt.Sprintf("invalid variable type for key %s: %s", key, typ))
		}
		switch strings.TrimSpace(strings.ToUpper(v.Sensitivity)) {
		case string(domain.SensNone), string(domain.SensPII):
		default:
			lint.add(path+".sensitivity", "ENUM_INVALID", fmt.Sprintf("invalid sensitivity for key %s: %s", key, v.Sensitivity))
		}
		switch strings.TrimSpace(strings.ToUpper(v.SetPolicy)) {
		case string(domain.VarAgentAllowed), string(domain.VarHumanRequired), string(domain.VarAgentFillHumanReview), string(domain.VarDeferToIdentity):
		default:
			lint.add(path+".set_policy", "ENUM_INVALID", fmt.Sprintf("invalid set_policy for key %s: %s", key, v.SetPolicy))
		}
		lintVariableConstraints(typ, key, v.Constraints, path+".constraints", lint)
	}
}

func lintVariableConstraints(varType, key string, c map[string]any, path string, lint *TemplateLintError) {
	if c == nil {
		return
	}
	allowedKeys := templateAllowedConstraintKeysByType[varType]
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := allowedKeys[k]; !ok {
			lint.add(path+"."+k, "CONSTRAINT_DISALLOWED", fmt.Sprintf("constraint %s is not allowed for variable %s of type %s", k, key, varType))
		}
	}
	if av, ok := c["allowed_values"]; ok {
		switch x := av.(type) {
		case []any:
			for _, it := range x {
				if strings.TrimSpace(fmt.Sprint(it)) == "" {
					lint.add(path+".allowed_values", "VALUE_INVALID", fmt.Sprintf("allowed_values contains empty value for variable %s", key))
				}
			}
		default:
			lint.add(path+".allowed_values", "TYPE_INVALID", fmt.Sprintf("allowed_values must be array for variable %s", key))
		}
	}
	if varType == string(domain.VarInt) {
		minSet, min, err := constraintIntValue(c, "min_int")
		if err != nil {
			lint.add(path+".min_int", "VALUE_INVALID", fmt.Sprintf("min_int invalid for variable %s: %v", key, err))
		}
		maxSet, max, err := constraintIntValue(c, "max_int")
		if err != nil {
			lint.add(path+".max_int", "VALUE_INVALID", fmt.Sprintf("max_int invalid for variable %s: %v", key, err))
		}
		if minSet && maxSet && min > max {
			lint.add(path, "RANGE_INVALID", fmt.Sprintf("min_int cannot exceed max_int for variable %s", key))
		}
	}
	if varType == string(domain.VarMoney) {
		minSet, minCents, minCur, err := constraintMoneyValue(c, "min_money")
		if err != nil {
			lint.add(path+".min_money", "VALUE_INVALID", fmt.Sprintf("min_money invalid for variable %s: %v", key, err))
		}
		maxSet, maxCents, maxCur, err := constraintMoneyValue(c, "max_money")
		if err != nil {
			lint.add(path+".max_money", "VALUE_INVALID", fmt.Sprintf("max_money invalid for variable %s: %v", key, err))
		}
		if minSet && maxSet {
			if minCur != maxCur {
				lint.add(path, "CURRENCY_MISMATCH", fmt.Sprintf("min_money/max_money currency mismatch for variable %s", key))
			}
			if minCents > maxCents {
				lint.add(path, "RANGE_INVALID", fmt.Sprintf("min_money cannot exceed max_money for variable %s", key))
			}
		}
	}
}

func lintTemplateSlots(protectedSlots, prohibitedSlots []string, vars []store.TemplateVariableInput, lint *TemplateLintError) {
	keys := map[string]struct{}{}
	for _, v := range vars {
		keys[strings.TrimSpace(v.Key)] = struct{}{}
	}
	seenProtected := map[string]struct{}{}
	for i, slot := range protectedSlots {
		slot = strings.TrimSpace(slot)
		if slot == "" {
			lint.add(fmt.Sprintf("protected_slots[%d]", i), "VALUE_INVALID", "protected_slots cannot contain empty values")
			continue
		}
		if _, ok := keys[slot]; !ok {
			lint.add(fmt.Sprintf("protected_slots[%d]", i), "REFERENCE_INVALID", fmt.Sprintf("protected slot must reference existing variable key: %s", slot))
		}
		seenProtected[slot] = struct{}{}
	}
	for i, slot := range prohibitedSlots {
		slot = strings.TrimSpace(slot)
		if slot == "" {
			lint.add(fmt.Sprintf("prohibited_slots[%d]", i), "VALUE_INVALID", "prohibited_slots cannot contain empty values")
			continue
		}
		if _, ok := keys[slot]; !ok {
			lint.add(fmt.Sprintf("prohibited_slots[%d]", i), "REFERENCE_INVALID", fmt.Sprintf("prohibited slot must reference existing variable key: %s", slot))
		}
		if _, overlap := seenProtected[slot]; overlap {
			lint.add(fmt.Sprintf("prohibited_slots[%d]", i), "CONFLICT", fmt.Sprintf("slot cannot be both protected and prohibited: %s", slot))
		}
	}
}

func constraintIntValue(c map[string]any, key string) (bool, int64, error) {
	raw, ok := c[key]
	if !ok {
		return false, 0, nil
	}
	switch v := raw.(type) {
	case float64:
		if v != float64(int64(v)) {
			return false, 0, errors.New("must be integer")
		}
		return true, int64(v), nil
	case int64:
		return true, v, nil
	case int:
		return true, int64(v), nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return false, 0, err
		}
		return true, n, nil
	default:
		return false, 0, errors.New("must be integer")
	}
}

func constraintMoneyValue(c map[string]any, key string) (bool, int64, string, error) {
	raw, ok := c[key]
	if !ok {
		return false, 0, "", nil
	}
	s := strings.TrimSpace(fmt.Sprint(raw))
	if !templateMoneyValueRe.MatchString(s) {
		return false, 0, "", errors.New("must match 'USD 12.34'")
	}
	parts := strings.Fields(s)
	cur := parts[0]
	amount := parts[1]
	neg := strings.HasPrefix(amount, "-")
	if neg {
		amount = strings.TrimPrefix(amount, "-")
	}
	ip := amount
	fp := "00"
	if idx := strings.Index(amount, "."); idx >= 0 {
		ip = amount[:idx]
		fp = amount[idx+1:]
	}
	if len(fp) == 1 {
		fp += "0"
	}
	cents, err := strconv.ParseInt(ip+fp, 10, 64)
	if err != nil {
		return false, 0, "", err
	}
	if neg {
		cents = -cents
	}
	return true, cents, cur, nil
}

func mapTemplateAdminUpsert(req templateAdminUpsertRequest) store.TemplateAdminUpsert {
	vis := strings.ToUpper(strings.TrimSpace(req.Visibility))
	if vis == "" {
		vis = "GLOBAL"
	}
	return store.TemplateAdminUpsert{
		TemplateID:       strings.TrimSpace(req.TemplateID),
		TemplateVersion:  strings.TrimSpace(req.TemplateVersion),
		ContractType:     strings.TrimSpace(req.ContractType),
		Jurisdiction:     strings.TrimSpace(req.Jurisdiction),
		DisplayName:      strings.TrimSpace(req.DisplayName),
		RiskTier:         strings.ToUpper(strings.TrimSpace(req.RiskTier)),
		Visibility:       vis,
		OwnerPrincipalID: req.OwnerPrincipal,
		Metadata:         req.Metadata,
		TemplateGates:    req.TemplateGates,
		ProtectedSlots:   req.ProtectedSlots,
		ProhibitedSlots:  req.ProhibitedSlots,
		Variables:        req.Variables,
	}
}

func writeTemplateLintError(w http.ResponseWriter, lintErr *TemplateLintError) {
	if lintErr == nil {
		writeStandardError(w, 422, "TEMPLATE_LINT_FAILED", "template validation failed", "")
		return
	}
	lintErr.sort()
	httpx.WriteJSON(w, 422, map[string]any{
		"error": map[string]any{
			"code":    "TEMPLATE_LINT_FAILED",
			"message": "template validation failed",
			"details": lintErr.Issues,
		},
		"request_id": httpx.NewRequestID(),
	})
}
