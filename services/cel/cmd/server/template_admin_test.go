package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"contractlane/pkg/authn"
	"contractlane/pkg/domain"
	"contractlane/services/cel/internal/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateTemplateAdminRequest(t *testing.T) {
	owner := "prn_owner"
	req := templateAdminUpsertRequest{
		TemplateID:      "tpl_demo_v1",
		TemplateVersion: "v1",
		ContractType:    "NDA",
		Jurisdiction:    "US",
		DisplayName:     "Demo",
		RiskTier:        "LOW",
		Visibility:      "PRIVATE",
		OwnerPrincipal:  &owner,
		Variables: []store.TemplateVariableInput{
			{
				Key:         "effective_date",
				Type:        "DATE",
				Required:    true,
				Sensitivity: "NONE",
				SetPolicy:   "AGENT_ALLOWED",
				Constraints: map[string]any{},
			},
		},
	}
	if err := validateTemplateAdminRequest(req, true); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	req.Visibility = "PRIVATE"
	req.OwnerPrincipal = nil
	if err := validateTemplateAdminRequest(req, true); err == nil {
		t.Fatalf("expected owner validation error")
	}
}

func TestValidateTemplateAdminRequest_LintFailures(t *testing.T) {
	owner := "prn_owner"
	base := templateAdminUpsertRequest{
		TemplateID:      "tpl_demo_v1",
		TemplateVersion: "v1",
		ContractType:    "NDA",
		Jurisdiction:    "US",
		DisplayName:     "Demo",
		RiskTier:        "LOW",
		Visibility:      "PRIVATE",
		OwnerPrincipal:  &owner,
		TemplateGates:   map[string]string{"SEND_FOR_SIGNATURE": "DEFER"},
		Variables: []store.TemplateVariableInput{
			{
				Key:         "effective_date",
				Type:        "DATE",
				Required:    true,
				Sensitivity: "NONE",
				SetPolicy:   "AGENT_ALLOWED",
				Constraints: map[string]any{},
			},
		},
	}

	badGate := base
	badGate.TemplateGates = map[string]string{"NOT_A_REAL_ACTION": "DEFER"}
	if err := validateTemplateAdminRequest(badGate, true); err == nil {
		t.Fatalf("expected invalid action gate error")
	} else {
		assertLintIssue(t, err, "template_gates.NOT_A_REAL_ACTION", "ACTION_UNSUPPORTED")
	}

	badVarKey := base
	badVarKey.Variables[0].Key = "Bad-Key"
	if err := validateTemplateAdminRequest(badVarKey, true); err == nil {
		t.Fatalf("expected variable key format error")
	} else {
		assertLintIssue(t, err, "variables[0].key", "FORMAT_INVALID")
	}

	badVersion := base
	badVersion.TemplateVersion = "v2"
	if err := validateTemplateAdminRequest(badVersion, true); err == nil {
		t.Fatalf("expected template version mismatch error")
	} else {
		assertLintIssue(t, err, "template_id", "VERSION_MISMATCH")
	}

	badConstraint := base
	badConstraint.Variables[0].Constraints = map[string]any{"min_int": 1}
	if err := validateTemplateAdminRequest(badConstraint, true); err == nil {
		t.Fatalf("expected invalid constraint for type error")
	} else {
		assertLintIssue(t, err, "variables[0].constraints.min_int", "CONSTRAINT_DISALLOWED")
	}
}

func TestRequireTemplateAdmin(t *testing.T) {
	cfg := hostedModeConfig{
		EnableTemplateAdminAPI:      true,
		TemplateAdminAuthMode:       "bootstrap",
		TemplateAdminBootstrapToken: "topsecret",
	}
	req := httptest.NewRequest("GET", "/cel/admin/templates", nil)
	req.Header.Set("Authorization", "Bearer topsecret")
	w := httptest.NewRecorder()
	subject, ok := requireTemplateAdmin(req, w, nil, cfg)
	if !ok {
		t.Fatalf("expected auth success")
	}
	if subject != "bootstrap" {
		t.Fatalf("unexpected admin subject: %s", subject)
	}

	req2 := httptest.NewRequest("GET", "/cel/admin/templates", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	w2 := httptest.NewRecorder()
	if _, ok := requireTemplateAdmin(req2, w2, nil, cfg); ok {
		t.Fatalf("expected auth failure")
	}
	if w2.Code == 200 {
		t.Fatalf("expected non-200 status")
	}
	if !strings.Contains(w2.Body.String(), "FORBIDDEN") {
		t.Fatalf("expected forbidden response")
	}
}

func TestRequireTemplateAdmin_AgentScopeMode(t *testing.T) {
	orig := requireBearerAgentScopeFn
	t.Cleanup(func() { requireBearerAgentScopeFn = orig })

	requireBearerAgentScopeFn = func(r *http.Request, w http.ResponseWriter, pool *pgxpool.Pool, endpoint, requiredScope string) (*authn.AgentIdentity, bool) {
		if endpoint != "TEMPLATE_ADMIN" {
			t.Fatalf("unexpected endpoint: %s", endpoint)
		}
		if requiredScope != "cel.admin:templates" {
			t.Fatalf("unexpected scope: %s", requiredScope)
		}
		return &authn.AgentIdentity{PrincipalID: "prn_1", ActorID: "act_1"}, true
	}

	cfg := hostedModeConfig{
		EnableTemplateAdminAPI:     true,
		TemplateAdminAuthMode:      "agent_scope",
		TemplateAdminRequiredScope: "cel.admin:templates",
	}
	req := httptest.NewRequest("GET", "/cel/admin/templates", nil)
	w := httptest.NewRecorder()
	subject, ok := requireTemplateAdmin(req, w, nil, cfg)
	if !ok {
		t.Fatalf("expected auth success in agent_scope mode")
	}
	if subject != "agent:prn_1/act_1" {
		t.Fatalf("unexpected admin subject: %s", subject)
	}
}

func TestRequireTemplateAdmin_AgentScopeModeFailure(t *testing.T) {
	orig := requireBearerAgentScopeFn
	t.Cleanup(func() { requireBearerAgentScopeFn = orig })

	requireBearerAgentScopeFn = func(r *http.Request, w http.ResponseWriter, pool *pgxpool.Pool, endpoint, requiredScope string) (*authn.AgentIdentity, bool) {
		writeStandardError(w, 401, "UNAUTHORIZED", "agent authentication required", "")
		return nil, false
	}
	cfg := hostedModeConfig{
		EnableTemplateAdminAPI:     true,
		TemplateAdminAuthMode:      "agent_scope",
		TemplateAdminRequiredScope: "cel.admin:templates",
	}
	req := httptest.NewRequest("GET", "/cel/admin/templates", nil)
	w := httptest.NewRecorder()
	if _, ok := requireTemplateAdmin(req, w, nil, cfg); ok {
		t.Fatalf("expected auth failure in agent_scope mode")
	}
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestValidateTemplatePublishReady(t *testing.T) {
	tpl := store.Template{
		TemplateID:      "tpl_demo_v1",
		TemplateVersion: "v1",
		Status:          "DRAFT",
	}
	gates := map[string]string{"SEND_FOR_SIGNATURE": "DEFER"}
	vars := []domain.VariableDefinition{
		{
			Key:      "effective_date",
			Type:     domain.VarDate,
			Required: true,
			Constraints: domain.VariableConstraint{
				AllowedValues: []string{"2026-02-21"},
			},
		},
		{
			Key:  "price",
			Type: domain.VarMoney,
			Constraints: domain.VariableConstraint{
				AllowedValues: []string{"USD 49.00", "USD 49.10"},
			},
		},
	}
	if err := validateTemplatePublishReady(tpl, gates, vars); err != nil {
		t.Fatalf("expected publish-ready template, got %v", err)
	}
}

func TestValidateTemplatePublishReady_MissingSendForSignature(t *testing.T) {
	tpl := store.Template{TemplateID: "tpl_demo_v1", TemplateVersion: "v1", Status: "DRAFT"}
	vars := []domain.VariableDefinition{
		{Key: "effective_date", Type: domain.VarDate, Required: true},
	}
	err := validateTemplatePublishReady(tpl, map[string]string{"READY_TO_SIGN": "DEFER"}, vars)
	if err == nil {
		t.Fatalf("expected lint error")
	}
	assertLintIssue(t, err, "template_gates.SEND_FOR_SIGNATURE", "REQUIRED")
}

func TestValidateTemplatePublishReady_NonCanonicalAllowedValues(t *testing.T) {
	tpl := store.Template{TemplateID: "tpl_demo_v1", TemplateVersion: "v1", Status: "DRAFT"}
	gates := map[string]string{"SEND_FOR_SIGNATURE": "DEFER"}
	vars := []domain.VariableDefinition{
		{
			Key:  "price",
			Type: domain.VarMoney,
			Constraints: domain.VariableConstraint{
				AllowedValues: []string{"USD 49.0"},
			},
		},
	}
	err := validateTemplatePublishReady(tpl, gates, vars)
	if err == nil {
		t.Fatalf("expected lint error")
	}
	assertLintIssue(t, err, "variables[0].constraints.allowed_values[0]", "VALUE_NON_CANONICAL")
}

func TestValidateTemplateCloneRequest(t *testing.T) {
	source := store.Template{
		TemplateID:      "tpl_demo_v1",
		TemplateVersion: "v1",
		Visibility:      "PRIVATE",
		OwnerPrincipalID: func() *string {
			s := "prn_owner"
			return &s
		}(),
	}

	in, err := validateTemplateCloneRequest(source, source.TemplateID, templateAdminCloneRequest{
		TemplateID: "tpl_demo_v2",
	})
	if err != nil {
		t.Fatalf("expected valid clone request, got %v", err)
	}
	if in.TargetTemplateVersion != "v2" {
		t.Fatalf("expected inferred target version v2, got %s", in.TargetTemplateVersion)
	}
	if in.OwnerPrincipalID == nil || *in.OwnerPrincipalID != "prn_owner" {
		t.Fatalf("expected owner to inherit source owner, got %v", in.OwnerPrincipalID)
	}
}

func TestValidateTemplateCloneRequest_LintFailures(t *testing.T) {
	source := store.Template{
		TemplateID:      "tpl_demo_v1",
		TemplateVersion: "v1",
		Visibility:      "GLOBAL",
	}

	_, err := validateTemplateCloneRequest(source, source.TemplateID, templateAdminCloneRequest{
		TemplateID:      "tpl_demo_v2",
		TemplateVersion: "v3",
	})
	if err == nil {
		t.Fatalf("expected mismatch lint error")
	}
	assertLintIssue(t, err, "template_id", "VERSION_MISMATCH")

	private := "PRIVATE"
	_, err = validateTemplateCloneRequest(source, source.TemplateID, templateAdminCloneRequest{
		TemplateID: "tpl_new_v2",
		Visibility: &private,
	})
	if err == nil {
		t.Fatalf("expected owner required lint error")
	}
	assertLintIssue(t, err, "owner_principal_id", "REQUIRED")
}

func assertLintIssue(t *testing.T, err error, path, code string) {
	t.Helper()
	var lintErr *TemplateLintError
	if !errors.As(err, &lintErr) {
		t.Fatalf("expected TemplateLintError, got %T (%v)", err, err)
	}
	for _, issue := range lintErr.Issues {
		if issue.Path == path && issue.Code == code {
			return
		}
	}
	t.Fatalf("expected lint issue path=%s code=%s, got %+v", path, code, lintErr.Issues)
}
