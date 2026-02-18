package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnauthorized = errors.New("unauthorized")

type AgentIdentity struct {
	ActorID     string
	PrincipalID string
	Scopes      []string
}

type DelegationContext struct {
	Capability string
	TemplateID string
	RiskLevel  string
}

func AuthenticateAgentBearer(ctx context.Context, db *pgxpool.Pool, authorization string) (*AgentIdentity, error) {
	token, ok := parseBearerToken(authorization)
	if !ok {
		return nil, ErrUnauthorized
	}
	tokenHash := hashToken(token)
	var out AgentIdentity
	err := db.QueryRow(ctx, `
SELECT a.actor_id,a.principal_id,ac.scopes
FROM agent_credentials ac
JOIN actors a ON a.actor_id=ac.actor_id
WHERE ac.token_hash=$1
  AND ac.revoked_at IS NULL
  AND a.actor_type='AGENT'
  AND a.status='ACTIVE'
`, tokenHash).Scan(&out.ActorID, &out.PrincipalID, &out.Scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	return &out, nil
}

func HasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}

func HasScopeOrDelegation(ctx context.Context, db *pgxpool.Pool, agent *AgentIdentity, requiredScope string, dctx DelegationContext) (bool, bool, error) {
	if HasScope(agent.Scopes, requiredScope) {
		return true, false, nil
	}
	if strings.TrimSpace(dctx.Capability) == "" {
		return false, false, nil
	}
	rows, err := db.Query(ctx, `
SELECT scope,expires_at,revoked_at
FROM delegation_records
WHERE principal_id=$1
  AND delegate_actor_id=$2
ORDER BY issued_at DESC, delegation_id ASC
`, agent.PrincipalID, agent.ActorID)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()

	type scope struct {
		Actions      []string `json:"actions"`
		Templates    []string `json:"templates"`
		MaxRiskLevel string   `json:"max_risk_level"`
	}
	now := time.Now().UTC()
	for rows.Next() {
		var b []byte
		var expiresAt *time.Time
		var revokedAt *time.Time
		if err := rows.Scan(&b, &expiresAt, &revokedAt); err != nil {
			return false, false, err
		}
		var s scope
		if err := json.Unmarshal(b, &s); err != nil {
			continue
		}
		if !delegationScopeAllows(now, dctx.Capability, dctx.TemplateID, dctx.RiskLevel, s.Actions, s.Templates, s.MaxRiskLevel, expiresAt, revokedAt) {
			continue
		}
		return true, true, nil
	}
	if err := rows.Err(); err != nil {
		return false, false, err
	}
	return false, false, nil
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func riskAtMost(actual, maxAllowed string) (bool, error) {
	order := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3}
	a := strings.ToUpper(strings.TrimSpace(actual))
	m := strings.ToUpper(strings.TrimSpace(maxAllowed))
	if a == "" {
		a = "LOW"
	}
	av, okA := order[a]
	mv, okM := order[m]
	if !okA || !okM {
		return false, fmt.Errorf("invalid risk level")
	}
	return av <= mv, nil
}

func LogAuthFailure(ctx context.Context, db *pgxpool.Pool, service, endpoint, principalID, actorID, reason string, details map[string]any) {
	b, _ := json.Marshal(details)
	_, _ = db.Exec(ctx, `
INSERT INTO auth_failures(service,endpoint,principal_id,actor_id,reason,details)
VALUES($1,$2,$3,$4,$5,$6::jsonb)
`, service, endpoint, principalID, actorID, reason, string(b))
}

func LogAuthEvent(ctx context.Context, db *pgxpool.Pool, service, endpoint, principalID, actorID, reason string, details map[string]any) {
	LogAuthFailure(ctx, db, service, endpoint, principalID, actorID, reason, details)
}

func parseBearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", false
	}
	return token, true
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func delegationScopeAllows(now time.Time, capability, templateID, riskLevel string, actions, templates []string, maxRiskLevel string, expiresAt, revokedAt *time.Time) bool {
	if revokedAt != nil {
		return false
	}
	if expiresAt != nil && !now.Before(expiresAt.UTC()) {
		return false
	}
	if !containsString(actions, capability) {
		return false
	}
	if len(templates) > 0 {
		if strings.TrimSpace(templateID) == "" || !containsString(templates, templateID) {
			return false
		}
	}
	if strings.TrimSpace(maxRiskLevel) != "" {
		ok, err := riskAtMost(riskLevel, maxRiskLevel)
		if err != nil || !ok {
			return false
		}
	}
	return true
}
