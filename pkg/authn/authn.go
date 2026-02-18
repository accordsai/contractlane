package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnauthorized = errors.New("unauthorized")

type AgentIdentity struct {
	ActorID     string
	PrincipalID string
	Scopes      []string
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

func LogAuthFailure(ctx context.Context, db *pgxpool.Pool, service, endpoint, principalID, actorID, reason string, details map[string]any) {
	b, _ := json.Marshal(details)
	_, _ = db.Exec(ctx, `
INSERT INTO auth_failures(service,endpoint,principal_id,actor_id,reason,details)
VALUES($1,$2,$3,$4,$5,$6::jsonb)
`, service, endpoint, principalID, actorID, reason, string(b))
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
