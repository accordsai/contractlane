package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ DB *pgxpool.Pool }

func New(db *pgxpool.Pool) *Store { return &Store{DB: db} }

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type Org struct {
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type Project struct {
	ProjectID   string    `json:"project_id"`
	OrgID       string    `json:"org_id"`
	PrincipalID string    `json:"principal_id"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
}

type Credential struct {
	CredentialID string    `json:"credential_id"`
	ProjectID    string    `json:"project_id"`
	PrincipalID  string    `json:"principal_id"`
	ActorID      string    `json:"actor_id"`
	TokenHash    string    `json:"-"`
	Scopes       []string  `json:"scopes"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type IdempotencyRecord struct {
	ScopeID        string
	ActorID        string
	IdempotencyKey string
	Endpoint       string
	ResponseStatus int
	ResponseBody   []byte
}

func (s *Store) GetIdempotencyRecord(ctx context.Context, scopeID, actorID, key, endpoint string) (*IdempotencyRecord, error) {
	var rec IdempotencyRecord
	err := s.DB.QueryRow(ctx, `
SELECT scope_id,actor_id,idempotency_key,endpoint,response_status,response_body
FROM onboarding_idempotency_records
WHERE scope_id=$1 AND actor_id=$2 AND idempotency_key=$3 AND endpoint=$4
`, scopeID, actorID, key, endpoint).Scan(&rec.ScopeID, &rec.ActorID, &rec.IdempotencyKey, &rec.Endpoint, &rec.ResponseStatus, &rec.ResponseBody)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (s *Store) SaveIdempotencyRecord(ctx context.Context, rec IdempotencyRecord) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_idempotency_records(scope_id,actor_id,idempotency_key,endpoint,response_status,response_body)
VALUES($1,$2,$3,$4,$5,$6::jsonb)
ON CONFLICT (scope_id,actor_id,idempotency_key,endpoint) DO NOTHING
`, rec.ScopeID, rec.ActorID, rec.IdempotencyKey, rec.Endpoint, rec.ResponseStatus, string(rec.ResponseBody))
	return err
}

func (s *Store) CreateOrgWithOwner(ctx context.Context, org Org, user User) (User, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `INSERT INTO onboarding_orgs(org_id,name) VALUES($1,$2)`, org.OrgID, org.Name); err != nil {
		return User{}, err
	}
	var effectiveUserID string
	if err := tx.QueryRow(ctx, `
INSERT INTO onboarding_users(user_id,email)
VALUES($1,lower($2))
ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email
RETURNING user_id
`, user.UserID, user.Email).Scan(&effectiveUserID); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO onboarding_memberships(org_id,user_id,role,status)
VALUES($1,$2,'OWNER','ACTIVE')
ON CONFLICT (org_id,user_id) DO UPDATE SET role='OWNER',status='ACTIVE'
`, org.OrgID, effectiveUserID); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	user.UserID = effectiveUserID
	return user, nil
}

func (s *Store) CreateProject(ctx context.Context, p Project) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_projects(project_id,org_id,principal_id,name)
VALUES($1,$2,$3,$4)
`, p.ProjectID, p.OrgID, p.PrincipalID, p.Name)
	return err
}

func (s *Store) GetProject(ctx context.Context, projectID string) (Project, error) {
	var p Project
	err := s.DB.QueryRow(ctx, `
SELECT project_id,org_id,principal_id,name,created_at
FROM onboarding_projects
WHERE project_id=$1
`, projectID).Scan(&p.ProjectID, &p.OrgID, &p.PrincipalID, &p.Name, &p.CreatedAt)
	return p, err
}

func (s *Store) CreateCredential(ctx context.Context, c Credential) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_credentials(credential_id,project_id,principal_id,actor_id,token_hash,scopes,status)
VALUES($1,$2,$3,$4,$5,$6,$7)
`, c.CredentialID, c.ProjectID, c.PrincipalID, c.ActorID, c.TokenHash, c.Scopes, c.Status)
	return err
}

func (s *Store) RecordAuditEvent(ctx context.Context, orgID, projectID, actorID, eventType string, payload []byte) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_audit_events(org_id,project_id,actor_id,event_type,payload)
VALUES($1,$2,$3,$4,$5::jsonb)
`, nullable(orgID), nullable(projectID), nullable(actorID), eventType, string(payload))
	return err
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) EnsureOrgExists(ctx context.Context, orgID string) error {
	var exists bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM onboarding_orgs WHERE org_id=$1)`, orgID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("org not found")
	}
	return nil
}
