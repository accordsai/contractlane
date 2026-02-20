package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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

type SignupSession struct {
	SessionID            string     `json:"session_id"`
	Email                string     `json:"email"`
	OrgName              string     `json:"org_name"`
	Status               string     `json:"status"`
	VerificationCodeHash string     `json:"-"`
	VerificationAttempts int        `json:"verification_attempts"`
	CreatedAt            time.Time  `json:"created_at"`
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	ExpiresAt            time.Time  `json:"expires_at"`
}

type SignupProvision struct {
	SessionID    string    `json:"session_id"`
	OrgID        string    `json:"org_id"`
	ProjectID    string    `json:"project_id"`
	PrincipalID  string    `json:"principal_id"`
	ActorID      string    `json:"actor_id"`
	CredentialID string    `json:"credential_id"`
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

func (s *Store) CreateSignupSession(ctx context.Context, sess SignupSession) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_signup_sessions(
  session_id,email,org_name,status,verification_code_hash,verification_attempts,expires_at
)
VALUES($1,lower($2),$3,$4,$5,0,$6)
`, sess.SessionID, sess.Email, sess.OrgName, sess.Status, sess.VerificationCodeHash, sess.ExpiresAt.UTC())
	return err
}

func (s *Store) GetSignupSession(ctx context.Context, sessionID string) (SignupSession, error) {
	var sess SignupSession
	err := s.DB.QueryRow(ctx, `
SELECT session_id,email,org_name,status,verification_code_hash,verification_attempts,created_at,verified_at,completed_at,expires_at
FROM onboarding_signup_sessions
WHERE session_id=$1
`, sessionID).Scan(
		&sess.SessionID,
		&sess.Email,
		&sess.OrgName,
		&sess.Status,
		&sess.VerificationCodeHash,
		&sess.VerificationAttempts,
		&sess.CreatedAt,
		&sess.VerifiedAt,
		&sess.CompletedAt,
		&sess.ExpiresAt,
	)
	return sess, err
}

func (s *Store) VerifySignupSession(ctx context.Context, sessionID, code string, now time.Time, maxAttempts int) (SignupSession, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return SignupSession{}, err
	}
	defer tx.Rollback(ctx)

	var sess SignupSession
	err = tx.QueryRow(ctx, `
SELECT session_id,email,org_name,status,verification_code_hash,verification_attempts,created_at,verified_at,completed_at,expires_at
FROM onboarding_signup_sessions
WHERE session_id=$1
FOR UPDATE
`, sessionID).Scan(
		&sess.SessionID,
		&sess.Email,
		&sess.OrgName,
		&sess.Status,
		&sess.VerificationCodeHash,
		&sess.VerificationAttempts,
		&sess.CreatedAt,
		&sess.VerifiedAt,
		&sess.CompletedAt,
		&sess.ExpiresAt,
	)
	if err != nil {
		return SignupSession{}, err
	}

	if now.UTC().After(sess.ExpiresAt.UTC()) && sess.Status != "VERIFIED" {
		sess.Status = "EXPIRED"
		_, _ = tx.Exec(ctx, `
UPDATE onboarding_signup_sessions
SET status='EXPIRED'
WHERE session_id=$1
`, sessionID)
		if err := tx.Commit(ctx); err != nil {
			return SignupSession{}, err
		}
		return sess, nil
	}

	if sess.Status == "VERIFIED" {
		if err := tx.Commit(ctx); err != nil {
			return SignupSession{}, err
		}
		return sess, nil
	}

	if !secureHashEq(sess.VerificationCodeHash, HashToken(strings.TrimSpace(code))) {
		sess.VerificationAttempts++
		nextStatus := "PENDING"
		if maxAttempts > 0 && sess.VerificationAttempts >= maxAttempts {
			nextStatus = "EXPIRED"
		}
		_, err := tx.Exec(ctx, `
UPDATE onboarding_signup_sessions
SET verification_attempts=$2,status=$3
WHERE session_id=$1
`, sessionID, sess.VerificationAttempts, nextStatus)
		if err != nil {
			return SignupSession{}, err
		}
		sess.Status = nextStatus
		if err := tx.Commit(ctx); err != nil {
			return SignupSession{}, err
		}
		return sess, nil
	}

	verifiedAt := now.UTC()
	sess.Status = "VERIFIED"
	sess.VerifiedAt = &verifiedAt
	_, err = tx.Exec(ctx, `
UPDATE onboarding_signup_sessions
SET status='VERIFIED',verified_at=$2
WHERE session_id=$1
`, sessionID, verifiedAt)
	if err != nil {
		return SignupSession{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return SignupSession{}, err
	}
	return sess, nil
}

func (s *Store) MarkSignupSessionCompleted(ctx context.Context, sessionID string, completedAt time.Time) error {
	_, err := s.DB.Exec(ctx, `
UPDATE onboarding_signup_sessions
SET status='COMPLETED',completed_at=$2
WHERE session_id=$1
`, sessionID, completedAt.UTC())
	return err
}

func (s *Store) CreateSignupProvision(ctx context.Context, p SignupProvision) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO onboarding_signup_provisions(session_id,org_id,project_id,principal_id,actor_id,credential_id)
VALUES($1,$2,$3,$4,$5,$6)
`, p.SessionID, p.OrgID, p.ProjectID, p.PrincipalID, p.ActorID, p.CredentialID)
	return err
}

func (s *Store) GetSignupProvision(ctx context.Context, sessionID string) (SignupProvision, error) {
	var p SignupProvision
	err := s.DB.QueryRow(ctx, `
SELECT session_id,org_id,project_id,principal_id,actor_id,credential_id,created_at
FROM onboarding_signup_provisions
WHERE session_id=$1
`, sessionID).Scan(&p.SessionID, &p.OrgID, &p.ProjectID, &p.PrincipalID, &p.ActorID, &p.CredentialID, &p.CreatedAt)
	return p, err
}

func secureHashEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := 0; i < len(a); i++ {
		out |= a[i] ^ b[i]
	}
	return out == 0
}
