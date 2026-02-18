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

type Principal struct {
	PrincipalID  string    `json:"principal_id"`
	Name         string    `json:"name"`
	Jurisdiction string    `json:"jurisdiction"`
	Timezone     string    `json:"timezone"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Store) CreatePrincipal(ctx context.Context, p Principal) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO principals(principal_id,name,jurisdiction,timezone) VALUES($1,$2,$3,$4)`,
		p.PrincipalID, p.Name, p.Jurisdiction, p.Timezone)
	return err
}

func (s *Store) GetPrincipal(ctx context.Context, id string) (Principal, error) {
	var p Principal
	err := s.DB.QueryRow(ctx, `SELECT principal_id,name,jurisdiction,timezone,created_at FROM principals WHERE principal_id=$1`, id).
		Scan(&p.PrincipalID, &p.Name, &p.Jurisdiction, &p.Timezone, &p.CreatedAt)
	return p, err
}

type Actor struct {
	ActorID     string    `json:"actor_id"`
	PrincipalID string    `json:"principal_id"`
	ActorType   string    `json:"actor_type"`
	Status      string    `json:"status"`
	Email       *string   `json:"email,omitempty"`
	Name        *string   `json:"name,omitempty"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
}

type PrincipalSubject struct {
	PrincipalID       string    `json:"principal_id"`
	ExternalSubjectID string    `json:"external_subject_id"`
	ActorID           string    `json:"actor_id"`
	ActorType         string    `json:"actor_type"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

var ErrActorTypeRequired = errors.New("NEEDS_ACTOR_TYPE")

func (s *Store) CreateAgent(ctx context.Context, a Actor, tokenHash string, scopes []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `INSERT INTO actors(actor_id,principal_id,actor_type,status,name,roles) VALUES($1,$2,'AGENT','ACTIVE',$3,$4)`,
		a.ActorID, a.PrincipalID, a.Name, scopes)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `INSERT INTO agent_credentials(actor_id,token_hash,scopes) VALUES($1,$2,$3)`,
		a.ActorID, tokenHash, scopes)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) CreateHuman(ctx context.Context, a Actor) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO actors(actor_id,principal_id,actor_type,status,email,roles) VALUES($1,$2,'HUMAN','ACTIVE',$3,$4)`,
		a.ActorID, a.PrincipalID, a.Email, a.Roles)
	return err
}

func (s *Store) ListActors(ctx context.Context, principalID string, typ *string) ([]Actor, error) {
	q := `SELECT actor_id,principal_id,actor_type,status,email,name,roles,created_at FROM actors WHERE principal_id=$1`
	args := []any{principalID}
	if typ != nil {
		q += ` AND actor_type=$2`
		args = append(args, *typ)
	}
	q += ` ORDER BY created_at ASC, actor_id ASC`
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Actor
	for rows.Next() {
		var a Actor
		var roles []string
		if err := rows.Scan(&a.ActorID, &a.PrincipalID, &a.ActorType, &a.Status, &a.Email, &a.Name, &roles, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Roles = roles
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetActor(ctx context.Context, actorID string) (Actor, error) {
	var a Actor
	var roles []string
	err := s.DB.QueryRow(ctx, `
SELECT actor_id,principal_id,actor_type,status,email,name,roles,created_at
FROM actors
WHERE actor_id=$1
`, actorID).Scan(&a.ActorID, &a.PrincipalID, &a.ActorType, &a.Status, &a.Email, &a.Name, &roles, &a.CreatedAt)
	if err != nil {
		return Actor{}, err
	}
	a.Roles = roles
	return a, nil
}

func (s *Store) ResolveOrCreateSubject(ctx context.Context, principalID, externalSubjectID string, actorTypeIfNeeded *string) (PrincipalSubject, error) {
	var out PrincipalSubject
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)

	// Serialize create-on-miss for the same tenant+subject to avoid duplicate actors on retries/races.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2))`, principalID, externalSubjectID); err != nil {
		return out, err
	}

	out, err = getPrincipalSubjectTx(ctx, tx, principalID, externalSubjectID)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return PrincipalSubject{}, err
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}

	if actorTypeIfNeeded == nil || strings.TrimSpace(*actorTypeIfNeeded) == "" {
		return PrincipalSubject{}, ErrActorTypeRequired
	}
	actorType := strings.ToUpper(strings.TrimSpace(*actorTypeIfNeeded))
	if actorType != "HUMAN" && actorType != "AGENT" {
		return PrincipalSubject{}, fmt.Errorf("invalid actor_type %q", actorType)
	}

	actorID := deterministicSubjectActorID(principalID, externalSubjectID, actorType)
	switch actorType {
	case "HUMAN":
		email := deterministicSubjectEmail(principalID, externalSubjectID)
		if _, err := tx.Exec(ctx, `
INSERT INTO actors(actor_id,principal_id,actor_type,status,email,roles)
VALUES($1,$2,'HUMAN','ACTIVE',$3,'{}')
ON CONFLICT (actor_id) DO NOTHING
`, actorID, principalID, email); err != nil {
			return PrincipalSubject{}, err
		}
	case "AGENT":
		name := "subject:" + externalSubjectID
		if _, err := tx.Exec(ctx, `
INSERT INTO actors(actor_id,principal_id,actor_type,status,name,roles)
VALUES($1,$2,'AGENT','ACTIVE',$3,'{}')
ON CONFLICT (actor_id) DO NOTHING
`, actorID, principalID, name); err != nil {
			return PrincipalSubject{}, err
		}
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO principal_subjects(principal_id,external_subject_id,actor_id,actor_type,status)
VALUES($1,$2,$3,$4,'ACTIVE')
ON CONFLICT (principal_id,external_subject_id) DO NOTHING
`, principalID, externalSubjectID, actorID, actorType); err != nil {
		return PrincipalSubject{}, err
	}

	out, err = getPrincipalSubjectTx(ctx, tx, principalID, externalSubjectID)
	if err != nil {
		return PrincipalSubject{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PrincipalSubject{}, err
	}
	return out, nil
}

func getPrincipalSubjectTx(ctx context.Context, tx pgx.Tx, principalID, externalSubjectID string) (PrincipalSubject, error) {
	var out PrincipalSubject
	err := tx.QueryRow(ctx, `
SELECT principal_id,external_subject_id,actor_id,actor_type,status,created_at,updated_at
FROM principal_subjects
WHERE principal_id=$1 AND external_subject_id=$2
`, principalID, externalSubjectID).Scan(
		&out.PrincipalID,
		&out.ExternalSubjectID,
		&out.ActorID,
		&out.ActorType,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	return out, err
}

func deterministicSubjectActorID(principalID, externalSubjectID, actorType string) string {
	sum := sha256.Sum256([]byte(principalID + "|" + externalSubjectID + "|" + actorType))
	return "act_subj_" + hex.EncodeToString(sum[:])[:24]
}

func deterministicSubjectEmail(principalID, externalSubjectID string) string {
	sum := sha256.Sum256([]byte(principalID + "|" + externalSubjectID))
	return "subject+" + hex.EncodeToString(sum[:])[:16] + "@local.invalid"
}

type Invite struct {
	InviteID       string    `json:"invite_id"`
	PrincipalID    string    `json:"principal_id"`
	Email          string    `json:"email"`
	RequestedRoles []string  `json:"requested_roles"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
	ActorID        *string   `json:"actor_id,omitempty"`
}

func (s *Store) CreateInvite(ctx context.Context, inv Invite, tokenHash string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO invites(invite_id,principal_id,email,requested_roles,status,expires_at,token_hash) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		inv.InviteID, inv.PrincipalID, inv.Email, inv.RequestedRoles, inv.Status, inv.ExpiresAt, tokenHash)
	return err
}

func (s *Store) GetInvite(ctx context.Context, id string) (Invite, string, error) {
	var inv Invite
	var tokenHash string
	err := s.DB.QueryRow(ctx, `SELECT invite_id,principal_id,email,requested_roles,status,expires_at,actor_id,token_hash FROM invites WHERE invite_id=$1`, id).
		Scan(&inv.InviteID, &inv.PrincipalID, &inv.Email, &inv.RequestedRoles, &inv.Status, &inv.ExpiresAt, &inv.ActorID, &tokenHash)
	return inv, tokenHash, err
}

func (s *Store) CompleteInvite(ctx context.Context, inviteID, actorID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE invites SET status='COMPLETED', actor_id=$2, completed_at=now() WHERE invite_id=$1`, inviteID, actorID)
	return err
}

func (s *Store) UpsertPolicyProfile(ctx context.Context, actorID, principalID, level string, actionGates, variableRules []byte) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO policy_profiles(actor_id,principal_id,automation_level,action_gates,variable_rules)
VALUES($1,$2,$3,$4::jsonb,$5::jsonb)
ON CONFLICT (actor_id) DO UPDATE SET
  automation_level=EXCLUDED.automation_level,
  action_gates=EXCLUDED.action_gates,
  variable_rules=EXCLUDED.variable_rules,
  updated_at=now()
`, actorID, principalID, level, string(actionGates), string(variableRules))
	return err
}

func (s *Store) GetPolicyProfile(ctx context.Context, actorID string) (principalID, level string, actionGates, variableRules []byte, err error) {
	err = s.DB.QueryRow(ctx, `SELECT principal_id,automation_level,action_gates,variable_rules FROM policy_profiles WHERE actor_id=$1`, actorID).
		Scan(&principalID, &level, &actionGates, &variableRules)
	return
}

func (s *Store) FindActiveHumanByEmail(ctx context.Context, principalID, email string) (Actor, error) {
	var a Actor
	var roles []string
	err := s.DB.QueryRow(ctx, `
SELECT actor_id,principal_id,actor_type,status,email,name,roles,created_at
FROM actors
WHERE principal_id=$1 AND actor_type='HUMAN' AND lower(email)=lower($2) AND status='ACTIVE'
ORDER BY created_at ASC
LIMIT 1
`, principalID, email).Scan(&a.ActorID, &a.PrincipalID, &a.ActorType, &a.Status, &a.Email, &a.Name, &roles, &a.CreatedAt)
	if err != nil {
		return Actor{}, err
	}
	a.Roles = roles
	return a, nil
}

func (s *Store) CreateMagicLinkToken(ctx context.Context, tokenID, principalID, actorID, email, tokenHash string, expiresAt time.Time) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO magic_link_tokens(token_id,principal_id,actor_id,email,token_hash,expires_at)
VALUES($1,$2,$3,$4,$5,$6)
`, tokenID, principalID, actorID, email, tokenHash, expiresAt)
	return err
}

func (s *Store) ConsumeMagicLinkToken(ctx context.Context, tokenHash string) (principalID, actorID, email string, err error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", "", "", err
	}
	defer tx.Rollback(ctx)
	var consumedAt *time.Time
	var expiresAt time.Time
	var tokenID string
	err = tx.QueryRow(ctx, `
SELECT token_id,principal_id,actor_id,email,expires_at,consumed_at
FROM magic_link_tokens
WHERE token_hash=$1
`, tokenHash).Scan(&tokenID, &principalID, &actorID, &email, &expiresAt, &consumedAt)
	if err != nil {
		return "", "", "", err
	}
	now := time.Now().UTC()
	if consumedAt != nil {
		return "", "", "", fmt.Errorf("TOKEN_ALREADY_USED")
	}
	if !expiresAt.After(now) {
		return "", "", "", fmt.Errorf("TOKEN_EXPIRED")
	}
	_, err = tx.Exec(ctx, `
UPDATE magic_link_tokens
SET consumed_at=now()
WHERE token_id=$1 AND consumed_at IS NULL
`, tokenID)
	if err != nil {
		return "", "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", err
	}
	return principalID, actorID, email, nil
}

func (s *Store) CreateHumanAuthSession(ctx context.Context, sessionID, principalID, actorID, tokenHash string, expiresAt time.Time) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO human_auth_sessions(session_id,principal_id,actor_id,auth_method,token_hash,expires_at)
VALUES($1,$2,$3,'MAGIC_LINK',$4,$5)
`, sessionID, principalID, actorID, tokenHash, expiresAt)
	return err
}

func (s *Store) GetHumanAuthSession(ctx context.Context, tokenHash string) (sessionID, principalID, actorID string, expiresAt time.Time, err error) {
	err = s.DB.QueryRow(ctx, `
SELECT session_id,principal_id,actor_id,expires_at
FROM human_auth_sessions
WHERE token_hash=$1 AND revoked_at IS NULL
`, tokenHash).Scan(&sessionID, &principalID, &actorID, &expiresAt)
	return
}
