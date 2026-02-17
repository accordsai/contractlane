package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

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

func (s *Store) CreateAgent(ctx context.Context, a Actor, tokenHash string, scopes []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil { return err }
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `INSERT INTO actors(actor_id,principal_id,actor_type,status,name,roles) VALUES($1,$2,'AGENT','ACTIVE',$3,$4)`,
		a.ActorID, a.PrincipalID, a.Name, scopes)
	if err != nil { return err }

	_, err = tx.Exec(ctx, `INSERT INTO agent_credentials(actor_id,token_hash,scopes) VALUES($1,$2,$3)`,
		a.ActorID, tokenHash, scopes)
	if err != nil { return err }

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
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil { return nil, err }
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

