package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"contractlane/pkg/domain"

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

type TemplateRef struct {
	TemplateID   string
	ContractType string
	DisplayName  string
}

func (s *Store) CreatePrincipal(ctx context.Context, p Principal) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO principals(principal_id,name,jurisdiction,timezone) VALUES($1,$2,$3,$4)`,
		p.PrincipalID, p.Name, p.Jurisdiction, p.Timezone)
	return err
}

func (s *Store) UpsertPrincipal(ctx context.Context, p Principal) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO principals(principal_id,name,jurisdiction,timezone)
VALUES($1,$2,$3,$4)
ON CONFLICT (principal_id) DO UPDATE SET
  name=EXCLUDED.name,
  jurisdiction=EXCLUDED.jurisdiction,
  timezone=EXCLUDED.timezone
`, p.PrincipalID, p.Name, p.Jurisdiction, p.Timezone)
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

func (s *Store) UpsertAgent(ctx context.Context, a Actor, tokenHash string, scopes []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
INSERT INTO actors(actor_id,principal_id,actor_type,status,name,roles)
VALUES($1,$2,'AGENT','ACTIVE',$3,$4)
ON CONFLICT (actor_id) DO UPDATE SET
  principal_id=EXCLUDED.principal_id,
  actor_type='AGENT',
  status='ACTIVE',
  name=EXCLUDED.name,
  roles=EXCLUDED.roles
`, a.ActorID, a.PrincipalID, a.Name, scopes)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
INSERT INTO agent_credentials(actor_id,token_hash,scopes,revoked_at)
VALUES($1,$2,$3,NULL)
ON CONFLICT (actor_id) DO UPDATE SET
  token_hash=EXCLUDED.token_hash,
  scopes=EXCLUDED.scopes,
  revoked_at=NULL
`, a.ActorID, tokenHash, scopes)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) UpsertTemplateAndGovernance(ctx context.Context, templateID, contractType, displayName string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
INSERT INTO templates(template_id,contract_type,jurisdiction,display_name,risk_tier)
VALUES($1,$2,'US',$3,'LOW')
ON CONFLICT (template_id) DO UPDATE SET
  contract_type=EXCLUDED.contract_type,
  display_name=EXCLUDED.display_name
`, templateID, contractType, displayName)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO template_governance(template_id,template_gates,protected_slots,prohibited_slots)
VALUES($1,'{"SEND_FOR_SIGNATURE":"DEFER"}'::jsonb,'{}','{}')
ON CONFLICT (template_id) DO NOTHING
`, templateID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FindDevTermsTemplate(ctx context.Context) (*TemplateRef, error) {
	var t TemplateRef
	err := s.DB.QueryRow(ctx, `
SELECT template_id,contract_type,display_name
FROM templates
ORDER BY
  CASE
    WHEN lower(template_id) = 'terms' THEN 0
    WHEN lower(template_id) LIKE '%terms%' THEN 1
    WHEN lower(display_name) LIKE '%terms%' THEN 2
    WHEN upper(contract_type) IN ('TERMS','T_AND_C','TNC','TERMS_AND_CONDITIONS') THEN 3
    ELSE 100
  END ASC,
  created_at DESC,
  template_id DESC
LIMIT 1
`).Scan(&t.TemplateID, &t.ContractType, &t.DisplayName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (s *Store) UpsertComplianceProgramPublished(ctx context.Context, principalID, programKey, mode, requiredTemplateID, requiredTemplateVersion, actorID string) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO compliance_programs(
  principal_id,program_key,mode,required_template_id,required_template_version,published_at,created_by_actor_id,updated_by_actor_id
)
VALUES($1,$2,$3,$4,$5,now(),$6,$6)
ON CONFLICT (principal_id,program_key) DO UPDATE SET
  mode=EXCLUDED.mode,
  required_template_id=EXCLUDED.required_template_id,
  required_template_version=EXCLUDED.required_template_version,
  published_at=now(),
  updated_by_actor_id=EXCLUDED.updated_by_actor_id,
  updated_at=now()
`, principalID, programKey, mode, requiredTemplateID, requiredTemplateVersion, actorID)
	return err
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

type BearerIdentity struct {
	PrincipalID string
	ActorID     string
	ActorType   string
	Scopes      []string
}

func (s *Store) ResolveBearerIdentity(ctx context.Context, token string) (*BearerIdentity, error) {
	tokenHash := HashToken(token)
	var sessionPrincipalID, sessionActorID string
	var sessionExpiresAt time.Time
	err := s.DB.QueryRow(ctx, `
SELECT principal_id,actor_id,expires_at
FROM human_auth_sessions
WHERE token_hash=$1
`, tokenHash).Scan(&sessionPrincipalID, &sessionActorID, &sessionExpiresAt)
	if err == nil && sessionExpiresAt.After(time.Now().UTC()) {
		actor, err := s.GetActor(ctx, sessionActorID)
		if err == nil && actor.PrincipalID == sessionPrincipalID && actor.Status == "ACTIVE" {
			return &BearerIdentity{
				PrincipalID: sessionPrincipalID,
				ActorID:     sessionActorID,
				ActorType:   actor.ActorType,
			}, nil
		}
	}

	var id BearerIdentity
	err = s.DB.QueryRow(ctx, `
SELECT a.principal_id,a.actor_id,a.actor_type,ac.scopes
FROM agent_credentials ac
JOIN actors a ON a.actor_id=ac.actor_id
WHERE ac.token_hash=$1
  AND ac.revoked_at IS NULL
  AND a.status='ACTIVE'
  AND a.actor_type='AGENT'
`, tokenHash).Scan(&id.PrincipalID, &id.ActorID, &id.ActorType, &id.Scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, pgx.ErrNoRows
		}
		return nil, err
	}
	return &id, nil
}

func (s *Store) CreateDelegation(ctx context.Context, d domain.DelegationRecord) error {
	scopeJSON, err := json.Marshal(d.Scope)
	if err != nil {
		return err
	}
	sigJSON, err := json.Marshal(d.Signature)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `
INSERT INTO delegation_records(
  delegation_id,principal_id,delegator_actor_id,delegate_actor_id,scope,issued_at,expires_at,revoked_at,signature
)
VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9::jsonb)
`, d.DelegationID, d.PrincipalID, d.DelegatorActorID, d.DelegateActorID, string(scopeJSON), d.IssuedAt.UTC(), d.ExpiresAt, d.RevokedAt, string(sigJSON))
	return err
}

func (s *Store) GetDelegation(ctx context.Context, delegationID string) (domain.DelegationRecord, error) {
	var d domain.DelegationRecord
	var scopeJSON []byte
	var sigJSON []byte
	err := s.DB.QueryRow(ctx, `
SELECT delegation_id,principal_id,delegator_actor_id,delegate_actor_id,scope,issued_at,expires_at,revoked_at,signature,created_at
FROM delegation_records
WHERE delegation_id=$1
`, delegationID).Scan(&d.DelegationID, &d.PrincipalID, &d.DelegatorActorID, &d.DelegateActorID, &scopeJSON, &d.IssuedAt, &d.ExpiresAt, &d.RevokedAt, &sigJSON, &d.CreatedAt)
	if err != nil {
		return domain.DelegationRecord{}, err
	}
	if err := json.Unmarshal(scopeJSON, &d.Scope); err != nil {
		return domain.DelegationRecord{}, err
	}
	if err := json.Unmarshal(sigJSON, &d.Signature); err != nil {
		return domain.DelegationRecord{}, err
	}
	return d, nil
}

func (s *Store) RevokeDelegation(ctx context.Context, delegationID string, revokedAt time.Time) error {
	_, err := s.DB.Exec(ctx, `
UPDATE delegation_records
SET revoked_at=COALESCE(revoked_at,$2)
WHERE delegation_id=$1
`, delegationID, revokedAt.UTC())
	return err
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
