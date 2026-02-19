package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"contractlane/pkg/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ DB *pgxpool.Pool }

func New(db *pgxpool.Pool) *Store { return &Store{DB: db} }

func (s *Store) AcquireGateResolveLock(ctx context.Context, principalID, gateKey, externalSubjectID, templateVersion string) (func(), error) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	lockKey := principalID + "|" + gateKey + "|" + externalSubjectID + "|" + templateVersion
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		conn.Release()
		return nil, err
	}
	release := func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockKey)
		conn.Release()
	}
	return release, nil
}

type Template struct {
	TemplateID   string `json:"template_id"`
	ContractType string `json:"contract_type"`
	Jurisdiction string `json:"jurisdiction"`
	DisplayName  string `json:"display_name"`
	RiskTier     string `json:"risk_tier"`
}

type TemplateVar struct {
	Key         domain.VarKey         `json:"key"`
	Type        domain.VarType        `json:"type"`
	Required    bool                  `json:"required"`
	Sensitivity domain.VarSensitivity `json:"sensitivity"`
	SetPolicy   domain.VarSetPolicy   `json:"set_policy"`
}

func (s *Store) UpsertSeedTemplate(ctx context.Context) (string, error) {
	// Seed a single NDA template for smoke tests.
	tplID := "tpl_nda_us_v1"
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	_, _ = tx.Exec(ctx, `INSERT INTO templates(template_id,contract_type,jurisdiction,display_name,risk_tier)
VALUES($1,'NDA','US','NDA (US) v1','LOW')
ON CONFLICT (template_id) DO NOTHING`, tplID)

	_, _ = tx.Exec(ctx, `INSERT INTO template_governance(template_id,template_gates,protected_slots,prohibited_slots)
VALUES($1,'{"SEND_FOR_SIGNATURE":"DEFER"}'::jsonb,'{}','{}')
ON CONFLICT (template_id) DO NOTHING`, tplID)

	// Variables: effective_date (agent allowed), party_address (defer), price (defer)
	_, _ = tx.Exec(ctx, `INSERT INTO template_variables(template_id,var_key,var_type,required,sensitivity,set_policy,constraints)
VALUES
($1,'effective_date','DATE',true,'NONE','AGENT_ALLOWED','{}'::jsonb),
($1,'party_address','ADDRESS',true,'PII','DEFER_TO_IDENTITY','{}'::jsonb),
($1,'price','MONEY',false,'NONE','DEFER_TO_IDENTITY','{}'::jsonb)
ON CONFLICT (template_id,var_key) DO UPDATE SET
  var_type=EXCLUDED.var_type,
  required=EXCLUDED.required,
  sensitivity=EXCLUDED.sensitivity,
  set_policy=EXCLUDED.set_policy,
  constraints=EXCLUDED.constraints`, tplID)

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return tplID, nil
}

func (s *Store) ListTemplates(ctx context.Context, contractType, jurisdiction string) ([]Template, error) {
	rows, err := s.DB.Query(ctx, `SELECT template_id,contract_type,jurisdiction,display_name,risk_tier FROM templates WHERE contract_type=$1 AND jurisdiction=$2`,
		contractType, jurisdiction)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.TemplateID, &t.ContractType, &t.Jurisdiction, &t.DisplayName, &t.RiskTier); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTemplate(ctx context.Context, templateID string) (Template, error) {
	var t Template
	err := s.DB.QueryRow(ctx, `
SELECT template_id,contract_type,jurisdiction,display_name,risk_tier
FROM templates
WHERE template_id=$1
`, templateID).Scan(&t.TemplateID, &t.ContractType, &t.Jurisdiction, &t.DisplayName, &t.RiskTier)
	return t, err
}

func (s *Store) GetPrincipalPolicyRouting(ctx context.Context, principalID string) (*string, string, error) {
	var actorID *string
	var role string
	err := s.DB.QueryRow(ctx, `
SELECT default_policy_actor_id,default_approval_role
FROM principals
WHERE principal_id=$1
`, principalID).Scan(&actorID, &role)
	if err != nil {
		return nil, "", err
	}
	if role == "" {
		role = "LEGAL"
	}
	return actorID, role, nil
}

func (s *Store) EnableTemplate(ctx context.Context, principalID, templateID, enabledBy string, overrideGates map[string]string) error {
	b, _ := json.Marshal(overrideGates)
	_, err := s.DB.Exec(ctx, `
INSERT INTO principal_templates(principal_id,template_id,enabled,enabled_by_actor_id,override_gates)
VALUES($1,$2,true,$3,$4::jsonb)
ON CONFLICT (principal_id,template_id) DO UPDATE SET enabled=true, enabled_by_actor_id=$3, override_gates=$4::jsonb, updated_at=now()
`, principalID, templateID, enabledBy, string(b))
	return err
}

func (s *Store) IsTemplateEnabledForPrincipal(ctx context.Context, principalID, templateID string) (bool, error) {
	var ok bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM principal_templates
  WHERE principal_id=$1 AND template_id=$2 AND enabled=true
)
`, principalID, templateID).Scan(&ok)
	return ok, err
}

func (s *Store) GetTemplateVars(ctx context.Context, templateID string) ([]domain.VariableDefinition, error) {
	rows, err := s.DB.Query(ctx, `SELECT var_key,var_type,required,sensitivity,set_policy,constraints FROM template_variables WHERE template_id=$1 ORDER BY var_key ASC`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.VariableDefinition
	for rows.Next() {
		var key, typ, sens, pol string
		var required bool
		var constraints []byte
		if err := rows.Scan(&key, &typ, &required, &sens, &pol, &constraints); err != nil {
			return nil, err
		}
		def := domain.VariableDefinition{
			Key:         domain.VarKey(key),
			Type:        domain.VarType(typ),
			Required:    required,
			Sensitivity: domain.VarSensitivity(sens),
			SetPolicy:   domain.VarSetPolicy(pol),
		}
		out = append(out, def)
	}
	return out, rows.Err()
}

func (s *Store) GetTemplateGates(ctx context.Context, templateID string) (map[string]string, error) {
	var gatesBytes []byte
	err := s.DB.QueryRow(ctx, `SELECT template_gates FROM template_governance WHERE template_id=$1`, templateID).Scan(&gatesBytes)
	if err != nil {
		return nil, err
	}
	var gates map[string]string
	_ = json.Unmarshal(gatesBytes, &gates)
	return gates, nil
}

type Contract struct {
	ContractID        string    `json:"contract_id"`
	PrincipalID       string    `json:"principal_id"`
	TemplateID        string    `json:"template_id"`
	TemplateVersion   *string   `json:"template_version,omitempty"`
	SubjectActorID    *string   `json:"subject_actor_id,omitempty"`
	GateKey           *string   `json:"gate_key,omitempty"`
	State             string    `json:"state"`
	RiskLevel         string    `json:"risk_level"`
	CounterpartyName  string    `json:"counterparty_name"`
	CounterpartyEmail string    `json:"counterparty_email"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
}

type Changeset struct {
	ChangesetID       string         `json:"changeset_id"`
	ContractID        string         `json:"contract_id"`
	Status            string         `json:"status"`
	Payload           map[string]any `json:"payload"`
	RequiredRoles     []string       `json:"required_roles"`
	ProposedByActorID string         `json:"proposed_by_actor_id"`
	DecidedByActorID  *string        `json:"decided_by_actor_id,omitempty"`
	AppliedByActorID  *string        `json:"applied_by_actor_id,omitempty"`
}

type ComplianceProgram struct {
	PrincipalID             string     `json:"principal_id"`
	ProgramKey              string     `json:"key"`
	Mode                    string     `json:"mode"`
	RequiredTemplateID      *string    `json:"required_template_id,omitempty"`
	RequiredTemplateVersion *string    `json:"required_template_version,omitempty"`
	PublishedAt             *time.Time `json:"published_at,omitempty"`
	CreatedByActorID        string     `json:"created_by_actor_id"`
	UpdatedByActorID        *string    `json:"updated_by_actor_id,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

func (s *Store) CreateContract(ctx context.Context, c Contract) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO contracts(contract_id,principal_id,template_id,template_version,subject_actor_id,gate_key,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		c.ContractID, c.PrincipalID, c.TemplateID, c.TemplateVersion, c.SubjectActorID, c.GateKey, c.State, c.RiskLevel, c.CounterpartyName, c.CounterpartyEmail, c.CreatedBy)
	return err
}

func (s *Store) CreateComplianceProgram(ctx context.Context, p ComplianceProgram) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO compliance_programs(principal_id,program_key,mode,created_by_actor_id,updated_by_actor_id)
VALUES($1,$2,$3,$4,$4)
`, p.PrincipalID, p.ProgramKey, p.Mode, p.CreatedByActorID)
	return err
}

func (s *Store) GetComplianceProgram(ctx context.Context, principalID, programKey string) (ComplianceProgram, error) {
	var p ComplianceProgram
	err := s.DB.QueryRow(ctx, `
SELECT principal_id,program_key,mode,required_template_id,required_template_version,published_at,created_by_actor_id,updated_by_actor_id,created_at,updated_at
FROM compliance_programs
WHERE principal_id=$1 AND program_key=$2
`, principalID, programKey).Scan(
		&p.PrincipalID,
		&p.ProgramKey,
		&p.Mode,
		&p.RequiredTemplateID,
		&p.RequiredTemplateVersion,
		&p.PublishedAt,
		&p.CreatedByActorID,
		&p.UpdatedByActorID,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	return p, err
}

func (s *Store) PublishComplianceProgram(ctx context.Context, principalID, programKey, requiredTemplateID, requiredTemplateVersion, actorID string) error {
	_, err := s.DB.Exec(ctx, `
UPDATE compliance_programs
SET required_template_id=$3,
    required_template_version=$4,
    published_at=now(),
    updated_by_actor_id=$5,
    updated_at=now()
WHERE principal_id=$1 AND program_key=$2
`, principalID, programKey, requiredTemplateID, requiredTemplateVersion, actorID)
	return err
}

func (s *Store) AddComplianceProgramEvent(ctx context.Context, principalID, programKey, eventType string, actorID *string, payload map[string]any) error {
	body, _ := json.Marshal(payload)
	_, err := s.DB.Exec(ctx, `
INSERT INTO compliance_program_events(principal_id,program_key,event_type,actor_id,payload)
VALUES($1,$2,$3,$4,$5::jsonb)
`, principalID, programKey, eventType, actorID, string(body))
	return err
}

func (s *Store) CreateChangeset(ctx context.Context, ch Changeset) error {
	payloadB, _ := json.Marshal(ch.Payload)
	_, err := s.DB.Exec(ctx, `
INSERT INTO contract_changesets(changeset_id,contract_id,status,payload,required_roles,proposed_by_actor_id)
VALUES($1,$2,$3,$4::jsonb,$5,$6)
`, ch.ChangesetID, ch.ContractID, ch.Status, string(payloadB), ch.RequiredRoles, ch.ProposedByActorID)
	return err
}

func (s *Store) GetChangeset(ctx context.Context, changesetID string) (Changeset, error) {
	var ch Changeset
	var payloadB []byte
	err := s.DB.QueryRow(ctx, `
SELECT changeset_id,contract_id,status,payload,required_roles,proposed_by_actor_id,decided_by_actor_id,applied_by_actor_id
FROM contract_changesets
WHERE changeset_id=$1
`, changesetID).Scan(&ch.ChangesetID, &ch.ContractID, &ch.Status, &payloadB, &ch.RequiredRoles, &ch.ProposedByActorID, &ch.DecidedByActorID, &ch.AppliedByActorID)
	if err != nil {
		return ch, err
	}
	_ = json.Unmarshal(payloadB, &ch.Payload)
	return ch, nil
}

func (s *Store) DecideChangeset(ctx context.Context, changesetID, status, actorID string) error {
	_, err := s.DB.Exec(ctx, `
UPDATE contract_changesets
SET status=$2,decided_by_actor_id=$3,decided_at=now()
WHERE changeset_id=$1
`, changesetID, status, actorID)
	return err
}

func (s *Store) ApplyChangeset(ctx context.Context, changesetID, actorID string) error {
	_, err := s.DB.Exec(ctx, `
UPDATE contract_changesets
SET status='APPLIED',applied_by_actor_id=$2,applied_at=now()
WHERE changeset_id=$1
`, changesetID, actorID)
	return err
}

func (s *Store) GetContract(ctx context.Context, id string) (Contract, error) {
	var c Contract
	err := s.DB.QueryRow(ctx, `SELECT contract_id,principal_id,template_id,template_version,subject_actor_id,gate_key,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id,created_at
FROM contracts WHERE contract_id=$1`, id).
		Scan(&c.ContractID, &c.PrincipalID, &c.TemplateID, &c.TemplateVersion, &c.SubjectActorID, &c.GateKey, &c.State, &c.RiskLevel, &c.CounterpartyName, &c.CounterpartyEmail, &c.CreatedBy, &c.CreatedAt)
	return c, err
}

func (s *Store) FindLatestGateContractForSubjectVersion(ctx context.Context, principalID, gateKey, subjectActorID, templateID, templateVersion string) (Contract, error) {
	var c Contract
	err := s.DB.QueryRow(ctx, `
SELECT contract_id,principal_id,template_id,template_version,subject_actor_id,gate_key,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id,created_at
FROM contracts
WHERE principal_id=$1
  AND gate_key=$2
  AND subject_actor_id=$3
  AND template_id=$4
  AND template_version=$5
ORDER BY created_at DESC, contract_id DESC
LIMIT 1
`, principalID, gateKey, subjectActorID, templateID, templateVersion).Scan(
		&c.ContractID, &c.PrincipalID, &c.TemplateID, &c.TemplateVersion, &c.SubjectActorID, &c.GateKey, &c.State, &c.RiskLevel, &c.CounterpartyName, &c.CounterpartyEmail, &c.CreatedBy, &c.CreatedAt,
	)
	return c, err
}

func (s *Store) FindLatestEffectiveGateContractForSubject(ctx context.Context, principalID, gateKey, subjectActorID string) (Contract, error) {
	var c Contract
	err := s.DB.QueryRow(ctx, `
SELECT contract_id,principal_id,template_id,template_version,subject_actor_id,gate_key,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id,created_at
FROM contracts
WHERE principal_id=$1
  AND gate_key=$2
  AND subject_actor_id=$3
  AND state='EFFECTIVE'
ORDER BY created_at DESC, contract_id DESC
LIMIT 1
`, principalID, gateKey, subjectActorID).Scan(
		&c.ContractID, &c.PrincipalID, &c.TemplateID, &c.TemplateVersion, &c.SubjectActorID, &c.GateKey, &c.State, &c.RiskLevel, &c.CounterpartyName, &c.CounterpartyEmail, &c.CreatedBy, &c.CreatedAt,
	)
	return c, err
}

func (s *Store) HasEffectiveContractForSubject(ctx context.Context, principalID, subjectActorID, templateID, templateVersion string) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM contracts
  WHERE principal_id=$1
    AND subject_actor_id=$2
    AND template_id=$3
    AND template_version=$4
    AND state='EFFECTIVE'
)
`, principalID, subjectActorID, templateID, templateVersion).Scan(&exists)
	return exists, err
}

func (s *Store) SetVariable(ctx context.Context, contractID string, key domain.VarKey, value string, source domain.VarSource, review domain.VarReviewStatus, actorID string) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO contract_variables(contract_id,var_key,value,source,review_status,updated_by_actor_id,updated_at)
VALUES($1,$2,$3,$4,$5,$6,now())
ON CONFLICT (contract_id,var_key) DO UPDATE SET
  value=EXCLUDED.value,
  source=EXCLUDED.source,
  review_status=EXCLUDED.review_status,
  updated_by_actor_id=EXCLUDED.updated_by_actor_id,
  updated_at=now()
`, contractID, string(key), value, string(source), string(review), actorID)
	return err
}

func (s *Store) GetVariables(ctx context.Context, contractID string) ([]domain.VariableValue, error) {
	rows, err := s.DB.Query(ctx, `SELECT var_key,value,source,review_status FROM contract_variables WHERE contract_id=$1 ORDER BY var_key ASC`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.VariableValue
	for rows.Next() {
		var key, val, src, rev string
		if err := rows.Scan(&key, &val, &src, &rev); err != nil {
			return nil, err
		}
		out = append(out, domain.VariableValue{
			Key:          domain.VarKey(key),
			Value:        val,
			Source:       domain.VarSource(src),
			ReviewStatus: domain.VarReviewStatus(rev),
		})
	}
	return out, rows.Err()
}

func (s *Store) ReviewVariables(ctx context.Context, contractID string, keys []string, decision string, reviewer string) error {
	status := "REJECTED"
	if decision == "APPROVE" {
		status = "APPROVED"
	}
	for _, k := range keys {
		_, err := s.DB.Exec(ctx, `UPDATE contract_variables SET review_status=$1, reviewed_by_actor_id=$2, reviewed_at=now() WHERE contract_id=$3 AND var_key=$4`,
			status, reviewer, contractID, k)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateApprovalRequest(ctx context.Context, id, contractID, action, tokenHash string, requiredRoles []string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO approval_requests(approval_request_id,contract_id,action,status,required_roles,review_token_hash)
VALUES($1,$2,$3,'PENDING',$4,$5)`, id, contractID, action, requiredRoles, tokenHash)
	return err
}

func (s *Store) GetApprovalRequest(ctx context.Context, id string) (status string, contractID string, action string, requiredRoles []string, err error) {
	err = s.DB.QueryRow(ctx, `SELECT status,contract_id,action,required_roles FROM approval_requests WHERE approval_request_id=$1`, id).
		Scan(&status, &contractID, &action, &requiredRoles)
	return
}

func (s *Store) ApproveApprovalRequest(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE approval_requests SET status='APPROVED', decided_at=now() WHERE approval_request_id=$1`, id)
	return err
}

func (s *Store) SaveApprovalDecision(ctx context.Context, approvalRequestID, actorID, decision string, signedPayload map[string]any, signedPayloadHash string, signature map[string]any) error {
	signedPayloadB, err := json.Marshal(signedPayload)
	if err != nil {
		return err
	}
	signatureB, err := json.Marshal(signature)
	if err != nil {
		return err
	}
	sigType := "WEBAUTHN_ASSERTION"
	if v, ok := signature["type"].(string); ok && strings.TrimSpace(v) != "" {
		sigType = v
	}
	_, err = s.DB.Exec(ctx, `
INSERT INTO approval_decisions(approval_request_id,actor_id,decision,signed_payload,signed_payload_hash,signature_type,signature_object)
VALUES($1,$2,$3,$4::jsonb,$5,$6,$7::jsonb)
ON CONFLICT (approval_request_id,actor_id) DO UPDATE SET
  decision=EXCLUDED.decision,
  signed_payload=EXCLUDED.signed_payload,
  signed_payload_hash=EXCLUDED.signed_payload_hash,
  signature_type=EXCLUDED.signature_type,
  signature_object=EXCLUDED.signature_object,
  decided_at=now()
`, approvalRequestID, actorID, decision, string(signedPayloadB), signedPayloadHash, sigType, string(signatureB))
	return err
}

func (s *Store) ListApprovalRequests(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT approval_request_id,action,status,required_roles FROM approval_requests WHERE contract_id=$1 ORDER BY created_at DESC`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, action, status string
		var roles []string
		if err := rows.Scan(&id, &action, &status, &roles); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"approval_request_id": id, "action": action, "status": status, "required_roles": roles})
	}
	return out, rows.Err()
}

func (s *Store) ListApprovalRequestsForEvidence(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT approval_request_id,action,status,required_roles,missing_required_vars,needs_human_entry,needs_human_review,created_at,decided_at
FROM approval_requests
WHERE contract_id=$1
ORDER BY created_at ASC, approval_request_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, action, status string
		var requiredRoles, missingRequired, needsHumanEntry, needsHumanReview []string
		var createdAt time.Time
		var decidedAt *time.Time
		if err := rows.Scan(&id, &action, &status, &requiredRoles, &missingRequired, &needsHumanEntry, &needsHumanReview, &createdAt, &decidedAt); err != nil {
			return nil, err
		}
		row := map[string]any{
			"approval_request_id":   id,
			"action":                action,
			"status":                status,
			"required_roles":        requiredRoles,
			"missing_required_vars": missingRequired,
			"needs_human_entry":     needsHumanEntry,
			"needs_human_review":    needsHumanReview,
			"created_at":            createdAt.UTC().Format(time.RFC3339),
		}
		if decidedAt != nil {
			row["decided_at"] = decidedAt.UTC().Format(time.RFC3339)
		} else {
			row["decided_at"] = nil
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) TransitionState(ctx context.Context, contractID, newState string) error {
	_, err := s.DB.Exec(ctx, `UPDATE contracts SET state=$1, updated_at=now() WHERE contract_id=$2`, newState, contractID)
	return err
}

func (s *Store) UpsertEnvelope(ctx context.Context, contractID, provider, envelopeID, status, signingURL string, recipients []map[string]any) error {
	recipientsB, _ := json.Marshal(recipients)
	_, err := s.DB.Exec(ctx, `
INSERT INTO signature_envelopes(contract_id,provider,envelope_id,status,signing_url,recipients)
VALUES($1,$2,$3,$4,$5,$6::jsonb)
ON CONFLICT (contract_id) DO UPDATE SET provider=$2, envelope_id=$3, status=$4, signing_url=$5, recipients=$6::jsonb, updated_at=now()
`, contractID, provider, envelopeID, status, signingURL, string(recipientsB))
	return err
}

func (s *Store) GetEnvelope(ctx context.Context, contractID string) (map[string]any, error) {
	var provider, env, status string
	var signingURL *string
	var recipientsB []byte
	err := s.DB.QueryRow(ctx, `SELECT provider,envelope_id,status,signing_url,recipients FROM signature_envelopes WHERE contract_id=$1`, contractID).Scan(&provider, &env, &status, &signingURL, &recipientsB)
	if err != nil {
		return nil, err
	}
	var recipients any
	_ = json.Unmarshal(recipientsB, &recipients)
	return map[string]any{"provider": provider, "envelope_id": env, "status": status, "signing_url": signingURL, "recipients": recipients}, nil
}

func (s *Store) ListSignatureEnvelopesForEvidence(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT provider,envelope_id,status,signing_url,recipients,created_at,updated_at
FROM signature_envelopes
WHERE contract_id=$1
ORDER BY created_at ASC, envelope_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var provider, envelopeID, status string
		var signingURL *string
		var recipientsB []byte
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&provider, &envelopeID, &status, &signingURL, &recipientsB, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		var recipients any
		_ = json.Unmarshal(recipientsB, &recipients)
		out = append(out, map[string]any{
			"provider":    provider,
			"envelope_id": envelopeID,
			"status":      status,
			"signing_url": signingURL,
			"recipients":  recipients,
			"created_at":  createdAt.UTC().Format(time.RFC3339),
			"updated_at":  updatedAt.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

func (s *Store) AddEvent(ctx context.Context, contractID, typ, actorID string, payload map[string]any) error {
	b, _ := json.Marshal(payload)
	_, err := s.DB.Exec(ctx, `INSERT INTO contract_events(contract_id,type,actor_id,payload) VALUES($1,$2,$3,$4::jsonb)`,
		contractID, typ, actorID, string(b))
	return err
}

func (s *Store) ListEvents(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT type,actor_id,occurred_at,payload FROM contract_events WHERE contract_id=$1 ORDER BY occurred_at ASC, event_id ASC`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var typ string
		var actorID *string
		var at time.Time
		var payload []byte
		if err := rows.Scan(&typ, &actorID, &at, &payload); err != nil {
			return nil, err
		}
		var obj any
		_ = json.Unmarshal(payload, &obj)
		out = append(out, map[string]any{"type": typ, "actor_id": actorID, "at": at.Format(time.RFC3339), "payload": obj})
	}
	return out, rows.Err()
}

func (s *Store) UpsertCommerceIntentArtifact(ctx context.Context, contractID, actorID, intentHash string, payload map[string]any) error {
	var exists bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM contract_events
  WHERE contract_id=$1
    AND type='COMMERCE_INTENT_ACCEPTED'
    AND payload->>'intent_hash'=$2
)
`, contractID, intentHash).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.AddEvent(ctx, contractID, "COMMERCE_INTENT_ACCEPTED", actorID, payload)
}

func (s *Store) UpsertCommerceAcceptArtifact(ctx context.Context, contractID, actorID, acceptHash string, payload map[string]any) error {
	var exists bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM contract_events
  WHERE contract_id=$1
    AND type='COMMERCE_ACCEPT_ACCEPTED'
    AND payload->>'accept_hash'=$2
)
`, contractID, acceptHash).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.AddEvent(ctx, contractID, "COMMERCE_ACCEPT_ACCEPTED", actorID, payload)
}

func (s *Store) CommerceIntentHashExists(ctx context.Context, contractID, intentHash string) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1
  FROM contract_events
  WHERE contract_id=$1
    AND type='COMMERCE_INTENT_ACCEPTED'
    AND payload->>'intent_hash'=$2
)
`, contractID, intentHash).Scan(&exists)
	return exists, err
}

func (s *Store) ListCommerceIntentsForEvidence(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT payload
FROM contract_events
WHERE contract_id=$1
  AND type='COMMERCE_INTENT_ACCEPTED'
ORDER BY payload->>'intent_hash' ASC, event_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var payloadB []byte
		if err := rows.Scan(&payloadB); err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadB, &payload); err != nil {
			return nil, err
		}
		intent, _ := payload["intent"].(map[string]any)
		sig, _ := payload["buyer_signature"].(map[string]any)
		if intent == nil || sig == nil {
			continue
		}
		out = append(out, map[string]any{
			"intent":          intent,
			"buyer_signature": sig,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListCommerceAcceptsForEvidence(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT payload
FROM contract_events
WHERE contract_id=$1
  AND type='COMMERCE_ACCEPT_ACCEPTED'
ORDER BY payload->>'accept_hash' ASC, event_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var payloadB []byte
		if err := rows.Scan(&payloadB); err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadB, &payload); err != nil {
			return nil, err
		}
		accept, _ := payload["accept"].(map[string]any)
		sig, _ := payload["seller_signature"].(map[string]any)
		if accept == nil || sig == nil {
			continue
		}
		out = append(out, map[string]any{
			"accept":           accept,
			"seller_signature": sig,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListCommerceDelegationsForAuthorization(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT payload
FROM contract_events
WHERE contract_id=$1
  AND type='COMMERCE_DELEGATION'
ORDER BY payload->'delegation'->>'delegation_id' ASC, event_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var payloadB []byte
		if err := rows.Scan(&payloadB); err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadB, &payload); err != nil {
			return nil, err
		}
		delegation, _ := payload["delegation"].(map[string]any)
		sig, _ := payload["issuer_signature"].(map[string]any)
		if delegation == nil || sig == nil {
			continue
		}
		out = append(out, map[string]any{
			"delegation":       delegation,
			"issuer_signature": sig,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListCommerceDelegationRevocationsForAuthorization(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT payload
FROM contract_events
WHERE contract_id=$1
  AND type='COMMERCE_DELEGATION_REVOCATION'
ORDER BY payload->>'revocation_hash' ASC, event_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var payloadB []byte
		if err := rows.Scan(&payloadB); err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadB, &payload); err != nil {
			return nil, err
		}
		revocation, _ := payload["revocation"].(map[string]any)
		sig, _ := payload["issuer_signature"].(map[string]any)
		if revocation == nil || sig == nil {
			continue
		}
		row := map[string]any{
			"revocation":       revocation,
			"issuer_signature": sig,
		}
		if h := strings.TrimSpace(fmt.Sprint(payload["revocation_hash"])); h != "" {
			row["revocation_hash"] = h
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) GetIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string) (int, map[string]any, bool, error) {
	var status int
	var body []byte
	err := s.DB.QueryRow(ctx, `
SELECT response_status,response_body
FROM idempotency_records
WHERE principal_id=$1 AND actor_id=$2 AND idempotency_key=$3 AND endpoint=$4
`, principalID, actorID, idempotencyKey, endpoint).Scan(&status, &body)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, false, nil
		}
		return 0, nil, false, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, nil, false, err
	}
	return status, out, true, nil
}

func (s *Store) SaveIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string, responseStatus int, responseBody map[string]any) error {
	body, err := json.Marshal(responseBody)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `
INSERT INTO idempotency_records(principal_id,actor_id,idempotency_key,endpoint,response_status,response_body)
VALUES($1,$2,$3,$4,$5,$6::jsonb)
ON CONFLICT (principal_id,actor_id,idempotency_key,endpoint) DO NOTHING
`, principalID, actorID, idempotencyKey, endpoint, responseStatus, string(body))
	return err
}

func (s *Store) ListIdempotencyRecordsForContract(ctx context.Context, principalID, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT principal_id,actor_id,idempotency_key,endpoint,response_status,response_body,created_at
FROM idempotency_records
WHERE principal_id=$1
  AND endpoint LIKE '%' || $2 || '%'
ORDER BY created_at ASC, idempotency_key ASC
`, principalID, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var pID, actorID, key, endpoint string
		var responseStatus int
		var responseBody []byte
		var createdAt time.Time
		if err := rows.Scan(&pID, &actorID, &key, &endpoint, &responseStatus, &responseBody, &createdAt); err != nil {
			return nil, err
		}
		var body any
		_ = json.Unmarshal(responseBody, &body)
		out = append(out, map[string]any{
			"principal_id":    pID,
			"actor_id":        actorID,
			"idempotency_key": key,
			"endpoint":        endpoint,
			"response_status": responseStatus,
			"response_body":   body,
			"created_at":      createdAt.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

func (s *Store) ListActiveDelegationsForEvidence(ctx context.Context, principalID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT delegation_id,principal_id,delegator_actor_id,delegate_actor_id,scope,issued_at,expires_at,signature,created_at
FROM delegation_records
WHERE principal_id=$1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR now() < expires_at)
ORDER BY issued_at ASC, delegation_id ASC
`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var delegationID, pID, delegatorActorID, delegateActorID string
		var scopeB, signatureB []byte
		var issuedAt, createdAt time.Time
		var expiresAt *time.Time
		if err := rows.Scan(&delegationID, &pID, &delegatorActorID, &delegateActorID, &scopeB, &issuedAt, &expiresAt, &signatureB, &createdAt); err != nil {
			return nil, err
		}
		var scopeObj any
		var signatureObj any
		_ = json.Unmarshal(scopeB, &scopeObj)
		_ = json.Unmarshal(signatureB, &signatureObj)
		row := map[string]any{
			"delegation_id":      delegationID,
			"principal_id":       pID,
			"delegator_actor_id": delegatorActorID,
			"delegate_actor_id":  delegateActorID,
			"scope":              scopeObj,
			"issued_at":          issuedAt.UTC().Format(time.RFC3339),
			"signature":          signatureObj,
			"created_at":         createdAt.UTC().Format(time.RFC3339),
		}
		if expiresAt != nil {
			row["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) ListVerifiedWebhookReceiptsForContractEvidence(ctx context.Context, principalID, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT receipt_id::text,provider,event_type,provider_event_id,received_at,request_method,request_path,
       raw_body_sha256,headers_sha256,request_sha256,signature_scheme,signature_details,linked_action
FROM webhook_receipts_v2
WHERE principal_id::text=$1
  AND linked_contract_id::text=$2
  AND signature_valid=true
ORDER BY received_at ASC, provider ASC, COALESCE(provider_event_id,'') ASC, receipt_id ASC
`, principalID, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var receiptID, provider, eventType, requestMethod, requestPath string
		var providerEventID, linkedAction *string
		var receivedAt time.Time
		var rawBodySHA256, headersSHA256, requestSHA256, signatureScheme string
		var signatureDetailsB []byte
		if err := rows.Scan(
			&receiptID, &provider, &eventType, &providerEventID, &receivedAt, &requestMethod, &requestPath,
			&rawBodySHA256, &headersSHA256, &requestSHA256, &signatureScheme, &signatureDetailsB, &linkedAction,
		); err != nil {
			return nil, err
		}
		var signatureDetails any = map[string]any{}
		if len(signatureDetailsB) > 0 {
			if err := json.Unmarshal(signatureDetailsB, &signatureDetails); err != nil {
				return nil, err
			}
		}
		row := map[string]any{
			"receipt_id":        receiptID,
			"provider":          provider,
			"event_type":        eventType,
			"provider_event_id": "",
			"received_at":       receivedAt.UTC().Format(time.RFC3339Nano),
			"request_method":    requestMethod,
			"request_path":      requestPath,
			"raw_body_sha256":   rawBodySHA256,
			"headers_sha256":    headersSHA256,
			"request_sha256":    requestSHA256,
			"signature_scheme":  signatureScheme,
			"signature_details": signatureDetails,
			"linked_action":     "",
		}
		if providerEventID != nil {
			row["provider_event_id"] = *providerEventID
		}
		if linkedAction != nil {
			row["linked_action"] = *linkedAction
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) ListApprovalDecisionsForEvidence(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT ad.approval_request_id,ad.actor_id,ad.decision,ad.decided_at,ad.signed_payload,ad.signed_payload_hash,ad.signature_type,ad.signature_object
FROM approval_decisions ad
JOIN approval_requests ar ON ar.approval_request_id=ad.approval_request_id
WHERE ar.contract_id=$1
ORDER BY ad.decided_at ASC, ad.approval_request_id ASC, ad.actor_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		//var approvalRequestID, actorID, decision, decidedAt, signedPayloadHash, signatureType string
		var approvalRequestID, actorID, decision, signedPayloadHash, signatureType string
		var decidedAt *time.Time
		var signedPayloadB, signatureObjB []byte
		if err := rows.Scan(&approvalRequestID, &actorID, &decision, &decidedAt, &signedPayloadB, &signedPayloadHash, &signatureType, &signatureObjB); err != nil {
			return nil, err
		}
		var signedPayloadObj any
		var signatureObj any
		_ = json.Unmarshal(signedPayloadB, &signedPayloadObj)
		_ = json.Unmarshal(signatureObjB, &signatureObj)
		/*
			out = append(out, map[string]any{
				"approval_request_id": approvalRequestID,
				"actor_id":            actorID,
				"decision":            decision,
				"decided_at":          decidedAt,
				"signed_payload":      signedPayloadObj,
				"signed_payload_hash": signedPayloadHash,
				"signature_type":      signatureType,
				"signature_object":    signatureObj,
			})
		*/
		row := map[string]any{
			"approval_request_id": approvalRequestID,
			"actor_id":            actorID,
			"decision":            decision,
			"signed_payload":      signedPayloadObj,
			"signed_payload_hash": signedPayloadHash,
			"signature_type":      signatureType,
			"signature_object":    signatureObj,
		}

		if decidedAt != nil {
			row["decided_at"] = decidedAt.UTC().Format(time.RFC3339)
		} else {
			row["decided_at"] = nil
		}

		out = append(out, row)

	}
	return out, rows.Err()
}

func (s *Store) ListApprovalRequestsForHash(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT action,status,required_roles
FROM approval_requests
WHERE contract_id=$1
ORDER BY action ASC, status ASC, approval_request_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var action, status string
		var roles []string
		if err := rows.Scan(&action, &status, &roles); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"action":         action,
			"status":         status,
			"required_roles": roles,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListApprovalDecisionsForHash(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT ar.approval_request_id,ar.action,ad.actor_id,ad.decision,ad.signed_payload,ad.signed_payload_hash,ad.signature_type,ad.signature_object
FROM approval_requests ar
JOIN approval_decisions ad ON ad.approval_request_id=ar.approval_request_id
WHERE ar.contract_id=$1
ORDER BY ar.approval_request_id ASC, ad.actor_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var approvalRequestID, action, actorID, decision, signedPayloadHash, signatureType string
		var signedPayloadB, signatureObjB []byte
		if err := rows.Scan(&approvalRequestID, &action, &actorID, &decision, &signedPayloadB, &signedPayloadHash, &signatureType, &signatureObjB); err != nil {
			return nil, err
		}
		var signedPayloadObj any
		var signatureObj any
		_ = json.Unmarshal(signedPayloadB, &signedPayloadObj)
		_ = json.Unmarshal(signatureObjB, &signatureObj)
		out = append(out, map[string]any{
			"approval_request_id": approvalRequestID,
			"action":              action,
			"actor_id":            actorID,
			"decision":            decision,
			"signed_payload":      signedPayloadObj,
			"signed_payload_hash": signedPayloadHash,
			"signature_type":      signatureType,
			"signature_object":    signatureObj,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListEventsForHash(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `
SELECT type,payload
FROM contract_events
WHERE contract_id=$1
ORDER BY occurred_at ASC, event_id ASC
`, contractID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var typ string
		var payload []byte
		if err := rows.Scan(&typ, &payload); err != nil {
			return nil, err
		}
		var obj any
		_ = json.Unmarshal(payload, &obj)
		out = append(out, map[string]any{"type": typ, "payload": obj})
	}
	return out, rows.Err()
}

func (s *Store) SaveContractHashes(ctx context.Context, contractID string, packetInput, diffInput, riskInput map[string]any, packetHash, diffHash, riskHash string) error {
	packetB, err := json.Marshal(packetInput)
	if err != nil {
		return err
	}
	diffB, err := json.Marshal(diffInput)
	if err != nil {
		return err
	}
	riskB, err := json.Marshal(riskInput)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `
INSERT INTO contract_hash_artifacts(contract_id,packet_input,diff_input,risk_input,packet_hash,diff_hash,risk_hash,updated_at)
VALUES($1,$2::jsonb,$3::jsonb,$4::jsonb,$5,$6,$7,now())
ON CONFLICT (contract_id) DO UPDATE SET
  packet_input=EXCLUDED.packet_input,
  diff_input=EXCLUDED.diff_input,
  risk_input=EXCLUDED.risk_input,
  packet_hash=EXCLUDED.packet_hash,
  diff_hash=EXCLUDED.diff_hash,
  risk_hash=EXCLUDED.risk_hash,
  updated_at=now()
`, contractID, string(packetB), string(diffB), string(riskB), packetHash, diffHash, riskHash)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `
UPDATE contracts
SET packet_hash=$2, diff_hash=$3, risk_hash=$4, updated_at=now()
WHERE contract_id=$1
`, contractID, packetHash, diffHash, riskHash)
	return err
}

func (s *Store) GetContractHashes(ctx context.Context, contractID string) (map[string]any, error) {
	var packetInput, diffInput, riskInput []byte
	var packetHash, diffHash, riskHash string
	err := s.DB.QueryRow(ctx, `
SELECT packet_input,diff_input,risk_input,packet_hash,diff_hash,risk_hash
FROM contract_hash_artifacts
WHERE contract_id=$1
`, contractID).Scan(&packetInput, &diffInput, &riskInput, &packetHash, &diffHash, &riskHash)
	if err != nil {
		return nil, err
	}
	var packetObj, diffObj, riskObj map[string]any
	_ = json.Unmarshal(packetInput, &packetObj)
	_ = json.Unmarshal(diffInput, &diffObj)
	_ = json.Unmarshal(riskInput, &riskObj)
	return map[string]any{
		"packet_input": packetObj,
		"diff_input":   diffObj,
		"risk_input":   riskObj,
		"packet_hash":  packetHash,
		"diff_hash":    diffHash,
		"risk_hash":    riskHash,
	}, nil
}

type AnchorRecord struct {
	AnchorID   string
	Target     string
	TargetHash string
	AnchorType string
	Status     string
	Request    map[string]any
	Proof      map[string]any
	CreatedAt  time.Time
	AnchoredAt *time.Time
}

func (s *Store) InsertAnchor(
	ctx context.Context,
	principalID, contractID, target, targetHash, anchorType, status string,
	request, proof map[string]any,
	anchoredAt *time.Time,
) (AnchorRecord, error) {
	principalUUID, err := parseResourceUUID(principalID)
	if err != nil {
		return AnchorRecord{}, err
	}
	contractUUID, err := parseResourceUUID(contractID)
	if err != nil {
		return AnchorRecord{}, err
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return AnchorRecord{}, err
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return AnchorRecord{}, err
	}

	var out AnchorRecord
	var reqB, proofB []byte
	err = s.DB.QueryRow(ctx, `
INSERT INTO anchors_v1(
  principal_id,contract_id,target,target_hash,anchor_type,status,request,proof,anchored_at
)
VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)
RETURNING anchor_id::text,target,target_hash,anchor_type,status,request,proof,created_at,anchored_at
`, principalUUID, contractUUID, target, targetHash, anchorType, status, string(requestJSON), string(proofJSON), anchoredAt).Scan(
		&out.AnchorID, &out.Target, &out.TargetHash, &out.AnchorType, &out.Status, &reqB, &proofB, &out.CreatedAt, &out.AnchoredAt,
	)
	if err != nil {
		return AnchorRecord{}, err
	}
	out.Request = map[string]any{}
	out.Proof = map[string]any{}
	if len(reqB) > 0 {
		if err := json.Unmarshal(reqB, &out.Request); err != nil {
			return AnchorRecord{}, err
		}
	}
	if len(proofB) > 0 {
		if err := json.Unmarshal(proofB, &out.Proof); err != nil {
			return AnchorRecord{}, err
		}
	}
	return out, nil
}

func (s *Store) ListAnchorsForContract(ctx context.Context, principalID, contractID string) ([]AnchorRecord, error) {
	principalUUID, err := parseResourceUUID(principalID)
	if err != nil {
		return nil, err
	}
	contractUUID, err := parseResourceUUID(contractID)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, `
SELECT anchor_id::text,target,target_hash,anchor_type,status,request,proof,created_at,anchored_at
FROM anchors_v1
WHERE principal_id=$1
  AND contract_id=$2
ORDER BY created_at ASC, anchor_id ASC
`, principalUUID, contractUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AnchorRecord, 0)
	for rows.Next() {
		var row AnchorRecord
		var reqB, proofB []byte
		if err := rows.Scan(
			&row.AnchorID, &row.Target, &row.TargetHash, &row.AnchorType, &row.Status, &reqB, &proofB, &row.CreatedAt, &row.AnchoredAt,
		); err != nil {
			return nil, err
		}
		row.Request = map[string]any{}
		row.Proof = map[string]any{}
		if len(reqB) > 0 {
			if err := json.Unmarshal(reqB, &row.Request); err != nil {
				return nil, err
			}
		}
		if len(proofB) > 0 {
			if err := json.Unmarshal(proofB, &row.Proof); err != nil {
				return nil, err
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) ListAnchorsForContractEvidence(ctx context.Context, principalID, contractID string) ([]map[string]any, error) {
	// Evidence export must remain available for legacy/dev identifiers that are not UUID-compatible.
	// anchors_v1 is UUID-keyed, so non-UUID principal/contract IDs cannot have anchor rows; return [] deterministically.
	if _, err := parseResourceUUID(principalID); err != nil {
		return []map[string]any{}, nil
	}
	if _, err := parseResourceUUID(contractID); err != nil {
		return []map[string]any{}, nil
	}
	anchors, err := s.ListAnchorsForContract(ctx, principalID, contractID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(anchors))
	for _, a := range anchors {
		row := map[string]any{
			"anchor_id":   a.AnchorID,
			"target":      a.Target,
			"target_hash": a.TargetHash,
			"anchor_type": a.AnchorType,
			"status":      a.Status,
			"request":     a.Request,
			"proof":       a.Proof,
			"created_at":  a.CreatedAt.UTC().Format(time.RFC3339Nano),
			"anchored_at": "",
		}
		if a.AnchoredAt != nil {
			row["anchored_at"] = a.AnchoredAt.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, row)
	}
	return out, nil
}

func parseResourceUUID(id string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return uuid.Nil, fmt.Errorf("empty identifier")
	}
	if u, err := uuid.Parse(trimmed); err == nil {
		return u, nil
	}
	parts := strings.SplitN(trimmed, "_", 2)
	if len(parts) == 2 {
		if u, err := uuid.Parse(parts[1]); err == nil {
			return u, nil
		}
	}
	return uuid.Nil, fmt.Errorf("identifier %q is not uuid-compatible", id)
}
