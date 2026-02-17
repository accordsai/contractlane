package store

import (
	"context"
	"encoding/json"
	"time"

	"contractlane/pkg/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ DB *pgxpool.Pool }
func New(db *pgxpool.Pool) *Store { return &Store{DB: db} }

type Template struct {
	TemplateID    string `json:"template_id"`
	ContractType  string `json:"contract_type"`
	Jurisdiction  string `json:"jurisdiction"`
	DisplayName   string `json:"display_name"`
	RiskTier      string `json:"risk_tier"`
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
	if err != nil { return "", err }
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
($1,'party_address','ADDRESS',true,'PII','HUMAN_REQUIRED','{}'::jsonb),
($1,'price','MONEY',false,'NONE','AGENT_FILL_HUMAN_REVIEW','{}'::jsonb)
ON CONFLICT (template_id,var_key) DO NOTHING`, tplID)

	if err := tx.Commit(ctx); err != nil { return "", err }
	return tplID, nil
}

func (s *Store) ListTemplates(ctx context.Context, contractType, jurisdiction string) ([]Template, error) {
	rows, err := s.DB.Query(ctx, `SELECT template_id,contract_type,jurisdiction,display_name,risk_tier FROM templates WHERE contract_type=$1 AND jurisdiction=$2`,
		contractType, jurisdiction)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.TemplateID,&t.ContractType,&t.Jurisdiction,&t.DisplayName,&t.RiskTier); err != nil { return nil, err }
		out = append(out, t)
	}
	return out, rows.Err()
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

func (s *Store) GetTemplateVars(ctx context.Context, templateID string) ([]domain.VariableDefinition, error) {
	rows, err := s.DB.Query(ctx, `SELECT var_key,var_type,required,sensitivity,set_policy,constraints FROM template_variables WHERE template_id=$1`, templateID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []domain.VariableDefinition
	for rows.Next() {
		var key, typ, sens, pol string
		var required bool
		var constraints []byte
		if err := rows.Scan(&key,&typ,&required,&sens,&pol,&constraints); err != nil { return nil, err }
		def := domain.VariableDefinition{
			Key: domain.VarKey(key),
			Type: domain.VarType(typ),
			Required: required,
			Sensitivity: domain.VarSensitivity(sens),
			SetPolicy: domain.VarSetPolicy(pol),
		}
		out = append(out, def)
	}
	return out, rows.Err()
}

func (s *Store) GetTemplateGates(ctx context.Context, templateID string) (map[string]string, error) {
	var gatesBytes []byte
	err := s.DB.QueryRow(ctx, `SELECT template_gates FROM template_governance WHERE template_id=$1`, templateID).Scan(&gatesBytes)
	if err != nil { return nil, err }
	var gates map[string]string
	_ = json.Unmarshal(gatesBytes, &gates)
	return gates, nil
}

type Contract struct {
	ContractID string `json:"contract_id"`
	PrincipalID string `json:"principal_id"`
	TemplateID string `json:"template_id"`
	State string `json:"state"`
	RiskLevel string `json:"risk_level"`
	CounterpartyName string `json:"counterparty_name"`
	CounterpartyEmail string `json:"counterparty_email"`
	CreatedBy string `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreateContract(ctx context.Context, c Contract) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO contracts(contract_id,principal_id,template_id,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		c.ContractID,c.PrincipalID,c.TemplateID,c.State,c.RiskLevel,c.CounterpartyName,c.CounterpartyEmail,c.CreatedBy)
	return err
}

func (s *Store) GetContract(ctx context.Context, id string) (Contract, error) {
	var c Contract
	err := s.DB.QueryRow(ctx, `SELECT contract_id,principal_id,template_id,state,risk_level,counterparty_name,counterparty_email,created_by_actor_id,created_at
FROM contracts WHERE contract_id=$1`, id).
Scan(&c.ContractID,&c.PrincipalID,&c.TemplateID,&c.State,&c.RiskLevel,&c.CounterpartyName,&c.CounterpartyEmail,&c.CreatedBy,&c.CreatedAt)
	return c, err
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
	rows, err := s.DB.Query(ctx, `SELECT var_key,value,source,review_status FROM contract_variables WHERE contract_id=$1`, contractID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []domain.VariableValue
	for rows.Next() {
		var key, val, src, rev string
		if err := rows.Scan(&key,&val,&src,&rev); err != nil { return nil, err }
		out = append(out, domain.VariableValue{
			Key: domain.VarKey(key),
			Value: val,
			Source: domain.VarSource(src),
			ReviewStatus: domain.VarReviewStatus(rev),
		})
	}
	return out, rows.Err()
}

func (s *Store) ReviewVariables(ctx context.Context, contractID string, keys []string, decision string, reviewer string) error {
	status := "REJECTED"
	if decision == "APPROVE" { status = "APPROVED" }
	for _, k := range keys {
		_, err := s.DB.Exec(ctx, `UPDATE contract_variables SET review_status=$1, reviewed_by_actor_id=$2, reviewed_at=now() WHERE contract_id=$3 AND var_key=$4`,
			status, reviewer, contractID, k)
		if err != nil { return err }
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
		Scan(&status,&contractID,&action,&requiredRoles)
	return
}

func (s *Store) ApproveApprovalRequest(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE approval_requests SET status='APPROVED', decided_at=now() WHERE approval_request_id=$1`, id)
	return err
}

func (s *Store) ListApprovalRequests(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT approval_request_id,action,status,required_roles FROM approval_requests WHERE contract_id=$1 ORDER BY created_at DESC`, contractID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, action, status string
		var roles []string
		if err := rows.Scan(&id,&action,&status,&roles); err != nil { return nil, err }
		out = append(out, map[string]any{"approval_request_id": id, "action": action, "status": status, "required_roles": roles})
	}
	return out, rows.Err()
}

func (s *Store) TransitionState(ctx context.Context, contractID, newState string) error {
	_, err := s.DB.Exec(ctx, `UPDATE contracts SET state=$1, updated_at=now() WHERE contract_id=$2`, newState, contractID)
	return err
}

func (s *Store) UpsertEnvelope(ctx context.Context, contractID, provider, envelopeID, status string) error {
	_, err := s.DB.Exec(ctx, `
INSERT INTO signature_envelopes(contract_id,provider,envelope_id,status)
VALUES($1,$2,$3,$4)
ON CONFLICT (contract_id) DO UPDATE SET provider=$2, envelope_id=$3, status=$4, updated_at=now()
`, contractID, provider, envelopeID, status)
	return err
}

func (s *Store) GetEnvelope(ctx context.Context, contractID string) (map[string]any, error) {
	var provider, env, status string
	err := s.DB.QueryRow(ctx, `SELECT provider,envelope_id,status FROM signature_envelopes WHERE contract_id=$1`, contractID).Scan(&provider,&env,&status)
	if err != nil { return nil, err }
	return map[string]any{"provider": provider, "envelope_id": env, "status": status}, nil
}

func (s *Store) AddEvent(ctx context.Context, contractID, typ, actorID string, payload map[string]any) error {
	b, _ := json.Marshal(payload)
	_, err := s.DB.Exec(ctx, `INSERT INTO contract_events(contract_id,type,actor_id,payload) VALUES($1,$2,$3,$4::jsonb)`,
		contractID, typ, actorID, string(b))
	return err
}

func (s *Store) ListEvents(ctx context.Context, contractID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT type,actor_id,occurred_at,payload FROM contract_events WHERE contract_id=$1 ORDER BY occurred_at ASC`, contractID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var typ string
		var actorID *string
		var at time.Time
		var payload []byte
		if err := rows.Scan(&typ,&actorID,&at,&payload); err != nil { return nil, err }
		var obj any
		_ = json.Unmarshal(payload, &obj)
		out = append(out, map[string]any{"type": typ, "actor_id": actorID, "at": at.Format(time.RFC3339), "payload": obj})
	}
	return out, rows.Err()
}
