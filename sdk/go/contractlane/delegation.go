package contractlane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"contractlane/pkg/evidencehash"
	signaturev1 "contractlane/pkg/signature"
)

const (
	DelegationScopeCommerceIntentSign = "commerce:intent:sign"
	DelegationScopeCommerceAcceptSign = "commerce:accept:sign"
	DelegationScopeCELActionExecute   = "cel:action:execute" // reserved
	DelegationScopeCELApprovalSign    = "cel:approval:sign"  // reserved
	DelegationScopeSettlementAttest   = "settlement:attest"  // reserved
)

const (
	DelegationFailureMissing           = "missing_delegation"
	DelegationFailureUntrustedIssuer   = "delegation_untrusted_issuer"
	DelegationFailureScopeMissing      = "delegation_scope_missing"
	DelegationFailureConstraintsFailed = "delegation_constraints_failed"
	DelegationFailureSignatureInvalid  = "delegation_signature_invalid"
	DelegationFailureExpired           = "delegation_expired"
	DelegationFailureAmountExceeded    = "delegation_amount_exceeded"
)

var knownDelegationScopes = map[string]struct{}{
	DelegationScopeCommerceIntentSign: {},
	DelegationScopeCommerceAcceptSign: {},
	DelegationScopeCELActionExecute:   {},
	DelegationScopeCELApprovalSign:    {},
	DelegationScopeSettlementAttest:   {},
}

type DelegationV1 struct {
	Version      string                  `json:"version"`
	DelegationID string                  `json:"delegation_id"`
	IssuerAgent  string                  `json:"issuer_agent"`
	SubjectAgent string                  `json:"subject_agent"`
	Scopes       []string                `json:"scopes"`
	Constraints  DelegationConstraintsV1 `json:"constraints"`
	Nonce        string                  `json:"nonce"`
	IssuedAt     string                  `json:"issued_at"`
}

type DelegationConstraintsV1 struct {
	ContractID        string            `json:"contract_id"`
	CounterpartyAgent string            `json:"counterparty_agent"`
	MaxAmount         *CommerceAmountV1 `json:"max_amount,omitempty"`
	ValidFrom         string            `json:"valid_from"`
	ValidUntil        string            `json:"valid_until"`
	MaxUses           *int64            `json:"max_uses,omitempty"`
	Purpose           *string           `json:"purpose,omitempty"`
}

type SignedDelegationV1 struct {
	Delegation      DelegationV1  `json:"delegation"`
	IssuerSignature SigV1Envelope `json:"issuer_signature"`
}

type DelegationEvalContext struct {
	ContractID        string
	CounterpartyAgent string
	IssuedAtUTC       string
	PaymentAmount     *CommerceAmountV1
}

type DelegationConstraintError struct {
	Reason string
	Err    error
}

func (e *DelegationConstraintError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Reason
	}
	return fmt.Sprintf("%s: %v", e.Reason, e.Err)
}

func HashDelegationV1(payload DelegationV1) (string, error) {
	n, err := normalizeDelegationV1(payload)
	if err != nil {
		return "", err
	}
	return canonicalSha256Hex(delegationPayloadMap(n))
}

func SignDelegationV1(payload DelegationV1, priv ed25519.PrivateKey, issuedAt time.Time) (SigV1Envelope, error) {
	n, err := normalizeDelegationV1(payload)
	if err != nil {
		return SigV1Envelope{}, err
	}
	return SignSigV1Ed25519(delegationPayloadMap(n), priv, issuedAt, "delegation")
}

func VerifyDelegationV1(payload DelegationV1, sig SigV1Envelope) error {
	n, err := normalizeDelegationV1(payload)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sig.Context) != "" && strings.TrimSpace(sig.Context) != "delegation" {
		return errors.New("signature context mismatch")
	}
	hash, err := HashDelegationV1(n)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sig.PayloadHash) != hash {
		return errors.New("payload hash mismatch")
	}
	_, err = signaturev1.VerifyEnvelopeV1(delegationPayloadMap(n), signaturev1.EnvelopeV1{
		Version:     sig.Version,
		Algorithm:   sig.Algorithm,
		PublicKey:   sig.PublicKey,
		Signature:   sig.Signature,
		PayloadHash: sig.PayloadHash,
		IssuedAt:    sig.IssuedAt,
		KeyID:       sig.KeyID,
		Context:     sig.Context,
	})
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return errors.New("invalid signature public_key encoding")
	}
	issuerAgentID, err := AgentIDFromEd25519PublicKey(pub)
	if err != nil {
		return err
	}
	if issuerAgentID != n.IssuerAgent {
		return errors.New("signature public key does not match issuer_agent")
	}
	return nil
}

func EvaluateDelegationConstraints(c DelegationConstraintsV1, ctx DelegationEvalContext) error {
	if strings.TrimSpace(c.ContractID) == "" {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("constraints.contract_id is required")}
	}
	if strings.TrimSpace(c.CounterpartyAgent) == "" {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("constraints.counterparty_agent is required")}
	}
	if err := validateRFC3339UTC(c.ValidFrom, "constraints.valid_from"); err != nil {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: err}
	}
	if err := validateRFC3339UTC(c.ValidUntil, "constraints.valid_until"); err != nil {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: err}
	}
	from, _ := time.Parse(time.RFC3339Nano, c.ValidFrom)
	until, _ := time.Parse(time.RFC3339Nano, c.ValidUntil)
	if from.After(until) {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("constraints.valid_from must be <= constraints.valid_until")}
	}

	checkAt := strings.TrimSpace(ctx.IssuedAtUTC)
	if checkAt == "" {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("eval issued_at is required")}
	}
	if err := validateRFC3339UTC(checkAt, "proof.issued_at_utc"); err != nil {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: err}
	}
	at, _ := time.Parse(time.RFC3339Nano, checkAt)
	if at.Before(from) || at.After(until) {
		return &DelegationConstraintError{Reason: DelegationFailureExpired, Err: errors.New("delegation outside validity window")}
	}
	if c.MaxUses != nil && *c.MaxUses < 1 {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("constraints.max_uses must be >= 1")}
	}

	if c.ContractID != "*" && strings.TrimSpace(ctx.ContractID) != strings.TrimSpace(c.ContractID) {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("contract_id constraint mismatch")}
	}
	if c.CounterpartyAgent != "*" && strings.TrimSpace(ctx.CounterpartyAgent) != strings.TrimSpace(c.CounterpartyAgent) {
		return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: errors.New("counterparty_agent constraint mismatch")}
	}
	if c.MaxAmount != nil && ctx.PaymentAmount != nil {
		maxMinor, err := parseNormalizedAmountToMinor(*c.MaxAmount)
		if err != nil {
			return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: err}
		}
		payMinor, err := parseNormalizedAmountToMinor(*ctx.PaymentAmount)
		if err != nil {
			return &DelegationConstraintError{Reason: DelegationFailureConstraintsFailed, Err: err}
		}
		if strings.ToUpper(c.MaxAmount.Currency) != strings.ToUpper(ctx.PaymentAmount.Currency) {
			return &DelegationConstraintError{Reason: DelegationFailureAmountExceeded, Err: errors.New("payment currency mismatch")}
		}
		if payMinor > maxMinor {
			return &DelegationConstraintError{Reason: DelegationFailureAmountExceeded, Err: errors.New("payment exceeds max_amount")}
		}
	}
	return nil
}

func normalizeDelegationV1(payload DelegationV1) (DelegationV1, error) {
	if payload.Version != "delegation-v1" {
		return DelegationV1{}, errors.New("version must be delegation-v1")
	}
	if strings.TrimSpace(payload.DelegationID) == "" {
		return DelegationV1{}, errors.New("delegation_id is required")
	}
	if !IsValidAgentID(payload.IssuerAgent) || !IsValidAgentID(payload.SubjectAgent) {
		return DelegationV1{}, errors.New("issuer_agent and subject_agent must be valid agent-id-v1")
	}
	if len(payload.Scopes) == 0 {
		return DelegationV1{}, errors.New("scopes must be non-empty")
	}
	scopeSet := map[string]struct{}{}
	for _, s := range payload.Scopes {
		scope := strings.TrimSpace(s)
		if _, ok := knownDelegationScopes[scope]; !ok {
			return DelegationV1{}, errors.New("unknown scope: " + scope)
		}
		if _, seen := scopeSet[scope]; seen {
			continue
		}
		scopeSet[scope] = struct{}{}
	}
	normalizedScopes := make([]string, 0, len(scopeSet))
	for s := range scopeSet {
		normalizedScopes = append(normalizedScopes, s)
	}
	sort.Strings(normalizedScopes)
	payload.Scopes = normalizedScopes

	if err := validateRFC3339UTC(payload.IssuedAt, "issued_at"); err != nil {
		return DelegationV1{}, err
	}
	if err := validateBase64URLNoPadding(payload.Nonce, "nonce"); err != nil {
		return DelegationV1{}, err
	}

	// closed constraints schema + value checks
	if err := validateDelegationConstraints(payload.Constraints); err != nil {
		return DelegationV1{}, err
	}
	return payload, nil
}

func validateDelegationConstraints(c DelegationConstraintsV1) error {
	if strings.TrimSpace(c.ContractID) == "" {
		return errors.New("constraints.contract_id is required")
	}
	if strings.TrimSpace(c.CounterpartyAgent) == "" {
		return errors.New("constraints.counterparty_agent is required")
	}
	if c.CounterpartyAgent != "*" && !IsValidAgentID(c.CounterpartyAgent) {
		return errors.New("constraints.counterparty_agent must be * or valid agent-id-v1")
	}
	if err := validateRFC3339UTC(c.ValidFrom, "constraints.valid_from"); err != nil {
		return err
	}
	if err := validateRFC3339UTC(c.ValidUntil, "constraints.valid_until"); err != nil {
		return err
	}
	from, _ := time.Parse(time.RFC3339Nano, c.ValidFrom)
	until, _ := time.Parse(time.RFC3339Nano, c.ValidUntil)
	if from.After(until) {
		return errors.New("constraints.valid_from must be <= constraints.valid_until")
	}
	if c.MaxUses != nil && *c.MaxUses < 1 {
		return errors.New("constraints.max_uses must be >= 1")
	}
	if c.MaxAmount != nil {
		if _, err := parseNormalizedAmountToMinor(*c.MaxAmount); err != nil {
			return err
		}
	}
	return nil
}

func parseDelegationStrict(v any) (DelegationV1, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return DelegationV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d DelegationV1
	if err := dec.Decode(&d); err != nil {
		return DelegationV1{}, err
	}
	if dec.More() {
		return DelegationV1{}, errors.New("invalid trailing delegation payload")
	}
	return normalizeDelegationV1(d)
}

func delegationPayloadMap(d DelegationV1) map[string]any {
	constraints := map[string]any{
		"contract_id":        d.Constraints.ContractID,
		"counterparty_agent": d.Constraints.CounterpartyAgent,
		"valid_from":         d.Constraints.ValidFrom,
		"valid_until":        d.Constraints.ValidUntil,
	}
	if d.Constraints.MaxAmount != nil {
		constraints["max_amount"] = map[string]any{
			"currency": strings.ToUpper(strings.TrimSpace(d.Constraints.MaxAmount.Currency)),
			"amount":   strings.TrimSpace(d.Constraints.MaxAmount.Amount),
		}
	}
	if d.Constraints.MaxUses != nil {
		constraints["max_uses"] = *d.Constraints.MaxUses
	}
	if d.Constraints.Purpose != nil {
		constraints["purpose"] = *d.Constraints.Purpose
	}
	return map[string]any{
		"version":       d.Version,
		"delegation_id": d.DelegationID,
		"issuer_agent":  d.IssuerAgent,
		"subject_agent": d.SubjectAgent,
		"scopes":        d.Scopes,
		"constraints":   constraints,
		"nonce":         d.Nonce,
		"issued_at":     d.IssuedAt,
	}
}

func parseNormalizedAmountToMinor(a CommerceAmountV1) (int64, error) {
	ccy := strings.ToUpper(strings.TrimSpace(a.Currency))
	amt := strings.TrimSpace(a.Amount)
	if amt == "" {
		return 0, errors.New("amount is required")
	}
	exp, ok := isoMinorUnitExponentV1[ccy]
	if !ok {
		return 0, errors.New("unknown currency")
	}
	if strings.HasPrefix(amt, "+") || strings.ContainsAny(amt, "eE") {
		return 0, errors.New("amount must be normalized decimal")
	}
	parts := strings.Split(amt, ".")
	if len(parts) > 2 {
		return 0, errors.New("amount must be normalized decimal")
	}
	intPart := parts[0]
	if intPart == "" {
		return 0, errors.New("amount must be normalized decimal")
	}
	if len(intPart) > 1 && strings.HasPrefix(intPart, "0") {
		return 0, errors.New("amount must be normalized decimal")
	}
	intVal, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil || intVal < 0 {
		return 0, errors.New("amount must be normalized decimal")
	}
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
		if frac == "" || strings.HasSuffix(frac, "0") {
			return 0, errors.New("amount must be normalized decimal")
		}
	}
	if exp == 0 {
		if frac != "" {
			return 0, errors.New("amount must be normalized decimal")
		}
		return intVal, nil
	}
	if len(frac) > exp {
		return 0, errors.New("amount precision exceeds currency minor units")
	}
	for len(frac) < exp {
		frac += "0"
	}
	fracVal := int64(0)
	if frac != "" {
		fracVal, err = strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return 0, errors.New("amount must be normalized decimal")
		}
	}
	pow := int64(1)
	for i := 0; i < exp; i++ {
		pow *= 10
	}
	if intVal > (1<<62)/pow {
		return 0, errors.New("amount overflow")
	}
	return intVal*pow + fracVal, nil
}

func canonicalSha256Hex(v any) (string, error) {
	h, _, err := evidencehash.CanonicalSHA256(v)
	return h, err
}
