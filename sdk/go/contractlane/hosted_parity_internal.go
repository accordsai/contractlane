package contractlane

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

)

type ValidatedCommerceIntentSubmission struct {
	Intent        CommerceIntentV1
	IntentHash    string
	SigningAgent  string
	SigningPubKey string
}

type ValidatedCommerceAcceptSubmission struct {
	Accept        CommerceAcceptV1
	AcceptHash    string
	SigningAgent  string
	SigningPubKey string
}

type DelegationDecision struct {
	OK            bool
	FailureReason string
}

type DelegationDecisionInput struct {
	RequiredScope     string
	SigningAgent      string
	CounterpartyAgent string
	ContractID        string
	IssuedAtUTC       string
	PaymentAmount     *CommerceAmountV1
	Delegations       []any
	Revocations       []any
	TrustAgents       []string
}

type delegationDecisionInput = DelegationDecisionInput

func ValidateCommerceIntentSubmission(intentPayload CommerceIntentV1, sig SigV1Envelope) (ValidatedCommerceIntentSubmission, error) {
	n, err := normalizeCommerceIntent(intentPayload)
	if err != nil {
		return ValidatedCommerceIntentSubmission{}, err
	}
	if strings.TrimSpace(sig.Context) != "" && sig.Context != "commerce-intent" {
		return ValidatedCommerceIntentSubmission{}, errors.New("signature context mismatch")
	}
	hash, err := HashCommerceIntentV1(n)
	if err != nil {
		return ValidatedCommerceIntentSubmission{}, err
	}
	if sig.PayloadHash != hash {
		return ValidatedCommerceIntentSubmission{}, errors.New("payload hash mismatch")
	}
	_, err = VerifySignatureEnvelope(commerceIntentPayload(n), sig)
	if err != nil {
		return ValidatedCommerceIntentSubmission{}, err
	}
	signingAgent, err := signingAgentFromEnvelope(sig)
	if err != nil {
		return ValidatedCommerceIntentSubmission{}, err
	}
	return ValidatedCommerceIntentSubmission{
		Intent:        n,
		IntentHash:    hash,
		SigningAgent:  signingAgent,
		SigningPubKey: sig.PublicKey,
	}, nil
}

func ValidateCommerceAcceptSubmission(acceptPayload CommerceAcceptV1, sig SigV1Envelope) (ValidatedCommerceAcceptSubmission, error) {
	n, err := normalizeCommerceAccept(acceptPayload)
	if err != nil {
		return ValidatedCommerceAcceptSubmission{}, err
	}
	if strings.TrimSpace(sig.Context) != "" && sig.Context != "commerce-accept" {
		return ValidatedCommerceAcceptSubmission{}, errors.New("signature context mismatch")
	}
	hash, err := HashCommerceAcceptV1(n)
	if err != nil {
		return ValidatedCommerceAcceptSubmission{}, err
	}
	if sig.PayloadHash != hash {
		return ValidatedCommerceAcceptSubmission{}, errors.New("payload hash mismatch")
	}
	_, err = VerifySignatureEnvelope(commerceAcceptPayload(n), sig)
	if err != nil {
		return ValidatedCommerceAcceptSubmission{}, err
	}
	signingAgent, err := signingAgentFromEnvelope(sig)
	if err != nil {
		return ValidatedCommerceAcceptSubmission{}, err
	}
	return ValidatedCommerceAcceptSubmission{
		Accept:        n,
		AcceptHash:    hash,
		SigningAgent:  signingAgent,
		SigningPubKey: sig.PublicKey,
	}, nil
}

func EvaluateDelegationDecision(in DelegationDecisionInput) DelegationDecision {
	scope := strings.TrimSpace(in.RequiredScope)
	if scope == "" {
		return DelegationDecision{FailureReason: DelegationFailureScopeMissing}
	}
	delegationsAny := in.Delegations
	if len(delegationsAny) == 0 {
		return DelegationDecision{FailureReason: DelegationFailureMissing}
	}

	trustSet := map[string]struct{}{}
	for _, a := range in.TrustAgents {
		v := strings.TrimSpace(a)
		if v != "" {
			trustSet[v] = struct{}{}
		}
	}

	var sawSubject, sawScope, sawSigInvalid, sawUntrusted bool
	constraintFailure := ""
	revocationsAny := in.Revocations
	for _, row := range delegationsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		delAny, ok := rm["delegation"]
		if !ok {
			continue
		}
		del, err := parseDelegationStrict(delAny)
		if err != nil {
			continue
		}
		if del.SubjectAgent != in.SigningAgent {
			continue
		}
		sawSubject = true

		if !containsString(del.Scopes, scope) {
			continue
		}
		sawScope = true

		sigMap, _ := rm["issuer_signature"].(map[string]any)
		if sigMap == nil {
			sawSigInvalid = true
			continue
		}
		sb, _ := json.Marshal(sigMap)
		var sig SigV1Envelope
		if err := json.Unmarshal(sb, &sig); err != nil {
			sawSigInvalid = true
			continue
		}
		if err := VerifyDelegationV1(del, sig); err != nil {
			sawSigInvalid = true
			continue
		}

		if del.IssuerAgent != del.SubjectAgent {
			if _, ok := trustSet[del.IssuerAgent]; !ok {
				sawUntrusted = true
				continue
			}
		}

		err = EvaluateDelegationConstraints(del.Constraints, DelegationEvalContext{
			ContractID:        in.ContractID,
			CounterpartyAgent: in.CounterpartyAgent,
			IssuedAtUTC:       in.IssuedAtUTC,
			PaymentAmount:     in.PaymentAmount,
		})
		if err != nil {
			if dErr, ok := err.(*DelegationConstraintError); ok {
				constraintFailure = dErr.Reason
			} else {
				constraintFailure = DelegationFailureConstraintsFailed
			}
			continue
		}
		if delegationIsRevoked(del, revocationsAny, trustSet) {
			return DelegationDecision{FailureReason: DelegationFailureRevoked}
		}
		return DelegationDecision{OK: true}
	}

	if !sawSubject {
		return DelegationDecision{FailureReason: DelegationFailureMissing}
	}
	if !sawScope {
		return DelegationDecision{FailureReason: DelegationFailureScopeMissing}
	}
	if sawSigInvalid {
		return DelegationDecision{FailureReason: DelegationFailureSignatureInvalid}
	}
	if sawUntrusted {
		return DelegationDecision{FailureReason: DelegationFailureUntrustedIssuer}
	}
	if constraintFailure != "" {
		return DelegationDecision{FailureReason: constraintFailure}
	}
	return DelegationDecision{FailureReason: DelegationFailureMissing}
}

func delegationIsRevoked(del DelegationV1, revocationsAny []any, trustSet map[string]struct{}) bool {
	if len(revocationsAny) == 0 {
		return false
	}
	for _, row := range revocationsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		revAny, ok := rm["revocation"]
		if !ok {
			continue
		}
		rev, err := parseDelegationRevocationStrict(revAny)
		if err != nil {
			continue
		}
		if rev.DelegationID != del.DelegationID {
			continue
		}
		sigMap, _ := rm["issuer_signature"].(map[string]any)
		if sigMap == nil {
			continue
		}
		sb, _ := json.Marshal(sigMap)
		var sig SigV1Envelope
		if err := json.Unmarshal(sb, &sig); err != nil {
			continue
		}
		_, _, issuer, err := ValidateDelegationRevocation(rev, sig)
		if err != nil {
			continue
		}
		if issuer == del.IssuerAgent {
			return true
		}
		if _, trusted := trustSet[issuer]; trusted {
			return true
		}
	}
	return false
}

func DeriveSettlementAttestations(receipts any) ([]SettlementAttestationV1, error) {
	receiptList, err := normalizeAnyArray(receipts)
	if err != nil {
		return nil, err
	}
	out := make([]SettlementAttestationV1, 0, len(receiptList))
	for _, row := range receiptList {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if valid, present := rm["signature_valid"]; present {
			if vb, ok := valid.(bool); !ok || !vb {
				continue
			}
		}
		provider := strings.ToLower(strings.TrimSpace(fmt.Sprint(rm["provider"])))
		if provider != "stripe" {
			continue
		}
		eventPayload, ok := extractReceiptPayload(rm)
		if !ok {
			continue
		}
		att, ok := deriveStripeAttestation(rm, eventPayload)
		if !ok {
			continue
		}
		out = append(out, att)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].ProviderEventID < out[j].ProviderEventID
		}
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

func signingAgentFromEnvelope(sig SigV1Envelope) (string, error) {
	return AgentIDFromSignatureEnvelope(sig)
}

func validateCommerceIntentSubmission(intentPayload CommerceIntentV1, sig SigV1Envelope) (ValidatedCommerceIntentSubmission, error) {
	return ValidateCommerceIntentSubmission(intentPayload, sig)
}

func validateCommerceAcceptSubmission(acceptPayload CommerceAcceptV1, sig SigV1Envelope) (ValidatedCommerceAcceptSubmission, error) {
	return ValidateCommerceAcceptSubmission(acceptPayload, sig)
}

func evaluateDelegationDecision(in delegationDecisionInput) DelegationDecision {
	return EvaluateDelegationDecision(DelegationDecisionInput(in))
}

func deriveSettlementAttestations(receipts any) ([]SettlementAttestationV1, error) {
	return DeriveSettlementAttestations(receipts)
}
