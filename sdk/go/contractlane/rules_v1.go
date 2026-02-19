package contractlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	rulesVersionV1 = "rules-v1"

	rulesEvalVersionV1 = "rules-eval-v1"

	rulesFailurePredicateFalse      = "predicate_false"
	rulesFailureMissingArtifact     = "missing_required_artifact"
	rulesFailureAuthorizationFailed = "authorization_failed"
	rulesFailureAmountMismatch      = "amount_mismatch"
	rulesFailureStatusMismatch      = "status_mismatch"
)

var validCELStates = map[string]struct{}{
	"DRAFT_CREATED":    {},
	"POLICY_VALIDATED": {},
	"RENDERED":         {},
	"READY_TO_SIGN":    {},
	"SIGNATURE_SENT":   {},
	"SIGNED_BY_US":     {},
	"SIGNED_BY_THEM":   {},
	"EFFECTIVE":        {},
	"ARCHIVED":         {},
}

type RulesV1 struct {
	Version string       `json:"version"`
	Rules   []RuleV1Item `json:"rules"`
}

type RuleV1Item struct {
	RuleID      string       `json:"rule_id"`
	Description string       `json:"description,omitempty"`
	When        PredicateV1  `json:"when"`
	Then        RuleEffectV1 `json:"then"`
}

type PredicateV1 struct {
	ContractStateIs           string            `json:"contract_state_is,omitempty"`
	HasCommerceIntent         *bool             `json:"has_commerce_intent,omitempty"`
	HasCommerceAccept         *bool             `json:"has_commerce_accept,omitempty"`
	SettlementStatusIs        string            `json:"settlement_status_is,omitempty"`
	SettlementAmountIs        *CommerceAmountV1 `json:"settlement_amount_is,omitempty"`
	AuthorizationSatisfiedFor string            `json:"authorization_satisfied_for,omitempty"`
	All                       []PredicateV1     `json:"all,omitempty"`
	Any                       []PredicateV1     `json:"any,omitempty"`
	Not                       *PredicateV1      `json:"not,omitempty"`
	op                        string
}

type RuleEffectV1 struct {
	Require          *RuleRequireEffectV1          `json:"require,omitempty"`
	PermitTransition *RulePermitTransitionEffectV1 `json:"permit_transition,omitempty"`
}

type RuleRequireEffectV1 struct {
	Name      string      `json:"name"`
	Predicate PredicateV1 `json:"predicate"`
}

type RulePermitTransitionEffectV1 struct {
	From string      `json:"from"`
	To   string      `json:"to"`
	If   PredicateV1 `json:"if"`
}

type RulesEvaluationInput struct {
	ContractID        string
	ContractState     string
	TransitionFrom    string
	TransitionTo      string
	Artifacts         map[string]any
	TrustAgents       []string
	SigningAgent      string
	CounterpartyAgent string
	IssuedAtUTC       string
	PaymentAmount     *CommerceAmountV1
}

type RulesEvaluationResult struct {
	Version     string                 `json:"version"`
	RuleResults []RulesRuleResultEntry `json:"rule_results"`
}

type RulesRuleResultEntry struct {
	RuleID  string                  `json:"rule_id"`
	Effects []RulesEffectResultItem `json:"effects"`
}

type RulesEffectResultItem struct {
	Type          string `json:"type"`
	Name          string `json:"name,omitempty"`
	From          string `json:"from,omitempty"`
	To            string `json:"to,omitempty"`
	Satisfied     *bool  `json:"satisfied,omitempty"`
	Permitted     *bool  `json:"permitted,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

type predicateEvalResult struct {
	ok     bool
	reason string
}

func ParseRulesV1Strict(v any) (RulesV1, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return RulesV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out RulesV1
	if err := dec.Decode(&out); err != nil {
		return RulesV1{}, err
	}
	if dec.More() {
		return RulesV1{}, errors.New("invalid trailing rules payload")
	}
	if err := validateRulesV1(out); err != nil {
		return RulesV1{}, err
	}
	return out, nil
}

func EvaluateRulesV1(rules RulesV1, in RulesEvaluationInput) (RulesEvaluationResult, error) {
	if err := validateRulesV1(rules); err != nil {
		return RulesEvaluationResult{}, err
	}
	out := RulesEvaluationResult{
		Version:     rulesEvalVersionV1,
		RuleResults: make([]RulesRuleResultEntry, 0, len(rules.Rules)),
	}

	for _, rule := range rules.Rules {
		ruleResult := RulesRuleResultEntry{
			RuleID:  rule.RuleID,
			Effects: make([]RulesEffectResultItem, 0, 2),
		}
		when := evalPredicate(rule.When, in)

		if rule.Then.Require != nil {
			entry := RulesEffectResultItem{
				Type: "require",
				Name: rule.Then.Require.Name,
			}
			if !when.ok {
				v := true
				entry.Satisfied = &v
			} else {
				res := evalPredicate(rule.Then.Require.Predicate, in)
				v := res.ok
				entry.Satisfied = &v
				if !res.ok {
					entry.FailureReason = failureOrPredicateFalse(res.reason)
				}
			}
			ruleResult.Effects = append(ruleResult.Effects, entry)
		}

		if rule.Then.PermitTransition != nil {
			entry := RulesEffectResultItem{
				Type: "permit_transition",
				From: rule.Then.PermitTransition.From,
				To:   rule.Then.PermitTransition.To,
			}
			if !when.ok {
				v := true
				entry.Permitted = &v
			} else if transitionSpecified(in) &&
				(strings.TrimSpace(in.TransitionFrom) != rule.Then.PermitTransition.From ||
					strings.TrimSpace(in.TransitionTo) != rule.Then.PermitTransition.To) {
				v := true
				entry.Permitted = &v
			} else {
				res := evalPredicate(rule.Then.PermitTransition.If, in)
				v := res.ok
				entry.Permitted = &v
				if !res.ok {
					entry.FailureReason = failureOrPredicateFalse(res.reason)
				}
			}
			ruleResult.Effects = append(ruleResult.Effects, entry)
		}

		out.RuleResults = append(out.RuleResults, ruleResult)
	}
	return out, nil
}

func transitionSpecified(in RulesEvaluationInput) bool {
	return strings.TrimSpace(in.TransitionFrom) != "" || strings.TrimSpace(in.TransitionTo) != ""
}

func validateRulesV1(r RulesV1) error {
	if r.Version != rulesVersionV1 {
		return errors.New("version must be rules-v1")
	}
	if len(r.Rules) == 0 {
		return errors.New("rules must be non-empty")
	}
	ids := map[string]struct{}{}
	requireNames := map[string]struct{}{}
	for i, rule := range r.Rules {
		if strings.TrimSpace(rule.RuleID) == "" {
			return fmt.Errorf("rules[%d].rule_id is required", i)
		}
		if _, dup := ids[rule.RuleID]; dup {
			return fmt.Errorf("duplicate rule_id: %s", rule.RuleID)
		}
		ids[rule.RuleID] = struct{}{}
		if err := validatePredicate(rule.When); err != nil {
			return fmt.Errorf("rules[%d].when: %w", i, err)
		}
		if rule.Then.Require == nil && rule.Then.PermitTransition == nil {
			return fmt.Errorf("rules[%d].then must contain require or permit_transition", i)
		}
		if rule.Then.Require != nil {
			name := strings.TrimSpace(rule.Then.Require.Name)
			if name == "" {
				return fmt.Errorf("rules[%d].then.require.name is required", i)
			}
			if _, dup := requireNames[name]; dup {
				return fmt.Errorf("duplicate require name: %s", name)
			}
			requireNames[name] = struct{}{}
			if err := validatePredicate(rule.Then.Require.Predicate); err != nil {
				return fmt.Errorf("rules[%d].then.require.predicate: %w", i, err)
			}
		}
		if rule.Then.PermitTransition != nil {
			if _, ok := validCELStates[rule.Then.PermitTransition.From]; !ok {
				return fmt.Errorf("rules[%d].then.permit_transition.from invalid state: %s", i, rule.Then.PermitTransition.From)
			}
			if _, ok := validCELStates[rule.Then.PermitTransition.To]; !ok {
				return fmt.Errorf("rules[%d].then.permit_transition.to invalid state: %s", i, rule.Then.PermitTransition.To)
			}
			if err := validatePredicate(rule.Then.PermitTransition.If); err != nil {
				return fmt.Errorf("rules[%d].then.permit_transition.if: %w", i, err)
			}
		}
	}
	return nil
}

func (p *PredicateV1) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) != 1 {
		return errors.New("predicate must contain exactly one operator")
	}
	for k, v := range raw {
		switch k {
		case "contract_state_is":
			p.op = k
			return json.Unmarshal(v, &p.ContractStateIs)
		case "has_commerce_intent":
			p.op = k
			var b bool
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			p.HasCommerceIntent = &b
			if !b {
				return errors.New("has_commerce_intent must be true")
			}
			return nil
		case "has_commerce_accept":
			p.op = k
			var b bool
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			p.HasCommerceAccept = &b
			if !b {
				return errors.New("has_commerce_accept must be true")
			}
			return nil
		case "settlement_status_is":
			p.op = k
			return json.Unmarshal(v, &p.SettlementStatusIs)
		case "settlement_amount_is":
			p.op = k
			var amt CommerceAmountV1
			if err := strictUnmarshal(v, &amt); err != nil {
				return err
			}
			p.SettlementAmountIs = &amt
			return nil
		case "authorization_satisfied_for":
			p.op = k
			return json.Unmarshal(v, &p.AuthorizationSatisfiedFor)
		case "all":
			p.op = k
			var all []PredicateV1
			if err := json.Unmarshal(v, &all); err != nil {
				return err
			}
			p.All = all
			return nil
		case "any":
			p.op = k
			var any []PredicateV1
			if err := json.Unmarshal(v, &any); err != nil {
				return err
			}
			p.Any = any
			return nil
		case "not":
			p.op = k
			var sub PredicateV1
			if err := json.Unmarshal(v, &sub); err != nil {
				return err
			}
			p.Not = &sub
			return nil
		default:
			return fmt.Errorf("unknown predicate operator: %s", k)
		}
	}
	return errors.New("predicate missing operator")
}

func (e *RuleEffectV1) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		switch k {
		case "require":
			var req RuleRequireEffectV1
			if err := strictUnmarshal(v, &req); err != nil {
				return err
			}
			e.Require = &req
		case "permit_transition":
			var p RulePermitTransitionEffectV1
			if err := strictUnmarshal(v, &p); err != nil {
				return err
			}
			e.PermitTransition = &p
		default:
			return fmt.Errorf("unknown effect operator: %s", k)
		}
	}
	if e.Require == nil && e.PermitTransition == nil {
		return errors.New("effect must include require or permit_transition")
	}
	return nil
}

func validatePredicate(p PredicateV1) error {
	switch p.op {
	case "contract_state_is":
		if _, ok := validCELStates[p.ContractStateIs]; !ok {
			return fmt.Errorf("invalid contract_state_is: %s", p.ContractStateIs)
		}
	case "has_commerce_intent":
		if p.HasCommerceIntent == nil || !*p.HasCommerceIntent {
			return errors.New("has_commerce_intent must be true")
		}
	case "has_commerce_accept":
		if p.HasCommerceAccept == nil || !*p.HasCommerceAccept {
			return errors.New("has_commerce_accept must be true")
		}
	case "settlement_status_is":
		switch p.SettlementStatusIs {
		case "PAID", "FAILED", "REFUNDED", "DISPUTED":
		default:
			return fmt.Errorf("invalid settlement_status_is: %s", p.SettlementStatusIs)
		}
	case "settlement_amount_is":
		if p.SettlementAmountIs == nil {
			return errors.New("settlement_amount_is is required")
		}
		if _, err := parseNormalizedAmountToMinor(*p.SettlementAmountIs); err != nil {
			return err
		}
	case "authorization_satisfied_for":
		if strings.TrimSpace(p.AuthorizationSatisfiedFor) == "" {
			return errors.New("authorization_satisfied_for is required")
		}
	case "all":
		if len(p.All) == 0 {
			return errors.New("all must be non-empty")
		}
		for _, sub := range p.All {
			if err := validatePredicate(sub); err != nil {
				return err
			}
		}
	case "any":
		if len(p.Any) == 0 {
			return errors.New("any must be non-empty")
		}
		for _, sub := range p.Any {
			if err := validatePredicate(sub); err != nil {
				return err
			}
		}
	case "not":
		if p.Not == nil {
			return errors.New("not must wrap exactly one predicate")
		}
		return validatePredicate(*p.Not)
	default:
		return errors.New("predicate missing operator")
	}
	return nil
}

func evalPredicate(p PredicateV1, in RulesEvaluationInput) predicateEvalResult {
	switch p.op {
	case "contract_state_is":
		if strings.TrimSpace(in.ContractState) == p.ContractStateIs {
			return predicateEvalResult{ok: true}
		}
		return predicateEvalResult{ok: false, reason: rulesFailurePredicateFalse}
	case "has_commerce_intent":
		rows, ok := in.Artifacts["commerce_intents"]
		if !ok {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		arr, err := normalizeAnyArray(rows)
		if err != nil || len(arr) == 0 {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		return predicateEvalResult{ok: true}
	case "has_commerce_accept":
		rows, ok := in.Artifacts["commerce_accepts"]
		if !ok {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		arr, err := normalizeAnyArray(rows)
		if err != nil || len(arr) == 0 {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		return predicateEvalResult{ok: true}
	case "settlement_status_is":
		arr, ok := in.Artifacts["settlement_attestations"]
		if !ok {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		rows, err := normalizeAnyArray(arr)
		if err != nil || len(rows) == 0 {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		want := strings.TrimSpace(p.SettlementStatusIs)
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if strings.TrimSpace(fmt.Sprint(rm["status"])) == want {
				return predicateEvalResult{ok: true}
			}
		}
		return predicateEvalResult{ok: false, reason: rulesFailureStatusMismatch}
	case "settlement_amount_is":
		if p.SettlementAmountIs == nil {
			return predicateEvalResult{ok: false, reason: rulesFailureAmountMismatch}
		}
		wantMinor, err := parseNormalizedAmountToMinor(*p.SettlementAmountIs)
		if err != nil {
			return predicateEvalResult{ok: false, reason: rulesFailureAmountMismatch}
		}
		wantCurrency := strings.ToUpper(strings.TrimSpace(p.SettlementAmountIs.Currency))
		arr, ok := in.Artifacts["settlement_attestations"]
		if !ok {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		rows, err := normalizeAnyArray(arr)
		if err != nil || len(rows) == 0 {
			return predicateEvalResult{ok: false, reason: rulesFailureMissingArtifact}
		}
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			amountMap, _ := rm["amount"].(map[string]any)
			if amountMap == nil {
				continue
			}
			got := CommerceAmountV1{
				Currency: strings.TrimSpace(fmt.Sprint(amountMap["currency"])),
				Amount:   strings.TrimSpace(fmt.Sprint(amountMap["amount"])),
			}
			gotMinor, err := parseNormalizedAmountToMinor(got)
			if err != nil {
				continue
			}
			if strings.ToUpper(got.Currency) == wantCurrency && gotMinor == wantMinor {
				return predicateEvalResult{ok: true}
			}
		}
		return predicateEvalResult{ok: false, reason: rulesFailureAmountMismatch}
	case "authorization_satisfied_for":
		scope := strings.TrimSpace(p.AuthorizationSatisfiedFor)
		delegations := in.Artifacts["delegations"]
		if delegations == nil {
			delegations = in.Artifacts["delegation_records"]
		}
		delegationList, _ := normalizeAnyArray(delegations)
		revocationList, _ := normalizeAnyArray(in.Artifacts["delegation_revocations"])
		decision := EvaluateDelegationDecision(DelegationDecisionInput{
			RequiredScope:     scope,
			SigningAgent:      strings.TrimSpace(in.SigningAgent),
			CounterpartyAgent: strings.TrimSpace(in.CounterpartyAgent),
			ContractID:        strings.TrimSpace(in.ContractID),
			IssuedAtUTC:       strings.TrimSpace(in.IssuedAtUTC),
			PaymentAmount:     in.PaymentAmount,
			Delegations:       delegationList,
			Revocations:       revocationList,
			TrustAgents:       in.TrustAgents,
		})
		if decision.OK {
			return predicateEvalResult{ok: true}
		}
		return predicateEvalResult{ok: false, reason: rulesFailureAuthorizationFailed}
	case "all":
		for _, sub := range p.All {
			res := evalPredicate(sub, in)
			if !res.ok {
				return res
			}
		}
		return predicateEvalResult{ok: true}
	case "any":
		firstFail := rulesFailurePredicateFalse
		for _, sub := range p.Any {
			res := evalPredicate(sub, in)
			if res.ok {
				return predicateEvalResult{ok: true}
			}
			if firstFail == rulesFailurePredicateFalse && res.reason != "" {
				firstFail = res.reason
			}
		}
		return predicateEvalResult{ok: false, reason: firstFail}
	case "not":
		if p.Not == nil {
			return predicateEvalResult{ok: false, reason: rulesFailurePredicateFalse}
		}
		res := evalPredicate(*p.Not, in)
		if !res.ok {
			if res.reason == rulesFailurePredicateFalse {
				return predicateEvalResult{ok: true}
			}
			return res
		}
		return predicateEvalResult{ok: false, reason: rulesFailurePredicateFalse}
	default:
		return predicateEvalResult{ok: false, reason: rulesFailurePredicateFalse}
	}
}

func failureOrPredicateFalse(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return rulesFailurePredicateFalse
	}
	switch reason {
	case rulesFailurePredicateFalse, rulesFailureMissingArtifact, rulesFailureAuthorizationFailed, rulesFailureAmountMismatch, rulesFailureStatusMismatch:
		return reason
	default:
		return rulesFailurePredicateFalse
	}
}

func strictUnmarshal(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("invalid trailing json")
	}
	return nil
}
