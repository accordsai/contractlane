package contractlane

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRulesV1StrictRejectsUnknownKeys(t *testing.T) {
	_, err := ParseRulesV1Strict(map[string]any{
		"version": "rules-v1",
		"rules": []any{
			map[string]any{
				"rule_id": "rl_1",
				"when":    map[string]any{"contract_state_is": "EFFECTIVE"},
				"then": map[string]any{
					"require": map[string]any{
						"name":      "n1",
						"predicate": map[string]any{"has_commerce_intent": true},
					},
				},
				"unknown_key": true,
			},
		},
	})
	if err == nil {
		t.Fatal("expected unknown key validation error")
	}
}

func TestEvaluateRulesV1CombinatorsDeterministic(t *testing.T) {
	rules := mustParseRules(t, map[string]any{
		"version": "rules-v1",
		"rules": []any{
			map[string]any{
				"rule_id": "rl_comb",
				"when": map[string]any{
					"all": []any{
						map[string]any{"contract_state_is": "EFFECTIVE"},
						map[string]any{
							"not": map[string]any{"has_commerce_accept": true},
						},
					},
				},
				"then": map[string]any{
					"require": map[string]any{
						"name":      "needs_intent",
						"predicate": map[string]any{"has_commerce_intent": true},
					},
				},
			},
		},
	})
	in := RulesEvaluationInput{
		ContractState: "EFFECTIVE",
		Artifacts: map[string]any{
			"commerce_intents": []any{map[string]any{"intent": map[string]any{"intent_id": "ci_1"}}},
		},
	}
	r1, err := EvaluateRulesV1(rules, in)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	r2, err := EvaluateRulesV1(rules, in)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("expected deterministic evaluation output")
	}
	got := *r1.RuleResults[0].Effects[0].Satisfied
	if !got {
		t.Fatalf("expected require satisfied=true")
	}
}

func TestEvaluateRulesV1SettlementStatusPredicate(t *testing.T) {
	rules := mustParseRules(t, map[string]any{
		"version": "rules-v1",
		"rules": []any{
			map[string]any{
				"rule_id": "rl_settlement_status",
				"when":    map[string]any{"contract_state_is": "EFFECTIVE"},
				"then": map[string]any{
					"require": map[string]any{
						"name":      "status_paid",
						"predicate": map[string]any{"settlement_status_is": "PAID"},
					},
				},
			},
		},
	})
	inOK := RulesEvaluationInput{
		ContractState: "EFFECTIVE",
		Artifacts: map[string]any{
			"settlement_attestations": []any{
				map[string]any{"status": "PAID", "amount": map[string]any{"currency": "USD", "amount": "49"}},
			},
		},
	}
	outOK, err := EvaluateRulesV1(rules, inOK)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	if !*outOK.RuleResults[0].Effects[0].Satisfied {
		t.Fatalf("expected settlement_status_is PAID to pass")
	}

	inFail := RulesEvaluationInput{
		ContractState: "EFFECTIVE",
		Artifacts: map[string]any{
			"settlement_attestations": []any{
				map[string]any{"status": "FAILED", "amount": map[string]any{"currency": "USD", "amount": "49"}},
			},
		},
	}
	outFail, err := EvaluateRulesV1(rules, inFail)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	eff := outFail.RuleResults[0].Effects[0]
	if *eff.Satisfied {
		t.Fatalf("expected settlement_status_is PAID to fail")
	}
	if eff.FailureReason != rulesFailureStatusMismatch {
		t.Fatalf("expected status_mismatch, got %s", eff.FailureReason)
	}
}

func TestEvaluateRulesV1SettlementAmountPredicate(t *testing.T) {
	rules := mustParseRules(t, map[string]any{
		"version": "rules-v1",
		"rules": []any{
			map[string]any{
				"rule_id": "rl_settlement_amount",
				"when":    map[string]any{"contract_state_is": "EFFECTIVE"},
				"then": map[string]any{
					"require": map[string]any{
						"name": "amount_match",
						"predicate": map[string]any{
							"settlement_amount_is": map[string]any{"currency": "USD", "amount": "49"},
						},
					},
				},
			},
		},
	})
	inOK := RulesEvaluationInput{
		ContractState: "EFFECTIVE",
		Artifacts: map[string]any{
			"settlement_attestations": []any{
				map[string]any{"status": "PAID", "amount": map[string]any{"currency": "USD", "amount": "49"}},
			},
		},
	}
	outOK, err := EvaluateRulesV1(rules, inOK)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	if !*outOK.RuleResults[0].Effects[0].Satisfied {
		t.Fatalf("expected settlement_amount_is match to pass")
	}

	inFail := RulesEvaluationInput{
		ContractState: "EFFECTIVE",
		Artifacts: map[string]any{
			"settlement_attestations": []any{
				map[string]any{"status": "PAID", "amount": map[string]any{"currency": "USD", "amount": "50"}},
			},
		},
	}
	outFail, err := EvaluateRulesV1(rules, inFail)
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	eff := outFail.RuleResults[0].Effects[0]
	if *eff.Satisfied {
		t.Fatalf("expected settlement_amount_is mismatch to fail")
	}
	if eff.FailureReason != rulesFailureAmountMismatch {
		t.Fatalf("expected amount_mismatch, got %s", eff.FailureReason)
	}
}

func TestEvaluateRulesV1PermitTransitionOrdering(t *testing.T) {
	rules := mustParseRules(t, map[string]any{
		"version": "rules-v1",
		"rules": []any{
			map[string]any{
				"rule_id": "rl_order",
				"when":    map[string]any{"contract_state_is": "READY_TO_SIGN"},
				"then": map[string]any{
					"require": map[string]any{
						"name":      "requires_intent",
						"predicate": map[string]any{"has_commerce_intent": true},
					},
					"permit_transition": map[string]any{
						"from": "READY_TO_SIGN",
						"to":   "SIGNATURE_SENT",
						"if":   map[string]any{"has_commerce_accept": true},
					},
				},
			},
		},
	})
	out, err := EvaluateRulesV1(rules, RulesEvaluationInput{
		ContractState:  "READY_TO_SIGN",
		TransitionFrom: "READY_TO_SIGN",
		TransitionTo:   "SIGNATURE_SENT",
		Artifacts: map[string]any{
			"commerce_intents": []any{map[string]any{"intent": map[string]any{"intent_id": "ci_1"}}},
			"commerce_accepts": []any{map[string]any{"accept": map[string]any{"intent_hash": "h1"}}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluateRulesV1: %v", err)
	}
	effects := out.RuleResults[0].Effects
	if len(effects) != 2 {
		t.Fatalf("expected 2 effect results, got %d", len(effects))
	}
	if effects[0].Type != "require" || effects[1].Type != "permit_transition" {
		t.Fatalf("unexpected effect order: %+v", effects)
	}
	if !*effects[0].Satisfied || !*effects[1].Permitted {
		t.Fatalf("expected require/permit to pass")
	}
}

func mustParseRules(t *testing.T, v any) RulesV1 {
	t.Helper()
	r, err := ParseRulesV1Strict(v)
	if err != nil {
		b, _ := json.Marshal(v)
		t.Fatalf("ParseRulesV1Strict(%s): %v", string(b), err)
	}
	return r
}
