package domain

import "testing"

func TestHumanRequiredBlocksUntilHumanSource(t *testing.T) {
	defs := []VariableDefinition{{Key: "party_address", Type: VarAddress, Required: true, SetPolicy: VarHumanRequired}}
	values := []VariableValue{{Key: "party_address", Value: "123", Source: SourceAgent, ReviewStatus: ReviewPending}}
	res := EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, IdentityVariableGovernance{}, values)
	if !res.Blocked || len(res.NeedsHumanEntry) != 1 {
		t.Fatalf("expected blocked needs entry, got %+v", res)
	}
	values[0].Source = SourceHuman
	res2 := EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, IdentityVariableGovernance{}, values)
	if res2.Blocked {
		t.Fatalf("expected unblocked, got %+v", res2)
	}
}

func TestAgentFillHumanReviewBlocksUntilApproved(t *testing.T) {
	defs := []VariableDefinition{{Key: "price", Type: VarMoney, Required: false, SetPolicy: VarAgentFillHumanReview}}
	values := []VariableValue{{Key: "price", Value: "USD 1.00", Source: SourceAgent, ReviewStatus: ReviewPending}}
	res := EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, IdentityVariableGovernance{}, values)
	if !res.Blocked || len(res.NeedsHumanReview) != 1 {
		t.Fatalf("expected blocked needs review, got %+v", res)
	}
	values[0].ReviewStatus = ReviewApproved
	res2 := EvaluateVariableGates("SEND_FOR_SIGNATURE", defs, IdentityVariableGovernance{}, values)
	if res2.Blocked {
		t.Fatalf("expected unblocked, got %+v", res2)
	}
}

func TestCanonicalizeMoney(t *testing.T) {
	def := VariableDefinition{Key: "price", Type: VarMoney}
	got, err := ValidateAndCanonicalize(def, "USD 12.5")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != "USD 12.50" {
		t.Fatalf("expected USD 12.50, got %q", got)
	}
}
