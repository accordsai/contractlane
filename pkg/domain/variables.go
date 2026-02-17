package domain

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type VarKey string
type VarType string

const (
	VarString   VarType = "STRING"
	VarDate     VarType = "DATE"
	VarMoney    VarType = "MONEY"
	VarInt      VarType = "INT"
	VarDuration VarType = "DURATION"
	VarAddress  VarType = "ADDRESS"
)

type VarSensitivity string

const (
	SensNone VarSensitivity = "NONE"
	SensPII  VarSensitivity = "PII"
)

type VarSetPolicy string

const (
	VarAgentAllowed         VarSetPolicy = "AGENT_ALLOWED"
	VarHumanRequired        VarSetPolicy = "HUMAN_REQUIRED"
	VarAgentFillHumanReview VarSetPolicy = "AGENT_FILL_HUMAN_REVIEW"
	VarDeferToIdentity      VarSetPolicy = "DEFER_TO_IDENTITY"
)

type VariableConstraint struct {
	AllowedValues []string
	MinInt        *int
	MaxInt        *int
	MinMoney      *string
	MaxMoney      *string
}

type VariableDefinition struct {
	Key         VarKey
	Type        VarType
	Required    bool
	Sensitivity VarSensitivity
	SetPolicy   VarSetPolicy
	Constraints VariableConstraint
}

type VarSource string

const (
	SourceHuman  VarSource = "HUMAN"
	SourceAgent  VarSource = "AGENT"
	SourceSystem VarSource = "SYSTEM"
)

type VarReviewStatus string

const (
	ReviewNotNeeded VarReviewStatus = "NOT_NEEDED"
	ReviewPending   VarReviewStatus = "PENDING"
	ReviewApproved  VarReviewStatus = "APPROVED"
	ReviewRejected  VarReviewStatus = "REJECTED"
)

type VariableValue struct {
	Key          VarKey
	Value        string
	Source       VarSource
	ReviewStatus VarReviewStatus
}

type IdentityVarRule struct {
	ForKey  *VarKey
	ForType *VarType
	Policy  VarSetPolicy
}

type IdentityVariableGovernance struct {
	Rules []IdentityVarRule
}

type ContractAction string

type VariableGateResult struct {
	Blocked bool

	MissingRequired  []VarKey
	NeedsHumanEntry  []VarKey
	NeedsHumanReview []VarKey

	Reason string
}

type VarValidationError struct {
	Key    VarKey
	Reason string
}

func (e *VarValidationError) Error() string {
	return fmt.Sprintf("variable %q invalid: %s", e.Key, e.Reason)
}

var (
	reMoney    = regexp.MustCompile(`^\s*([A-Z]{3})\s+(-?\d+)(\.\d{1,2})?\s*$`)
	reISODate  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reDuration = regexp.MustCompile(`^\s*P(\d+Y)?(\d+M)?(\d+D)?\s*$`)
)

type money struct {
	Currency string
	Cents    int64
}

func ValidateAndCanonicalize(def VariableDefinition, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", &VarValidationError{Key: def.Key, Reason: "empty value"}
	}
	var canonical string

	switch def.Type {
	case VarString, VarAddress:
		canonical = raw

	case VarDate:
		if !reISODate.MatchString(raw) {
			return "", &VarValidationError{Key: def.Key, Reason: "date must be YYYY-MM-DD"}
		}
		if _, err := time.Parse("2006-01-02", raw); err != nil {
			return "", &VarValidationError{Key: def.Key, Reason: "invalid date"}
		}
		canonical = raw

	case VarInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return "", &VarValidationError{Key: def.Key, Reason: "invalid integer"}
		}
		if def.Constraints.MinInt != nil && n < *def.Constraints.MinInt {
			return "", &VarValidationError{Key: def.Key, Reason: fmt.Sprintf("must be >= %d", *def.Constraints.MinInt)}
		}
		if def.Constraints.MaxInt != nil && n > *def.Constraints.MaxInt {
			return "", &VarValidationError{Key: def.Key, Reason: fmt.Sprintf("must be <= %d", *def.Constraints.MaxInt)}
		}
		canonical = strconv.Itoa(n)

	case VarMoney:
		m, err := parseMoney(raw)
		if err != nil {
			return "", &VarValidationError{Key: def.Key, Reason: err.Error()}
		}
		canonical = moneyToCanonical(m)

	case VarDuration:
		up := strings.ToUpper(strings.ReplaceAll(raw, " ", ""))
		if !reDuration.MatchString(up) || up == "P" {
			return "", &VarValidationError{Key: def.Key, Reason: "duration must be ISO8601 like P12M or P30D"}
		}
		canonical = up

	default:
		return "", &VarValidationError{Key: def.Key, Reason: "unsupported type"}
	}

	if len(def.Constraints.AllowedValues) > 0 {
		ok := false
		for _, av := range def.Constraints.AllowedValues {
			if canonical == av {
				ok = true
				break
			}
		}
		if !ok {
			return "", &VarValidationError{Key: def.Key, Reason: "value not in allowed set"}
		}
	}

	return canonical, nil
}

func parseMoney(s string) (money, error) {
	matches := reMoney.FindStringSubmatch(s)
	if matches == nil {
		return money{}, errors.New(`money must be like "USD 120000.00"`)
	}
	ccy := matches[1]
	intPart := matches[2]
	fracPart := matches[3]

	neg := strings.HasPrefix(intPart, "-")
	intAbs := strings.TrimPrefix(intPart, "-")
	dollars, err := strconv.ParseInt(intAbs, 10, 64)
	if err != nil {
		return money{}, errors.New("invalid money amount")
	}

	var cents int64
	if fracPart == "" {
		cents = 0
	} else {
		frac := strings.TrimPrefix(fracPart, ".")
		if len(frac) == 1 {
			frac += "0"
		}
		if len(frac) != 2 {
			return money{}, errors.New("invalid money cents precision")
		}
		c, err := strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return money{}, errors.New("invalid money cents")
		}
		cents = c
	}

	total := dollars*100 + cents
	if neg {
		total = -total
	}
	return money{Currency: ccy, Cents: total}, nil
}

func moneyToCanonical(m money) string {
	sign := ""
	c := m.Cents
	if c < 0 {
		sign = "-"
		c = -c
	}
	dollars := c / 100
	cents := c % 100
	return fmt.Sprintf("%s %s%d.%02d", m.Currency, sign, dollars, cents)
}

func EffectiveVarSetPolicy(def VariableDefinition, idGov IdentityVariableGovernance) VarSetPolicy {
	switch def.SetPolicy {
	case VarAgentAllowed, VarHumanRequired, VarAgentFillHumanReview:
		return def.SetPolicy
	case VarDeferToIdentity:
	default:
	}

	var keyMatches []IdentityVarRule
	var typeMatches []IdentityVarRule
	for _, r := range idGov.Rules {
		if r.Policy != VarAgentAllowed && r.Policy != VarHumanRequired && r.Policy != VarAgentFillHumanReview {
			continue
		}
		if r.ForKey != nil && *r.ForKey == def.Key {
			keyMatches = append(keyMatches, r)
			continue
		}
		if r.ForType != nil && *r.ForType == def.Type {
			typeMatches = append(typeMatches, r)
		}
	}
	if len(keyMatches) > 0 {
		sort.Slice(keyMatches, func(i, j int) bool { return string(keyMatches[i].Policy) < string(keyMatches[j].Policy) })
		return keyMatches[0].Policy
	}
	if len(typeMatches) > 0 {
		sort.Slice(typeMatches, func(i, j int) bool { return string(typeMatches[i].Policy) < string(typeMatches[j].Policy) })
		return typeMatches[0].Policy
	}
	return VarAgentAllowed
}

func EvaluateVariableGates(action ContractAction, defs []VariableDefinition, idGov IdentityVariableGovernance, values []VariableValue) VariableGateResult {
	if !isVariableGatedAction(action) {
		return VariableGateResult{Blocked: false}
	}
	valByKey := map[VarKey]VariableValue{}
	for _, v := range values {
		valByKey[v.Key] = v
	}
	var missing, needsEntry, needsReview []VarKey
	for _, def := range defs {
		v, has := valByKey[def.Key]
		eff := EffectiveVarSetPolicy(def, idGov)

		if def.Required && !has {
			missing = append(missing, def.Key)
			continue
		}
		if !has {
			continue
		}
		if eff == VarHumanRequired {
			if v.Source != SourceHuman {
				needsEntry = append(needsEntry, def.Key)
			}
			continue
		}
		if eff == VarAgentFillHumanReview {
			if v.Source == SourceAgent && v.ReviewStatus != ReviewApproved {
				needsReview = append(needsReview, def.Key)
			}
		}
	}
	sort.Slice(missing, func(i, j int) bool { return string(missing[i]) < string(missing[j]) })
	sort.Slice(needsEntry, func(i, j int) bool { return string(needsEntry[i]) < string(needsEntry[j]) })
	sort.Slice(needsReview, func(i, j int) bool { return string(needsReview[i]) < string(needsReview[j]) })
	blocked := len(missing) > 0 || len(needsEntry) > 0 || len(needsReview) > 0
	reason := ""
	switch {
	case len(missing) > 0:
		reason = "MISSING_REQUIRED_VARIABLES"
	case len(needsEntry) > 0:
		reason = "VARIABLES_REQUIRE_HUMAN_ENTRY"
	case len(needsReview) > 0:
		reason = "VARIABLES_REQUIRE_HUMAN_REVIEW"
	}
	return VariableGateResult{Blocked: blocked, MissingRequired: missing, NeedsHumanEntry: needsEntry, NeedsHumanReview: needsReview, Reason: reason}
}

func isVariableGatedAction(a ContractAction) bool {
	switch a {
	case "SEND_TO_COUNTERPARTY", "MARK_READY_TO_SIGN", "SEND_FOR_SIGNATURE":
		return true
	default:
		return false
	}
}

