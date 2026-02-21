package contractlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/accordsai/contractlane/pkg/evidencehash"
	"github.com/accordsai/contractlane/pkg/evp"
)

type ContractExportV1 struct {
	ContractID      string `json:"contract_id"`
	PrincipalID     string `json:"principal_id,omitempty"`
	TemplateID      string `json:"template_id,omitempty"`
	TemplateVersion string `json:"template_version,omitempty"`
	State           string `json:"state,omitempty"`
	RiskLevel       string `json:"risk_level,omitempty"`
	GateKey         string `json:"gate_key,omitempty"`
}

type ProofBundleContentV1 struct {
	Contract     ContractExportV1 `json:"contract"`
	Evidence     map[string]any   `json:"evidence"`
	Rules        any              `json:"rules,omitempty"`
	Capabilities any              `json:"capabilities,omitempty"`
}

type ProofBundleV1 struct {
	Version         string               `json:"version"`
	Protocol        string               `json:"protocol"`
	ProtocolVersion string               `json:"protocol_version"`
	Bundle          ProofBundleContentV1 `json:"bundle"`
}

type ProofBundleVerifyOptions struct {
	TrustAgents []string
}

func BuildProofBundleV1(contract ContractExportV1, evidence map[string]any, rules any, capabilities any) (ProofBundleV1, error) {
	if strings.TrimSpace(contract.ContractID) == "" {
		return ProofBundleV1{}, errors.New("contract.contract_id is required")
	}
	if evidence == nil {
		return ProofBundleV1{}, errors.New("bundle.evidence is required")
	}
	out := ProofBundleV1{
		Version:         "proof-bundle-v1",
		Protocol:        "contract-lane",
		ProtocolVersion: "1",
		Bundle: ProofBundleContentV1{
			Contract: contract,
			Evidence: evidence,
		},
	}
	if rules != nil {
		out.Bundle.Rules = rules
	}
	if capabilities != nil {
		out.Bundle.Capabilities = capabilities
	}
	return out, nil
}

func ComputeProofID(proof ProofBundleV1) (string, error) {
	if err := validateProofBundleShape(proof); err != nil {
		return "", err
	}
	hashInput, err := proofBundleHashInput(proof)
	if err != nil {
		return "", err
	}
	return canonicalSha256Hex(hashInput)
}

func VerifyProofBundleV1(proof ProofBundleV1) (string, error) {
	return VerifyProofBundleV1WithOptions(proof, ProofBundleVerifyOptions{})
}

func VerifyProofBundleV1WithOptions(proof ProofBundleV1, opts ProofBundleVerifyOptions) (string, error) {
	if err := validateProofBundleShape(proof); err != nil {
		return "", err
	}
	hashInput, err := proofBundleHashInput(proof)
	if err != nil {
		return "", err
	}
	proofID, err := canonicalSha256Hex(hashInput)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(proof.Bundle.Contract.ContractID) == "" {
		return "", errors.New("bundle.contract.contract_id is required")
	}

	_, evidenceBytes, err := evidencehash.CanonicalSHA256(proof.Bundle.Evidence)
	if err != nil {
		return "", err
	}
	evpResult, err := evp.VerifyBundleJSON(evidenceBytes)
	if err != nil {
		return "", err
	}
	if evpResult.Status != evp.StatusVerified {
		return "", fmt.Errorf("evidence verification failed: %s", evpResult.Status)
	}
	eContract, _ := proof.Bundle.Evidence["contract"].(map[string]any)
	if strings.TrimSpace(fmt.Sprint(eContract["contract_id"])) != proof.Bundle.Contract.ContractID {
		return "", errors.New("contract/evidence contract_id mismatch")
	}
	artifacts, _ := proof.Bundle.Evidence["artifacts"].(map[string]any)
	if artifacts == nil {
		return "", errors.New("evidence missing artifacts")
	}

	if err := verifyProofBundleSignaturesAndDelegations(artifacts); err != nil {
		return "", err
	}
	if proof.Bundle.Rules != nil {
		rules, err := ParseRulesV1Strict(proof.Bundle.Rules)
		if err != nil {
			return "", err
		}
		contractState := strings.TrimSpace(fmt.Sprint(eContract["state"]))
		out, err := EvaluateRulesV1(rules, RulesEvaluationInput{
			ContractID:    proof.Bundle.Contract.ContractID,
			ContractState: contractState,
			Artifacts:     artifacts,
			TrustAgents:   opts.TrustAgents,
		})
		if err != nil {
			return "", err
		}
		for _, rr := range out.RuleResults {
			for _, eff := range rr.Effects {
				if eff.Type == "require" && eff.Satisfied != nil && !*eff.Satisfied {
					return "", fmt.Errorf("rules_requirement_failed: rule_id=%s require=%s failure_reason=%s", rr.RuleID, eff.Name, eff.FailureReason)
				}
			}
		}
	}
	return proofID, nil
}

func ParseProofBundleV1Strict(v any) (ProofBundleV1, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return ProofBundleV1{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var out ProofBundleV1
	if err := dec.Decode(&out); err != nil {
		return ProofBundleV1{}, err
	}
	if dec.More() {
		return ProofBundleV1{}, errors.New("invalid trailing proof bundle payload")
	}
	if err := validateProofBundleShape(out); err != nil {
		return ProofBundleV1{}, err
	}
	return out, nil
}

func validateProofBundleShape(proof ProofBundleV1) error {
	if proof.Version != "proof-bundle-v1" {
		return errors.New("version must be proof-bundle-v1")
	}
	if proof.Protocol != "contract-lane" {
		return errors.New("protocol must be contract-lane")
	}
	if proof.ProtocolVersion != "1" {
		return errors.New("protocol_version must be 1")
	}
	if strings.TrimSpace(proof.Bundle.Contract.ContractID) == "" {
		return errors.New("bundle.contract.contract_id is required")
	}
	if proof.Bundle.Evidence == nil {
		return errors.New("bundle.evidence is required")
	}
	return nil
}

func proofBundleHashInput(proof ProofBundleV1) (any, error) {
	// Normalize to a generic JSON value so hashing is independent of struct field order
	// vs map key order across different callers.
	b, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func verifyProofBundleSignaturesAndDelegations(artifacts map[string]any) error {
	if raw, ok := artifacts["commerce_intents"]; ok {
		rows, err := normalizeAnyArray(raw)
		if err != nil {
			return err
		}
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			intentMap, _ := rm["intent"].(map[string]any)
			sigMap, _ := rm["buyer_signature"].(map[string]any)
			if intentMap == nil || sigMap == nil {
				continue
			}
			bIntent, _ := json.Marshal(intentMap)
			bSig, _ := json.Marshal(sigMap)
			var intent CommerceIntentV1
			var sig SigV1Envelope
			if err := json.Unmarshal(bIntent, &intent); err != nil {
				return err
			}
			if err := json.Unmarshal(bSig, &sig); err != nil {
				return err
			}
			if _, err := ValidateCommerceIntentSubmission(intent, sig); err != nil {
				return err
			}
		}
	}
	if raw, ok := artifacts["commerce_accepts"]; ok {
		rows, err := normalizeAnyArray(raw)
		if err != nil {
			return err
		}
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			accMap, _ := rm["accept"].(map[string]any)
			sigMap, _ := rm["seller_signature"].(map[string]any)
			if accMap == nil || sigMap == nil {
				continue
			}
			bAcc, _ := json.Marshal(accMap)
			bSig, _ := json.Marshal(sigMap)
			var acc CommerceAcceptV1
			var sig SigV1Envelope
			if err := json.Unmarshal(bAcc, &acc); err != nil {
				return err
			}
			if err := json.Unmarshal(bSig, &sig); err != nil {
				return err
			}
			if _, err := ValidateCommerceAcceptSubmission(acc, sig); err != nil {
				return err
			}
		}
	}
	if raw, ok := artifacts["delegations"]; ok {
		rows, err := normalizeAnyArray(raw)
		if err != nil {
			return err
		}
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			delegation := rm["delegation"]
			sigMap, _ := rm["issuer_signature"].(map[string]any)
			if delegation == nil || sigMap == nil {
				continue
			}
			d, err := parseDelegationStrict(delegation)
			if err != nil {
				return err
			}
			bSig, _ := json.Marshal(sigMap)
			var sig SigV1Envelope
			if err := json.Unmarshal(bSig, &sig); err != nil {
				return err
			}
			if err := VerifyDelegationV1(d, sig); err != nil {
				return err
			}
		}
	}
	if raw, ok := artifacts["delegation_revocations"]; ok {
		rows, err := normalizeAnyArray(raw)
		if err != nil {
			return err
		}
		for _, r := range rows {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			revocation := rm["revocation"]
			sigMap, _ := rm["issuer_signature"].(map[string]any)
			if revocation == nil || sigMap == nil {
				continue
			}
			rev, err := parseDelegationRevocationStrict(revocation)
			if err != nil {
				return err
			}
			bSig, _ := json.Marshal(sigMap)
			var sig SigV1Envelope
			if err := json.Unmarshal(bSig, &sig); err != nil {
				return err
			}
			if _, _, _, err := ValidateDelegationRevocation(rev, sig); err != nil {
				return err
			}
		}
	}
	return nil
}
