package contractlane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"contractlane/pkg/evidencehash"
	"contractlane/pkg/evp"
)

type SettlementProofV1 struct {
	Version               string                        `json:"version"`
	Protocol              string                        `json:"protocol"`
	ProtocolVersion       string                        `json:"protocol_version"`
	ContractID            string                        `json:"contract_id"`
	IntentID              string                        `json:"intent_id"`
	IntentHash            string                        `json:"intent_hash"`
	ManifestHash          string                        `json:"manifest_hash"`
	BundleHash            string                        `json:"bundle_hash"`
	BuyerIntentSignature  SigV1Envelope                 `json:"buyer_intent_signature"`
	SellerAcceptSignature SigV1Envelope                 `json:"seller_accept_signature"`
	ReceiptRefs           []string                      `json:"receipt_refs"`
	Payment               *SettlementProofPayment       `json:"payment,omitempty"`
	Authorization         *SettlementProofAuthorization `json:"authorization,omitempty"`
	IssuedAtUTC           string                        `json:"issued_at_utc"`
}

type SettlementProofPayment struct {
	RequiredStatus string           `json:"required_status"`
	Amount         CommerceAmountV1 `json:"amount"`
}

type SettlementProofAuthorization struct {
	Required bool   `json:"required"`
	Scope    string `json:"scope"`
}

type SettlementProofVerifyOptions struct {
	TrustAgents []string
}

type BuildSettlementProofV1Options struct {
	ContractID  string
	IntentID    string
	IssuedAtUTC string
}

func BuildSettlementProofV1(evidenceBytes []byte, opts BuildSettlementProofV1Options) (*SettlementProofV1, []byte, error) {
	evpResult, err := evp.VerifyBundleJSON(evidenceBytes)
	if err != nil {
		return nil, nil, err
	}
	if evpResult.Status != evp.StatusVerified {
		return nil, nil, fmt.Errorf("evidence verification failed: %s", evpResult.Status)
	}

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		return nil, nil, errors.New("invalid evidence json")
	}
	hashes, _ := evidence["hashes"].(map[string]any)
	if hashes == nil {
		return nil, nil, errors.New("evidence missing hashes")
	}
	artifacts, _ := evidence["artifacts"].(map[string]any)
	if artifacts == nil {
		return nil, nil, errors.New("evidence missing artifacts")
	}

	intent, buyerSig, err := selectIntentForProof(artifacts, strings.TrimSpace(opts.IntentID))
	if err != nil {
		return nil, nil, err
	}
	intentHash, err := HashCommerceIntentV1(intent)
	if err != nil {
		return nil, nil, err
	}
	_, sellerSig, err := findAcceptByIntentHash(artifacts, intentHash)
	if err != nil {
		return nil, nil, err
	}

	contractID := strings.TrimSpace(opts.ContractID)
	if contractID == "" {
		contractID = strings.TrimSpace(intent.ContractID)
	}
	if contractID == "" {
		contract, _ := evidence["contract"].(map[string]any)
		contractID = strings.TrimSpace(fmt.Sprint(contract["contract_id"]))
	}
	if contractID == "" {
		return nil, nil, errors.New("contract_id required")
	}

	issuedAt := strings.TrimSpace(opts.IssuedAtUTC)
	if issuedAt == "" {
		issuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if !isRFC3339UTC(issuedAt) {
		return nil, nil, errors.New("issued_at_utc must be RFC3339 UTC")
	}

	refs := collectReceiptRefs(artifacts)
	sort.Strings(refs)

	proof := &SettlementProofV1{
		Version:               "settlement-proof-v1",
		Protocol:              "contractlane",
		ProtocolVersion:       "v1",
		ContractID:            contractID,
		IntentID:              intent.IntentID,
		IntentHash:            intentHash,
		ManifestHash:          strings.TrimSpace(fmt.Sprint(hashes["manifest_hash"])),
		BundleHash:            strings.TrimSpace(fmt.Sprint(hashes["bundle_hash"])),
		BuyerIntentSignature:  buyerSig,
		SellerAcceptSignature: sellerSig,
		ReceiptRefs:           refs,
		Payment: &SettlementProofPayment{
			RequiredStatus: "PAID",
			Amount:         normalizeProofAmount(intent.Total),
		},
		Authorization: &SettlementProofAuthorization{
			Required: true,
			Scope:    DelegationScopeCommerceIntentSign,
		},
		IssuedAtUTC: issuedAt,
	}
	_, bytes, err := evidencehash.CanonicalSHA256(proof)
	if err != nil {
		return nil, nil, err
	}
	return proof, bytes, nil
}

func VerifySettlementProofV1(evidenceBytes []byte, proofBytes []byte) error {
	return VerifySettlementProofV1WithOptions(evidenceBytes, proofBytes, SettlementProofVerifyOptions{})
}

func VerifySettlementProofV1WithOptions(evidenceBytes []byte, proofBytes []byte, opts SettlementProofVerifyOptions) error {
	evpResult, err := evp.VerifyBundleJSON(evidenceBytes)
	if err != nil {
		return err
	}
	if evpResult.Status != evp.StatusVerified {
		return fmt.Errorf("evidence verification failed: %s", evpResult.Status)
	}

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		return errors.New("invalid evidence json")
	}

	var proof SettlementProofV1
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		return errors.New("invalid settlement proof json")
	}

	if proof.Version != "settlement-proof-v1" {
		return errors.New("invalid settlement proof version")
	}
	if proof.Protocol != "contractlane" || proof.ProtocolVersion != "v1" {
		return errors.New("invalid settlement proof protocol")
	}
	if !isRFC3339UTC(proof.IssuedAtUTC) {
		return errors.New("issued_at_utc must be RFC3339 UTC")
	}

	eContract, _ := evidence["contract"].(map[string]any)
	eHashes, _ := evidence["hashes"].(map[string]any)
	if eContract == nil || eHashes == nil {
		return errors.New("evidence missing contract/hashes")
	}
	eContractID := strings.TrimSpace(fmt.Sprint(eContract["contract_id"]))
	if proof.ContractID != eContractID {
		return errors.New("contract_id mismatch")
	}

	evManifestHash := strings.TrimSpace(fmt.Sprint(eHashes["manifest_hash"]))
	evBundleHash := strings.TrimSpace(fmt.Sprint(eHashes["bundle_hash"]))
	if !hashStringsEquivalent(proof.ManifestHash, evManifestHash) {
		return errors.New("manifest_hash mismatch")
	}
	if !hashStringsEquivalent(proof.BundleHash, evBundleHash) {
		return errors.New("bundle_hash mismatch")
	}

	artifacts, _ := evidence["artifacts"].(map[string]any)
	if artifacts == nil {
		return errors.New("evidence missing artifacts")
	}

	intent, buyerSig, err := findIntentByID(artifacts, proof.IntentID)
	if err != nil {
		return err
	}
	intentHash, err := HashCommerceIntentV1(intent)
	if err != nil {
		return err
	}
	if !hashStringsEquivalent(proof.IntentHash, intentHash) {
		return errors.New("intent_hash mismatch")
	}
	if err := VerifyCommerceIntentV1(intent, proof.BuyerIntentSignature); err != nil {
		return fmt.Errorf("buyer_intent_signature verification failed: %w", err)
	}
	if err := ensureSignaturePubKeyMatchesAgent(proof.BuyerIntentSignature, intent.BuyerAgent); err != nil {
		return err
	}
	_ = buyerSig

	accept, _, err := findAcceptByIntentHash(artifacts, stripSHA256Prefix(proof.IntentHash))
	if err != nil {
		return err
	}
	if err := VerifyCommerceAcceptV1(accept, proof.SellerAcceptSignature); err != nil {
		return fmt.Errorf("seller_accept_signature verification failed: %w", err)
	}
	if err := ensureSignaturePubKeyMatchesAgent(proof.SellerAcceptSignature, intent.SellerAgent); err != nil {
		return err
	}

	if len(proof.ReceiptRefs) > 0 {
		if err := verifyReceiptRefs(artifacts, proof.ReceiptRefs); err != nil {
			return err
		}
	}
	if proof.Payment != nil {
		if err := verifyPaymentRequirement(artifacts, proof, intent); err != nil {
			return err
		}
	}
	if proof.Authorization != nil && proof.Authorization.Required {
		if err := verifyDelegationAuthorization(artifacts, proof, intent, opts); err != nil {
			return err
		}
	}

	return nil
}

func hashStringsEquivalent(a, b string) bool {
	return stripSHA256Prefix(a) == stripSHA256Prefix(b)
}

func stripSHA256Prefix(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "sha256:")
}

func isRFC3339UTC(v string) bool {
	if !strings.HasSuffix(v, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, v)
	return err == nil
}

func findIntentByID(artifacts map[string]any, intentID string) (CommerceIntentV1, SigV1Envelope, error) {
	intentsAny, ok := artifacts["commerce_intents"].([]any)
	if !ok {
		return CommerceIntentV1{}, SigV1Envelope{}, errors.New("evidence missing artifacts.commerce_intents")
	}
	for _, row := range intentsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		intentMap, _ := rm["intent"].(map[string]any)
		if intentMap == nil || fmt.Sprint(intentMap["intent_id"]) != intentID {
			continue
		}
		b, _ := json.Marshal(intentMap)
		var intent CommerceIntentV1
		if err := json.Unmarshal(b, &intent); err != nil {
			return CommerceIntentV1{}, SigV1Envelope{}, err
		}
		sigMap, _ := rm["buyer_signature"].(map[string]any)
		if sigMap == nil {
			return CommerceIntentV1{}, SigV1Envelope{}, errors.New("missing buyer_signature in commerce_intents")
		}
		sb, _ := json.Marshal(sigMap)
		var sig SigV1Envelope
		if err := json.Unmarshal(sb, &sig); err != nil {
			return CommerceIntentV1{}, SigV1Envelope{}, err
		}
		return intent, sig, nil
	}
	return CommerceIntentV1{}, SigV1Envelope{}, errors.New("intent_id not found in evidence artifacts")
}

func findAcceptByIntentHash(artifacts map[string]any, intentHash string) (CommerceAcceptV1, SigV1Envelope, error) {
	acceptsAny, ok := artifacts["commerce_accepts"].([]any)
	if !ok {
		return CommerceAcceptV1{}, SigV1Envelope{}, errors.New("evidence missing artifacts.commerce_accepts")
	}
	for _, row := range acceptsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		acceptMap, _ := rm["accept"].(map[string]any)
		if acceptMap == nil || stripSHA256Prefix(fmt.Sprint(acceptMap["intent_hash"])) != intentHash {
			continue
		}
		b, _ := json.Marshal(acceptMap)
		var accept CommerceAcceptV1
		if err := json.Unmarshal(b, &accept); err != nil {
			return CommerceAcceptV1{}, SigV1Envelope{}, err
		}
		sigMap, _ := rm["seller_signature"].(map[string]any)
		if sigMap == nil {
			return CommerceAcceptV1{}, SigV1Envelope{}, errors.New("missing seller_signature in commerce_accepts")
		}
		sb, _ := json.Marshal(sigMap)
		var sig SigV1Envelope
		if err := json.Unmarshal(sb, &sig); err != nil {
			return CommerceAcceptV1{}, SigV1Envelope{}, err
		}
		return accept, sig, nil
	}
	return CommerceAcceptV1{}, SigV1Envelope{}, errors.New("intent_hash not found in commerce_accepts")
}

func ensureSignaturePubKeyMatchesAgent(sig SigV1Envelope, expectedAgentID string) error {
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return errors.New("invalid signature public_key encoding")
	}
	agentID, err := AgentIDFromEd25519PublicKey(pub)
	if err != nil {
		return err
	}
	if agentID != expectedAgentID {
		return errors.New("signature public key does not match expected agent")
	}
	return nil
}

func verifyReceiptRefs(artifacts map[string]any, refs []string) error {
	receiptsAny, ok := artifacts["webhook_receipts"].([]any)
	if !ok {
		return errors.New("evidence missing artifacts.webhook_receipts")
	}
	seen := map[string]struct{}{}
	for _, row := range receiptsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		requestHash := strings.TrimSpace(fmt.Sprint(rm["request_sha256"]))
		if requestHash == "" {
			requestHash = strings.TrimSpace(fmt.Sprint(rm["request_hash"]))
		}
		if requestHash != "" {
			seen[requestHash] = struct{}{}
		}
	}
	for _, ref := range refs {
		if _, ok := seen[ref]; !ok {
			return fmt.Errorf("receipt_ref not found in webhook_receipts: %s", ref)
		}
	}
	return nil
}

func selectIntentForProof(artifacts map[string]any, intentID string) (CommerceIntentV1, SigV1Envelope, error) {
	if intentID != "" {
		return findIntentByID(artifacts, intentID)
	}
	intentsAny, ok := artifacts["commerce_intents"].([]any)
	if !ok {
		return CommerceIntentV1{}, SigV1Envelope{}, errors.New("evidence missing artifacts.commerce_intents")
	}
	if len(intentsAny) != 1 {
		return CommerceIntentV1{}, SigV1Envelope{}, errors.New("intent_id required")
	}
	row, _ := intentsAny[0].(map[string]any)
	intentMap, _ := row["intent"].(map[string]any)
	if intentMap == nil {
		return CommerceIntentV1{}, SigV1Envelope{}, errors.New("intent payload missing in commerce_intents")
	}
	return findIntentByID(artifacts, strings.TrimSpace(fmt.Sprint(intentMap["intent_id"])))
}

func collectReceiptRefs(artifacts map[string]any) []string {
	receiptsAny, ok := artifacts["webhook_receipts"].([]any)
	if !ok {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(receiptsAny))
	for _, row := range receiptsAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		requestHash := strings.TrimSpace(fmt.Sprint(rm["request_sha256"]))
		if requestHash == "" {
			requestHash = strings.TrimSpace(fmt.Sprint(rm["request_hash"]))
		}
		if requestHash == "" {
			continue
		}
		if _, ok := seen[requestHash]; ok {
			continue
		}
		seen[requestHash] = struct{}{}
		out = append(out, requestHash)
	}
	return out
}

func verifyPaymentRequirement(artifacts map[string]any, proof SettlementProofV1, intent CommerceIntentV1) error {
	requiredStatus := strings.TrimSpace(proof.Payment.RequiredStatus)
	if requiredStatus == "" {
		return errors.New("payment.required_status is required")
	}
	if requiredStatus != "PAID" {
		return errors.New("unsupported payment requirement status")
	}
	requiredAmount := proof.Payment.Amount
	if strings.TrimSpace(requiredAmount.Currency) == "" || strings.TrimSpace(requiredAmount.Amount) == "" {
		return errors.New("payment.amount is required")
	}

	attAny, ok := artifacts["settlement_attestations"].([]any)
	if !ok {
		return errors.New("evidence missing artifacts.settlement_attestations")
	}
	for _, row := range attAny {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		b, _ := json.Marshal(rm)
		var att SettlementAttestationV1
		if err := json.Unmarshal(b, &att); err != nil {
			continue
		}
		if err := att.validateForProof(); err != nil {
			continue
		}
		if stripSHA256Prefix(att.IntentHash) != stripSHA256Prefix(proof.IntentHash) {
			continue
		}
		if strings.TrimSpace(att.IntentID) != strings.TrimSpace(proof.IntentID) {
			continue
		}
		if strings.TrimSpace(att.ContractID) != strings.TrimSpace(proof.ContractID) {
			continue
		}
		if att.Status != requiredStatus {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(att.Amount.Currency)) != strings.ToUpper(strings.TrimSpace(requiredAmount.Currency)) {
			return errors.New("payment attestation amount currency mismatch")
		}
		if strings.TrimSpace(att.Amount.Amount) != strings.TrimSpace(requiredAmount.Amount) {
			return errors.New("payment attestation amount mismatch")
		}
		// Ensure requested proof amount still matches the intent total.
		intentNormalized := normalizeProofAmount(intent.Total)
		if strings.ToUpper(strings.TrimSpace(intentNormalized.Currency)) != strings.ToUpper(strings.TrimSpace(requiredAmount.Currency)) ||
			strings.TrimSpace(intentNormalized.Amount) != strings.TrimSpace(requiredAmount.Amount) {
			return errors.New("payment requirement does not match intent total")
		}
		return nil
	}
	return errors.New("no matching PAID settlement attestation")
}

func normalizeProofAmount(in CommerceAmountV1) CommerceAmountV1 {
	ccy := strings.ToUpper(strings.TrimSpace(in.Currency))
	amt := strings.TrimSpace(in.Amount)
	if strings.Contains(amt, ".") {
		amt = strings.TrimRight(amt, "0")
		amt = strings.TrimSuffix(amt, ".")
	}
	if amt == "" {
		amt = "0"
	}
	return CommerceAmountV1{Currency: ccy, Amount: amt}
}

func verifyDelegationAuthorization(artifacts map[string]any, proof SettlementProofV1, intent CommerceIntentV1, opts SettlementProofVerifyOptions) error {
	scope := strings.TrimSpace(proof.Authorization.Scope)
	if scope == "" {
		return errors.New(DelegationFailureScopeMissing)
	}

	signingAgent := ""
	counterparty := ""
	switch scope {
	case DelegationScopeCommerceIntentSign:
		signingAgent = intent.BuyerAgent
		counterparty = intent.SellerAgent
	case DelegationScopeCommerceAcceptSign:
		signingAgent = intent.SellerAgent
		counterparty = intent.BuyerAgent
	default:
		return errors.New(DelegationFailureScopeMissing)
	}

	delegationsAny, ok := artifacts["delegations"].([]any)
	if !ok || len(delegationsAny) == 0 {
		return errors.New(DelegationFailureMissing)
	}
	trustSet := map[string]struct{}{}
	for _, a := range opts.TrustAgents {
		v := strings.TrimSpace(a)
		if v != "" {
			trustSet[v] = struct{}{}
		}
	}

	var sawSubject, sawScope, sawSigInvalid, sawUntrusted bool
	constraintFailure := ""
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
		if del.SubjectAgent != signingAgent {
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

		var pay *CommerceAmountV1
		if proof.Payment != nil {
			p := normalizeProofAmount(proof.Payment.Amount)
			pay = &p
		}
		err = EvaluateDelegationConstraints(del.Constraints, DelegationEvalContext{
			ContractID:        proof.ContractID,
			CounterpartyAgent: counterparty,
			IssuedAtUTC:       proof.IssuedAtUTC,
			PaymentAmount:     pay,
		})
		if err != nil {
			if dErr, ok := err.(*DelegationConstraintError); ok {
				constraintFailure = dErr.Reason
			} else {
				constraintFailure = DelegationFailureConstraintsFailed
			}
			continue
		}
		return nil
	}

	if !sawSubject {
		return errors.New(DelegationFailureMissing)
	}
	if !sawScope {
		return errors.New(DelegationFailureScopeMissing)
	}
	if sawSigInvalid {
		return errors.New(DelegationFailureSignatureInvalid)
	}
	if sawUntrusted {
		return errors.New(DelegationFailureUntrustedIssuer)
	}
	if constraintFailure != "" {
		return errors.New(constraintFailure)
	}
	return errors.New(DelegationFailureMissing)
}
