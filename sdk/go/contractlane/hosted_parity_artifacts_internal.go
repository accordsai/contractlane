package contractlane

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type hashedArtifactSet struct {
	byHash map[string]any
}

func newHashedArtifactSet() *hashedArtifactSet {
	return &hashedArtifactSet{byHash: map[string]any{}}
}

func (s *hashedArtifactSet) upsert(hash string, payload any) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return
	}
	if _, ok := s.byHash[hash]; ok {
		return
	}
	s.byHash[hash] = payload
}

func (s *hashedArtifactSet) sortedHashes() []string {
	hashes := make([]string, 0, len(s.byHash))
	for h := range s.byHash {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return hashes
}

func (s *hashedArtifactSet) sortedItems() []any {
	hashes := s.sortedHashes()
	out := make([]any, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, s.byHash[h])
	}
	return out
}

type hostedCommerceAccumulator struct {
	intents *hashedArtifactSet
	accepts *hashedArtifactSet
}

func newHostedCommerceAccumulator() *hostedCommerceAccumulator {
	return &hostedCommerceAccumulator{
		intents: newHashedArtifactSet(),
		accepts: newHashedArtifactSet(),
	}
}

func (a *hostedCommerceAccumulator) upsertIntent(v ValidatedCommerceIntentSubmission) {
	a.intents.upsert(v.IntentHash, map[string]any{
		"intent":          commerceIntentPayload(v.Intent),
		"buyer_signature": map[string]any{},
	})
}

func (a *hostedCommerceAccumulator) upsertAccept(v ValidatedCommerceAcceptSubmission) {
	a.accepts.upsert(v.AcceptHash, map[string]any{
		"accept":           commerceAcceptPayload(v.Accept),
		"seller_signature": map[string]any{},
	})
}

func (a *hostedCommerceAccumulator) upsertSignedIntent(v ValidatedCommerceIntentSubmission, sig SigV1Envelope) {
	a.intents.upsert(v.IntentHash, map[string]any{
		"intent":          commerceIntentPayload(v.Intent),
		"buyer_signature": signatureEnvelopePayload(sig),
	})
}

func (a *hostedCommerceAccumulator) upsertSignedAccept(v ValidatedCommerceAcceptSubmission, sig SigV1Envelope) {
	a.accepts.upsert(v.AcceptHash, map[string]any{
		"accept":           commerceAcceptPayload(v.Accept),
		"seller_signature": signatureEnvelopePayload(sig),
	})
}

func (a *hostedCommerceAccumulator) sortedIntentItems() []any {
	return a.intents.sortedItems()
}

func (a *hostedCommerceAccumulator) sortedAcceptItems() []any {
	return a.accepts.sortedItems()
}

func BuildContractProofBundle(contractSnapshot map[string]any, evidenceBundle map[string]any, requirements map[string]any) (map[string]any, error) {
	if contractSnapshot == nil {
		return nil, errors.New("contract snapshot is required")
	}
	if evidenceBundle == nil {
		return nil, errors.New("evidence bundle is required")
	}
	if requirements == nil {
		requirements = map[string]any{}
	}

	hashes, _ := evidenceBundle["hashes"].(map[string]any)
	if hashes == nil {
		return nil, errors.New("evidence bundle missing hashes")
	}
	manifestHash := strings.TrimSpace(fmt.Sprint(hashes["manifest_hash"]))
	bundleHash := strings.TrimSpace(fmt.Sprint(hashes["bundle_hash"]))
	if manifestHash == "" || bundleHash == "" {
		return nil, errors.New("evidence bundle missing manifest_hash/bundle_hash")
	}

	return map[string]any{
		"protocol":         "contractlane",
		"protocol_version": "v1",
		"contract":         contractSnapshot,
		"evidence":         evidenceBundle,
		"requirements": map[string]any{
			"authorization_required":         requirements["authorization_required"],
			"required_scopes":                requirements["required_scopes"],
			"settlement_required_status":     requirements["settlement_required_status"],
			"evidence_manifest_hash":         manifestHash,
			"evidence_bundle_hash":           bundleHash,
			"determinism_version":            "proof-bundle-v1",
			"evidence_hash_binding_required": true,
		},
	}, nil
}

func buildContractProofBundle(contractSnapshot map[string]any, evidenceBundle map[string]any, requirements map[string]any) (map[string]any, error) {
	return BuildContractProofBundle(contractSnapshot, evidenceBundle, requirements)
}
