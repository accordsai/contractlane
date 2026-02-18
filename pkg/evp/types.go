package evp

import "encoding/json"

type EvidenceBundleV1 struct {
	BundleVersion string                     `json:"bundle_version"`
	GeneratedAt   string                     `json:"generated_at,omitempty"`
	PrincipalID   string                     `json:"principal_id,omitempty"`
	RequestID     string                     `json:"request_id,omitempty"`
	Contract      EvidenceContract           `json:"contract"`
	Hashes        EvidenceHashes             `json:"hashes"`
	Manifest      EvidenceManifestV1         `json:"manifest"`
	Artifacts     map[string]json.RawMessage `json:"artifacts"`
}

type EvidenceContract struct {
	ContractID         string `json:"contract_id"`
	State              string `json:"state,omitempty"`
	TemplateID         string `json:"template_id,omitempty"`
	TemplateVersion    string `json:"template_version,omitempty"`
	PacketHash         string `json:"packet_hash"`
	DiffHash           string `json:"diff_hash,omitempty"`
	RiskHash           string `json:"risk_hash,omitempty"`
	VariablesHash      string `json:"variables_hash,omitempty"`
	DeterminismVersion string `json:"determinism_version"`
}

type EvidenceHashes struct {
	BundleHash   string `json:"bundle_hash"`
	ManifestHash string `json:"manifest_hash"`
}

type EvidenceManifestV1 struct {
	Canonicalization EvidenceCanonicalizationV1 `json:"canonicalization"`
	Artifacts        []map[string]any           `json:"artifacts"`
}

type EvidenceCanonicalizationV1 struct {
	JSON             string `json:"json,omitempty"`
	Newlines         string `json:"newlines,omitempty"`
	Encoding         string `json:"encoding,omitempty"`
	BundleV          string `json:"bundle_v,omitempty"`
	ManifestHashRule string `json:"manifest_hash_rule,omitempty"`
	BundleHashRule   string `json:"bundle_hash_rule,omitempty"`
}

type Result struct {
	Status  string         `json:"status"`
	Details map[string]any `json:"details,omitempty"`
}

const (
	StatusVerified                      = "VERIFIED"
	StatusInvalidBundleHash             = "INVALID_BUNDLE_HASH"
	StatusInvalidManifestHash           = "INVALID_MANIFEST_HASH"
	StatusInvalidArtifactHash           = "INVALID_ARTIFACT_HASH"
	StatusInvalidOrdering               = "INVALID_ORDERING"
	StatusUnsupportedDeterminismVersion = "UNSUPPORTED_DETERMINISM_VERSION"
	StatusMalformedBundle               = "MALFORMED_BUNDLE"
)
