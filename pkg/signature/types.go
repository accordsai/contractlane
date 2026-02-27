package signature

type EnvelopeV1 struct {
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Signature   string `json:"signature"`
	PayloadHash string `json:"payload_hash"`
	IssuedAt    string `json:"issued_at"`
	KeyID       string `json:"key_id,omitempty"`
	Context     string `json:"context,omitempty"`
}

type EnvelopeV2 struct {
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Signature   string `json:"signature"`
	PayloadHash string `json:"payload_hash"`
	IssuedAt    string `json:"issued_at"`
	KeyID       string `json:"key_id,omitempty"`
	Context     string `json:"context,omitempty"`
}

type Envelope = EnvelopeV2
