package contractlane

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	agentIDPrefix = "agent:pk:ed25519:"
	ed25519PubLen = 32
)

func AgentIDFromEd25519PublicKey(pub []byte) (string, error) {
	if len(pub) != ed25519PubLen {
		return "", errors.New("ed25519 public key must be 32 bytes")
	}
	return agentIDPrefix + base64.RawURLEncoding.EncodeToString(pub), nil
}

func ParseAgentID(id string) (algo string, pub []byte, err error) {
	parts := strings.Split(id, ":")
	if len(parts) != 4 {
		return "", nil, errors.New("invalid agent id format")
	}
	if parts[0] != "agent" || parts[1] != "pk" {
		return "", nil, errors.New("invalid agent id prefix")
	}
	if parts[2] != "ed25519" {
		return "", nil, errors.New("unsupported algorithm")
	}
	b64 := parts[3]
	if b64 == "" {
		return "", nil, errors.New("missing public key")
	}
	if strings.Contains(b64, "=") {
		return "", nil, errors.New("invalid base64url padding")
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(b64)
	if decodeErr != nil {
		return "", nil, errors.New("invalid base64url public key")
	}
	if len(decoded) != ed25519PubLen {
		return "", nil, errors.New("invalid ed25519 public key length")
	}
	return "ed25519", decoded, nil
}

func IsValidAgentID(id string) bool {
	_, _, err := ParseAgentID(id)
	return err == nil
}
