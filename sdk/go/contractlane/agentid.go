package contractlane

import (
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

const (
	agentIDV1Prefix  = "agent:pk:ed25519:"
	agentIDV2Prefix  = "agent:v2:pk:p256:"
	ed25519PubLen    = 32
	p256Sec1PubLen   = 65
	p256Sec1PubStart = byte(0x04)
)

func AgentIDFromEd25519PublicKey(pub []byte) (string, error) {
	if len(pub) != ed25519PubLen {
		return "", errors.New("ed25519 public key must be 32 bytes")
	}
	return agentIDV1Prefix + base64.RawURLEncoding.EncodeToString(pub), nil
}

func AgentIDFromP256PublicKey(pub []byte) (string, error) {
	if len(pub) != p256Sec1PubLen || pub[0] != p256Sec1PubStart {
		return "", errors.New("p256 public key must be SEC1 uncompressed 65 bytes")
	}
	x := new(big.Int).SetBytes(pub[1:33])
	y := new(big.Int).SetBytes(pub[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return "", errors.New("invalid p256 public key encoding")
	}
	return agentIDV2Prefix + base64.RawURLEncoding.EncodeToString(pub), nil
}

func ParseAgentID(id string) (algo string, pub []byte, err error) {
	parts := strings.Split(id, ":")
	if len(parts) == 4 {
		if parts[0] != "agent" || parts[1] != "pk" {
			return "", nil, errors.New("invalid agent id prefix")
		}
		if parts[2] != "ed25519" {
			return "", nil, errors.New("unsupported algorithm")
		}
		decoded, decodeErr := decodeBase64URLNoPadding(parts[3], "public key")
		if decodeErr != nil {
			return "", nil, decodeErr
		}
		if len(decoded) != ed25519PubLen {
			return "", nil, errors.New("invalid ed25519 public key length")
		}
		return "ed25519", decoded, nil
	}
	if len(parts) == 5 {
		if parts[0] != "agent" || parts[1] != "v2" || parts[2] != "pk" {
			return "", nil, errors.New("invalid agent id prefix")
		}
		if parts[3] != "p256" {
			return "", nil, errors.New("unsupported algorithm")
		}
		decoded, decodeErr := decodeBase64URLNoPadding(parts[4], "public key")
		if decodeErr != nil {
			return "", nil, decodeErr
		}
		if len(decoded) != p256Sec1PubLen || decoded[0] != p256Sec1PubStart {
			return "", nil, errors.New("invalid p256 public key encoding")
		}
		x := new(big.Int).SetBytes(decoded[1:33])
		y := new(big.Int).SetBytes(decoded[33:65])
		if !elliptic.P256().IsOnCurve(x, y) {
			return "", nil, errors.New("invalid p256 public key encoding")
		}
		return "p256", decoded, nil
	}
	return "", nil, errors.New("invalid agent id format")
}

func decodeBase64URLNoPadding(s string, what string) ([]byte, error) {
	b64 := strings.TrimSpace(s)
	if b64 == "" {
		return nil, errors.New("missing " + what)
	}
	if strings.Contains(b64, "=") {
		return nil, errors.New("invalid base64url padding")
	}
	for i := 0; i < len(b64); i++ {
		c := b64[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return nil, errors.New("invalid base64url " + what)
		}
	}
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(b64)
	if decodeErr != nil {
		return nil, errors.New("invalid base64url " + what)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != b64 {
		return nil, errors.New("invalid base64url " + what)
	}
	return decoded, nil
}

func IsValidAgentID(id string) bool {
	_, _, err := ParseAgentID(id)
	return err == nil
}
