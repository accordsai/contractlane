package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func PayloadHash(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SignBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifySignature(secret string, body []byte, signatureHeader string) bool {
	sig := strings.TrimSpace(signatureHeader)
	if sig == "" || secret == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(sig), "sha256=") {
		sig = sig[len("sha256="):]
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(got, expected)
}
