package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	genericHMACSignatureHeader = "X-Signature"
	genericHMACEventIDHeader   = "X-Event-Id"
	genericHMACEventTypeHeader = "X-Event-Type"
	genericHMACScheme          = "generic-hmac-sha256/v1"
)

type genericHMACVerifier struct {
	provider string
}

func NewGenericHMACVerifier(provider string) Verifier {
	return &genericHMACVerifier{provider: strings.TrimSpace(provider)}
}

func (v *genericHMACVerifier) Provider() string {
	return v.provider
}

func (v *genericHMACVerifier) Verify(headers http.Header, rawBody []byte, _ time.Time, secret string) (VerificationResult, error) {
	if strings.TrimSpace(secret) == "" {
		return VerificationResult{}, fmt.Errorf("webhook verifier secret is empty")
	}

	res := VerificationResult{
		Valid:  false,
		Scheme: genericHMACScheme,
		Details: map[string]any{
			"signature_header_present": false,
			"signature_hex_decodable":  false,
			"provider":                 v.provider,
			"used_header":              genericHMACSignatureHeader,
		},
		ProviderEventID: strings.TrimSpace(headers.Get(genericHMACEventIDHeader)),
		EventType:       strings.TrimSpace(headers.Get(genericHMACEventTypeHeader)),
	}
	if res.EventType == "" {
		res.EventType = "unknown"
	}

	sigHex := strings.TrimSpace(headers.Get(genericHMACSignatureHeader))
	if sigHex == "" {
		return res, nil
	}
	res.Details["signature_header_present"] = true

	providedSig, err := hex.DecodeString(sigHex)
	if err != nil {
		return res, nil
	}
	res.Details["signature_hex_decodable"] = true

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(rawBody)
	expected := mac.Sum(nil)
	res.Valid = hmac.Equal(expected, providedSig)
	return res, nil
}
