package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	stripeSignatureHeader  = "Stripe-Signature"
	stripeScheme           = "stripe-v1"
	defaultStripeTolerance = 300
)

type stripeV1Verifier struct {
	provider         string
	toleranceSeconds int
}

func NewStripeV1Verifier(provider string) Verifier {
	return &stripeV1Verifier{
		provider:         strings.TrimSpace(provider),
		toleranceSeconds: stripeToleranceFromEnv(),
	}
}

func NewStripeV1VerifierWithTolerance(provider string, toleranceSeconds int) Verifier {
	return &stripeV1Verifier{
		provider:         strings.TrimSpace(provider),
		toleranceSeconds: toleranceSeconds,
	}
}

func (v *stripeV1Verifier) Provider() string {
	return v.provider
}

func (v *stripeV1Verifier) Verify(headers http.Header, rawBody []byte, receivedAt time.Time, secret string) (VerificationResult, error) {
	if strings.TrimSpace(secret) == "" {
		return VerificationResult{}, fmt.Errorf("webhook verifier secret is empty")
	}

	timestamp, signatures := parseStripeSignatureHeader(headers.Values(stripeSignatureHeader))
	timestampUnix, parseErr := strconv.ParseInt(timestamp, 10, 64)
	if parseErr != nil {
		timestampUnix = 0
	}
	skew := 0
	if timestampUnix > 0 {
		skew = int(receivedAt.UTC().Unix() - timestampUnix)
		if skew < 0 {
			skew = -skew
		}
	}

	result := VerificationResult{
		Valid:  false,
		Scheme: stripeScheme,
		Details: map[string]any{
			"signature_header_present": len(strings.TrimSpace(strings.Join(headers.Values(stripeSignatureHeader), ","))) > 0,
			"parsed_timestamp":         timestampUnix,
			"tolerance_seconds":        v.toleranceSeconds,
			"skew_seconds":             skew,
			"v1_present":               len(signatures) > 0,
		},
		ProviderEventID: "",
		EventType:       "unknown",
	}
	if !result.Details["signature_header_present"].(bool) || timestampUnix <= 0 || len(signatures) == 0 {
		return result, nil
	}

	mac := hmac.New(sha256.New, []byte(secret))
	signedPayload := append([]byte(timestamp), '.')
	signedPayload = append(signedPayload, rawBody...)
	_, _ = mac.Write(signedPayload)
	expectedSig := mac.Sum(nil)

	validSig := false
	for _, sigHex := range signatures {
		decoded, err := hex.DecodeString(sigHex)
		if err != nil {
			continue
		}
		if hmac.Equal(expectedSig, decoded) {
			validSig = true
			break
		}
	}
	if !validSig {
		return result, nil
	}
	if v.toleranceSeconds > 0 && skew > v.toleranceSeconds {
		return result, nil
	}

	result.Valid = true
	var evt struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rawBody, &evt); err == nil {
		result.ProviderEventID = strings.TrimSpace(evt.ID)
		if t := strings.TrimSpace(evt.Type); t != "" {
			result.EventType = t
		}
	}
	return result, nil
}

func stripeToleranceFromEnv() int {
	raw := strings.TrimSpace(os.Getenv("STRIPE_TOLERANCE_SECONDS"))
	if raw == "" {
		return defaultStripeTolerance
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return defaultStripeTolerance
	}
	return v
}

func parseStripeSignatureHeader(values []string) (string, []string) {
	joined := strings.TrimSpace(strings.Join(values, ","))
	if joined == "" {
		return "", nil
	}
	var t string
	v1 := make([]string, 0, 2)
	for _, part := range strings.Split(joined, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if k == "t" && t == "" {
			t = val
			continue
		}
		if k == "v1" && val != "" {
			v1 = append(v1, val)
		}
	}
	return t, v1
}
