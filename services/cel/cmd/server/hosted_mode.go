package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"contractlane/pkg/httpx"
)

type hostedModeConfig struct {
	EnableHostedCommerce                      bool
	EnableProofExport                         bool
	EnableProofBundleExport                   bool
	EnableTemplateAdminAPI                    bool
	EnableServerDerivedSettlementAttestations bool
	TemplateAdminBootstrapToken               string
	TemplateAdminAuthMode                     string
	TemplateAdminRequiredScope                string
	HostedMaxBodyBytes                        int64
	HostedRateLimitPerMinute                  int
	ProofRateLimitPerMinute                   int
}

func loadHostedModeConfig() hostedModeConfig {
	adminMode := strings.ToLower(strings.TrimSpace(os.Getenv("TEMPLATE_ADMIN_AUTH_MODE")))
	if adminMode == "" {
		adminMode = "bootstrap"
	}
	adminScope := strings.TrimSpace(os.Getenv("TEMPLATE_ADMIN_REQUIRED_SCOPE"))
	if adminScope == "" {
		adminScope = "cel.admin:templates"
	}
	return hostedModeConfig{
		EnableHostedCommerce:                      envBoolDefault("ENABLE_HOSTED_COMMERCE", true),
		EnableProofExport:                         envBoolDefault("ENABLE_PROOF_EXPORT", true),
		EnableProofBundleExport:                   envBoolDefault("ENABLE_PROOF_BUNDLE_EXPORT", true),
		EnableTemplateAdminAPI:                    envBoolDefault("ENABLE_TEMPLATE_ADMIN_API", false),
		EnableServerDerivedSettlementAttestations: envBoolDefault("ENABLE_SERVER_DERIVED_SETTLEMENT_ATTESTATIONS", false),
		TemplateAdminBootstrapToken:               strings.TrimSpace(os.Getenv("TEMPLATE_ADMIN_BOOTSTRAP_TOKEN")),
		TemplateAdminAuthMode:                     adminMode,
		TemplateAdminRequiredScope:                adminScope,
		HostedMaxBodyBytes:                        envInt64Default("HOSTED_MAX_BODY_BYTES", 262144),
		HostedRateLimitPerMinute:                  envIntDefault("HOSTED_RATE_LIMIT_PER_MINUTE", 0),
		ProofRateLimitPerMinute:                   envIntDefault("PROOF_RATE_LIMIT_PER_MINUTE", 0),
	}
}

func envBoolDefault(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envIntDefault(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < 0 {
		return 0
	}
	return v
}

func envInt64Default(key string, def int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	if v <= 0 {
		return def
	}
	return v
}

type fixedWindowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	byKey  map[string]windowState
	now    func() time.Time
}

type windowState struct {
	start time.Time
	count int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:  limit,
		window: window,
		byKey:  map[string]windowState{},
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (l *fixedWindowLimiter) Allow(key string) bool {
	if l == nil || l.now == nil {
		return l.AllowAt(key, time.Now().UTC())
	}
	return l.AllowAt(key, l.now())
}

func (l *fixedWindowLimiter) AllowAt(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "anonymous"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	cur := l.byKey[key]
	if cur.start.IsZero() || now.Sub(cur.start) >= l.window {
		l.byKey[key] = windowState{start: now, count: 1}
		return true
	}
	if cur.count >= l.limit {
		return false
	}
	cur.count++
	l.byKey[key] = cur
	return true
}

func rateLimitKey(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth != "" {
		return auth
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func enforceRateLimit(w http.ResponseWriter, r *http.Request, limiter *fixedWindowLimiter) bool {
	if limiter == nil || limiter.limit <= 0 {
		return true
	}
	if limiter.Allow(rateLimitKey(r)) {
		return true
	}
	writeStandardError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded", "rate_limited")
	return false
}

func precheckHostedCommerceRequest(w http.ResponseWriter, r *http.Request, cfg hostedModeConfig, limiter *fixedWindowLimiter) bool {
	if !cfg.EnableHostedCommerce {
		writeStandardError(w, 404, "NOT_FOUND", "not found", "")
		return false
	}
	if !enforceRateLimit(w, r, limiter) {
		return false
	}
	return true
}

func precheckProofExportRequest(w http.ResponseWriter, r *http.Request, cfg hostedModeConfig, limiter *fixedWindowLimiter) bool {
	if !cfg.EnableProofExport {
		writeStandardError(w, 404, "NOT_FOUND", "not found", "")
		return false
	}
	if !enforceRateLimit(w, r, limiter) {
		return false
	}
	return true
}

func precheckProofBundleExportRequest(w http.ResponseWriter, r *http.Request, cfg hostedModeConfig, limiter *fixedWindowLimiter) bool {
	if !cfg.EnableProofBundleExport {
		writeStandardError(w, 404, "NOT_FOUND", "not found", "")
		return false
	}
	if !enforceRateLimit(w, r, limiter) {
		return false
	}
	return true
}

func readJSONWithLimit(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	if maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	if err := httpx.ReadJSON(r, dst); err != nil {
		msg := strings.TrimSpace(err.Error())
		if strings.Contains(strings.ToLower(msg), "request body too large") {
			writeStandardError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body too large", "")
			return false
		}
		writeStandardError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON", "")
		return false
	}
	return true
}

func writeStandardError(w http.ResponseWriter, status int, code, message, reason string) {
	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if strings.TrimSpace(reason) != "" {
		errObj["reason"] = reason
	}
	httpx.WriteJSON(w, status, map[string]any{
		"error":      errObj,
		"request_id": httpx.NewRequestID(),
	})
}

type protocolInfo struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type evidenceInfo struct {
	BundleVersions         []string `json:"bundle_versions"`
	AlwaysPresentArtifacts []string `json:"always_present_artifacts"`
}

type signaturesInfo struct {
	Envelopes  []string `json:"envelopes"`
	Algorithms []string `json:"algorithms"`
}

type featuresInfo struct {
	Webhooks       bool `json:"webhooks"`
	Anchors        bool `json:"anchors"`
	StripeVerifier bool `json:"stripe_verifier"`
	RFC3161        bool `json:"rfc3161"`
	Delegation     bool `json:"delegation"`
}

type endpointCapability struct {
	Hosted   bool   `json:"hosted"`
	Endpoint string `json:"endpoint"`
}

type settlementAttestationsInfo struct {
	ServerDerived bool `json:"server_derived"`
}

type commerceInfo struct {
	IntentV1               endpointCapability         `json:"intent_v1"`
	AcceptV1               endpointCapability         `json:"accept_v1"`
	SettlementAttestations settlementAttestationsInfo `json:"settlement_attestations"`
}

type delegationV1Info struct {
	ServerEnforced          bool `json:"server_enforced"`
	TrustAgentsConfigurable bool `json:"trust_agents_configurable"`
}

type authorizationInfo struct {
	DelegationV1 delegationV1Info `json:"delegation_v1"`
}

type proofExportInfo struct {
	Endpoint string   `json:"endpoint"`
	Formats  []string `json:"formats"`
}

type capabilitiesResponse struct {
	Protocol      protocolInfo      `json:"protocol"`
	Evidence      evidenceInfo      `json:"evidence"`
	Signatures    signaturesInfo    `json:"signatures"`
	Features      featuresInfo      `json:"features"`
	Commerce      commerceInfo      `json:"commerce"`
	Authorization authorizationInfo `json:"authorization"`
	ProofExport   proofExportInfo   `json:"proof_export"`
}

func buildCapabilitiesResponse(cfg hostedModeConfig) capabilitiesResponse {
	intentEndpoint := "/commerce/intents"
	acceptEndpoint := "/commerce/accepts"
	if !cfg.EnableHostedCommerce {
		intentEndpoint = ""
		acceptEndpoint = ""
	}
	proofEndpoint := "/cel/contracts/{id}/proof"
	formats := []string{"json"}
	if !cfg.EnableProofExport {
		proofEndpoint = ""
		formats = []string{}
	}
	return capabilitiesResponse{
		Protocol: protocolInfo{
			Name:     "contractlane",
			Versions: []string{"v1"},
		},
		Evidence: evidenceInfo{
			BundleVersions:         []string{"evidence-v1"},
			AlwaysPresentArtifacts: []string{"anchors", "webhook_receipts"},
		},
		Signatures: signaturesInfo{
			Envelopes:  []string{"sig-v1"},
			Algorithms: []string{"ed25519"},
		},
		Features: featuresInfo{
			Webhooks:       true,
			Anchors:        true,
			StripeVerifier: true,
			RFC3161:        true,
			Delegation:     true,
		},
		Commerce: commerceInfo{
			IntentV1: endpointCapability{
				Hosted:   cfg.EnableHostedCommerce,
				Endpoint: intentEndpoint,
			},
			AcceptV1: endpointCapability{
				Hosted:   cfg.EnableHostedCommerce,
				Endpoint: acceptEndpoint,
			},
			SettlementAttestations: settlementAttestationsInfo{
				ServerDerived: cfg.EnableServerDerivedSettlementAttestations,
			},
		},
		Authorization: authorizationInfo{
			DelegationV1: delegationV1Info{
				ServerEnforced:          cfg.EnableHostedCommerce,
				TrustAgentsConfigurable: cfg.EnableHostedCommerce,
			},
		},
		ProofExport: proofExportInfo{
			Endpoint: proofEndpoint,
			Formats:  formats,
		},
	}
}

func marshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (c capabilitiesResponse) String() string {
	return fmt.Sprintf("capabilities=%s", marshalJSON(c))
}
