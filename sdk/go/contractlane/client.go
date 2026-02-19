package contractlane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"contractlane/pkg/evidencehash"
)

const APIVersion = "v1"

var ErrIncompatibleNode = errors.New("incompatible contractlane node")

type RetryConfig struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

type Error struct {
	StatusCode int
	ErrorCode  string
	Message    string
	RequestID  string
	Details    map[string]any
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("contractlane sdk error: status=%d code=%s message=%s", e.StatusCode, e.ErrorCode, e.Message)
}

type NextStep struct {
	Type        string         `json:"type,omitempty"`
	ContinueURL string         `json:"continue_url,omitempty"`
	Raw         map[string]any `json:"-"`
}

type GateResult struct {
	Status      string         `json:"status"`
	NextStep    *NextStep      `json:"-"`
	Remediation map[string]any `json:"remediation,omitempty"`
	Raw         map[string]any `json:"-"`
}

type ActionResult struct {
	Result      string         `json:"result"`
	NextStep    *NextStep      `json:"-"`
	Reason      string         `json:"reason,omitempty"`
	ErrorCode   string         `json:"error_code,omitempty"`
	Remediation map[string]any `json:"remediation,omitempty"`
	Raw         map[string]any `json:"-"`
}

type Contract struct {
	ID              string         `json:"id,omitempty"`
	ContractID      string         `json:"contract_id,omitempty"`
	State           string         `json:"state,omitempty"`
	TemplateID      string         `json:"template_id,omitempty"`
	TemplateVersion string         `json:"template_version,omitempty"`
	Raw             map[string]any `json:"-"`
}

type ContractRender struct {
	ContractID         string            `json:"contract_id"`
	PrincipalID        string            `json:"principal_id,omitempty"`
	TemplateID         string            `json:"template_id,omitempty"`
	TemplateVersion    string            `json:"template_version,omitempty"`
	ContractState      string            `json:"contract_state,omitempty"`
	Format             string            `json:"format,omitempty"`
	Locale             string            `json:"locale,omitempty"`
	Rendered           string            `json:"rendered"`
	RenderHash         string            `json:"render_hash"`
	PacketHash         string            `json:"packet_hash,omitempty"`
	VariablesHash      string            `json:"variables_hash"`
	VariablesSnapshot  map[string]string `json:"variables_snapshot,omitempty"`
	DeterminismVersion string            `json:"determinism_version,omitempty"`
	Raw                map[string]any    `json:"-"`
}

type ResolveOptions struct {
	ActorType       string
	IdempotencyKey  string
	ClientReturnURL string
}

type ActorContext struct {
	PrincipalID    string `json:"principal_id"`
	ActorID        string `json:"actor_id"`
	ActorType      string `json:"actor_type"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type ApprovalDecideOptions struct {
	ActorContext      ActorContext
	Decision          string
	SignedPayload     map[string]any
	SignedPayloadHash string
	Signature         map[string]any
	SignatureEnvelope *SignatureEnvelopeV1
}

type ApprovalDecisionResult struct {
	ApprovalRequestID string         `json:"approval_request_id,omitempty"`
	Status            string         `json:"status,omitempty"`
	Raw               map[string]any `json:"-"`
}

type SignatureEnvelopeV1 struct {
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Signature   string `json:"signature"`
	PayloadHash string `json:"payload_hash"`
	IssuedAt    string `json:"issued_at"`
	KeyID       string `json:"key_id,omitempty"`
	Context     string `json:"context,omitempty"`
}

type Capabilities struct {
	Protocol struct {
		Name     string   `json:"name"`
		Versions []string `json:"versions"`
	} `json:"protocol"`
	Evidence struct {
		BundleVersions         []string `json:"bundle_versions"`
		AlwaysPresentArtifacts []string `json:"always_present_artifacts"`
	} `json:"evidence"`
	Signatures struct {
		Envelopes  []string `json:"envelopes"`
		Algorithms []string `json:"algorithms"`
	} `json:"signatures"`
}

type IncompatibleNodeError struct {
	Missing []string
}

func (e *IncompatibleNodeError) Error() string {
	if e == nil || len(e.Missing) == 0 {
		return ErrIncompatibleNode.Error()
	}
	return fmt.Sprintf("%s: missing %s", ErrIncompatibleNode.Error(), strings.Join(e.Missing, ", "))
}

func (e *IncompatibleNodeError) Unwrap() error { return ErrIncompatibleNode }

func SignSigV1Ed25519(payload any, priv ed25519.PrivateKey, issuedAt time.Time, context string) (env SignatureEnvelopeV1, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignatureEnvelopeV1{}, errors.New("ed25519 private key is required")
	}
	issuedAtUTC := issuedAt.UTC()
	if issuedAtUTC.IsZero() {
		return SignatureEnvelopeV1{}, errors.New("issued_at is required")
	}
	payloadHashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		return SignatureEnvelopeV1{}, err
	}
	hashBytes, err := hex.DecodeString(payloadHashHex)
	if err != nil {
		return SignatureEnvelopeV1{}, err
	}
	sig := ed25519.Sign(priv, hashBytes)
	pub := priv.Public().(ed25519.PublicKey)

	env = SignatureEnvelopeV1{
		Version:     "sig-v1",
		Algorithm:   "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		PayloadHash: payloadHashHex,
		IssuedAt:    issuedAtUTC.Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(context) != "" {
		env.Context = strings.TrimSpace(context)
	}
	return env, nil
}

type AuthStrategy interface {
	Apply(req *http.Request, body []byte) error
}

type PrincipalAuth struct{ Token string }

func (a PrincipalAuth) Apply(req *http.Request, _ []byte) error {
	if strings.TrimSpace(a.Token) == "" {
		return errors.New("principal bearer token is required")
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return nil
}

type AgentHMACAuth struct {
	AgentID string
	Secret  string
	Now     func() time.Time
}

func (a AgentHMACAuth) Apply(req *http.Request, body []byte) error {
	if strings.TrimSpace(a.AgentID) == "" || strings.TrimSpace(a.Secret) == "" {
		return errors.New("agent_id and secret are required for hmac auth")
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := newNonce()
	pathWithQuery := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		pathWithQuery += "?" + req.URL.RawQuery
	}
	bodyHash := ""
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(sum[:])
	}
	signingString := strings.ToUpper(req.Method) + "\n" + pathWithQuery + "\n" + ts + "\n" + nonce + "\n" + bodyHash
	mac := hmac.New(sha256.New, []byte(a.Secret))
	_, _ = mac.Write([]byte(signingString))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-CL-Agent-Id", a.AgentID)
	req.Header.Set("X-CL-Timestamp", ts)
	req.Header.Set("X-CL-Nonce", nonce)
	req.Header.Set("X-CL-Signature", signature)
	return nil
}

type Client struct {
	baseURL                string
	httpClient             *http.Client
	auth                   AuthStrategy
	retry                  RetryConfig
	signingKey             ed25519.PrivateKey
	signingKeyID           string
	signingContext         string
	disableCapabilityCheck bool
	caps                   Capabilities
	capsFetchedAt          time.Time
	capsTTL                time.Duration
	now                    func() time.Time
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

func WithRetry(cfg RetryConfig) Option {
	return func(c *Client) { c.retry = cfg }
}

func WithSigningKeyEd25519(priv ed25519.PrivateKey) Option {
	return func(c *Client) { c.signingKey = priv }
}

func WithKeyID(keyID string) Option {
	return func(c *Client) { c.signingKeyID = strings.TrimSpace(keyID) }
}

func WithContext(context string) Option {
	return func(c *Client) { c.signingContext = strings.TrimSpace(context) }
}

func WithDisableCapabilityCheck(disable bool) Option {
	return func(c *Client) { c.disableCapabilityCheck = disable }
}

func NewClient(baseURL string, auth AuthStrategy, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		auth:       auth,
		retry:      RetryConfig{MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second},
		capsTTL:    5 * time.Minute,
		now:        func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.retry.MaxAttempts < 1 {
		c.retry.MaxAttempts = 1
	}
	if c.retry.BaseDelay <= 0 {
		c.retry.BaseDelay = 200 * time.Millisecond
	}
	if c.retry.MaxDelay <= 0 {
		c.retry.MaxDelay = 5 * time.Second
	}
	if strings.TrimSpace(c.signingContext) == "" {
		c.signingContext = "contract-action"
	}
	return c
}

func NewIdempotencyKey() string { return newNonce() }

func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error) {
	if c.hasFreshCapabilities() {
		return c.caps, nil
	}
	raw, err := c.do(ctx, http.MethodGet, "/cel/.well-known/contractlane", nil, nil, true)
	if err != nil {
		return Capabilities{}, err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return Capabilities{}, err
	}
	var caps Capabilities
	if err := json.Unmarshal(b, &caps); err != nil {
		return Capabilities{}, err
	}
	c.caps = caps
	c.capsFetchedAt = c.now().UTC()
	return caps, nil
}

func (c *Client) RequireProtocolV1(ctx context.Context) error {
	caps, err := c.FetchCapabilities(ctx)
	if err != nil {
		return err
	}
	missing := make([]string, 0, 7)
	if caps.Protocol.Name != "contractlane" {
		missing = append(missing, "protocol.name=contractlane")
	}
	if !containsString(caps.Protocol.Versions, "v1") {
		missing = append(missing, "protocol.versions contains v1")
	}
	if !containsString(caps.Evidence.BundleVersions, "evidence-v1") {
		missing = append(missing, "evidence.bundle_versions contains evidence-v1")
	}
	if !containsString(caps.Signatures.Envelopes, "sig-v1") {
		missing = append(missing, "signatures.envelopes contains sig-v1")
	}
	if !containsString(caps.Signatures.Algorithms, "ed25519") {
		missing = append(missing, "signatures.algorithms contains ed25519")
	}
	if !containsString(caps.Evidence.AlwaysPresentArtifacts, "anchors") {
		missing = append(missing, "evidence.always_present_artifacts contains anchors")
	}
	if !containsString(caps.Evidence.AlwaysPresentArtifacts, "webhook_receipts") {
		missing = append(missing, "evidence.always_present_artifacts contains webhook_receipts")
	}
	if len(missing) > 0 {
		return &IncompatibleNodeError{Missing: missing}
	}
	return nil
}

func (c *Client) GateStatus(ctx context.Context, gateKey, externalSubjectID string) (*GateResult, error) {
	v := url.Values{}
	v.Set("external_subject_id", externalSubjectID)
	path := "/cel/gates/" + url.PathEscape(gateKey) + "/status?" + v.Encode()
	payload, err := c.do(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	return parseGateResult(payload), nil
}

func (c *Client) GateResolve(ctx context.Context, gateKey, externalSubjectID string, opts ResolveOptions) (*GateResult, error) {
	if strings.TrimSpace(opts.IdempotencyKey) == "" {
		return nil, errors.New("idempotency key is required for gateResolve")
	}
	body := map[string]any{"external_subject_id": externalSubjectID, "idempotency_key": opts.IdempotencyKey}
	if strings.TrimSpace(opts.ActorType) != "" {
		body["actor_type"] = opts.ActorType
	}
	if strings.TrimSpace(opts.ClientReturnURL) != "" {
		body["client_return_url"] = opts.ClientReturnURL
	}
	path := "/cel/gates/" + url.PathEscape(gateKey) + "/resolve"
	payload, err := c.do(ctx, http.MethodPost, path, body, map[string]string{"Idempotency-Key": opts.IdempotencyKey}, true)
	if err != nil {
		return nil, err
	}
	return parseGateResult(payload), nil
}

func (c *Client) ContractAction(ctx context.Context, contractID, action string, body map[string]any, idempotencyKey string) (*ActionResult, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return nil, errors.New("idempotency key is required for contractAction")
	}
	path := "/cel/contracts/" + url.PathEscape(contractID) + "/actions/" + url.PathEscape(action)
	payload, err := c.do(ctx, http.MethodPost, path, body, map[string]string{"Idempotency-Key": idempotencyKey}, true)
	if err != nil {
		return nil, err
	}
	return parseActionResult(payload), nil
}

func (c *Client) GetContract(ctx context.Context, contractID string) (*Contract, error) {
	path := "/cel/contracts/" + url.PathEscape(contractID)
	payload, err := c.do(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	contractRaw, _ := payload["contract"].(map[string]any)
	if contractRaw == nil {
		contractRaw = payload
	}
	return parseContract(contractRaw), nil
}

func (c *Client) Evidence(ctx context.Context, gateKey, externalSubjectID string) (map[string]any, error) {
	v := url.Values{}
	v.Set("external_subject_id", externalSubjectID)
	path := "/cel/gates/" + url.PathEscape(gateKey) + "/evidence?" + v.Encode()
	payload, err := c.do(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	if ev, ok := payload["evidence"].(map[string]any); ok {
		return ev, nil
	}
	return payload, nil
}

func (c *Client) GetContractEvidence(ctx context.Context, contractID, format string, include []string, redact string) (map[string]any, error) {
	v := url.Values{}
	if strings.TrimSpace(format) != "" {
		v.Set("format", format)
	}
	if len(include) > 0 {
		v.Set("include", strings.Join(include, ","))
	}
	if strings.TrimSpace(redact) != "" {
		v.Set("redact", redact)
	}
	path := "/cel/contracts/" + url.PathEscape(contractID) + "/evidence"
	if enc := v.Encode(); enc != "" {
		path += "?" + enc
	}
	return c.do(ctx, http.MethodGet, path, nil, nil, true)
}

func (c *Client) GetContractRender(ctx context.Context, contractID, format, locale string, includeMeta *bool) (*ContractRender, error) {
	v := url.Values{}
	if strings.TrimSpace(format) != "" {
		v.Set("format", format)
	}
	if strings.TrimSpace(locale) != "" {
		v.Set("locale", locale)
	}
	if includeMeta != nil {
		if *includeMeta {
			v.Set("include_meta", "true")
		} else {
			v.Set("include_meta", "false")
		}
	}
	path := "/cel/contracts/" + url.PathEscape(contractID) + "/render"
	if enc := v.Encode(); enc != "" {
		path += "?" + enc
	}
	payload, err := c.do(ctx, http.MethodGet, path, nil, nil, true)
	if err != nil {
		return nil, err
	}
	return parseContractRender(payload), nil
}

func (c *Client) RenderTemplate(ctx context.Context, templateID, version string, variables map[string]string, format, locale string) (map[string]any, error) {
	path := "/cel/templates/" + url.PathEscape(templateID) + "/versions/" + url.PathEscape(version) + "/render"
	body := map[string]any{"variables": variables}
	if strings.TrimSpace(format) != "" {
		body["format"] = format
	}
	if strings.TrimSpace(locale) != "" {
		body["locale"] = locale
	}
	return c.do(ctx, http.MethodPost, path, body, nil, true)
}

func (c *Client) ApprovalDecide(ctx context.Context, approvalRequestID string, opts ApprovalDecideOptions) (*ApprovalDecisionResult, error) {
	if strings.TrimSpace(approvalRequestID) == "" {
		return nil, errors.New("approval_request_id is required")
	}
	if strings.TrimSpace(opts.Decision) == "" {
		return nil, errors.New("decision is required")
	}
	if opts.SignedPayload == nil {
		opts.SignedPayload = map[string]any{}
	}
	body := map[string]any{
		"actor_context":  opts.ActorContext,
		"decision":       opts.Decision,
		"signed_payload": opts.SignedPayload,
	}
	if strings.TrimSpace(opts.SignedPayloadHash) != "" {
		body["signed_payload_hash"] = opts.SignedPayloadHash
	}

	env := opts.SignatureEnvelope
	if env == nil && len(c.signingKey) == ed25519.PrivateKeySize {
		signed, err := SignSigV1Ed25519(opts.SignedPayload, c.signingKey, c.now().UTC(), c.signingContext)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(c.signingKeyID) != "" {
			signed.KeyID = c.signingKeyID
		}
		env = &signed
	}
	if env != nil {
		if !c.disableCapabilityCheck {
			if err := c.RequireProtocolV1(ctx); err != nil {
				return nil, err
			}
		}
		body["signature_envelope"] = env
	} else {
		legacy := opts.Signature
		if legacy == nil {
			legacy = map[string]any{
				"type":               "WEBAUTHN_ASSERTION",
				"assertion_response": map[string]any{},
			}
		}
		body["signature"] = legacy
	}

	path := "/cel/approvals/" + url.PathEscape(approvalRequestID) + ":decide"
	raw, err := c.do(ctx, http.MethodPost, path, body, nil, true)
	if err != nil {
		return nil, err
	}
	out := &ApprovalDecisionResult{Raw: raw}
	out.ApprovalRequestID, _ = raw["approval_request_id"].(string)
	out.Status, _ = raw["status"].(string)
	return out, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, headers map[string]string, retryable bool) (map[string]any, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = canonicalJSON(body)
		if err != nil {
			return nil, err
		}
	}
	attempts := 1
	if retryable {
		attempts = c.retry.MaxAttempts
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "contractlane-go-sdk/0.1.0 (api:"+APIVersion+")")
		if len(bodyBytes) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if c.auth != nil {
			if err := c.auth.Apply(req, bodyBytes); err != nil {
				return nil, err
			}
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt < attempts {
				sleepWithBackoff(c.retry, attempt, "")
				continue
			}
			return nil, err
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var obj map[string]any
			if len(respBody) == 0 {
				return map[string]any{}, nil
			}
			if err := json.Unmarshal(respBody, &obj); err != nil {
				return nil, err
			}
			return obj, nil
		}
		if shouldRetryStatus(resp.StatusCode) && attempt < attempts {
			sleepWithBackoff(c.retry, attempt, resp.Header.Get("Retry-After"))
			continue
		}
		return nil, parseSDKError(resp.StatusCode, respBody)
	}
	return nil, errors.New("unreachable")
}

func shouldRetryStatus(status int) bool {
	return status == 429 || status == 502 || status == 503 || status == 504
}

func sleepWithBackoff(cfg RetryConfig, attempt int, retryAfter string) {
	if strings.TrimSpace(retryAfter) != "" {
		if sec, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil {
			d := time.Duration(sec) * time.Second
			if d > cfg.MaxDelay {
				d = cfg.MaxDelay
			}
			time.Sleep(d)
			return
		}
	}
	max := float64(cfg.BaseDelay) * math.Pow(2, float64(attempt-1))
	if max > float64(cfg.MaxDelay) {
		max = float64(cfg.MaxDelay)
	}
	n, _ := rand.Int(rand.Reader, bigInt(int64(max)))
	time.Sleep(time.Duration(n.Int64()))
}

func parseSDKError(status int, body []byte) error {
	out := &Error{StatusCode: status}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		out.Message = strings.TrimSpace(string(body))
		if out.Message == "" {
			out.Message = http.StatusText(status)
		}
		return out
	}
	if inner, ok := obj["error"].(map[string]any); ok {
		obj = inner
	}
	out.ErrorCode, _ = obj["error_code"].(string)
	if out.ErrorCode == "" {
		out.ErrorCode, _ = obj["code"].(string)
	}
	out.Message, _ = obj["message"].(string)
	out.RequestID, _ = obj["request_id"].(string)
	if d, ok := obj["details"].(map[string]any); ok {
		out.Details = d
	}
	if out.Message == "" {
		out.Message = http.StatusText(status)
	}
	return out
}

func (c *Client) hasFreshCapabilities() bool {
	if c.capsFetchedAt.IsZero() || c.capsTTL <= 0 {
		return false
	}
	if strings.TrimSpace(c.caps.Protocol.Name) == "" {
		return false
	}
	return c.now().UTC().Before(c.capsFetchedAt.Add(c.capsTTL))
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func parseGateResult(raw map[string]any) *GateResult {
	r := &GateResult{Raw: raw}
	r.Status, _ = raw["status"].(string)
	if rem, ok := raw["remediation"].(map[string]any); ok {
		r.Remediation = rem
	}
	r.NextStep = parseNextStep(raw)
	return r
}

func parseActionResult(raw map[string]any) *ActionResult {
	r := &ActionResult{Raw: raw}
	r.Result, _ = raw["result"].(string)
	if r.Result == "" {
		r.Result, _ = raw["status"].(string)
	}
	r.Reason, _ = raw["reason"].(string)
	r.ErrorCode, _ = raw["error_code"].(string)
	if rem, ok := raw["remediation"].(map[string]any); ok {
		r.Remediation = rem
	}
	r.NextStep = parseNextStep(raw)
	return r
}

func parseNextStep(raw map[string]any) *NextStep {
	nsRaw, _ := raw["next_step"].(map[string]any)
	if nsRaw == nil {
		if rem, ok := raw["remediation"].(map[string]any); ok {
			nsRaw = rem
		}
	}
	if nsRaw == nil {
		return nil
	}
	ns := &NextStep{Raw: nsRaw}
	ns.Type, _ = nsRaw["type"].(string)
	ns.ContinueURL, _ = nsRaw["continue_url"].(string)
	return ns
}

func parseContract(raw map[string]any) *Contract {
	c := &Contract{Raw: raw}
	c.ContractID, _ = raw["contract_id"].(string)
	c.ID, _ = raw["id"].(string)
	if c.ID == "" {
		c.ID = c.ContractID
	}
	c.State, _ = raw["state"].(string)
	c.TemplateID, _ = raw["template_id"].(string)
	c.TemplateVersion, _ = raw["template_version"].(string)
	return c
}

func parseContractRender(raw map[string]any) *ContractRender {
	cr := &ContractRender{Raw: raw}
	cr.ContractID, _ = raw["contract_id"].(string)
	cr.PrincipalID, _ = raw["principal_id"].(string)
	cr.TemplateID, _ = raw["template_id"].(string)
	cr.TemplateVersion, _ = raw["template_version"].(string)
	cr.ContractState, _ = raw["contract_state"].(string)
	cr.Format, _ = raw["format"].(string)
	cr.Locale, _ = raw["locale"].(string)
	cr.Rendered, _ = raw["rendered"].(string)
	cr.RenderHash, _ = raw["render_hash"].(string)
	cr.PacketHash, _ = raw["packet_hash"].(string)
	cr.VariablesHash, _ = raw["variables_hash"].(string)
	cr.DeterminismVersion, _ = raw["determinism_version"].(string)
	if s, ok := raw["variables_snapshot"].(map[string]any); ok {
		cr.VariablesSnapshot = map[string]string{}
		for k, v := range s {
			if sv, ok := v.(string); ok {
				cr.VariablesSnapshot[k] = sv
			}
		}
	}
	return cr
}

func canonicalJSON(v any) ([]byte, error) {
	norm := normalize(v)
	buf := &bytes.Buffer{}
	if err := encodeCanonical(buf, norm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range t {
			out[k] = normalize(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = normalize(t[i])
		}
		return out
	default:
		return t
	}
}

func encodeCanonical(w io.Writer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		_, _ = w.Write([]byte("{"))
		for i, k := range keys {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			kb, _ := json.Marshal(k)
			_, _ = w.Write(kb)
			_, _ = w.Write([]byte(":"))
			if err := encodeCanonical(w, t[k]); err != nil {
				return err
			}
		}
		_, _ = w.Write([]byte("}"))
		return nil
	case []any:
		_, _ = w.Write([]byte("["))
		for i, vv := range t {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			if err := encodeCanonical(w, vv); err != nil {
				return err
			}
		}
		_, _ = w.Write([]byte("]"))
		return nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		_, _ = w.Write(b)
		return nil
	}
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func bigInt(v int64) *big.Int {
	if v <= 1 {
		v = 1
	}
	return big.NewInt(v)
}
