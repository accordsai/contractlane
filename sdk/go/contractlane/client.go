package contractlane

import (
	"bytes"
	"context"
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
)

const APIVersion = "v1"

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
	baseURL    string
	httpClient *http.Client
	auth       AuthStrategy
	retry      RetryConfig
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

func WithRetry(cfg RetryConfig) Option {
	return func(c *Client) { c.retry = cfg }
}

func NewClient(baseURL string, auth AuthStrategy, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		auth:       auth,
		retry:      RetryConfig{MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second},
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
	return c
}

func NewIdempotencyKey() string { return newNonce() }

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
