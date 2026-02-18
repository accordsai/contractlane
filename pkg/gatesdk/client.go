package gatesdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Bearer     string
}

func New(baseURL, bearer string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{},
		Bearer:     bearer,
	}
}

type NextStep struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type Subject struct {
	PrincipalID       string `json:"principal_id"`
	ExternalSubjectID string `json:"external_subject_id"`
	ActorID           string `json:"actor_id"`
	ActorType         string `json:"actor_type"`
	Status            string `json:"status"`
}

type StatusResponse struct {
	RequestID         string         `json:"request_id"`
	GateKey           string         `json:"gate_key"`
	Status            string         `json:"status"`
	Reason            string         `json:"reason,omitempty"`
	ExternalSubjectID string         `json:"external_subject_id,omitempty"`
	Subject           *Subject       `json:"subject,omitempty"`
	NextStep          *NextStep      `json:"next_step,omitempty"`
	Remediation       map[string]any `json:"remediation,omitempty"`
	Required          map[string]any `json:"required,omitempty"`
}

type ResolveRequest struct {
	ExternalSubjectID string `json:"external_subject_id"`
	ActorType         string `json:"actor_type,omitempty"`
	IdempotencyKey    string `json:"idempotency_key,omitempty"`
	ClientReturnURL   string `json:"client_return_url,omitempty"`
}

type ResolveResponse struct {
	RequestID         string         `json:"request_id"`
	GateKey           string         `json:"gate_key"`
	Status            string         `json:"status"`
	Reason            string         `json:"reason,omitempty"`
	ExternalSubjectID string         `json:"external_subject_id,omitempty"`
	ContractID        string         `json:"contract_id,omitempty"`
	Subject           *Subject       `json:"subject,omitempty"`
	NextStep          *NextStep      `json:"next_step,omitempty"`
	Remediation       map[string]any `json:"remediation,omitempty"`
}

type EvidenceEnvelope struct {
	RequestID string         `json:"request_id"`
	Evidence  map[string]any `json:"evidence"`
}

func (c *Client) Status(ctx context.Context, gateKey, externalSubjectID, actorType string) (*StatusResponse, error) {
	q := url.Values{}
	q.Set("external_subject_id", externalSubjectID)
	if actorType != "" {
		q.Set("actor_type", actorType)
	}
	u := fmt.Sprintf("%s/cel/gates/%s/status?%s", c.BaseURL, url.PathEscape(gateKey), q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return doJSON[StatusResponse](c, req)
}

func (c *Client) Resolve(ctx context.Context, gateKey string, in ResolveRequest) (*ResolveResponse, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/cel/gates/%s/resolve", c.BaseURL, url.PathEscape(gateKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON[ResolveResponse](c, req)
}

func (c *Client) Evidence(ctx context.Context, gateKey, externalSubjectID string) (*EvidenceEnvelope, error) {
	q := url.Values{}
	q.Set("external_subject_id", externalSubjectID)
	u := fmt.Sprintf("%s/cel/gates/%s/evidence?%s", c.BaseURL, url.PathEscape(gateKey), q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return doJSON[EvidenceEnvelope](c, req)
}

func doJSON[T any](c *Client, req *http.Request) (*T, error) {
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("http %d: %v", resp.StatusCode, errBody)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
