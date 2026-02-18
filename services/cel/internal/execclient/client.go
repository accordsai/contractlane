package execclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{}}
}

type SendForSignatureRequest struct {
	ActorContext struct {
		PrincipalID string `json:"principal_id"`
		ActorID     string `json:"actor_id"`
		ActorType   string `json:"actor_type"`
	} `json:"actor_context"`
	TemplateID   string `json:"template_id"`
	Counterparty struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"counterparty"`
}

type SendForSignatureResponse struct {
	Provider   string           `json:"provider"`
	EnvelopeID string           `json:"envelope_id"`
	Status     string           `json:"status"`
	SigningURL string           `json:"signing_url"`
	Recipients []map[string]any `json:"recipients"`
}

func (c *Client) SendForSignature(ctx context.Context, contractID string, req SendForSignatureRequest, authorization string) (*SendForSignatureResponse, error) {
	b, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/contracts/%s/sendForSignature", c.BaseURL, contractID), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	if authorization != "" {
		httpReq.Header.Set("Authorization", authorization)
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return nil, fmt.Errorf("execution returned %d", resp.StatusCode)
	}
	var out struct {
		Provider   string           `json:"provider"`
		EnvelopeID string           `json:"envelope_id"`
		Status     string           `json:"status"`
		SigningURL string           `json:"signing_url"`
		Recipients []map[string]any `json:"recipients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &SendForSignatureResponse{
		Provider:   out.Provider,
		EnvelopeID: out.EnvelopeID,
		Status:     out.Status,
		SigningURL: out.SigningURL,
		Recipients: out.Recipients,
	}, nil
}
