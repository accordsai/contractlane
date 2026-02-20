package ialclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

type Principal struct {
	PrincipalID string `json:"principal_id"`
}

type Agent struct {
	ActorID     string `json:"actor_id"`
	PrincipalID string `json:"principal_id"`
}

type AgentCredentials struct {
	Token string `json:"token"`
}

func (c *Client) CreatePrincipal(name, jurisdiction, timezone string) (*Principal, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"name":         name,
		"jurisdiction": jurisdiction,
		"timezone":     timezone,
	})
	resp, err := c.HTTP.Post(c.BaseURL+"/principals", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		Principal Principal `json:"principal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out.Principal, nil
}

func (c *Client) CreateAgent(principalID, name string, scopes []string) (*Agent, *AgentCredentials, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"principal_id": principalID,
		"name":         name,
		"auth": map[string]any{
			"mode":   "HMAC",
			"scopes": scopes,
		},
	})
	resp, err := c.HTTP.Post(c.BaseURL+"/actors/agents", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		Agent       Agent            `json:"agent"`
		Credentials AgentCredentials `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, err
	}
	return &out.Agent, &out.Credentials, nil
}
