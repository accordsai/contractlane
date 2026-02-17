package ialclient

import (
	"bytes"
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

type PolicyProfile struct {
	ActorID         string                 `json:"actor_id"`
	PrincipalID     string                 `json:"principal_id"`
	AutomationLevel string                 `json:"automation_level"`
	ActionGates     map[string]string      `json:"action_gates"`
	VariableRules   []map[string]any       `json:"variable_rules"`
}

func (c *Client) GetPolicyProfile(actorID string) (*PolicyProfile, error) {
	resp, err := c.HTTP.Get(fmt.Sprintf("%s/actors/%s/policy-profile", c.BaseURL, actorID))
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct{
		PolicyProfile PolicyProfile `json:"policy_profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return nil, err }
	return &out.PolicyProfile, nil
}

func (c *Client) VerifySignature(principalID, actorID string) (bool, error) {
	body := map[string]any{"principal_id": principalID, "actor_id": actorID, "signature_type":"WEBAUTHN_ASSERTION"}
	b, _ := json.Marshal(body)
	resp, err := c.HTTP.Post(c.BaseURL+"/verify-signature", "application/json", bytes.NewReader(b))
	if err != nil { return false, err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { return false, fmt.Errorf("ial returned %d", resp.StatusCode) }
	var out struct{ Valid bool `json:"valid"` }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return false, err }
	return out.Valid, nil
}
