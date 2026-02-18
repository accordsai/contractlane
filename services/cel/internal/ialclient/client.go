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
	ActorID         string            `json:"actor_id"`
	PrincipalID     string            `json:"principal_id"`
	AutomationLevel string            `json:"automation_level"`
	ActionGates     map[string]string `json:"action_gates"`
	VariableRules   []map[string]any  `json:"variable_rules"`
}

type Actor struct {
	ActorID     string   `json:"actor_id"`
	PrincipalID string   `json:"principal_id"`
	ActorType   string   `json:"actor_type"`
	Status      string   `json:"status"`
	Email       *string  `json:"email,omitempty"`
	Name        *string  `json:"name,omitempty"`
	Roles       []string `json:"roles"`
}

type Subject struct {
	PrincipalID       string `json:"principal_id"`
	ExternalSubjectID string `json:"external_subject_id"`
	ActorID           string `json:"actor_id"`
	ActorType         string `json:"actor_type"`
	Status            string `json:"status"`
}

func (c *Client) GetPolicyProfile(actorID string) (*PolicyProfile, error) {
	resp, err := c.HTTP.Get(fmt.Sprintf("%s/actors/%s/policy-profile", c.BaseURL, actorID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		PolicyProfile PolicyProfile `json:"policy_profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out.PolicyProfile, nil
}

func (c *Client) VerifySignature(principalID, actorID, authorization string) (bool, error) {
	body := map[string]any{"principal_id": principalID, "actor_id": actorID, "signature_type": "WEBAUTHN_ASSERTION"}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/verify-signature", bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Valid, nil
}

func (c *Client) ListActors(principalID string, actorType string) ([]Actor, error) {
	url := fmt.Sprintf("%s/actors?principal_id=%s", c.BaseURL, principalID)
	if actorType != "" {
		url = fmt.Sprintf("%s&type=%s", url, actorType)
	}
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		Actors []Actor `json:"actors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Actors, nil
}

func (c *Client) ResolveSubject(principalID, externalSubjectID string, actorTypeIfNeeded *string) (*Subject, error) {
	body := map[string]any{
		"principal_id":        principalID,
		"external_subject_id": externalSubjectID,
	}
	if actorTypeIfNeeded != nil {
		body["actor_type_if_needed"] = *actorTypeIfNeeded
	}
	b, _ := json.Marshal(body)
	resp, err := c.HTTP.Post(c.BaseURL+"/subjects:resolve", "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ial returned %d", resp.StatusCode)
	}
	var out struct {
		Subject Subject `json:"subject"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out.Subject, nil
}
