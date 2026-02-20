package contractlane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	signaturev1 "contractlane/pkg/signature"
)

func TestAgentID_GenerateAndParse_RoundTrip(t *testing.T) {
	pub := make([]byte, 32)
	_, err := rand.Read(pub)
	if err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	id, err := AgentIDFromEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey: %v", err)
	}
	if !strings.HasPrefix(id, "agent:pk:ed25519:") {
		t.Fatalf("unexpected prefix: %s", id)
	}
	algo, parsed, err := ParseAgentID(id)
	if err != nil {
		t.Fatalf("ParseAgentID: %v", err)
	}
	if algo != "ed25519" {
		t.Fatalf("unexpected algo: %s", algo)
	}
	if string(parsed) != string(pub) {
		t.Fatalf("parsed pubkey mismatch")
	}
	if !IsValidAgentID(id) {
		t.Fatalf("expected IsValidAgentID true")
	}
}

func TestAgentID_ParseRejects_InvalidPrefix(t *testing.T) {
	_, _, err := ParseAgentID("agent:xx:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestAgentID_ParseRejects_UnknownAlgo(t *testing.T) {
	_, _, err := ParseAgentID("agent:pk:rsa:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestAgentID_ParseRejects_PaddedBase64(t *testing.T) {
	_, _, err := ParseAgentID("agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestAgentID_ParseRejects_WrongLength(t *testing.T) {
	pub31 := make([]byte, 31)
	pub33 := make([]byte, 33)
	id31 := "agent:pk:ed25519:" + base64.RawURLEncoding.EncodeToString(pub31)
	id33 := "agent:pk:ed25519:" + base64.RawURLEncoding.EncodeToString(pub33)

	if _, _, err := ParseAgentID(id31); err == nil {
		t.Fatal("expected 31-byte parse failure")
	}
	if _, _, err := ParseAgentID(id33); err == nil {
		t.Fatal("expected 33-byte parse failure")
	}
}

func TestAgentID_ParseRejects_InvalidBase64Chars(t *testing.T) {
	_, _, err := ParseAgentID("agent:pk:ed25519:AAECAwQF$gcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestAgentID_GenerateRejects_WrongLength(t *testing.T) {
	if _, err := AgentIDFromEd25519PublicKey(make([]byte, 31)); err == nil {
		t.Fatal("expected error for 31-byte key")
	}
	if _, err := AgentIDFromEd25519PublicKey(make([]byte, 33)); err == nil {
		t.Fatal("expected error for 33-byte key")
	}
}

func TestAgentID_ConformanceVector(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	fixturePath := filepath.Join(root, "conformance", "cases", "agent_id_v1_roundtrip.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("ReadFile fixture: %v", err)
	}
	var fx struct {
		PublicKeyHex string   `json:"public_key_hex"`
		ExpectedID   string   `json:"expected_agent_id"`
		Invalid      []string `json:"invalid_agent_ids"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("Unmarshal fixture: %v", err)
	}
	pub, err := hex.DecodeString(fx.PublicKeyHex)
	if err != nil {
		t.Fatalf("DecodeString public_key_hex: %v", err)
	}
	id, err := AgentIDFromEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("AgentIDFromEd25519PublicKey: %v", err)
	}
	if id != fx.ExpectedID {
		t.Fatalf("expected %s, got %s", fx.ExpectedID, id)
	}
	algo, parsed, err := ParseAgentID(fx.ExpectedID)
	if err != nil {
		t.Fatalf("ParseAgentID expected_id: %v", err)
	}
	if algo != "ed25519" || string(parsed) != string(pub) {
		t.Fatalf("roundtrip mismatch")
	}
	if !IsValidAgentID(fx.ExpectedID) {
		t.Fatalf("expected id to be valid")
	}
	for _, bad := range fx.Invalid {
		if IsValidAgentID(bad) {
			t.Fatalf("expected invalid agent id to fail: %s", bad)
		}
	}
}

func TestGateResolveRequiresIdempotency(t *testing.T) {
	c := NewClient("http://example.com", PrincipalAuth{Token: "t"})
	_, err := c.GateResolve(context.Background(), "terms_current", "ext_1", ResolveOptions{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestSDKConformanceCases(t *testing.T) {
	var attempt429 int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "sub_done":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "sub_blocked":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "BLOCKED", "next_step": map[string]any{"type": "SIGN", "continue_url": "https://example/sign"}})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "retry429":
			if attempt429 == 0 {
				attempt429++
				w.WriteHeader(429)
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": "RATE_LIMIT", "message": "try later"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})
		case r.URL.Path == "/cel/gates/terms_current/status" && r.URL.Query().Get("external_subject_id") == "unauth":
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_code": "UNAUTHORIZED", "message": "bad token", "request_id": "req_1"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"})
	if _, err := c.GateStatus(context.Background(), "terms_current", "sub_done"); err != nil {
		t.Fatalf("done: %v", err)
	}
	blocked, err := c.GateStatus(context.Background(), "terms_current", "sub_blocked")
	if err != nil || blocked.Status != "BLOCKED" || blocked.NextStep == nil || blocked.NextStep.ContinueURL == "" {
		t.Fatalf("blocked mismatch err=%v blocked=%+v", err, blocked)
	}
	if _, err := c.GateStatus(context.Background(), "terms_current", "retry429"); err != nil {
		t.Fatalf("retry mismatch: %v", err)
	}
	if _, err := c.GateStatus(context.Background(), "terms_current", "unauth"); err == nil {
		t.Fatalf("expected 401 sdk error")
	}
}

func TestCreateContract_RequestAndResponse(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"contract": map[string]any{
				"contract_id": "ctr_123",
				"state":       "DRAFT_CREATED",
				"template_id": "tpl_1",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"})
	resp, err := c.CreateContract(context.Background(), CreateContractRequest{
		ActorContext: ActorContext{
			PrincipalID: "prn_1",
			ActorID:     "act_1",
			ActorType:   "AGENT",
		},
		TemplateID: "tpl_1",
		Counterparty: CreateContractCounterparty{
			Name:  "Buyer",
			Email: "buyer@example.com",
		},
		InitialVariables: map[string]string{"price": "10"},
	})
	if err != nil {
		t.Fatalf("CreateContract: %v", err)
	}
	if gotPath != "/cel/contracts" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotBody["template_id"] != "tpl_1" {
		t.Fatalf("unexpected template_id: %#v", gotBody["template_id"])
	}
	ac, _ := gotBody["actor_context"].(map[string]any)
	if ac == nil || ac["principal_id"] != "prn_1" || ac["actor_id"] != "act_1" || ac["actor_type"] != "AGENT" {
		t.Fatalf("unexpected actor_context: %#v", gotBody["actor_context"])
	}
	if resp == nil || resp.Contract == nil || resp.Contract.ContractID != "ctr_123" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestCreateContract_ErrorMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    "BAD_REQUEST",
				"message": "template missing",
			},
			"request_id": "req_123",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"})
	_, err := c.CreateContract(context.Background(), CreateContractRequest{
		ActorContext: ActorContext{PrincipalID: "prn_1", ActorID: "act_1", ActorType: "AGENT"},
		TemplateID:   "",
		Counterparty: CreateContractCounterparty{Name: "Buyer", Email: "buyer@example.com"},
	})
	if err == nil {
		t.Fatalf("expected sdk error")
	}
	sdkErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if sdkErr.StatusCode != 400 || sdkErr.ErrorCode != "BAD_REQUEST" || sdkErr.Message != "template missing" {
		t.Fatalf("unexpected error mapping: %#v", sdkErr)
	}
}

func TestConformanceCasesExist(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	cases := []string{
		"conformance/cases/well_known_protocol_capabilities.json",
		"conformance/cases/gate_status_done.json",
		"conformance/cases/gate_status_blocked.json",
		"conformance/cases/gate_resolve_requires_idempotency.json",
		"conformance/cases/error_model_401.json",
		"conformance/cases/retry_429_then_success.json",
		"conformance/cases/sig_v1_approval_happy_path.json",
		"conformance/cases/evidence_contains_anchors_and_receipts.json",
		"conformance/cases/evp_verify_bundle_good.json",
		"conformance/cases/agent_id_v1_roundtrip.json",
	}
	for _, c := range cases {
		if strings.TrimSpace(c) == "" {
			t.Fatal("invalid case path")
		}
		if _, err := os.Stat(filepath.Join(root, c)); err != nil {
			t.Fatalf("missing conformance case %s: %v", c, err)
		}
	}
}

func TestSignSigV1Ed25519_ProducesVerifiableEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = pub
	payload := map[string]any{
		"contract_id":         "ctr_1",
		"approval_request_id": "aprq_1",
		"nonce":               "n1",
	}
	issuedAt := time.Now().UTC()
	env, err := SignSigV1Ed25519(payload, priv, issuedAt, "contract-action")
	if err != nil {
		t.Fatalf("SignSigV1Ed25519: %v", err)
	}
	if env.Version != "sig-v1" || env.Algorithm != "ed25519" {
		t.Fatalf("unexpected envelope version/algorithm: %+v", env)
	}
	if env.IssuedAt == "" || !strings.HasSuffix(env.IssuedAt, "Z") {
		t.Fatalf("expected RFC3339Nano UTC issued_at, got %q", env.IssuedAt)
	}

	_, err = signaturev1.VerifyEnvelopeV1(payload, signaturev1.EnvelopeV1{
		Version:     env.Version,
		Algorithm:   env.Algorithm,
		PublicKey:   env.PublicKey,
		Signature:   env.Signature,
		PayloadHash: env.PayloadHash,
		IssuedAt:    env.IssuedAt,
		Context:     env.Context,
	})
	if err != nil {
		t.Fatalf("expected signature envelope to verify, got err=%v", err)
	}
}

func TestApprovalDecide_UsesSigV1ByDefaultWithEd25519Key(t *testing.T) {
	var gotBody map[string]any
	var capabilityHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cel/.well-known/contractlane":
			capabilityHits++
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{
				"protocol":{"name":"contractlane","versions":["v1"]},
				"evidence":{"bundle_versions":["evidence-v1"],"always_present_artifacts":["anchors","webhook_receipts"]},
				"signatures":{"envelopes":["sig-v1"],"algorithms":["ed25519"]}
			}`))
		case strings.HasPrefix(r.URL.Path, "/cel/approvals/") && strings.HasSuffix(r.URL.Path, ":decide"):
			defer r.Body.Close()
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"approval_request_id": "aprq_1", "status": "APPROVED"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"}, WithSigningKeyEd25519(priv), WithKeyID("kid_1"), WithContext("contract-action"))
	c.now = func() time.Time { return time.Date(2026, 2, 18, 12, 0, 0, 0, time.UTC) }

	_, err = c.ApprovalDecide(context.Background(), "aprq_1", ApprovalDecideOptions{
		ActorContext: ActorContext{PrincipalID: "prn_1", ActorID: "act_1", ActorType: "HUMAN"},
		Decision:     "APPROVE",
		SignedPayload: map[string]any{
			"contract_id":         "ctr_1",
			"approval_request_id": "aprq_1",
			"nonce":               "n1",
		},
	})
	if err != nil {
		t.Fatalf("ApprovalDecide: %v", err)
	}
	if _, ok := gotBody["signature_envelope"]; !ok {
		t.Fatalf("expected signature_envelope in request body")
	}
	if _, ok := gotBody["signature"]; ok {
		t.Fatalf("did not expect legacy signature field when signing key configured")
	}
	if capabilityHits != 1 {
		t.Fatalf("expected one capability probe before sig-v1 approval, got %d", capabilityHits)
	}
}

func TestApprovalDecide_LegacyFallbackWithoutSigningKey(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"approval_request_id": "aprq_1", "status": "APPROVED"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"})
	_, err := c.ApprovalDecide(context.Background(), "aprq_1", ApprovalDecideOptions{
		ActorContext: ActorContext{PrincipalID: "prn_1", ActorID: "act_1", ActorType: "HUMAN"},
		Decision:     "APPROVE",
		SignedPayload: map[string]any{
			"contract_id":         "ctr_1",
			"approval_request_id": "aprq_1",
			"nonce":               "n1",
		},
		Signature: map[string]any{"type": "WEBAUTHN_ASSERTION", "assertion_response": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("ApprovalDecide: %v", err)
	}
	if _, ok := gotBody["signature"]; !ok {
		t.Fatalf("expected legacy signature field in request body")
	}
	if _, ok := gotBody["signature_envelope"]; ok {
		t.Fatalf("did not expect signature_envelope without signing key")
	}
}

func TestRequireProtocolV1_PassesForCompatibleNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cel/.well-known/contractlane" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"protocol":{"name":"contractlane","versions":["v1"]},
			"evidence":{"bundle_versions":["evidence-v1"],"always_present_artifacts":["anchors","webhook_receipts"]},
			"signatures":{"envelopes":["sig-v1"],"algorithms":["ed25519"]}
		}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	if err := c.RequireProtocolV1(context.Background()); err != nil {
		t.Fatalf("RequireProtocolV1 unexpected error: %v", err)
	}
}

func TestRequireProtocolV1_FailsWhenSigV1Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cel/.well-known/contractlane" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"protocol":{"name":"contractlane","versions":["v1"]},
			"evidence":{"bundle_versions":["evidence-v1"],"always_present_artifacts":["anchors","webhook_receipts"]},
			"signatures":{"envelopes":[],"algorithms":["ed25519"]}
		}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	err := c.RequireProtocolV1(context.Background())
	if err == nil {
		t.Fatal("expected compatibility error")
	}
	if !errors.Is(err, ErrIncompatibleNode) {
		t.Fatalf("expected ErrIncompatibleNode, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sig-v1") {
		t.Fatalf("expected error to mention sig-v1, got: %v", err)
	}
}

func TestFetchCapabilities_UsesCacheWithinTTL(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cel/.well-known/contractlane" {
			w.WriteHeader(404)
			return
		}
		hits++
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
			"protocol":{"name":"contractlane","versions":["v1"]},
			"evidence":{"bundle_versions":["evidence-v1"],"always_present_artifacts":["anchors","webhook_receipts"]},
			"signatures":{"envelopes":["sig-v1"],"algorithms":["ed25519"]}
		}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	if _, err := c.FetchCapabilities(context.Background()); err != nil {
		t.Fatalf("FetchCapabilities first call: %v", err)
	}
	if _, err := c.FetchCapabilities(context.Background()); err != nil {
		t.Fatalf("FetchCapabilities second call: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected one HTTP fetch due to cache, got %d", hits)
	}
}

func TestApprovalDecide_DisableCapabilityCheckSkipsFetch(t *testing.T) {
	wellKnownHits := 0
	var decideHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cel/.well-known/contractlane":
			wellKnownHits++
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{
				"protocol":{"name":"contractlane","versions":["v1"]},
				"evidence":{"bundle_versions":["evidence-v1"],"always_present_artifacts":["anchors","webhook_receipts"]},
				"signatures":{"envelopes":["sig-v1"],"algorithms":["ed25519"]}
			}`))
			return
		case strings.HasPrefix(r.URL.Path, "/cel/approvals/") && strings.HasSuffix(r.URL.Path, ":decide"):
			decideHits++
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"approval_request_id": "aprq_1", "status": "APPROVED"})
			return
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := NewClient(srv.URL, PrincipalAuth{Token: "tok"}, WithSigningKeyEd25519(priv), WithDisableCapabilityCheck(true))
	c.now = func() time.Time { return time.Date(2026, 2, 18, 12, 0, 0, 0, time.UTC) }

	_, err = c.ApprovalDecide(context.Background(), "aprq_1", ApprovalDecideOptions{
		ActorContext: ActorContext{PrincipalID: "prn_1", ActorID: "act_1", ActorType: "HUMAN"},
		Decision:     "APPROVE",
		SignedPayload: map[string]any{
			"contract_id":         "ctr_1",
			"approval_request_id": "aprq_1",
			"nonce":               "n1",
		},
	})
	if err != nil {
		t.Fatalf("ApprovalDecide: %v", err)
	}
	if wellKnownHits != 0 {
		t.Fatalf("expected capability fetch to be skipped, got %d hits", wellKnownHits)
	}
	if decideHits != 1 {
		t.Fatalf("expected approval decide request to be sent once, got %d", decideHits)
	}
}
