package main

import (
	"net/http"
	"testing"
)

func TestParseBearer(t *testing.T) {
	tok, ok := parseBearer("Bearer abc123")
	if !ok || tok != "abc123" {
		t.Fatalf("expected parsed bearer token, got ok=%v token=%q", ok, tok)
	}

	_, ok = parseBearer("abc123")
	if ok {
		t.Fatal("expected parse failure without Bearer prefix")
	}
}

func TestMaskEmail(t *testing.T) {
	got := maskEmail("Owner@Test.com")
	if got != "ow***@test.com" {
		t.Fatalf("unexpected masked email: %s", got)
	}
}

func TestRandomVerificationCode(t *testing.T) {
	code := randomVerificationCode()
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Fatalf("expected numeric code, got %q", code)
		}
	}
}

func TestIsAllowedSignupEmail(t *testing.T) {
	cfg := publicSignupConfig{
		AllowedEmailDomains: map[string]struct{}{"example.com": {}},
		DeniedEmailDomains:  map[string]struct{}{"blocked.com": {}},
	}
	if !isAllowedSignupEmail("a@example.com", cfg) {
		t.Fatal("expected allowed email")
	}
	if isAllowedSignupEmail("a@blocked.com", cfg) {
		t.Fatal("expected denied domain to be blocked")
	}
	if isAllowedSignupEmail("a@other.com", cfg) {
		t.Fatal("expected non-allowlisted domain to be blocked")
	}
}

func TestClientIPFromRequestFallback(t *testing.T) {
	req := testReq("203.0.113.10:12345", "")
	if got := clientIPFromRequest(req); got != "203.0.113.10" {
		t.Fatalf("unexpected ip: %s", got)
	}

	req2 := testReq("203.0.113.10:12345", "198.51.100.5, 198.51.100.8")
	if got := clientIPFromRequest(req2); got != "198.51.100.5" {
		t.Fatalf("unexpected xff ip: %s", got)
	}
}

func testReq(remoteAddr, xff string) *http.Request {
	req, _ := http.NewRequest("GET", "http://example.test", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}
