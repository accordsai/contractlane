package rfc3161

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildTimeStampRequestFromHashHex(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	req, err := BuildTimeStampRequestFromHashHex("sha256:"+digest, "1.2.3.4")
	if err != nil {
		t.Fatalf("BuildTimeStampRequestFromHashHex error: %v", err)
	}
	if len(req) == 0 {
		t.Fatalf("expected non-empty DER request")
	}
}

func TestRequestTimestampToken(t *testing.T) {
	fixedToken := []byte{0x30, 0x03, 0x01, 0x01, 0xff}
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST")
		}
		if got := r.Header.Get("Content-Type"); got != "application/timestamp-query" {
			t.Fatalf("unexpected content type %q", got)
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(fixedToken)
	}))
	defer tsa.Close()

	c := NewClient(tsa.Client())
	req, err := BuildTimeStampRequest(mustDecodeHex(t, strings.Repeat("ab", 32)), "")
	if err != nil {
		t.Fatalf("build request error: %v", err)
	}
	token, contentType, err := c.RequestTimestampToken(context.Background(), tsa.URL, req)
	if err != nil {
		t.Fatalf("RequestTimestampToken error: %v", err)
	}
	if contentType != "application/timestamp-reply" {
		t.Fatalf("unexpected content-type %q", contentType)
	}
	if !strings.EqualFold(hex.EncodeToString(token), hex.EncodeToString(fixedToken)) {
		t.Fatalf("token mismatch")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
