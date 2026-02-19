package webhooks

import (
	"net/http"
	"testing"
)

func TestCanonicalizeHeaders_DeterministicAcrossCalls(t *testing.T) {
	h := http.Header{
		"X-Z":          {"  b ", "a"},
		"Content-TYpe": {"application/json"},
		"X-A":          {"  z", "y  "},
	}
	first, _, err := CanonicalizeHeaders(h)
	if err != nil {
		t.Fatalf("CanonicalizeHeaders err: %v", err)
	}
	for i := 0; i < 20; i++ {
		got, _, err := CanonicalizeHeaders(h)
		if err != nil {
			t.Fatalf("CanonicalizeHeaders err: %v", err)
		}
		if string(got) != string(first) {
			t.Fatalf("non-deterministic output:\nfirst=%s\ngot=%s", string(first), string(got))
		}
	}
}

func TestCanonicalizeHeaders_SortsKeysAndValues_AndLowercases(t *testing.T) {
	h := http.Header{
		" X-Test ": {" b ", "a", "  "},
		"X-a":      {"2", "1"},
		"":         {"ignored"},
	}
	gotJSON, gotMap, err := CanonicalizeHeaders(h)
	if err != nil {
		t.Fatalf("CanonicalizeHeaders err: %v", err)
	}
	wantJSON := `{"x-a":["1","2"],"x-test":["","a","b"]}`
	if string(gotJSON) != wantJSON {
		t.Fatalf("unexpected canonical JSON:\nwant=%s\ngot=%s", wantJSON, string(gotJSON))
	}
	if len(gotMap) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(gotMap))
	}
	if gotMap["x-test"][0] != "" || gotMap["x-test"][1] != "a" || gotMap["x-test"][2] != "b" {
		t.Fatalf("unexpected x-test values: %#v", gotMap["x-test"])
	}
}

func TestComputeWebhookHashes_StableAndSensitive(t *testing.T) {
	method := "POST"
	path := "/hooks"
	headers := []byte(`{"x-test":["a","b"]}`)
	body := []byte("hello")

	raw1, headers1, req1 := ComputeWebhookHashes(method, path, headers, body)
	raw2, headers2, req2 := ComputeWebhookHashes(method, path, headers, body)
	if raw1 != raw2 || headers1 != headers2 || req1 != req2 {
		t.Fatalf("hashes not stable across calls")
	}

	if raw1 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("unexpected rawBodySHA: %s", raw1)
	}
	if headers1 != "3172d49fed2ee33feac4cbd223958c647dacea9ce3abd1daeb20d29929c345da" {
		t.Fatalf("unexpected headersSHA: %s", headers1)
	}
	if req1 != "c6e7cb718482c348c92152f81256f7116b292dea81bc4d72081b0fce84c8175d" {
		t.Fatalf("unexpected requestSHA: %s", req1)
	}

	_, _, reqMethod := ComputeWebhookHashes("GET", path, headers, body)
	_, _, reqPath := ComputeWebhookHashes(method, "/other", headers, body)
	_, _, reqHeaders := ComputeWebhookHashes(method, path, []byte(`{"x-test":["a","c"]}`), body)
	_, _, reqBody := ComputeWebhookHashes(method, path, headers, []byte("hello!"))
	if reqMethod == req1 || reqPath == req1 || reqHeaders == req1 || reqBody == req1 {
		t.Fatalf("expected request hash to change with method/path/headers/body changes")
	}
}
