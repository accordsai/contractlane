package evp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyBundleJSON_Good(t *testing.T) {
	b := loadFixture(t, "bundle.good.json")
	res, err := VerifyBundleJSON(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("expected %s, got %s details=%v", StatusVerified, res.Status, res.Details)
	}
}

func TestVerifyBundleJSON_GoodWithWebhooks(t *testing.T) {
	b := loadFixture(t, "bundle.good.with_webhooks.json")
	res, err := VerifyBundleJSON(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("expected %s, got %s details=%v", StatusVerified, res.Status, res.Details)
	}
}

func TestVerifyBundleJSON_InvalidArtifactHash(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		artifacts := root["artifacts"].(map[string]any)
		render := artifacts["render"].(map[string]any)
		render["rendered"] = "tampered terms"
		artifacts["render"] = render
		root["artifacts"] = artifacts
	})
	assertStatus(t, b, StatusInvalidArtifactHash)
}

func TestVerifyBundleJSON_InvalidArtifactHash_Delegations(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		artifacts := root["artifacts"].(map[string]any)
		artifacts["delegation_records"] = []any{
			map[string]any{
				"delegation_id": "dlg_tampered",
			},
		}
		root["artifacts"] = artifacts
	})
	assertStatus(t, b, StatusInvalidArtifactHash)
}

func TestVerifyBundleJSON_InvalidOrdering(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		manifest := root["manifest"].(map[string]any)
		artifacts := manifest["artifacts"].([]any)
		artifacts[0], artifacts[1] = artifacts[1], artifacts[0]
		manifest["artifacts"] = artifacts
		root["manifest"] = manifest
	})
	assertStatus(t, b, StatusInvalidOrdering)
}

func TestVerifyBundleJSON_InvalidManifestHash(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		hashes := root["hashes"].(map[string]any)
		hashes["manifest_hash"] = "sha256:deadbeef"
		root["hashes"] = hashes
	})
	assertStatus(t, b, StatusInvalidManifestHash)
}

func TestVerifyBundleJSON_InvalidBundleHash(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		hashes := root["hashes"].(map[string]any)
		hashes["bundle_hash"] = "sha256:deadbeef"
		root["hashes"] = hashes
	})
	assertStatus(t, b, StatusInvalidBundleHash)
}

func TestVerifyBundleJSON_UnsupportedDeterminismVersion(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		contract := root["contract"].(map[string]any)
		contract["determinism_version"] = "evidence-v999"
		root["contract"] = contract
	})
	assertStatus(t, b, StatusUnsupportedDeterminismVersion)
}

func TestVerifyBundleJSON_MalformedMissingBundleVersion(t *testing.T) {
	b := mutateBundle(t, loadGoodBundle(t), func(root map[string]any) {
		delete(root, "bundle_version")
	})
	assertStatus(t, b, StatusMalformedBundle)
}

func assertStatus(t *testing.T, bundle []byte, expected string) {
	t.Helper()
	res, err := VerifyBundleJSON(bundle)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Status != expected {
		t.Fatalf("expected %s, got %s details=%v", expected, res.Status, res.Details)
	}
}

func mutateBundle(t *testing.T, bundle []byte, mut func(root map[string]any)) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(bundle, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mut(root)
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func loadGoodBundle(t *testing.T) []byte {
	t.Helper()
	return loadFixture(t, "bundle.good.json")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime caller unavailable")
	}
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "evp", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %s: %v", p, err)
	}
	return b
}
