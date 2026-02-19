package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sigv1_go_helper '<payload-json>'")
		os.Exit(2)
	}

	var payload any
	if err := json.Unmarshal([]byte(os.Args[1]), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "invalid payload json:", err)
		os.Exit(2)
	}

	canonical, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal payload:", err)
		os.Exit(2)
	}

	h := sha256.Sum256(canonical)
	seed := sha256.Sum256([]byte("contractlane-conformance-sigv1-ed25519-seed-v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, h[:])

	envelope := map[string]any{
		"version":      "sig-v1",
		"algorithm":    "ed25519",
		"public_key":   base64.StdEncoding.EncodeToString(pub),
		"signature":    base64.StdEncoding.EncodeToString(sig),
		"payload_hash": hex.EncodeToString(h[:]),
		"issued_at":    "2026-01-01T00:00:00Z",
		"context":      "contract-action",
	}

	out, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal envelope:", err)
		os.Exit(2)
	}
	fmt.Print(string(out))
}
