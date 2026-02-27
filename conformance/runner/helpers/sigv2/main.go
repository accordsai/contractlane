package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/accordsai/contractlane/pkg/evidencehash"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: sigv2_go_helper '<payload-json>' [context]")
		os.Exit(2)
	}

	var payload any
	if err := json.Unmarshal([]byte(os.Args[1]), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "invalid payload json:", err)
		os.Exit(2)
	}

	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canonical hash:", err)
		os.Exit(2)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decode hash hex:", err)
		os.Exit(2)
	}

	priv, err := deterministicP256Key("contractlane-conformance-sigv2-p256-seed-v1")
	if err != nil {
		fmt.Fprintln(os.Stderr, "deterministic key:", err)
		os.Exit(2)
	}

	r, s, err := ecdsa.Sign(rand.Reader, priv, hashBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(2)
	}
	sigRaw := make([]byte, 64)
	r.FillBytes(sigRaw[:32])
	s.FillBytes(sigRaw[32:])

	ctx := "contract-action"
	if len(os.Args) == 3 && os.Args[2] != "" {
		ctx = os.Args[2]
	}

	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	envelope := map[string]any{
		"version":      "sig-v2",
		"algorithm":    "es256",
		"public_key":   base64.RawURLEncoding.EncodeToString(pub),
		"signature":    base64.RawURLEncoding.EncodeToString(sigRaw),
		"payload_hash": hashHex,
		"issued_at":    "2026-01-01T00:00:00Z",
		"context":      ctx,
	}

	out, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal envelope:", err)
		os.Exit(2)
	}
	fmt.Print(string(out))
}

func deterministicP256Key(seed string) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	n := curve.Params().N
	seedHash := sha256.Sum256([]byte(seed))
	d := new(big.Int).SetBytes(seedHash[:])
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(n, one)
	d.Mod(d, nMinusOne)
	d.Add(d, one)

	x, y := curve.ScalarBaseMult(d.Bytes())
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid scalar")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}
