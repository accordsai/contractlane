package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/accordsai/contractlane/pkg/evidencehash"
)

const (
	deterministicSeed = "contractlane-conformance-sigv3-webauthn-seed-v1"
	credentialIDRaw   = "conformance_sigv3_credential_v1"
	issuedAtFixed     = "2026-01-01T00:00:00Z"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "credential":
		handleCredential()
	case "hash":
		if len(os.Args) != 3 {
			usage()
		}
		handleHash(os.Args[2])
	case "client-data-create":
		if len(os.Args) != 4 {
			usage()
		}
		handleClientDataCreate(os.Args[2], os.Args[3])
	case "sign":
		if len(os.Args) < 7 || len(os.Args) > 8 {
			usage()
		}
		context := "contract-action"
		if len(os.Args) == 8 && os.Args[7] != "" {
			context = os.Args[7]
		}
		handleSign(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], context)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  sigv3_go_helper credential")
	fmt.Fprintln(os.Stderr, "  sigv3_go_helper hash '<payload-json>'")
	fmt.Fprintln(os.Stderr, "  sigv3_go_helper client-data-create <challenge_b64url> <origin>")
	fmt.Fprintln(os.Stderr, "  sigv3_go_helper sign '<payload-json>' <challenge_id> <challenge_b64url> <origin> <rp_id> [context]")
	os.Exit(2)
}

func handleHash(payloadJSON string) {
	var payload any
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "invalid payload json:", err)
		os.Exit(2)
	}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canonical hash:", err)
		os.Exit(2)
	}
	fmt.Print(hashHex)
}

func handleCredential() {
	priv, err := deterministicP256Key(deterministicSeed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deterministic key:", err)
		os.Exit(2)
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	out := map[string]any{
		"credential_id": base64.RawURLEncoding.EncodeToString([]byte(credentialIDRaw)),
		"public_key":    base64.RawURLEncoding.EncodeToString(pub),
	}
	writeJSON(out)
}

func handleClientDataCreate(challengeB64URL, origin string) {
	clientData := map[string]any{
		"type":      "webauthn.create",
		"challenge": challengeB64URL,
		"origin":    origin,
	}
	b, _ := json.Marshal(clientData)
	fmt.Print(base64.RawURLEncoding.EncodeToString(b))
}

func handleSign(payloadJSON, challengeID, challengeB64URL, origin, rpID, context string) {
	var payload any
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		fmt.Fprintln(os.Stderr, "invalid payload json:", err)
		os.Exit(2)
	}
	hashHex, _, err := evidencehash.CanonicalSHA256(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canonical hash:", err)
		os.Exit(2)
	}

	priv, err := deterministicP256Key(deterministicSeed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deterministic key:", err)
		os.Exit(2)
	}
	clientData := map[string]any{
		"type":      "webauthn.get",
		"challenge": challengeB64URL,
		"origin":    origin,
	}
	clientDataJSON, _ := json.Marshal(clientData)
	clientDataHash := sha256.Sum256(clientDataJSON)

	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpIDHash[:])
	authData[32] = 0x01 | 0x04 // UP + UV
	binary.BigEndian.PutUint32(authData[33:37], 1)

	signedData := make([]byte, 0, len(authData)+len(clientDataHash))
	signedData = append(signedData, authData...)
	signedData = append(signedData, clientDataHash[:]...)
	digest := sha256.Sum256(signedData)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(2)
	}
	out := map[string]any{
		"version":            "sig-v3",
		"algorithm":          "webauthn-es256",
		"credential_id":      base64.RawURLEncoding.EncodeToString([]byte(credentialIDRaw)),
		"challenge_id":       challengeID,
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientDataJSON),
		"authenticator_data": base64.RawURLEncoding.EncodeToString(authData),
		"signature":          base64.RawURLEncoding.EncodeToString(sigDER),
		"payload_hash":       hashHex,
		"issued_at":          issuedAtFixed,
		"context":            context,
	}
	writeJSON(out)
}

func writeJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(2)
	}
	fmt.Print(string(b))
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
