package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/accordsai/contractlane/pkg/evidencehash"
	clsdk "github.com/accordsai/contractlane/sdk/go/contractlane"
)

func main() {
	mode := "compute"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	proof, err := clsdk.ParseProofBundleV1Strict(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch mode {
	case "compute":
		id, err := clsdk.ComputeProofID(proof)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(id)
	case "debug":
		id, err := clsdk.ComputeProofID(proof)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		b, err := json.Marshal(proof)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		h, canonicalBytes, err := evidencehash.CanonicalSHA256(generic)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out := map[string]any{
			"proof_id":       id,
			"canonical_sha":  h,
			"canonical_len":  len(canonicalBytes),
			"canonical_json": string(canonicalBytes),
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
	case "verify":
		id, err := clsdk.VerifyProofBundleV1(proof)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(id)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(1)
	}
}
