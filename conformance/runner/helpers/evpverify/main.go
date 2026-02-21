package main

import (
	"fmt"
	"io"
	"os"

	"github.com/accordsai/contractlane/pkg/evp"
)

func main() {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(2)
	}
	result, err := evp.VerifyBundleJSON(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify error:", err)
		os.Exit(1)
	}
	if result.Status != evp.StatusVerified {
		fmt.Fprintf(os.Stderr, "verify failed: status=%s details=%v\n", result.Status, result.Details)
		os.Exit(1)
	}
	fmt.Println("VERIFIED")
}
