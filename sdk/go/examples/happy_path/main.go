package main

import (
	"encoding/json"
	"fmt"
	"os"

	contractlane "contractlane/sdk/go/contractlane"
)

func main() {
	b, err := os.ReadFile("conformance/fixtures/agent-commerce-offline/proof_bundle_v1.json")
	if err != nil {
		panic(err)
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		panic(err)
	}
	proof, err := contractlane.ParseProofBundleV1Strict(raw)
	if err != nil {
		panic(err)
	}
	proofID, err := contractlane.ComputeProofID(proof)
	if err != nil {
		panic(err)
	}
	report := contractlane.VerifyProofBundleV1Report(proof)
	out := map[string]any{
		"proof_id": proofID,
		"report":   report,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	fmt.Println("ok")
}
