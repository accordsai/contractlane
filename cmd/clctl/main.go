package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/accordsai/contractlane/sdk/go/contractlane"
)

type repeatStringFlag []string

func (r *repeatStringFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatStringFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*r = append(*r, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		failSummary("", "", "", "", "usage: clctl proof verify --evidence <path> --proof <path> [--trust-agent <agent_id>] | clctl proof make --evidence <path> --out <path> [--intent-id <id>] [--contract-id <id>] [--issued-at-utc <rfc3339>]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "proof":
		runProof(os.Args[2:])
	default:
		failSummary("", "", "", "", "unknown command")
		os.Exit(2)
	}
}

func runProof(args []string) {
	if len(args) < 1 {
		failSummary("", "", "", "", "usage: clctl proof verify --evidence <path> --proof <path> [--trust-agent <agent_id>] | clctl proof make --evidence <path> --out <path> [--intent-id <id>] [--contract-id <id>] [--issued-at-utc <rfc3339>]")
		os.Exit(2)
	}
	switch args[0] {
	case "verify":
		runProofVerify(args[1:])
	case "make":
		runProofMake(args[1:])
	default:
		failSummary("", "", "", "", "usage: clctl proof verify --evidence <path> --proof <path> [--trust-agent <agent_id>] | clctl proof make --evidence <path> --out <path> [--intent-id <id>] [--contract-id <id>] [--issued-at-utc <rfc3339>]")
		os.Exit(2)
	}
}

func runProofVerify(args []string) {
	fs := flag.NewFlagSet("proof verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	evidencePath := fs.String("evidence", "", "path to evidence bundle json")
	proofPath := fs.String("proof", "", "path to settlement proof json")
	var trustAgents repeatStringFlag
	fs.Var(&trustAgents, "trust-agent", "trusted issuer agent id (repeatable)")
	if err := fs.Parse(args); err != nil {
		failSummary("", "", "", "", err.Error())
		os.Exit(2)
	}
	if strings.TrimSpace(*evidencePath) == "" || strings.TrimSpace(*proofPath) == "" {
		failSummary("", "", "", "", "both --evidence and --proof are required")
		os.Exit(2)
	}

	evidenceBytes, err := os.ReadFile(*evidencePath)
	if err != nil {
		failSummary("", "", "", "", "read evidence failed: "+err.Error())
		os.Exit(1)
	}
	proofBytes, err := os.ReadFile(*proofPath)
	if err != nil {
		failSummary("", "", "", "", "read proof failed: "+err.Error())
		os.Exit(1)
	}

	var proof struct {
		Protocol        string `json:"protocol"`
		ProtocolVersion string `json:"protocol_version"`
		ContractID      string `json:"contract_id"`
		IntentID        string `json:"intent_id"`
		ManifestHash    string `json:"manifest_hash"`
		BundleHash      string `json:"bundle_hash"`
	}
	_ = json.Unmarshal(proofBytes, &proof)

	if err := contractlane.VerifySettlementProofV1WithOptions(evidenceBytes, proofBytes, contractlane.SettlementProofVerifyOptions{
		TrustAgents: trustAgents,
	}); err != nil {
		failSummary(proof.ContractID, proof.IntentID, proof.ManifestHash, proof.BundleHash, err.Error())
		os.Exit(1)
	}
	passSummary(proof.ContractID, proof.IntentID, proof.ManifestHash, proof.BundleHash)
}

func runProofMake(args []string) {
	fs := flag.NewFlagSet("proof make", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	evidencePath := fs.String("evidence", "", "path to evidence bundle json")
	outPath := fs.String("out", "", "path to write settlement proof json")
	intentID := fs.String("intent-id", "", "intent id to select")
	contractID := fs.String("contract-id", "", "contract id override")
	issuedAtUTC := fs.String("issued-at-utc", "", "issued_at_utc RFC3339 UTC")
	if err := fs.Parse(args); err != nil {
		failMakeSummary("", "", "", "", "", err.Error())
		os.Exit(2)
	}
	if strings.TrimSpace(*evidencePath) == "" || strings.TrimSpace(*outPath) == "" {
		failMakeSummary("", "", "", "", strings.TrimSpace(*outPath), "both --evidence and --out are required")
		os.Exit(2)
	}

	evidenceBytes, err := os.ReadFile(*evidencePath)
	if err != nil {
		failMakeSummary("", "", "", "", strings.TrimSpace(*outPath), "read evidence failed: "+err.Error())
		os.Exit(1)
	}

	proof, proofBytes, err := contractlane.BuildSettlementProofV1(evidenceBytes, contractlane.BuildSettlementProofV1Options{
		ContractID:  strings.TrimSpace(*contractID),
		IntentID:    strings.TrimSpace(*intentID),
		IssuedAtUTC: strings.TrimSpace(*issuedAtUTC),
	})
	if err != nil {
		failMakeSummary("", "", "", "", strings.TrimSpace(*outPath), err.Error())
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, proofBytes, 0o644); err != nil {
		failMakeSummary(proof.ContractID, proof.IntentID, proof.ManifestHash, proof.BundleHash, strings.TrimSpace(*outPath), "write proof failed: "+err.Error())
		os.Exit(1)
	}

	passMakeSummary(proof.ContractID, proof.IntentID, proof.ManifestHash, proof.BundleHash, strings.TrimSpace(*outPath))
}

func passSummary(contractID, intentID, manifestHash, bundleHash string) {
	fmt.Printf("{\"protocol\":\"contractlane\",\"protocol_version\":\"v1\",\"status\":\"PASS\",\"contract_id\":%s,\"intent_id\":%s,\"manifest_hash\":%s,\"bundle_hash\":%s,\"timestamp_utc\":\"%s\"}\n",
		jsonQuote(contractID),
		jsonQuote(intentID),
		jsonQuote(manifestHash),
		jsonQuote(bundleHash),
		time.Now().UTC().Format(time.RFC3339),
	)
}

func failSummary(contractID, intentID, manifestHash, bundleHash, reason string) {
	fmt.Printf("{\"protocol\":\"contractlane\",\"protocol_version\":\"v1\",\"status\":\"FAIL\",\"contract_id\":%s,\"intent_id\":%s,\"manifest_hash\":%s,\"bundle_hash\":%s,\"reason\":%s,\"timestamp_utc\":\"%s\"}\n",
		jsonQuote(contractID),
		jsonQuote(intentID),
		jsonQuote(manifestHash),
		jsonQuote(bundleHash),
		jsonQuote(reason),
		time.Now().UTC().Format(time.RFC3339),
	)
}

func passMakeSummary(contractID, intentID, manifestHash, bundleHash, proofPath string) {
	fmt.Printf("{\"protocol\":\"contractlane\",\"protocol_version\":\"v1\",\"status\":\"PASS\",\"contract_id\":%s,\"intent_id\":%s,\"manifest_hash\":%s,\"bundle_hash\":%s,\"proof_path\":%s,\"timestamp_utc\":\"%s\"}\n",
		jsonQuote(contractID),
		jsonQuote(intentID),
		jsonQuote(manifestHash),
		jsonQuote(bundleHash),
		jsonQuote(proofPath),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
}

func failMakeSummary(contractID, intentID, manifestHash, bundleHash, proofPath, reason string) {
	fmt.Printf("{\"protocol\":\"contractlane\",\"protocol_version\":\"v1\",\"status\":\"FAIL\",\"contract_id\":%s,\"intent_id\":%s,\"manifest_hash\":%s,\"bundle_hash\":%s,\"proof_path\":%s,\"reason\":%s,\"timestamp_utc\":\"%s\"}\n",
		jsonQuote(contractID),
		jsonQuote(intentID),
		jsonQuote(manifestHash),
		jsonQuote(bundleHash),
		jsonQuote(proofPath),
		jsonQuote(reason),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
}

func jsonQuote(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}
