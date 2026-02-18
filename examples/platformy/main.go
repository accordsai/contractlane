package main

import (
	"context"
	"log"
	"os"

	"contractlane/pkg/gatesdk"
)

func main() {
	baseURL := os.Getenv("ACCORDS_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8082"
	}
	token := os.Getenv("ACCORDS_BEARER_TOKEN")
	subject := os.Getenv("PLATFORMY_SUBJECT_ID")
	if subject == "" {
		subject = "platformy-user-123"
	}
	gate := "terms_current"

	sdk := gatesdk.New(baseURL, token)
	ctx := context.Background()

	status, err := sdk.Status(ctx, gate, subject, "")
	if err != nil {
		log.Fatal(err)
	}
	if status.Status == "DONE" {
		log.Println("gate satisfied")
		return
	}

	resolved, err := sdk.Resolve(ctx, gate, gatesdk.ResolveRequest{
		ExternalSubjectID: subject,
		ActorType:         "HUMAN",
		IdempotencyKey:    "platformy-demo-resolve-1",
		ClientReturnURL:   "https://platformy.example/return",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("subject blocked; continue at: %v", resolved.Remediation["continue_url"])

	evidence, err := sdk.Evidence(ctx, gate, subject)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("evidence snapshot: %+v", evidence.Evidence)
}
