package main

import (
	"context"
	"fmt"
	"os"

	"github.com/accordsai/contractlane/sdk/go/contractlane"
)

func main() {
	base := getenv("CONTRACTLANE_BASE_URL", "http://localhost:8082")
	token := os.Getenv("CONTRACTLANE_TOKEN")
	subject := getenv("EXTERNAL_SUBJECT_ID", "platform-user-1")
	client := contractlane.NewClient(base, contractlane.PrincipalAuth{Token: token})

	status, err := client.GateStatus(context.Background(), "terms_current", subject)
	if err != nil {
		panic(err)
	}
	if status.Status == "BLOCKED" {
		res, err := client.GateResolve(context.Background(), "terms_current", subject, contractlane.ResolveOptions{ActorType: "HUMAN", IdempotencyKey: contractlane.NewIdempotencyKey()})
		if err != nil {
			panic(err)
		}
		fmt.Println("continue_url:", res.NextStep.ContinueURL)
	}
	ev, err := client.Evidence(context.Background(), "terms_current", subject)
	if err == nil {
		fmt.Println("evidence keys:", len(ev))
	}
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}
