package main

import (
	"net/http"
	"os"

	"contractlane/pkg/httpx"

	"github.com/go-chi/chi/v5"
)

func main() {
	port := os.Getenv("SERVICE_PORT")
	if port == "" { port = "8083" }

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	r.Route("/exec", func(api chi.Router) {
		api.Post("/contracts/{contract_id}/sendForSignature", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "provider":"INTERNAL", "envelope_id":"env_dev", "status":"SENT"})
		})
		api.Post("/webhooks/esign/{provider}", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"request_id": httpx.NewRequestID(), "accepted": true})
		})
	})

	http.ListenAndServe(":"+port, r)
}
