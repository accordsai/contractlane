package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func NewRequestID() string { return "req_" + uuid.NewString() }

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ReadJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func WriteError(w http.ResponseWriter, status int, code, message string, details any) {
	resp := map[string]any{
		"request_id": NewRequestID(),
		"error": map[string]any{
			"code": code, "message": message, "details": details,
		},
	}
	WriteJSON(w, status, resp)
}

