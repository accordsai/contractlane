# Integration Quickstart (Go, 3 calls)

`docs/` is locked in this repo, so this quickstart lives at root.

## Install + Setup

```bash
go get contractlane/pkg/gatesdk
export ACCORDS_BASE_URL=http://localhost:8082
export ACCORDS_BEARER_TOKEN=<agent_bearer_token>
```

## PlatformY flow (about 15 lines)

```go
sdk := gatesdk.New(os.Getenv("ACCORDS_BASE_URL"), os.Getenv("ACCORDS_BEARER_TOKEN"))
ctx := context.Background()
subjectID := "platformy-user-42"

st, _ := sdk.Status(ctx, "terms_current", subjectID, "")
if st.Status != "DONE" {
    rs, _ := sdk.Resolve(ctx, "terms_current", gatesdk.ResolveRequest{
        ExternalSubjectID: subjectID,
        ActorType:         "HUMAN",
        IdempotencyKey:    "req-123",
    })
    // Redirect user to provider signing page:
    // rs.Remediation["continue_url"]
}

ev, _ := sdk.Evidence(ctx, "terms_current", subjectID)
// Store ev.Evidence as your compliance blob
```

## Minimal middleware pattern

```go
func EnsureTerms(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        subjectID := r.Header.Get("X-Platform-Subject")
        st, err := sdk.Status(r.Context(), "terms_current", subjectID, "")
        if err != nil { http.Error(w, "gate check failed", 502); return }
        if st.Status == "DONE" { next.ServeHTTP(w, r); return }
        rs, err := sdk.Resolve(r.Context(), "terms_current", gatesdk.ResolveRequest{
            ExternalSubjectID: subjectID, ActorType: "HUMAN", IdempotencyKey: r.Header.Get("X-Request-Id"),
        })
        if err != nil { http.Error(w, "gate resolve failed", 502); return }
        http.Redirect(w, r, rs.Remediation["continue_url"].(string), http.StatusSeeOther)
    })
}
```
