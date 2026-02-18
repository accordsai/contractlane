package idempotency

import (
	"context"
	"errors"
	"testing"
)

type fakeStore struct {
	status int
	body   map[string]any
	found  bool
	getErr error
	saveN  int
}

func (f *fakeStore) GetIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string) (int, map[string]any, bool, error) {
	if f.getErr != nil {
		return 0, nil, false, f.getErr
	}
	return f.status, f.body, f.found, nil
}

func (f *fakeStore) SaveIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string, responseStatus int, responseBody map[string]any) error {
	f.status = responseStatus
	f.body = responseBody
	f.found = true
	f.saveN++
	return nil
}

func TestReplayNoKeyNoop(t *testing.T) {
	st := &fakeStore{}
	_, _, replayed, err := Replay(context.Background(), st, ActorContext{
		PrincipalID:    "prn_1",
		ActorID:        "act_1",
		IdempotencyKey: "",
	}, "POST /cel/contracts")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if replayed {
		t.Fatalf("expected replayed=false without key")
	}
}

func TestSaveThenReplayReturnsSamePayload(t *testing.T) {
	st := &fakeStore{}
	actor := ActorContext{PrincipalID: "prn_1", ActorID: "act_1", IdempotencyKey: "k1"}
	resp := map[string]any{"request_id": "req_1", "status": "DONE"}

	if err := Save(context.Background(), st, actor, "POST /cel/contracts", 201, resp); err != nil {
		t.Fatalf("save err: %v", err)
	}
	if st.saveN != 1 {
		t.Fatalf("expected one save, got %d", st.saveN)
	}

	status, body, replayed, err := Replay(context.Background(), st, actor, "POST /cel/contracts")
	if err != nil {
		t.Fatalf("replay err: %v", err)
	}
	if !replayed {
		t.Fatalf("expected replayed=true")
	}
	if status != 201 {
		t.Fatalf("expected status 201, got %d", status)
	}
	if body["request_id"] != "req_1" || body["status"] != "DONE" {
		t.Fatalf("unexpected replay body: %+v", body)
	}
}

func TestReplayStoreError(t *testing.T) {
	st := &fakeStore{getErr: errors.New("db down")}
	_, _, replayed, err := Replay(context.Background(), st, ActorContext{
		PrincipalID:    "prn_1",
		ActorID:        "act_1",
		IdempotencyKey: "k1",
	}, "POST /cel/contracts")
	if replayed {
		t.Fatalf("expected replayed=false on error")
	}
	if err == nil {
		t.Fatalf("expected error")
	}
}
