package idempotency

import "context"

type ActorContext struct {
	PrincipalID    string
	ActorID        string
	IdempotencyKey string
}

type Store interface {
	GetIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string) (int, map[string]any, bool, error)
	SaveIdempotencyRecord(ctx context.Context, principalID, actorID, idempotencyKey, endpoint string, responseStatus int, responseBody map[string]any) error
}

func Replay(ctx context.Context, st Store, actor ActorContext, endpoint string) (int, map[string]any, bool, error) {
	if actor.IdempotencyKey == "" {
		return 0, nil, false, nil
	}
	status, body, found, err := st.GetIdempotencyRecord(ctx, actor.PrincipalID, actor.ActorID, actor.IdempotencyKey, endpoint)
	if err != nil {
		return 0, nil, false, err
	}
	if !found {
		return 0, nil, false, nil
	}
	return status, body, true, nil
}

func Save(ctx context.Context, st Store, actor ActorContext, endpoint string, status int, response map[string]any) error {
	if actor.IdempotencyKey == "" {
		return nil
	}
	return st.SaveIdempotencyRecord(ctx, actor.PrincipalID, actor.ActorID, actor.IdempotencyKey, endpoint, status, response)
}
