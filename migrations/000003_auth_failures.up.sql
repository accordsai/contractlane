CREATE TABLE auth_failures (
  auth_failure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  principal_id TEXT NULL,
  actor_id TEXT NULL,
  reason TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
