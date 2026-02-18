ALTER TABLE principals
ADD COLUMN default_policy_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
ADD COLUMN default_approval_role TEXT NOT NULL DEFAULT 'LEGAL';
