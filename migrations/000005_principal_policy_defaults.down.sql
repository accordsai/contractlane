ALTER TABLE principals
DROP COLUMN IF EXISTS default_policy_actor_id,
DROP COLUMN IF EXISTS default_approval_role;
