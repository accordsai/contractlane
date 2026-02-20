DROP INDEX IF EXISTS onboarding_signup_provisions_org_idx;
DROP TABLE IF EXISTS onboarding_signup_provisions;

ALTER TABLE onboarding_signup_sessions
  DROP COLUMN IF EXISTS completed_at;

ALTER TABLE onboarding_signup_sessions
  DROP CONSTRAINT IF EXISTS onboarding_signup_sessions_status_check;

ALTER TABLE onboarding_signup_sessions
  ADD CONSTRAINT onboarding_signup_sessions_status_check
  CHECK (status IN ('PENDING','VERIFIED','EXPIRED'));
