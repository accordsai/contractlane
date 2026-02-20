DROP INDEX IF EXISTS onboarding_audit_events_org_created_idx;
DROP INDEX IF EXISTS onboarding_credentials_project_idx;
DROP INDEX IF EXISTS onboarding_projects_org_idx;

DROP TABLE IF EXISTS onboarding_audit_events;
DROP TABLE IF EXISTS onboarding_idempotency_records;
DROP TABLE IF EXISTS onboarding_credentials;
DROP TABLE IF EXISTS onboarding_projects;
DROP TABLE IF EXISTS onboarding_memberships;
DROP TABLE IF EXISTS onboarding_users;
DROP TABLE IF EXISTS onboarding_orgs;
