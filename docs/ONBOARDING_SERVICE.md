# Onboarding Service (Control Plane)

This service is an operational companion to Contract Lane.
It does **not** change protocol semantics.

## Purpose

- Bootstrap org/project records for hosted or on-prem operators
- Provision `principal_id` and `actor_id` by calling private IAL APIs
- Issue initial agent credential tokens

## Scope Boundary

- Protocol surfaces (`sig-v1`, `evidence-v1`, `proof-bundle-v1`) are unchanged.
- Onboarding handles identity/provisioning operations only.

## Run Alongside Existing Contract Lane Stack

Prerequisites:

- Existing services already running (`postgres`, `ial`, `cel`, `execution`)
- Shared Docker network name (default: `accords_default`)

Environment:

- `CONTRACTLANE_SHARED_NETWORK=accords_default`
- `ONBOARDING_DATABASE_URL=postgres://contractlane:...@postgres:5432/contractlane?sslmode=disable`
- `ONBOARDING_IAL_BASE_URL=http://ial:8081/ial`
- `ONBOARDING_BOOTSTRAP_TOKEN=<strong-secret>`

Commands:

```bash
make onboarding-up
make onboarding-smoke
```

Stop:

```bash
make onboarding-down
```

## API Surface

Base path: `/onboarding/v1`

- `POST /orgs`
- `POST /orgs/{org_id}/projects`
- `POST /projects/{project_id}/agents`

Auth:

- Bearer token (`Authorization: Bearer <ONBOARDING_BOOTSTRAP_TOKEN>`)

Idempotency:

- Optional `Idempotency-Key` header on mutating requests

## Example Flow

Create org:

```bash
curl -sS -X POST http://localhost:8084/onboarding/v1/orgs \
  -H "Authorization: Bearer $ONBOARDING_BOOTSTRAP_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Acme","admin_email":"owner@acme.com"}'
```

Create project (provisions IAL principal):

```bash
curl -sS -X POST http://localhost:8084/onboarding/v1/orgs/<org_id>/projects \
  -H "Authorization: Bearer $ONBOARDING_BOOTSTRAP_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Treasury","jurisdiction":"US","timezone":"UTC"}'
```

Create agent (provisions IAL actor + returns one-time token):

```bash
curl -sS -X POST http://localhost:8084/onboarding/v1/projects/<project_id>/agents \
  -H "Authorization: Bearer $ONBOARDING_BOOTSTRAP_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Clawbot","scopes":["cel.contracts:write","cel.approvals:decide"]}'
```

Response includes:

- `principal_id`
- `actor_id`
- one-time `token` (store in your secret manager)

## Agent Usage Guidance

For agent integrators:

1. Use onboarding API once to obtain `principal_id`, `actor_id`, token.
2. Store token in vault/secret manager.
3. Use Contract Lane SDKs against CEL with those credentials.
4. Do not call IAL directly from public agents in hosted mode.

## Nginx Routing

Use existing nginx and add onboarding path routing in the TLS server block:

```nginx
location ^~ /onboarding/ {
  proxy_pass http://127.0.0.1:8084/;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep existing CEL route as fallback (`location /`).

## Publish Checklist

- Set non-default secrets in `.env`
- Confirm onboarding can reach `postgres` and `ial` over shared Docker network
- Run:
  - `go test ./... -count=1`
  - `make onboarding-smoke`
  - `make smoke`
- Confirm no protocol schema/hash/signature changes were introduced
- Document deployment values for operators (`ONBOARDING_*`, network name)
