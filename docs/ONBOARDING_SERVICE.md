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
- `ONBOARDING_SIGNUP_TTL_MINUTES=15`
- `ONBOARDING_SIGNUP_MAX_ATTEMPTS=5`
- `ONBOARDING_PUBLIC_SIGNUP_DEV_MODE=false` (set `true` only for non-production testing)
- `ONBOARDING_PUBLIC_SIGNUP_CHALLENGE_TOKEN=<optional-shared-challenge-token>`
- `ONBOARDING_PUBLIC_SIGNUP_START_IP_RATE_PER_MINUTE=20`
- `ONBOARDING_PUBLIC_SIGNUP_START_EMAIL_RATE_PER_HOUR=5`
- `ONBOARDING_PUBLIC_SIGNUP_VERIFY_IP_RATE_PER_MINUTE=60`
- `ONBOARDING_PUBLIC_SIGNUP_COMPLETE_IP_RATE_PER_MINUTE=10`
- `ONBOARDING_PUBLIC_SIGNUP_ALLOWED_EMAIL_DOMAINS=` (optional CSV allowlist)
- `ONBOARDING_PUBLIC_SIGNUP_DENIED_EMAIL_DOMAINS=` (optional CSV denylist)

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

Public signup phase A:

- `POST /public/v1/signup/start`
- `POST /public/v1/signup/verify`
- `GET /public/v1/signup/{session_id}`
- `POST /public/v1/signup/complete` (phase C provisioning bridge)

Auth:

- Bearer token (`Authorization: Bearer <ONBOARDING_BOOTSTRAP_TOKEN>`)
- Public signup endpoints are intentionally unauthenticated in Phase A and must be protected by network controls/rate limiting upstream.
- If `ONBOARDING_PUBLIC_SIGNUP_CHALLENGE_TOKEN` is set, clients must send `X-Signup-Challenge: <token>`.

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

Public self-signup (phase C):

1. Start signup session via `POST /public/v1/signup/start`.
2. Verify challenge via `POST /public/v1/signup/verify`.
3. Complete provisioning via `POST /public/v1/signup/complete` to receive one-time credential bundle.

## Reverse Proxy (Nginx) Changes

Add both public routes:

- `/onboarding/*` -> onboarding control-plane endpoints
- `/public/*` -> public signup endpoints

Important:

- Place these blocks before your `location /` catch-all.
- Use `proxy_pass` **without trailing slash** to avoid stripping route prefixes.

If nginx runs in Docker on the same network:

```nginx
location ^~ /onboarding/ {
  proxy_pass http://onboarding:8084;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location ^~ /public/ {
  proxy_pass http://onboarding:8084;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

If nginx runs directly on host:

```nginx
location ^~ /onboarding/ {
  proxy_pass http://127.0.0.1:8084;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location ^~ /public/ {
  proxy_pass http://127.0.0.1:8084;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep existing CEL route as fallback (`location /`).

## Overlay Compose Notes

When onboarding runs as an overlay against existing Contract Lane containers, ensure:

1. `onboarding` joins `${CONTRACTLANE_SHARED_NETWORK}`.
2. `ONBOARDING_DATABASE_URL` uses internal `postgres` hostname on that network.
3. `ONBOARDING_IAL_BASE_URL` uses internal `ial` hostname on that network.

## Publish Checklist

- Set non-default secrets in `.env`
- Confirm onboarding can reach `postgres` and `ial` over shared Docker network
- Confirm `ONBOARDING_PUBLIC_SIGNUP_DEV_MODE=false` in production
- If public signup is enabled, set `ONBOARDING_PUBLIC_SIGNUP_CHALLENGE_TOKEN` and rate limit values
- Run:
  - `go test ./... -count=1`
  - `make onboarding-smoke`
  - `make smoke`
- Confirm no protocol schema/hash/signature changes were introduced
- Document deployment values for operators (`ONBOARDING_*`, network name)
