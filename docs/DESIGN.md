# Contract Lane V1 — Design Overview (Headless)

V1 is headless to prioritize correctness and agent integrator experience.

## Microservices
- IAL: principals, actors, invites, policy profiles, signature verification (stubbed in MVP)
- CEL: templates, contracts, variables, approvals, attempt-action endpoint
- Execution: send-for-signature + webhook intake (stubbed)

## Key endpoint
`POST /cel/contracts/{contract_id}/actions/{action}` returns:
- DONE
- BLOCKED + next_step (FILL_VARIABLES | REVIEW_VARIABLES | APPROVE_ACTION)
- or error

