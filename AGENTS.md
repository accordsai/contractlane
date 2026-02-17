# Instructions for Coding Agents (Codex / Claude Code / Cursor)

This repo is spec-driven. BEFORE making changes, read:
1) docs/DESIGN.md
2) docs/API_SPEC.md
3) docs/STATE_MACHINE.md
4) docs/GATING.md
5) docs/DB_SCHEMA.md

## Locked V1 invariants
- Route list + JSON contracts are locked (docs/API_SPEC.md).
- State machine includes SIGNATURE_SENT.
- Variables are immutable at and after SIGNATURE_SENT.
- Gating precedence for an action:
  1) variable gates -> BLOCKED (FILL_VARIABLES or REVIEW_VARIABLES)
  2) action gates -> BLOCKED (APPROVE_ACTION)
  3) otherwise DONE (apply transition)
- Template gates: FORCE_HUMAN | ALLOW_AUTOMATION | DEFER
- Identity gates: FORCE_HUMAN | ALLOW_AUTOMATION | DEFER (only used when template gate is DEFER)
- Variable policies:
  - HUMAN_REQUIRED blocks until Source=HUMAN
  - AGENT_FILL_HUMAN_REVIEW blocks until ReviewStatus=APPROVED when Source=AGENT
  - DEFER_TO_IDENTITY consults identity variable rules (key overrides type)

## Dev loop
- Run `make test` and `make smoke` before concluding changes.
- Keep edits minimal and aligned to spec.

