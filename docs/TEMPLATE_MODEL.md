# Template Model (Global vs Principal vs Actor vs Contract)

This document explains how template behavior is scoped in the current implementation.

## Scope Layers

1. Deployment-global template definition
- Stored in global template tables.
- Defines:
  - `template_id`, metadata (`contract_type`, `jurisdiction`, `risk_tier`)
  - governance defaults (`template_gates`)
  - variable definitions (`key`, `type`, `required`, `set_policy`, constraints)
- This is the reusable baseline for all principals on that deployment.

2. Principal template enablement/override
- Principal can enable a template and apply principal-level gate overrides.
- Scope is `(principal_id, template_id)`.
- This is a policy overlay, not a full template fork.

3. Actor policy profile
- Actor-level policy affects gate resolution when template policy defers to identity.
- Actor policy does not redefine template schema.

4. Contract instance data
- Per-contract variable values, approvals, signatures, events, evidence/proof artifacts.
- Contract-level requirements should be expressed using contract-scoped rules/proof requirements, not by mutating template schema.

## What Is Template-Level vs Contract-Level

Template-level (many contracts):
- Reusable legal/governance defaults for a class of contracts.
- Example: `SEND_FOR_SIGNATURE` gate default is `FORCE_HUMAN` for all vendor agreements.

Contract-level (single contract):
- Deal-specific requirements and evidence/proof constraints.
- Example: this one contract requires settlement `PAID` for `USD 49`.

## Paid vs Free NDA Pattern

Recommended pattern:
- Keep one reusable NDA template with shared fields.
- Keep `price` optional in template when not universally required.
- For paid NDA instances, add contract-scoped payment/rules requirements (for example `settlement_status_is=PAID` and `settlement_amount_is`).
- For free NDA instances, omit payment requirement.

Use separate template variants only when legal structure is materially different and reused often.

## Template Discovery and Selection

Typical flow:
1. Discover available templates (`GET /cel/templates`).
2. Inspect governance/variables (`GET /cel/templates/{template_id}/governance`).
3. (Optional) enable for principal (`POST /cel/principals/{principal_id}/templates/{template_id}/enable`).
4. Create contract with selected `template_id` (`POST /cel/contracts`).

## Important Notes

- In this implementation, template authoring is operator/admin-oriented; agent flows typically consume existing templates.
- Principal override is template-scoped; it affects future usage of that template by that principal.
- Variables are contract-scoped values; template variable definitions (`required`, `type`, policies) are not per-contract knobs.
