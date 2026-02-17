# V1 Gating (Locked)

Action gating precedence:
1) Variable gates (missing / needs human entry / needs review) => BLOCKED (FILL_VARIABLES or REVIEW_VARIABLES)
2) Action gates (template/identity) => BLOCKED (APPROVE_ACTION)
3) Otherwise DONE (apply transition)

Variable policies:
- HUMAN_REQUIRED blocks until Source=HUMAN
- AGENT_FILL_HUMAN_REVIEW blocks until review approved (if Source=AGENT)
- DEFER_TO_IDENTITY consults identity rules (key overrides type)

