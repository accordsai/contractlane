# GUARANTEES

Protocol v1.0.0 guarantees:

- Deterministic canonical JSON hashing for protocol objects.
- Stable evidence hash semantics (`manifest_hash`, `bundle_hash`) for `evidence-v1`.
- Stable signature envelope semantics for `sig-v1`.
- Stable proof identifier rule for `proof-bundle-v1`.
- Principal isolation semantics enforced by service behavior and tests.

Not guaranteed:

- Backward compatibility for future `*-v2` schemas.
- Automatic rule-driven state mutation (not part of v1 semantics).
