# Conformance

The conformance suite verifies Protocol v1 compatibility against a running Contract Lane node.

## Run locally

```bash
bash conformance/runner/run_local_conformance.sh
```

## Run against another node

Set `BASE_URL` (CEL base), plus identity/auth env vars as needed (`IAL_BASE_URL`, `PRINCIPAL_ID`, `AGENT_ACTOR_ID`, `AGENT_TOKEN`), then run the same command.

A node is Protocol v1 compatible if it passes all cases in `conformance/runner`.

For CI parsing, set `CONFORMANCE_OUTPUT=json` to emit only a final single-line JSON summary on stdout. Summary keys: `protocol`, `protocol_version`, `status`, `base_url`, `cases_passed`, `cases_failed`, `cases`, `failed_case`, `failure_reason`, `timestamp_utc`, `git_commit`.
