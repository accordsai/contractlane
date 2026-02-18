import os
import uuid
from typing import Optional

import httpx
import pytest

from contractlane import ContractLaneClient, PrincipalAuth, new_idempotency_key


CL_INTEGRATION = os.getenv("CL_INTEGRATION") == "1"
CL_CONFORMANCE = os.getenv("CL_CONFORMANCE") == "1"
CL_BASE_URL = os.getenv("CL_BASE_URL", "http://localhost:8080")
CL_IAL_BASE_URL = os.getenv("CL_IAL_BASE_URL", "http://localhost:8081")


def _post(url: str, body: dict, token: Optional[str] = None) -> dict:
    headers = {"content-type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = httpx.post(url, json=body, headers=headers, timeout=20)
    if resp.status_code < 200 or resp.status_code >= 300:
        raise RuntimeError(f"POST {url} -> {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


def _setup() -> tuple[str, str]:
    principal = _post(f"{CL_IAL_BASE_URL}/ial/principals", {"name": "SDK PY", "jurisdiction": "US", "timezone": "UTC"})
    principal_id = principal["principal"]["principal_id"]
    agent = _post(f"{CL_IAL_BASE_URL}/ial/actors/agents", {
        "principal_id": principal_id,
        "name": "SDKPYAgent",
        "auth": {"mode": "HMAC", "scopes": ["cel.contracts:write", "exec.signatures:send"]},
    })
    token = agent["credentials"]["token"]
    agent_id = agent["agent"]["actor_id"]

    _post(f"{CL_BASE_URL}/cel/dev/seed-template", {"principal_id": principal_id})
    _post(f"{CL_BASE_URL}/cel/programs", {
        "actor_context": {"principal_id": principal_id, "actor_id": agent_id, "actor_type": "AGENT", "idempotency_key": str(uuid.uuid4())},
        "key": "terms_current",
        "mode": "STRICT_RECONSENT",
    }, token)
    _post(f"{CL_BASE_URL}/cel/programs/terms_current/publish", {
        "actor_context": {"principal_id": principal_id, "actor_id": agent_id, "actor_type": "AGENT", "idempotency_key": str(uuid.uuid4())},
        "required_template_id": "tpl_nda_us_v1",
        "required_template_version": "v1",
    }, token)
    return principal_id, token


@pytest.mark.skipif(not CL_INTEGRATION, reason="set CL_INTEGRATION=1")
def test_integration_gate_status_and_resolve_union():
    _, token = _setup()
    client = ContractLaneClient(CL_BASE_URL, PrincipalAuth(token))
    subject = f"py-sub-{uuid.uuid4()}"

    status = client.gate_status("terms_current", subject)
    assert status.get("status") in ("DONE", "BLOCKED")

    resolved = client.gate_resolve("terms_current", subject, "HUMAN", new_idempotency_key())
    assert resolved.get("status") in ("DONE", "BLOCKED")
    if resolved.get("status") == "BLOCKED":
        assert resolved.get("next_step") or resolved.get("remediation")


@pytest.mark.skipif(not CL_CONFORMANCE, reason="set CL_CONFORMANCE=1")
def test_conformance_live_smoke():
    _, token = _setup()
    client = ContractLaneClient(CL_BASE_URL, PrincipalAuth(token))
    status = client.gate_status("terms_current", f"py-conf-{uuid.uuid4()}")
    assert status.get("status") in ("DONE", "BLOCKED")
