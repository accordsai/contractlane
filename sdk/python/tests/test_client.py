import json
from pathlib import Path

import httpx
import pytest

from contractlane.client import ContractLaneClient, PrincipalAuth, RetryConfig


def test_gate_resolve_requires_idempotency():
    c = ContractLaneClient("http://example", PrincipalAuth("tok"))
    with pytest.raises(ValueError):
        c.gate_resolve("terms_current", "sub", "HUMAN", "")


def test_retry_429_then_success():
    attempts = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, json={"error_code": "RATE_LIMIT", "message": "slow"})
        return httpx.Response(200, json={"status": "DONE"})

    c = ContractLaneClient("http://x", PrincipalAuth("tok"), retry=RetryConfig(max_attempts=3, base_delay_ms=1, max_delay_ms=5))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    out = c.gate_status("terms_current", "sub")
    assert out["status"] == "DONE"


def test_error_model_401():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error_code": "UNAUTHORIZED", "message": "bad token", "request_id": "req_1"})

    c = ContractLaneClient("http://x", PrincipalAuth("bad"))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(Exception):
        c.gate_status("terms_current", "sub")


def test_conformance_cases_exist():
    root = Path(__file__).resolve().parents[3]
    for name in [
        "gate_status_done.json",
        "gate_status_blocked.json",
        "gate_resolve_requires_idempotency.json",
        "error_model_401.json",
        "retry_429_then_success.json",
    ]:
        p = root / "conformance" / "cases" / name
        assert p.exists(), f"missing {p}"
        json.loads(p.read_text())
