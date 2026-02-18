from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

APIVersion = "v1"


@dataclass
class RetryConfig:
    max_attempts: int = 3
    base_delay_ms: int = 200
    max_delay_ms: int = 5000


class SDKError(Exception):
    def __init__(self, status_code: int, error_code: Optional[str], message: str, request_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id
        self.details = details or {}


class AuthStrategy:
    def apply(self, headers: Dict[str, str], method: str, path_with_query: str, body_bytes: str) -> None:
        raise NotImplementedError


class PrincipalAuth(AuthStrategy):
    def __init__(self, token: str):
        self.token = token

    def apply(self, headers: Dict[str, str], method: str, path_with_query: str, body_bytes: str) -> None:
        if not self.token:
            raise ValueError("principal bearer token is required")
        headers["Authorization"] = f"Bearer {self.token}"


class AgentHmacAuth(AuthStrategy):
    def __init__(self, agent_id: str, secret: str):
        self.agent_id = agent_id
        self.secret = secret

    def apply(self, headers: Dict[str, str], method: str, path_with_query: str, body_bytes: str) -> None:
        if not self.agent_id or not self.secret:
            raise ValueError("agent_id and secret are required for hmac auth")
        ts = str(int(time.time()))
        nonce = str(uuid.uuid4())
        body_hash = hashlib.sha256(body_bytes.encode("utf-8")).hexdigest() if body_bytes else ""
        signing = f"{method.upper()}\n{path_with_query}\n{ts}\n{nonce}\n{body_hash}"
        sig = base64.b64encode(hmac.new(self.secret.encode("utf-8"), signing.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
        headers["X-CL-Agent-Id"] = self.agent_id
        headers["X-CL-Timestamp"] = ts
        headers["X-CL-Nonce"] = nonce
        headers["X-CL-Signature"] = sig


class ContractLaneClient:
    def __init__(self, base_url: str, auth: Optional[AuthStrategy] = None, timeout_seconds: float = 10.0, retry: Optional[RetryConfig] = None, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.timeout_seconds = timeout_seconds
        self.retry = retry or RetryConfig()
        self.headers = headers or {}
        self.http = httpx.Client(timeout=self.timeout_seconds)

    def gate_status(self, gate_key: str, external_subject_id: str) -> Dict[str, Any]:
        path = f"/cel/gates/{quote(gate_key, safe='')}/status?external_subject_id={quote(external_subject_id, safe='')}"
        return self._request("GET", path, None, None, True)

    def gateStatus(self, gate_key: str, external_subject_id: str) -> Dict[str, Any]:
        return self.gate_status(gate_key, external_subject_id)

    def gate_resolve(self, gate_key: str, external_subject_id: str, actor_type: Optional[str], idempotency_key: str) -> Dict[str, Any]:
        if not idempotency_key:
            raise ValueError("idempotency key is required for gate_resolve")
        path = f"/cel/gates/{quote(gate_key, safe='')}/resolve"
        body: Dict[str, Any] = {"external_subject_id": external_subject_id, "idempotency_key": idempotency_key}
        if actor_type:
            body["actor_type"] = actor_type
        return self._request("POST", path, body, {"Idempotency-Key": idempotency_key}, True)

    def gateResolve(self, gate_key: str, external_subject_id: str, actor_type: Optional[str], idempotency_key: str) -> Dict[str, Any]:
        return self.gate_resolve(gate_key, external_subject_id, actor_type, idempotency_key)

    def contract_action(self, contract_id: str, action: str, body: Optional[Dict[str, Any]], idempotency_key: str) -> Dict[str, Any]:
        if not idempotency_key:
            raise ValueError("idempotency key is required for contract_action")
        path = f"/cel/contracts/{quote(contract_id, safe='')}/actions/{quote(action, safe='')}"
        return self._request("POST", path, body or {}, {"Idempotency-Key": idempotency_key}, True)

    def contractAction(self, contract_id: str, action: str, body: Optional[Dict[str, Any]], idempotency_key: str) -> Dict[str, Any]:
        return self.contract_action(contract_id, action, body, idempotency_key)

    def get_contract(self, contract_id: str) -> Dict[str, Any]:
        path = f"/cel/contracts/{quote(contract_id, safe='')}"
        return self._request("GET", path, None, None, True)

    def getContract(self, contract_id: str) -> Dict[str, Any]:
        return self.get_contract(contract_id)

    def evidence(self, gate_key: str, external_subject_id: str) -> Dict[str, Any]:
        path = f"/cel/gates/{quote(gate_key, safe='')}/evidence?external_subject_id={quote(external_subject_id, safe='')}"
        raw = self._request("GET", path, None, None, True)
        return raw.get("evidence", raw) if isinstance(raw, dict) else raw

    def _request(self, method: str, path_with_query: str, body: Optional[Dict[str, Any]], extra_headers: Optional[Dict[str, str]], retryable: bool) -> Dict[str, Any]:
        body_bytes = stable_json(body) if body is not None else ""
        attempts = self.retry.max_attempts if retryable else 1
        for attempt in range(1, attempts + 1):
            headers: Dict[str, str] = {
                "Accept": "application/json",
                "User-Agent": f"contractlane-python-sdk/0.1.0 api/{APIVersion}",
                **self.headers,
                **(extra_headers or {}),
            }
            if body_bytes:
                headers["Content-Type"] = "application/json"
            if self.auth:
                self.auth.apply(headers, method, path_with_query, body_bytes)
            try:
                resp = self.http.request(method, self.base_url + path_with_query, content=body_bytes.encode("utf-8") if body_bytes else None, headers=headers)
            except Exception:
                if attempt < attempts:
                    self._sleep(attempt, None)
                    continue
                raise
            if 200 <= resp.status_code < 300:
                return resp.json() if resp.content else {}
            if attempt < attempts and resp.status_code in (429, 502, 503, 504):
                self._sleep(attempt, resp.headers.get("Retry-After"))
                continue
            raise self._to_error(resp)
        raise RuntimeError("unreachable")

    def _sleep(self, attempt: int, retry_after: Optional[str]) -> None:
        if retry_after:
            try:
                sec = int(retry_after.strip())
                ms = min(sec * 1000, self.retry.max_delay_ms)
                time.sleep(ms / 1000)
                return
            except Exception:
                pass
        max_ms = min(self.retry.base_delay_ms * (2 ** (attempt - 1)), self.retry.max_delay_ms)
        time.sleep((random.randint(0, max(1, max_ms))) / 1000)

    def _to_error(self, resp: httpx.Response) -> SDKError:
        try:
            parsed = resp.json()
        except Exception:
            return SDKError(resp.status_code, None, resp.text or f"HTTP {resp.status_code}")
        inner = parsed.get("error") if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict) else parsed
        return SDKError(
            status_code=resp.status_code,
            error_code=inner.get("error_code") or inner.get("code"),
            message=inner.get("message") or f"HTTP {resp.status_code}",
            request_id=inner.get("request_id") or parsed.get("request_id"),
            details=inner.get("details") if isinstance(inner.get("details"), dict) else None,
        )


def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def new_idempotency_key() -> str:
    return str(uuid.uuid4())
