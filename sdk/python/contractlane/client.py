from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx
from nacl.signing import SigningKey
from nacl.signing import VerifyKey

APIVersion = "v1"


@dataclass
class RetryConfig:
    max_attempts: int = 3
    base_delay_ms: int = 200
    max_delay_ms: int = 5000


class SDKError(Exception):
    def __init__(self, status_code: int, error_code: Optional[str], message: str, request_id: Optional[str] = None, details: Optional[Any] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.request_id = request_id
        self.details = details


class IncompatibleNodeError(Exception):
    def __init__(self, missing_requirements: List[str]):
        self.missing_requirements = missing_requirements
        msg = "incompatible contractlane node"
        if missing_requirements:
            msg += ": missing " + ", ".join(missing_requirements)
        super().__init__(msg)


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
    def __init__(
        self,
        base_url: str,
        auth: Optional[AuthStrategy] = None,
        timeout_seconds: float = 10.0,
        retry: Optional[RetryConfig] = None,
        headers: Optional[Dict[str, str]] = None,
        disable_capability_check: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.timeout_seconds = timeout_seconds
        self.retry = retry or RetryConfig()
        self.headers = headers or {}
        self.disable_capability_check = disable_capability_check
        self.http = httpx.Client(timeout=self.timeout_seconds)
        self._signing_seed_ed25519: Optional[bytes] = None
        self._signing_key_id: Optional[str] = None
        self._signing_context: str = "contract-action"
        self._capabilities_cache: Optional[Dict[str, Any]] = None
        self._capabilities_fetched_at: float = 0.0
        self._capabilities_ttl_seconds: int = 300

    def fetch_capabilities(self) -> Dict[str, Any]:
        now = time.time()
        if (
            self._capabilities_cache is not None
            and self._capabilities_fetched_at > 0
            and (now - self._capabilities_fetched_at) < self._capabilities_ttl_seconds
        ):
            return self._capabilities_cache
        caps = self._request("GET", "/cel/.well-known/contractlane", None, None, True)
        self._capabilities_cache = caps
        self._capabilities_fetched_at = now
        return caps

    def require_protocol_v1(self) -> None:
        caps = self.fetch_capabilities()
        missing: List[str] = []

        protocol = caps.get("protocol") if isinstance(caps, dict) else {}
        evidence = caps.get("evidence") if isinstance(caps, dict) else {}
        signatures = caps.get("signatures") if isinstance(caps, dict) else {}

        protocol_name = protocol.get("name") if isinstance(protocol, dict) else None
        protocol_versions = protocol.get("versions") if isinstance(protocol, dict) else []
        evidence_bundle_versions = evidence.get("bundle_versions") if isinstance(evidence, dict) else []
        evidence_always_present = evidence.get("always_present_artifacts") if isinstance(evidence, dict) else []
        signatures_envelopes = signatures.get("envelopes") if isinstance(signatures, dict) else []
        signatures_algorithms = signatures.get("algorithms") if isinstance(signatures, dict) else []

        if protocol_name != "contractlane":
            missing.append("protocol.name=contractlane")
        if not isinstance(protocol_versions, list) or "v1" not in protocol_versions:
            missing.append("protocol.versions contains v1")
        if not isinstance(evidence_bundle_versions, list) or "evidence-v1" not in evidence_bundle_versions:
            missing.append("evidence.bundle_versions contains evidence-v1")
        if not isinstance(signatures_envelopes, list) or "sig-v1" not in signatures_envelopes:
            missing.append("signatures.envelopes contains sig-v1")
        if not isinstance(signatures_algorithms, list) or "ed25519" not in signatures_algorithms:
            missing.append("signatures.algorithms contains ed25519")
        if not isinstance(evidence_always_present, list) or "anchors" not in evidence_always_present:
            missing.append("evidence.always_present_artifacts contains anchors")
        if not isinstance(evidence_always_present, list) or "webhook_receipts" not in evidence_always_present:
            missing.append("evidence.always_present_artifacts contains webhook_receipts")

        if missing:
            raise IncompatibleNodeError(missing)

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

    def create_contract(
        self,
        actor_context: Dict[str, Any],
        template_id: str,
        counterparty: Dict[str, Any],
        initial_variables: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "actor_context": actor_context,
            "template_id": template_id,
            "counterparty": counterparty,
        }
        if initial_variables is not None:
            body["initial_variables"] = initial_variables
        return self._request("POST", "/cel/contracts", body, None, True)

    def createContract(
        self,
        actor_context: Dict[str, Any],
        template_id: str,
        counterparty: Dict[str, Any],
        initial_variables: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return self.create_contract(
            actor_context=actor_context,
            template_id=template_id,
            counterparty=counterparty,
            initial_variables=initial_variables,
        )

    def evidence(self, gate_key: str, external_subject_id: str) -> Dict[str, Any]:
        path = f"/cel/gates/{quote(gate_key, safe='')}/evidence?external_subject_id={quote(external_subject_id, safe='')}"
        raw = self._request("GET", path, None, None, True)
        return raw.get("evidence", raw) if isinstance(raw, dict) else raw

    def get_contract_evidence(
        self,
        contract_id: str,
        format: Optional[str] = None,
        include: Optional[list[str]] = None,
        redact: Optional[str] = None,
    ) -> Dict[str, Any]:
        q: list[str] = []
        if format:
            q.append(f"format={quote(format, safe='')}")
        if include:
            q.append(f"include={quote(','.join(include), safe='')}")
        if redact:
            q.append(f"redact={quote(redact, safe='')}")
        suffix = ("?" + "&".join(q)) if q else ""
        path = f"/cel/contracts/{quote(contract_id, safe='')}/evidence{suffix}"
        return self._request("GET", path, None, None, True)

    def get_contract_render(
        self,
        contract_id: str,
        format: Optional[str] = None,
        locale: Optional[str] = None,
        include_meta: Optional[bool] = None,
    ) -> Dict[str, Any]:
        q: list[str] = []
        if format:
            q.append(f"format={quote(format, safe='')}")
        if locale:
            q.append(f"locale={quote(locale, safe='')}")
        if include_meta is not None:
            q.append(f"include_meta={'true' if include_meta else 'false'}")
        suffix = ("?" + "&".join(q)) if q else ""
        path = f"/cel/contracts/{quote(contract_id, safe='')}/render{suffix}"
        return self._request("GET", path, None, None, True)

    def render_template(
        self,
        template_id: str,
        version: str,
        variables: Dict[str, str],
        format: Optional[str] = None,
        locale: Optional[str] = None,
    ) -> Dict[str, Any]:
        path = f"/cel/templates/{quote(template_id, safe='')}/versions/{quote(version, safe='')}/render"
        body: Dict[str, Any] = {"variables": variables}
        if format:
            body["format"] = format
        if locale:
            body["locale"] = locale
        return self._request("POST", path, body, None, True)

    def create_template(self, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._request("POST", "/cel/admin/templates", payload, headers, True)

    def update_template(self, template_id: str, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}"
        return self._request("PUT", path, payload, headers, True)

    def publish_template(self, template_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}:publish"
        return self._request("POST", path, {}, headers, True)

    def archive_template(self, template_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}:archive"
        return self._request("POST", path, {}, headers, True)

    def clone_template(self, template_id: str, payload: Dict[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}:clone"
        return self._request("POST", path, payload, headers, True)

    def get_template_admin(self, template_id: str) -> Dict[str, Any]:
        path = f"/cel/admin/templates/{quote(template_id, safe='')}"
        return self._request("GET", path, None, None, True)

    def list_templates_admin(
        self,
        *,
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        owner_principal_id: Optional[str] = None,
        contract_type: Optional[str] = None,
        jurisdiction: Optional[str] = None,
    ) -> Dict[str, Any]:
        q: list[str] = []
        if status:
            q.append(f"status={quote(status, safe='')}")
        if visibility:
            q.append(f"visibility={quote(visibility, safe='')}")
        if owner_principal_id:
            q.append(f"owner_principal_id={quote(owner_principal_id, safe='')}")
        if contract_type:
            q.append(f"contract_type={quote(contract_type, safe='')}")
        if jurisdiction:
            q.append(f"jurisdiction={quote(jurisdiction, safe='')}")
        suffix = ("?" + "&".join(q)) if q else ""
        return self._request("GET", f"/cel/admin/templates{suffix}", None, None, True)

    def list_template_shares(self, template_id: str) -> Dict[str, Any]:
        path = f"/cel/admin/templates/{quote(template_id, safe='')}/shares"
        return self._request("GET", path, None, None, True)

    def add_template_share(self, template_id: str, principal_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}/shares"
        return self._request("POST", path, {"principal_id": principal_id}, headers, True)

    def remove_template_share(self, template_id: str, principal_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        path = f"/cel/admin/templates/{quote(template_id, safe='')}/shares/{quote(principal_id, safe='')}"
        return self._request("DELETE", path, None, headers, True)

    def createTemplate(self, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.create_template(payload, idempotency_key=idempotency_key)

    def updateTemplate(self, template_id: str, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.update_template(template_id, payload, idempotency_key=idempotency_key)

    def publishTemplate(self, template_id: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.publish_template(template_id, idempotency_key=idempotency_key)

    def archiveTemplate(self, template_id: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.archive_template(template_id, idempotency_key=idempotency_key)

    def cloneTemplate(self, template_id: str, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.clone_template(template_id, payload, idempotency_key=idempotency_key)

    def getTemplateAdmin(self, template_id: str) -> Dict[str, Any]:
        return self.get_template_admin(template_id)

    def listTemplatesAdmin(
        self,
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        owner_principal_id: Optional[str] = None,
        contract_type: Optional[str] = None,
        jurisdiction: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.list_templates_admin(
            status=status,
            visibility=visibility,
            owner_principal_id=owner_principal_id,
            contract_type=contract_type,
            jurisdiction=jurisdiction,
        )

    def listTemplateShares(self, template_id: str) -> Dict[str, Any]:
        return self.list_template_shares(template_id)

    def addTemplateShare(self, template_id: str, principal_id: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.add_template_share(template_id, principal_id, idempotency_key=idempotency_key)

    def removeTemplateShare(self, template_id: str, principal_id: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self.remove_template_share(template_id, principal_id, idempotency_key=idempotency_key)

    def set_signing_key_ed25519(self, seed32: bytes, key_id: Optional[str] = None) -> None:
        if not isinstance(seed32, (bytes, bytearray)) or len(seed32) != 32:
            raise ValueError("ed25519 signing key seed must be 32 bytes")
        self._signing_seed_ed25519 = bytes(seed32)
        self._signing_key_id = key_id

    def set_signing_context(self, context: str) -> None:
        self._signing_context = context

    def approval_decide(
        self,
        approval_request_id: str,
        actor_context: Dict[str, Any],
        decision: str,
        signed_payload: Dict[str, Any],
        signature: Optional[Dict[str, Any]] = None,
        signed_payload_hash: Optional[str] = None,
        signature_envelope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not approval_request_id:
            raise ValueError("approval_request_id is required")
        body: Dict[str, Any] = {
            "actor_context": actor_context,
            "decision": decision,
            "signed_payload": signed_payload,
        }

        if signature_envelope is None and self._signing_seed_ed25519 is not None:
            if not self.disable_capability_check:
                self.require_protocol_v1()
            signature_envelope = build_signature_envelope_v1(
                payload=signed_payload,
                signing_key=self._signing_seed_ed25519,
                issued_at=datetime.now(timezone.utc),
                context=self._signing_context or "contract-action",
                key_id=self._signing_key_id,
            )
            body["signed_payload_hash"] = _canonical_sha256_hex(signed_payload)
        elif signed_payload_hash:
            body["signed_payload_hash"] = signed_payload_hash

        if signature_envelope is not None:
            body["signature_envelope"] = signature_envelope
        else:
            body["signature"] = signature or {"type": "WEBAUTHN_ASSERTION", "assertion_response": {}}

        path = f"/cel/approvals/{quote(approval_request_id, safe='')}:decide"
        return self._request("POST", path, body, None, True)

    def approvalDecide(
        self,
        approval_request_id: str,
        actor_context: Dict[str, Any],
        decision: str,
        signed_payload: Dict[str, Any],
        signature: Optional[Dict[str, Any]] = None,
        signed_payload_hash: Optional[str] = None,
        signature_envelope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.approval_decide(
            approval_request_id=approval_request_id,
            actor_context=actor_context,
            decision=decision,
            signed_payload=signed_payload,
            signature=signature,
            signed_payload_hash=signed_payload_hash,
            signature_envelope=signature_envelope,
        )

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
            details=inner.get("details"),
        )


def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_json_bytes(obj: Any) -> bytes:
    return stable_json(obj).encode("utf-8")


def _canonical_sha256_hex(obj: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(obj)).hexdigest()


def _format_issued_at_utc(issued_at: datetime) -> str:
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("issued_at must be timezone-aware UTC")
    if issued_at.utcoffset() != timezone.utc.utcoffset(issued_at):
        raise ValueError("issued_at must be UTC")
    return issued_at.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def build_signature_envelope_v1(
    payload: Dict[str, Any],
    signing_key: bytes,
    issued_at: datetime,
    context: str = "contract-action",
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) != 32:
        raise ValueError("signing_key must be 32 bytes ed25519 seed")

    payload_hash = _canonical_sha256_hex(payload)
    payload_hash_bytes = bytes.fromhex(payload_hash)

    sk = SigningKey(bytes(signing_key))
    vk_raw = bytes(sk.verify_key)
    sig_raw = sk.sign(payload_hash_bytes).signature

    env: Dict[str, Any] = {
        "version": "sig-v1",
        "algorithm": "ed25519",
        "public_key": base64.b64encode(vk_raw).decode("ascii"),
        "signature": base64.b64encode(sig_raw).decode("ascii"),
        "payload_hash": payload_hash,
        "issued_at": _format_issued_at_utc(issued_at),
        "context": context,
    }
    if key_id:
        env["key_id"] = key_id
    return env


def agent_id_from_public_key(pub: bytes) -> str:
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    b64 = base64.urlsafe_b64encode(bytes(pub)).decode("ascii").rstrip("=")
    return "agent:pk:ed25519:" + b64


def parse_agent_id(id: str) -> tuple[str, bytes]:
    parts = id.split(":")
    if len(parts) != 4:
        raise ValueError("invalid agent id format")
    if parts[0] != "agent" or parts[1] != "pk":
        raise ValueError("invalid agent id prefix")
    if parts[2] != "ed25519":
        raise ValueError("unsupported algorithm")
    encoded = parts[3]
    if not encoded:
        raise ValueError("missing public key")
    if "=" in encoded:
        raise ValueError("invalid base64url padding")
    if re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        raise ValueError("invalid base64url public key")
    pad_len = (4 - (len(encoded) % 4)) % 4
    try:
        pub = base64.urlsafe_b64decode(encoded + ("=" * pad_len))
    except Exception as exc:
        raise ValueError("invalid base64url public key") from exc
    if len(pub) != 32:
        raise ValueError("invalid ed25519 public key length")
    return "ed25519", pub


def is_valid_agent_id(id: str) -> bool:
    try:
        parse_agent_id(id)
        return True
    except Exception:
        return False


def _parse_rfc3339_utc(ts: str, field_name: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError(f"{field_name} must be RFC3339 UTC")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError(f"{field_name} must be RFC3339 UTC") from exc
    if dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ValueError(f"{field_name} must be RFC3339 UTC")
    return dt.astimezone(timezone.utc)


def _validate_base64url_no_padding(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
    if "=" in value:
        raise ValueError(f"{field_name} must be base64url without padding")
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError(f"{field_name} must be base64url without padding")
    pad_len = (4 - (len(value) % 4)) % 4
    try:
        base64.urlsafe_b64decode(value + ("=" * pad_len))
    except Exception as exc:
        raise ValueError(f"{field_name} must be base64url without padding") from exc


def _validate_commerce_intent_v1(intent: Dict[str, Any]) -> Dict[str, Any]:
    if intent.get("version") != "commerce-intent-v1":
        raise ValueError("version must be commerce-intent-v1")
    if not isinstance(intent.get("intent_id"), str) or not intent["intent_id"]:
        raise ValueError("intent_id is required")
    if not isinstance(intent.get("contract_id"), str) or not intent["contract_id"]:
        raise ValueError("contract_id is required")
    if not is_valid_agent_id(str(intent.get("buyer_agent", ""))):
        raise ValueError("buyer_agent must be valid agent-id-v1")
    if not is_valid_agent_id(str(intent.get("seller_agent", ""))):
        raise ValueError("seller_agent must be valid agent-id-v1")
    items = intent.get("items")
    if not isinstance(items, list) or len(items) == 0:
        raise ValueError("items are required")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("item must be object")
        if not isinstance(item.get("sku"), str) or not item["sku"]:
            raise ValueError("item.sku is required")
        qty = item.get("qty")
        if not isinstance(qty, int) or qty < 1:
            raise ValueError("item.qty must be integer >= 1")
        unit_price = item.get("unit_price")
        if not isinstance(unit_price, dict):
            raise ValueError("item.unit_price is required")
        if not isinstance(unit_price.get("currency"), str) or not isinstance(unit_price.get("amount"), str):
            raise ValueError("item.unit_price currency/amount must be strings")
    total = intent.get("total")
    if not isinstance(total, dict):
        raise ValueError("total is required")
    if not isinstance(total.get("currency"), str) or not isinstance(total.get("amount"), str):
        raise ValueError("total currency/amount must be strings")
    _parse_rfc3339_utc(str(intent.get("expires_at", "")), "expires_at")
    _validate_base64url_no_padding(str(intent.get("nonce", "")), "nonce")
    metadata = intent.get("metadata")
    if metadata is None:
        intent["metadata"] = {}
    elif not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    return intent


def _validate_commerce_accept_v1(acc: Dict[str, Any]) -> Dict[str, Any]:
    if acc.get("version") != "commerce-accept-v1":
        raise ValueError("version must be commerce-accept-v1")
    if not isinstance(acc.get("contract_id"), str) or not acc["contract_id"]:
        raise ValueError("contract_id is required")
    intent_hash = acc.get("intent_hash")
    if not isinstance(intent_hash, str) or re.fullmatch(r"[0-9a-f]{64}", intent_hash) is None:
        raise ValueError("intent_hash must be lowercase hex sha256")
    _parse_rfc3339_utc(str(acc.get("accepted_at", "")), "accepted_at")
    _validate_base64url_no_padding(str(acc.get("nonce", "")), "nonce")
    metadata = acc.get("metadata")
    if metadata is None:
        acc["metadata"] = {}
    elif not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    return acc


def hash_commerce_intent_v1(intent: Dict[str, Any]) -> str:
    normalized = _validate_commerce_intent_v1(dict(intent))
    return _canonical_sha256_hex(normalized)


def sign_commerce_intent_v1(intent: Dict[str, Any], signing_key: bytes, issued_at: str) -> Dict[str, Any]:
    normalized = _validate_commerce_intent_v1(dict(intent))
    issued_dt = _parse_rfc3339_utc(issued_at, "issued_at")
    return build_signature_envelope_v1(
        payload=normalized,
        signing_key=signing_key,
        issued_at=issued_dt,
        context="commerce-intent",
    )


def verify_commerce_intent_v1(intent: Dict[str, Any], sig: Dict[str, Any]) -> None:
    normalized = _validate_commerce_intent_v1(dict(intent))
    if sig.get("version") != "sig-v1":
        raise ValueError("signature_envelope version must be sig-v1")
    if sig.get("algorithm") != "ed25519":
        raise ValueError("signature_envelope algorithm must be ed25519")
    if "context" in sig and sig.get("context") != "commerce-intent":
        raise ValueError("signature context mismatch")
    _parse_rfc3339_utc(str(sig.get("issued_at", "")), "issued_at")
    expected_hash = hash_commerce_intent_v1(normalized)
    if sig.get("payload_hash") != expected_hash:
        raise ValueError("payload hash mismatch")
    try:
        pub = base64.b64decode(str(sig.get("public_key", "")))
        signature = base64.b64decode(str(sig.get("signature", "")))
    except Exception as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(pub) != 32 or len(signature) != 64:
        raise ValueError("invalid signature encoding")
    VerifyKey(pub).verify(bytes.fromhex(expected_hash), signature)


def hash_commerce_accept_v1(acc: Dict[str, Any]) -> str:
    normalized = _validate_commerce_accept_v1(dict(acc))
    return _canonical_sha256_hex(normalized)


def sign_commerce_accept_v1(acc: Dict[str, Any], signing_key: bytes, issued_at: str) -> Dict[str, Any]:
    normalized = _validate_commerce_accept_v1(dict(acc))
    issued_dt = _parse_rfc3339_utc(issued_at, "issued_at")
    return build_signature_envelope_v1(
        payload=normalized,
        signing_key=signing_key,
        issued_at=issued_dt,
        context="commerce-accept",
    )


def verify_commerce_accept_v1(acc: Dict[str, Any], sig: Dict[str, Any]) -> None:
    normalized = _validate_commerce_accept_v1(dict(acc))
    if sig.get("version") != "sig-v1":
        raise ValueError("signature_envelope version must be sig-v1")
    if sig.get("algorithm") != "ed25519":
        raise ValueError("signature_envelope algorithm must be ed25519")
    if "context" in sig and sig.get("context") != "commerce-accept":
        raise ValueError("signature context mismatch")
    _parse_rfc3339_utc(str(sig.get("issued_at", "")), "issued_at")
    expected_hash = hash_commerce_accept_v1(normalized)
    if sig.get("payload_hash") != expected_hash:
        raise ValueError("payload hash mismatch")
    try:
        pub = base64.b64decode(str(sig.get("public_key", "")))
        signature = base64.b64decode(str(sig.get("signature", "")))
    except Exception as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(pub) != 32 or len(signature) != 64:
        raise ValueError("invalid signature encoding")
    VerifyKey(pub).verify(bytes.fromhex(expected_hash), signature)


_DELEGATION_ALLOWED_TOP_LEVEL_KEYS = {
    "version",
    "delegation_id",
    "issuer_agent",
    "subject_agent",
    "scopes",
    "constraints",
    "nonce",
    "issued_at",
}

_DELEGATION_ALLOWED_CONSTRAINT_KEYS = {
    "contract_id",
    "counterparty_agent",
    "max_amount",
    "valid_from",
    "valid_until",
    "max_uses",
    "purpose",
}

_DELEGATION_KNOWN_SCOPES = {
    "commerce:intent:sign",
    "commerce:accept:sign",
    "cel:action:execute",
    "cel:approval:sign",
    "settlement:attest",
}

_AMOUNT_EXPONENTS = {
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "JPY": 0,
    "KRW": 0,
    "INR": 2,
    "CHF": 2,
    "CAD": 2,
    "AUD": 2,
}


def _parse_normalized_amount_to_minor(amount: Dict[str, Any]) -> int:
    if not isinstance(amount, dict):
        raise ValueError("amount must be object")
    currency = str(amount.get("currency", "")).strip().upper()
    value = str(amount.get("amount", "")).strip()
    if re.fullmatch(r"[A-Z]{3}", currency) is None:
        raise ValueError("amount currency must be ISO4217 uppercase 3 letters")
    if currency not in _AMOUNT_EXPONENTS:
        raise ValueError("unknown currency")
    if value == "" or value.startswith("+") or ("e" in value.lower()):
        raise ValueError("amount must be normalized decimal")
    if value.count(".") > 1:
        raise ValueError("amount must be normalized decimal")
    if value.startswith("0") and value not in {"0"} and not value.startswith("0."):
        raise ValueError("amount must be normalized decimal")
    parts = value.split(".")
    if not parts[0].isdigit():
        raise ValueError("amount must be normalized decimal")
    frac = parts[1] if len(parts) == 2 else ""
    if frac:
        if not frac.isdigit() or frac.endswith("0"):
            raise ValueError("amount must be normalized decimal")
    exp = _AMOUNT_EXPONENTS[currency]
    if exp == 0:
        if frac:
            raise ValueError("amount must be normalized decimal")
        return int(parts[0])
    if len(frac) > exp:
        raise ValueError("amount precision exceeds currency minor units")
    frac_padded = frac + ("0" * (exp - len(frac)))
    return int(parts[0]) * (10**exp) + (int(frac_padded) if frac_padded else 0)


def _validate_delegation_v1(payload: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(payload.keys()) - _DELEGATION_ALLOWED_TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(f"unknown delegation keys: {sorted(unknown)}")
    if payload.get("version") != "delegation-v1":
        raise ValueError("version must be delegation-v1")
    if not isinstance(payload.get("delegation_id"), str) or not payload["delegation_id"].strip():
        raise ValueError("delegation_id is required")
    if not is_valid_agent_id(str(payload.get("issuer_agent", ""))):
        raise ValueError("issuer_agent must be valid agent-id-v1")
    if not is_valid_agent_id(str(payload.get("subject_agent", ""))):
        raise ValueError("subject_agent must be valid agent-id-v1")
    scopes = payload.get("scopes")
    if not isinstance(scopes, list) or len(scopes) == 0:
        raise ValueError("scopes must be non-empty")
    normalized_scopes = sorted(set(str(s).strip() for s in scopes))
    if not all(s in _DELEGATION_KNOWN_SCOPES for s in normalized_scopes):
        raise ValueError("scopes contain unknown values")

    constraints = payload.get("constraints")
    if not isinstance(constraints, dict):
        raise ValueError("constraints is required")
    unknown_constraints = set(constraints.keys()) - _DELEGATION_ALLOWED_CONSTRAINT_KEYS
    if unknown_constraints:
        raise ValueError(f"unknown delegation constraints keys: {sorted(unknown_constraints)}")
    if not isinstance(constraints.get("contract_id"), str) or not constraints["contract_id"]:
        raise ValueError("constraints.contract_id is required")
    cp = constraints.get("counterparty_agent")
    if not isinstance(cp, str) or not cp:
        raise ValueError("constraints.counterparty_agent is required")
    if cp != "*" and not is_valid_agent_id(cp):
        raise ValueError("constraints.counterparty_agent must be * or valid agent-id-v1")
    valid_from = _parse_rfc3339_utc(str(constraints.get("valid_from", "")), "constraints.valid_from")
    valid_until = _parse_rfc3339_utc(str(constraints.get("valid_until", "")), "constraints.valid_until")
    if valid_from > valid_until:
        raise ValueError("constraints.valid_from must be <= constraints.valid_until")
    if "max_uses" in constraints and constraints.get("max_uses") is not None:
        max_uses = constraints.get("max_uses")
        if not isinstance(max_uses, int) or max_uses < 1:
            raise ValueError("constraints.max_uses must be integer >=1")
    if constraints.get("max_amount") is not None:
        _parse_normalized_amount_to_minor(constraints["max_amount"])
    _validate_base64url_no_padding(str(payload.get("nonce", "")), "nonce")
    _parse_rfc3339_utc(str(payload.get("issued_at", "")), "issued_at")

    out = dict(payload)
    out["scopes"] = normalized_scopes
    return out


def hash_delegation_v1(payload: Dict[str, Any]) -> str:
    normalized = _validate_delegation_v1(dict(payload))
    return _canonical_sha256_hex(normalized)


def sign_delegation_v1(payload: Dict[str, Any], signing_key: bytes, issued_at: str) -> Dict[str, Any]:
    normalized = _validate_delegation_v1(dict(payload))
    issued_dt = _parse_rfc3339_utc(issued_at, "issued_at")
    return build_signature_envelope_v1(
        payload=normalized,
        signing_key=signing_key,
        issued_at=issued_dt,
        context="delegation",
    )


def verify_delegation_v1(payload: Dict[str, Any], sig: Dict[str, Any]) -> None:
    normalized = _validate_delegation_v1(dict(payload))
    if sig.get("version") != "sig-v1":
        raise ValueError("signature_envelope version must be sig-v1")
    if sig.get("algorithm") != "ed25519":
        raise ValueError("signature_envelope algorithm must be ed25519")
    if "context" in sig and sig.get("context") != "delegation":
        raise ValueError("signature context mismatch")
    _parse_rfc3339_utc(str(sig.get("issued_at", "")), "issued_at")
    expected_hash = hash_delegation_v1(normalized)
    if sig.get("payload_hash") != expected_hash:
        raise ValueError("payload hash mismatch")
    try:
        pub = base64.b64decode(str(sig.get("public_key", "")))
        signature = base64.b64decode(str(sig.get("signature", "")))
    except Exception as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(pub) != 32 or len(signature) != 64:
        raise ValueError("invalid signature encoding")
    VerifyKey(pub).verify(bytes.fromhex(expected_hash), signature)
    issuer = agent_id_from_public_key(pub)
    if issuer != normalized["issuer_agent"]:
        raise ValueError("signature public key does not match issuer_agent")


def evaluate_delegation_constraints(constraints: Dict[str, Any], eval_ctx: Dict[str, Any]) -> None:
    c = _validate_delegation_v1({
        "version": "delegation-v1",
        "delegation_id": "del_eval",
        "issuer_agent": eval_ctx.get("issuer_agent", eval_ctx.get("subject_agent", "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")),
        "subject_agent": eval_ctx.get("subject_agent", "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"),
        "scopes": [eval_ctx.get("scope", "commerce:intent:sign")],
        "constraints": constraints,
        "nonce": "bm9uY2VfdjE",
        "issued_at": eval_ctx.get("issued_at_utc", "2026-02-18T00:00:00Z"),
    })["constraints"]
    if c["contract_id"] != "*" and c["contract_id"] != eval_ctx.get("contract_id"):
        raise ValueError("delegation_constraints_failed")
    cp = eval_ctx.get("counterparty_agent")
    if c["counterparty_agent"] != "*" and c["counterparty_agent"] != cp:
        raise ValueError("delegation_constraints_failed")
    at = _parse_rfc3339_utc(str(eval_ctx.get("issued_at_utc", "")), "issued_at_utc")
    vf = _parse_rfc3339_utc(str(c["valid_from"]), "constraints.valid_from")
    vu = _parse_rfc3339_utc(str(c["valid_until"]), "constraints.valid_until")
    if at < vf or at > vu:
        raise ValueError("delegation_expired")
    if c.get("max_amount") is not None and eval_ctx.get("payment_amount") is not None:
        mx = _parse_normalized_amount_to_minor(c["max_amount"])
        pay = _parse_normalized_amount_to_minor(eval_ctx["payment_amount"])
        if str(c["max_amount"].get("currency", "")).upper() != str(eval_ctx["payment_amount"].get("currency", "")).upper() or pay > mx:
            raise ValueError("delegation_amount_exceeded")


def new_idempotency_key() -> str:
    return str(uuid.uuid4())


class VerifyFailureCode:
    VERIFIED = "VERIFIED"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    RULES_FAILED = "RULES_FAILED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class VerifyReport:
    ok: bool
    code: str
    proof_id: str = ""
    message: str = ""


def canonicalize(obj: Any) -> bytes:
    return _canonical_json_bytes(obj)


def sha256_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    return hashlib.sha256(bytes(data)).hexdigest()


def canonical_sha256_hex(obj: Any) -> str:
    return _canonical_sha256_hex(obj)


def parse_sig_v1(sig: Dict[str, Any], expected_context: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(sig, dict):
        raise ValueError("signature_envelope must be object")
    allowed = {"version", "algorithm", "public_key", "signature", "payload_hash", "issued_at", "key_id", "context"}
    unknown = set(sig.keys()) - allowed
    if unknown:
        raise ValueError(f"unknown signature keys: {sorted(unknown)}")
    if sig.get("version") != "sig-v1":
        raise ValueError("signature_envelope version must be sig-v1")
    if sig.get("algorithm") != "ed25519":
        raise ValueError("signature_envelope algorithm must be ed25519")
    payload_hash = str(sig.get("payload_hash", ""))
    if re.fullmatch(r"[0-9a-f]{64}", payload_hash) is None:
        raise ValueError("payload_hash must be lowercase hex sha256")
    _parse_rfc3339_utc(str(sig.get("issued_at", "")), "issued_at")
    if expected_context and sig.get("context") not in (None, "", expected_context):
        raise ValueError("signature context mismatch")
    try:
        pub = base64.b64decode(str(sig.get("public_key", "")))
        signature = base64.b64decode(str(sig.get("signature", "")))
    except Exception as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(pub) != 32 or len(signature) != 64:
        raise ValueError("invalid signature encoding")
    return sig


def normalize_amount_v1(currency: str, minor_units: int) -> Dict[str, str]:
    if not isinstance(minor_units, int) or minor_units < 0:
        raise ValueError("minor units must be non-negative integer")
    ccy = str(currency).strip().upper()
    if re.fullmatch(r"[A-Z]{3}", ccy) is None:
        raise ValueError("currency must be ISO4217 uppercase 3 letters")
    exp = _AMOUNT_EXPONENTS.get(ccy)
    if exp is None:
        raise ValueError("unknown currency")
    if exp == 0:
        return {"currency": ccy, "amount": str(minor_units)}
    base = 10**exp
    integer = minor_units // base
    fraction = minor_units % base
    amount = f"{integer}.{fraction:0{exp}d}".rstrip("0").rstrip(".")
    if amount == "":
        amount = "0"
    return {"currency": ccy, "amount": amount}


def parse_amount_v1(amount: Dict[str, Any]) -> int:
    return _parse_normalized_amount_to_minor(amount)


def parse_delegation_v1(payload: Dict[str, Any]) -> Dict[str, Any]:
    return _validate_delegation_v1(dict(payload))


_DELEGATION_REVOCATION_ALLOWED_KEYS = {
    "version",
    "revocation_id",
    "delegation_id",
    "issuer_agent",
    "nonce",
    "issued_at",
    "reason",
}


def parse_delegation_revocation_v1(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("delegation revocation payload must be object")
    unknown = set(payload.keys()) - _DELEGATION_REVOCATION_ALLOWED_KEYS
    if unknown:
        raise ValueError(f"unknown delegation revocation keys: {sorted(unknown)}")
    if payload.get("version") != "delegation-revocation-v1":
        raise ValueError("version must be delegation-revocation-v1")
    if not isinstance(payload.get("revocation_id"), str) or not payload["revocation_id"].strip():
        raise ValueError("revocation_id is required")
    if not isinstance(payload.get("delegation_id"), str) or not payload["delegation_id"].strip():
        raise ValueError("delegation_id is required")
    issuer = str(payload.get("issuer_agent", "")).strip()
    if not is_valid_agent_id(issuer):
        raise ValueError("issuer_agent must be valid agent-id-v1")
    _validate_base64url_no_padding(str(payload.get("nonce", "")), "nonce")
    _parse_rfc3339_utc(str(payload.get("issued_at", "")), "issued_at")
    out = dict(payload)
    out["issuer_agent"] = issuer
    if "reason" in out and out["reason"] is not None:
        out["reason"] = str(out["reason"]).strip()
    return out


def parse_proof_bundle_v1(proof: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(proof, dict):
        raise ValueError("proof bundle must be object")
    unknown = set(proof.keys()) - {"version", "protocol", "protocol_version", "bundle"}
    if unknown:
        raise ValueError(f"unknown proof bundle keys: {sorted(unknown)}")
    if proof.get("version") != "proof-bundle-v1":
        raise ValueError("version must be proof-bundle-v1")
    if proof.get("protocol") != "contract-lane":
        raise ValueError("protocol must be contract-lane")
    if str(proof.get("protocol_version", "")) != "1":
        raise ValueError("protocol_version must be 1")
    bundle = proof.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("bundle is required")
    contract = bundle.get("contract")
    if not isinstance(contract, dict) or not str(contract.get("contract_id", "")).strip():
        raise ValueError("bundle.contract.contract_id is required")
    evidence = bundle.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("bundle.evidence is required")
    return proof


def new_commerce_intent_v1(
    *,
    intent_id: str,
    contract_id: str,
    buyer_agent: str,
    seller_agent: str,
    items: List[Dict[str, Any]],
    total: Dict[str, Any],
    expires_at: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "version": "commerce-intent-v1",
        "intent_id": intent_id,
        "contract_id": contract_id,
        "buyer_agent": buyer_agent,
        "seller_agent": seller_agent,
        "items": items,
        "total": total,
        "expires_at": expires_at,
        "nonce": base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("="),
        "metadata": metadata or {},
    }
    return _validate_commerce_intent_v1(payload)


def new_commerce_accept_v1(
    *,
    contract_id: str,
    intent_hash: str,
    accepted_at: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = {
        "version": "commerce-accept-v1",
        "contract_id": contract_id,
        "intent_hash": intent_hash,
        "accepted_at": accepted_at,
        "nonce": base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("="),
        "metadata": metadata or {},
    }
    return _validate_commerce_accept_v1(payload)


def new_delegation_v1(
    *,
    delegation_id: str,
    issuer_agent: str,
    subject_agent: str,
    scopes: List[str],
    constraints: Dict[str, Any],
    issued_at: str,
) -> Dict[str, Any]:
    payload = {
        "version": "delegation-v1",
        "delegation_id": delegation_id,
        "issuer_agent": issuer_agent,
        "subject_agent": subject_agent,
        "scopes": scopes,
        "constraints": constraints,
        "nonce": base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("="),
        "issued_at": issued_at,
    }
    return _validate_delegation_v1(payload)


def new_delegation_revocation_v1(
    *,
    revocation_id: str,
    delegation_id: str,
    issuer_agent: str,
    issued_at: str,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {
        "version": "delegation-revocation-v1",
        "revocation_id": revocation_id,
        "delegation_id": delegation_id,
        "issuer_agent": issuer_agent,
        "nonce": base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("="),
        "issued_at": issued_at,
    }
    if reason is not None:
        payload["reason"] = reason
    return parse_delegation_revocation_v1(payload)


def sig_v1_sign(context: str, payload_hash: str, signing_key: bytes, issued_at: str, key_id: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(signing_key, (bytes, bytearray)) or len(signing_key) != 32:
        raise ValueError("signing_key must be 32 bytes ed25519 seed")
    if re.fullmatch(r"[0-9a-f]{64}", str(payload_hash)) is None:
        raise ValueError("payload_hash must be lowercase hex sha256")
    issued_dt = _parse_rfc3339_utc(issued_at, "issued_at")
    sk = SigningKey(bytes(signing_key))
    vk_raw = bytes(sk.verify_key)
    sig_raw = sk.sign(bytes.fromhex(payload_hash)).signature
    env: Dict[str, Any] = {
        "version": "sig-v1",
        "algorithm": "ed25519",
        "public_key": base64.b64encode(vk_raw).decode("ascii"),
        "signature": base64.b64encode(sig_raw).decode("ascii"),
        "payload_hash": str(payload_hash),
        "issued_at": _format_issued_at_utc(issued_dt),
        "context": context,
    }
    if key_id:
        env["key_id"] = key_id
    return env


def compute_proof_id(proof_bundle_v1: Dict[str, Any]) -> str:
    parse_proof_bundle_v1(dict(proof_bundle_v1))
    return _canonical_sha256_hex(proof_bundle_v1)


def _verify_proof_bundle_signatures(proof: Dict[str, Any]) -> None:
    artifacts = (((proof.get("bundle") or {}).get("evidence") or {}).get("artifacts") or {})
    if not isinstance(artifacts, dict):
        raise ValueError("evidence missing artifacts")
    for row in artifacts.get("commerce_intents", []) or []:
        if isinstance(row, dict) and isinstance(row.get("intent"), dict) and isinstance(row.get("buyer_signature"), dict):
            verify_commerce_intent_v1(dict(row["intent"]), dict(row["buyer_signature"]))
    for row in artifacts.get("commerce_accepts", []) or []:
        if isinstance(row, dict) and isinstance(row.get("accept"), dict) and isinstance(row.get("seller_signature"), dict):
            verify_commerce_accept_v1(dict(row["accept"]), dict(row["seller_signature"]))
    for row in artifacts.get("delegations", []) or []:
        if isinstance(row, dict) and isinstance(row.get("delegation"), dict) and isinstance(row.get("issuer_signature"), dict):
            verify_delegation_v1(dict(row["delegation"]), dict(row["issuer_signature"]))


def verify_proof_bundle_v1(proof_bundle_v1: Dict[str, Any]) -> VerifyReport:
    try:
        proof = parse_proof_bundle_v1(dict(proof_bundle_v1))
        proof_id = compute_proof_id(proof)
        evidence = (((proof.get("bundle") or {}).get("evidence")) or {})
        contract = evidence.get("contract") if isinstance(evidence, dict) else None
        if not isinstance(contract, dict):
            return VerifyReport(ok=False, code=VerifyFailureCode.INVALID_EVIDENCE, message="evidence.contract missing")
        if str(contract.get("contract_id", "")).strip() != str(((proof.get("bundle") or {}).get("contract") or {}).get("contract_id", "")).strip():
            return VerifyReport(ok=False, code=VerifyFailureCode.INVALID_EVIDENCE, message="contract/evidence contract_id mismatch")
        _verify_proof_bundle_signatures(proof)
        return VerifyReport(ok=True, code=VerifyFailureCode.VERIFIED, proof_id=proof_id)
    except Exception as exc:
        msg = str(exc)
        code = VerifyFailureCode.UNKNOWN_ERROR
        if "version must be proof-bundle-v1" in msg or "protocol_version must be 1" in msg or "bundle." in msg:
            code = VerifyFailureCode.INVALID_SCHEMA
        elif "evidence" in msg:
            code = VerifyFailureCode.INVALID_EVIDENCE
        elif "signature" in msg or "payload hash mismatch" in msg:
            code = VerifyFailureCode.INVALID_SIGNATURE
        elif "delegation_" in msg:
            code = VerifyFailureCode.AUTHORIZATION_FAILED
        elif "rules_" in msg:
            code = VerifyFailureCode.RULES_FAILED
        else:
            code = VerifyFailureCode.MALFORMED_INPUT
        return VerifyReport(ok=False, code=code, message=msg)
