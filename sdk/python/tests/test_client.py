import json
import base64
from pathlib import Path
from datetime import datetime, timezone

import httpx
import pytest

from contractlane.client import (
    ContractLaneClient,
    IncompatibleNodeError,
    PrincipalAuth,
    RetryConfig,
    agent_id_from_public_key,
    parse_agent_id,
    is_valid_agent_id,
    hash_commerce_intent_v1,
    sign_commerce_intent_v1,
    verify_commerce_intent_v1,
    hash_commerce_accept_v1,
    sign_commerce_accept_v1,
    verify_commerce_accept_v1,
    hash_delegation_v1,
    sign_delegation_v1,
    verify_delegation_v1,
    evaluate_delegation_constraints,
    _canonical_sha256_hex,
    build_signature_envelope_v1,
    canonicalize,
    sha256_hex,
    canonical_sha256_hex,
    parse_sig_v1,
    parse_delegation_revocation_v1,
    parse_proof_bundle_v1,
    compute_proof_id,
    verify_proof_bundle_v1,
    VerifyFailureCode,
)


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
        "well_known_protocol_capabilities.json",
        "gate_status_done.json",
        "gate_status_blocked.json",
        "gate_resolve_requires_idempotency.json",
        "error_model_401.json",
        "retry_429_then_success.json",
        "sig_v1_approval_happy_path.json",
        "evidence_contains_anchors_and_receipts.json",
        "evp_verify_bundle_good.json",
        "agent_id_v1_roundtrip.json",
    ]:
        p = root / "conformance" / "cases" / name
        assert p.exists(), f"missing {p}"
        json.loads(p.read_text())


def test_agent_id_roundtrip():
    pub = bytes(range(32))
    aid = agent_id_from_public_key(pub)
    assert aid == "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    algo, parsed = parse_agent_id(aid)
    assert algo == "ed25519"
    assert parsed == pub
    assert is_valid_agent_id(aid) is True


def test_agent_id_reject_cases():
    bad = [
        "Agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "agent:pk:rsa:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "agent:pk:ed25519:AAECAwQF$gcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg",
    ]
    for aid in bad:
        with pytest.raises(ValueError):
            parse_agent_id(aid)
        assert is_valid_agent_id(aid) is False

    with pytest.raises(ValueError):
        agent_id_from_public_key(bytes(31))
    with pytest.raises(ValueError):
        agent_id_from_public_key(bytes(33))


def test_agent_id_conformance_fixture():
    root = Path(__file__).resolve().parents[3]
    fx = json.loads((root / "conformance" / "cases" / "agent_id_v1_roundtrip.json").read_text())
    pub = bytes.fromhex(fx["public_key_hex"])
    expected = fx["expected_agent_id"]
    assert agent_id_from_public_key(pub) == expected
    algo, parsed = parse_agent_id(expected)
    assert algo == "ed25519"
    assert parsed == pub
    assert is_valid_agent_id(expected) is True
    for aid in fx["invalid_agent_ids"]:
        assert is_valid_agent_id(aid) is False


def _fixed_intent() -> dict:
    return {
        "version": "commerce-intent-v1",
        "intent_id": "ci_test_001",
        "contract_id": "ctr_test_001",
        "buyer_agent": "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "seller_agent": "agent:pk:ed25519:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
        "items": [
            {"sku": "sku_alpha", "qty": 2, "unit_price": {"currency": "USD", "amount": "10.50"}},
            {"sku": "sku_beta", "qty": 1, "unit_price": {"currency": "USD", "amount": "5.00"}},
        ],
        "total": {"currency": "USD", "amount": "26.00"},
        "expires_at": "2026-02-20T12:00:00Z",
        "nonce": "bm9uY2VfdjE",
        "metadata": {},
    }


def _fixed_accept() -> dict:
    return {
        "version": "commerce-accept-v1",
        "contract_id": "ctr_test_001",
        "intent_hash": "f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f",
        "accepted_at": "2026-02-20T12:05:00Z",
        "nonce": "YWNjZXB0X25vbmNlX3Yx",
        "metadata": {},
    }


def test_commerce_intent_known_vector_hash():
    assert hash_commerce_intent_v1(_fixed_intent()) == "f400f47a36d29865f79e79be6a88364888c2c8bba1dfc277c4bff8781782aa4f"


def test_commerce_accept_known_vector_hash():
    assert hash_commerce_accept_v1(_fixed_accept()) == "670a209431d7b80bc997fabf40a707952a6494af07ddf374d4efdd4532449e21"


def test_commerce_intent_sign_verify():
    sig = sign_commerce_intent_v1(
        _fixed_intent(),
        bytes([11] * 32),
        "2026-02-20T11:00:00Z",
    )
    assert sig["context"] == "commerce-intent"
    verify_commerce_intent_v1(_fixed_intent(), sig)


def test_commerce_accept_sign_verify():
    sig = sign_commerce_accept_v1(
        _fixed_accept(),
        bytes([12] * 32),
        "2026-02-20T11:05:00Z",
    )
    assert sig["context"] == "commerce-accept"
    verify_commerce_accept_v1(_fixed_accept(), sig)


def test_commerce_verify_rejects_context_and_hash_mismatch():
    sig = sign_commerce_intent_v1(_fixed_intent(), bytes([13] * 32), "2026-02-20T11:10:00Z")
    bad_context = dict(sig)
    bad_context["context"] = "commerce-accept"
    with pytest.raises(ValueError):
        verify_commerce_intent_v1(_fixed_intent(), bad_context)

    bad_hash = dict(sig)
    bad_hash["payload_hash"] = "0" * 64
    with pytest.raises(ValueError):
        verify_commerce_intent_v1(_fixed_intent(), bad_hash)


def test_build_signature_envelope_v1_ed25519():
    payload = {"b": "two", "a": 1}
    seed = bytes([7] * 32)
    issued_at = datetime(2026, 2, 18, 12, 0, 0, 123456, tzinfo=timezone.utc)

    env = build_signature_envelope_v1(payload, seed, issued_at, context="contract-action", key_id="k1")

    assert env["version"] == "sig-v1"
    assert env["algorithm"] == "ed25519"
    assert env["context"] == "contract-action"
    assert env["key_id"] == "k1"
    assert env["payload_hash"] == _canonical_sha256_hex(payload)
    assert env["issued_at"].endswith("Z")
    assert len(base64.b64decode(env["public_key"])) == 32
    assert len(base64.b64decode(env["signature"])) == 64


def test_approval_decide_uses_sigv1_when_signing_key_configured():
    captured = {}
    caps_hits = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/cel/.well-known/contractlane":
            caps_hits["n"] += 1
            return httpx.Response(
                200,
                json={
                    "protocol": {"name": "contractlane", "versions": ["v1"]},
                    "evidence": {"bundle_versions": ["evidence-v1"], "always_present_artifacts": ["anchors", "webhook_receipts"]},
                    "signatures": {"envelopes": ["sig-v1"], "algorithms": ["ed25519"]},
                },
            )
        captured["json"] = json.loads(req.content.decode("utf-8"))
        return httpx.Response(200, json={"approval_request_id": "aprq_1", "status": "APPROVED"})

    c = ContractLaneClient("http://x", PrincipalAuth("tok"))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    c.set_signing_key_ed25519(bytes([9] * 32), key_id="kid_py_1")

    out = c.approval_decide(
        "aprq_1",
        actor_context={"principal_id": "prn_1", "actor_id": "act_1", "actor_type": "HUMAN"},
        decision="APPROVE",
        signed_payload={"contract_id": "ctr_1", "approval_request_id": "aprq_1", "nonce": "n1"},
    )
    assert out["status"] == "APPROVED"
    body = captured["json"]
    assert "signature_envelope" in body
    assert body["signature_envelope"]["version"] == "sig-v1"
    assert "signature" not in body
    assert body.get("signed_payload_hash") == _canonical_sha256_hex(body["signed_payload"])
    assert caps_hits["n"] == 1


def test_approval_decide_legacy_fallback_without_key():
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(req.content.decode("utf-8"))
        return httpx.Response(200, json={"approval_request_id": "aprq_1", "status": "APPROVED"})

    c = ContractLaneClient("http://x", PrincipalAuth("tok"))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))

    out = c.approval_decide(
        "aprq_1",
        actor_context={"principal_id": "prn_1", "actor_id": "act_1", "actor_type": "HUMAN"},
        decision="APPROVE",
        signed_payload={"contract_id": "ctr_1", "approval_request_id": "aprq_1", "nonce": "n1"},
        signature={"type": "WEBAUTHN_ASSERTION", "assertion_response": {}},
    )
    assert out["status"] == "APPROVED"
    body = captured["json"]
    assert "signature" in body
    assert "signature_envelope" not in body


def test_require_protocol_v1_passes_for_valid_capabilities():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/cel/.well-known/contractlane"
        return httpx.Response(
            200,
            json={
                "protocol": {"name": "contractlane", "versions": ["v1"]},
                "evidence": {"bundle_versions": ["evidence-v1"], "always_present_artifacts": ["anchors", "webhook_receipts"]},
                "signatures": {"envelopes": ["sig-v1"], "algorithms": ["ed25519"]},
            },
        )

    c = ContractLaneClient("http://x", PrincipalAuth("tok"))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    c.require_protocol_v1()


def test_require_protocol_v1_fails_when_sig_v1_missing():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/cel/.well-known/contractlane"
        return httpx.Response(
            200,
            json={
                "protocol": {"name": "contractlane", "versions": ["v1"]},
                "evidence": {"bundle_versions": ["evidence-v1"], "always_present_artifacts": ["anchors", "webhook_receipts"]},
                "signatures": {"envelopes": [], "algorithms": ["ed25519"]},
            },
        )

    c = ContractLaneClient("http://x", PrincipalAuth("tok"))
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(IncompatibleNodeError) as ex:
        c.require_protocol_v1()
    assert "sig-v1" in str(ex.value)


def test_approval_decide_disable_capability_check_skips_probe():
    captured = {}
    caps_hits = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/cel/.well-known/contractlane":
            caps_hits["n"] += 1
            return httpx.Response(200, json={})
        captured["json"] = json.loads(req.content.decode("utf-8"))
        return httpx.Response(200, json={"approval_request_id": "aprq_1", "status": "APPROVED"})

    c = ContractLaneClient("http://x", PrincipalAuth("tok"), disable_capability_check=True)
    c.http = httpx.Client(transport=httpx.MockTransport(handler))
    c.set_signing_key_ed25519(bytes([9] * 32), key_id="kid_py_1")
    out = c.approval_decide(
        "aprq_1",
        actor_context={"principal_id": "prn_1", "actor_id": "act_1", "actor_type": "HUMAN"},
        decision="APPROVE",
        signed_payload={"contract_id": "ctr_1", "approval_request_id": "aprq_1", "nonce": "n1"},
    )
    assert out["status"] == "APPROVED"
    assert caps_hits["n"] == 0
    assert "signature_envelope" in captured["json"]


def _fixed_delegation() -> dict:
    return {
        "version": "delegation-v1",
        "delegation_id": "del_01HZX9Y0H2J7F2S0P5R8M6T4YA",
        "issuer_agent": "agent:pk:ed25519:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No",
        "subject_agent": "agent:pk:ed25519:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No",
        "scopes": ["commerce:intent:sign", "commerce:accept:sign"],
        "constraints": {
            "contract_id": "ctr_offline_reference",
            "counterparty_agent": "agent:pk:ed25519:URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo",
            "max_amount": {"currency": "USD", "amount": "250"},
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z",
            "max_uses": 5,
        },
        "nonce": "ZGVsZWdhdGlvbl9ub25jZV92MQ",
        "issued_at": "2026-02-20T12:06:00Z",
    }


def test_delegation_v1_known_vector_hash():
    assert hash_delegation_v1(_fixed_delegation()) == "75ef154464ecbfd012b7dc7e6fca65d81f10d6d56938cb085ec222f9790fb357"


def test_delegation_v1_sign_verify():
    sig = sign_delegation_v1(_fixed_delegation(), bytes([21] * 32), "2026-02-20T12:06:00Z")
    assert sig["context"] == "delegation"
    verify_delegation_v1(_fixed_delegation(), sig)
    bad = dict(sig)
    bad["context"] = "commerce-intent"
    with pytest.raises(ValueError):
        verify_delegation_v1(_fixed_delegation(), bad)


def test_delegation_constraints_eval_failures():
    c = _fixed_delegation()["constraints"]
    evaluate_delegation_constraints(
        c,
        {
            "contract_id": "ctr_offline_reference",
            "counterparty_agent": c["counterparty_agent"],
            "issued_at_utc": "2026-02-18T00:00:00Z",
            "payment_amount": {"currency": "USD", "amount": "26"},
        },
    )
    with pytest.raises(ValueError):
        evaluate_delegation_constraints(
            c,
            {"contract_id": "ctr_other", "counterparty_agent": c["counterparty_agent"], "issued_at_utc": "2026-02-18T00:00:00Z"},
        )
    with pytest.raises(ValueError):
        evaluate_delegation_constraints(
            c,
            {"contract_id": "ctr_offline_reference", "counterparty_agent": "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "issued_at_utc": "2026-02-18T00:00:00Z"},
        )


def test_public_canonical_hash_utilities():
    obj = {"b": 2, "a": 1}
    b = canonicalize(obj)
    assert b == b'{"a":1,"b":2}'
    assert sha256_hex(b) == "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    assert canonical_sha256_hex(obj) == "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"


def test_parse_sig_v1_rejects_non_utc():
    with pytest.raises(ValueError):
        parse_sig_v1(
            {
                "version": "sig-v1",
                "algorithm": "ed25519",
                "public_key": base64.b64encode(bytes(32)).decode("ascii"),
                "signature": base64.b64encode(bytes(64)).decode("ascii"),
                "payload_hash": "a" * 64,
                "issued_at": "2026-01-01T00:00:00+01:00",
            }
        )


def test_parse_delegation_revocation_v1_rejects_unknown_key():
    with pytest.raises(ValueError):
        parse_delegation_revocation_v1(
            {
                "version": "delegation-revocation-v1",
                "revocation_id": "rev_1",
                "delegation_id": "del_1",
                "issuer_agent": "agent:pk:ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "nonce": "bm9uY2VfdjE",
                "issued_at": "2026-01-01T00:00:00Z",
                "bad": 1,
            }
        )


def test_proof_bundle_compute_and_verify_fixture():
    root = Path(__file__).resolve().parents[3]
    proof_path = root / "conformance" / "fixtures" / "agent-commerce-offline" / "proof_bundle_v1.json"
    proof = json.loads(proof_path.read_text())
    parse_proof_bundle_v1(proof)
    got = compute_proof_id(proof)
    expected = (root / "conformance" / "fixtures" / "agent-commerce-offline" / "proof_bundle_v1.id").read_text().strip()
    assert got == expected
    report = verify_proof_bundle_v1(proof)
    assert report.ok is True
    assert report.code == VerifyFailureCode.VERIFIED
