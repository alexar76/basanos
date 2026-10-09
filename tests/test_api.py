from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

import agent


def _envelope(payload: dict | None = None) -> dict:
    return {
        "input": payload or {"roots": ["sound"], "ingest_intel": False},
        "product_id": agent.PRODUCT_ID,
        "capability_id": agent.CAPABILITY_ID,
    }


def _verify(response, input_payload: dict) -> None:
    body = response.json()
    signature = base64.b64decode(response.headers["x-provider-signature"], validate=True)
    input_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical = json.dumps(
        {
            "capability_id": agent.CAPABILITY_ID,
            "product_id": agent.PRODUCT_ID,
            "input_sha256": hashlib.sha256(input_json.encode()).hexdigest(),
            "result": body["result"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    public_key = base64.b64decode(TestClient(agent.app).get("/health").json()["provider_pubkey"])
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical.encode())


def test_health_and_signed_invoke():
    payload = {"roots": ["sound"], "ingest_intel": False}
    with TestClient(agent.app) as client:
        health = client.get("/health")
        assert health.json()["ok"] is True
        response = client.post("/invoke", json=_envelope(payload))
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"]["verdict"] == "PASS"
    assert "scoreBps" not in body["result"]
    assert response.headers["x-frame-options"] == "DENY"
    _verify(response, payload)


def test_identity_lock_and_framework_closed():
    with TestClient(agent.app) as client:
        wrong = _envelope()
        wrong["product_id"] = "themis"
        assert client.post("/invoke", json=wrong).status_code == 400
        wrong = _envelope()
        wrong["capability_id"] = "agent.security.supply-chain.audit@v1"
        assert client.post("/invoke", json=wrong).status_code == 400
        assert client.get("/docs").status_code == 404
        oversized = client.post("/invoke", content=b"x" * (agent.MAX_INVOKE_BYTES + 1))
        assert oversized.status_code == 413


def test_duplicate_json_keys_rejected():
    raw = '{"input": {"roots": []}, "input": {"roots": ["sound"]}, "product_id": "basanos", "capability_id": "agent.security.contract-assurance@v1"}'
    with TestClient(agent.app) as client:
        response = client.post("/invoke", content=raw.encode(), headers={"content-type": "application/json"})
    assert response.status_code == 400


def test_unknown_root_is_400():
    with TestClient(agent.app) as client:
        response = client.post("/invoke", json=_envelope({"roots": ["not-a-root"]}))
    assert response.status_code == 400


def test_signature_binds_input():
    first_payload = {"roots": ["sound"], "ingest_intel": False}
    second_payload = {"roots": ["fixtures"], "ingest_intel": False}
    with TestClient(agent.app) as client:
        first = client.post("/invoke", json=_envelope(first_payload))
        second = client.post("/invoke", json=_envelope(second_payload))
    assert first.headers["x-provider-signature"] != second.headers["x-provider-signature"]
    assert deepcopy(first.json())["result"]["verdict"] == "PASS"
    assert second.json()["result"]["verdict"] == "FAIL"


def test_memos_surface_and_learning_fields():
    with TestClient(agent.app) as client:
        client.post("/invoke", json=_envelope({"roots": ["fixtures"], "ingest_intel": False}))
        memos = client.get("/memos").json()
        pack = client.post("/invoke", json=_envelope({"roots": ["fixtures"], "ingest_intel": False})).json()["result"]
    assert "memos_total" in memos
    assert "lessons" in memos
    assert "scoreBps" not in pack
    assert "memos_total" in pack["learning"]
    assert "cannot add detectors" in pack["learning"]["rule"]
