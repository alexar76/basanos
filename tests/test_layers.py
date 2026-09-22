"""BASANOS is not AgentAuditPool, MOMUS, THEMIS, or HEPHAESTUS."""

from __future__ import annotations

from fastapi.testclient import TestClient

import agent
from basanos.limits import FORBIDDEN_PACK_KEYS, NOT_IN_SCOPE
from basanos.scanner import scan


def test_health_declares_the_layer_split():
    with TestClient(agent.app) as client:
        body = client.get("/health").json()
    assert body["role"] == "contract-assurance"
    for name in ("AgentAuditPool", "MOMUS", "THEMIS", "HEPHAESTUS"):
        assert name in body["not"]


def test_pack_never_emits_insurance_or_admission_fields():
    pack = scan(root_names=["sound"])
    assert FORBIDDEN_PACK_KEYS.isdisjoint(pack)
    joined = " ".join(NOT_IN_SCOPE)
    assert "MOMUS" in joined
    assert "THEMIS" in joined
    assert "AgentAuditPool" in joined
    assert "scoreBps" in joined
    assert "HEPHAESTUS" in joined


def test_capability_is_assurance_not_admission():
    assert agent.CAPABILITY_ID == "agent.security.contract-assurance@v1"
    assert agent.PRODUCT_ID == "basanos"
    assert "supply-chain.audit" not in agent.CAPABILITY_ID


def test_own_fixtures_are_scanned_even_inside_a_host_monorepo(tmp_path, monkeypatch):
    """`fixtures` is BASANOS's own corpus and must never lose to the surrounding tree.

    Preferring the discovered repo root meant that inside the aicom monorepo `fixtures`
    resolved to *its* unrelated `tests/fixtures` (no Solidity at all), so the detector
    fixtures were never opened — and three tests asserted FAIL and got it from
    "no sources found", passing while exercising nothing.
    """
    from basanos.inventory import resolve_roots, satellite_root

    # A host tree that also owns a tests/fixtures, like the monorepo does.
    (tmp_path / "acex" / "contracts").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    monkeypatch.setenv("BASANOS_CONTRACT_ROOT", str(tmp_path))

    roots = resolve_roots(["fixtures"])
    assert roots == [(satellite_root() / "tests" / "fixtures").resolve()]
    assert list(roots[0].rglob("*.sol")), "the fixture corpus must actually be there"
