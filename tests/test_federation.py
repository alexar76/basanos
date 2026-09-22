"""Federation surface — the two GETs that make this node discoverable.

Serving only ``/invoke`` made BASANOS an agent but not a peer: the hub crawler finds nodes
through ``/.well-known/ai-market.json`` → a signed manifest, and what it cannot find never
enters the federated catalogue. ``signal-hunt`` keeps no node list at all — it derives its
sources from ``tool["source_hub"]`` in that catalogue — and the LOGOS assistant answers from
the same live list, so an undiscoverable node is invisible to both.

The signature is the part that silently breaks. The hub verifies it with ITS canonical form,
so these tests check the real thing: that ``oracle_core``'s signer — byte-identical to the
hub's, and the reason this module imports the formula instead of copying it — accepts what
we produce.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from basanos.federation import (
    PROTOCOL_VERSION,
    load_capability,
    manifest,
    oracle_signer,
    well_known,
)
from basanos.signing import ProviderSigner

PUBLIC = "https://basanos.example"


@pytest.fixture
def signer(tmp_path, monkeypatch) -> ProviderSigner:
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / "provider.key"))
    return ProviderSigner()


def _manifest(signer: ProviderSigner, tmp_path) -> dict:
    return manifest(
        public_url=PUBLIC,
        version="0.1.0",
        seed=signer.seed,
        capability=load_capability(),
        key_path=tmp_path / "never-written.key",
    )


def test_well_known_carries_what_the_crawler_requires(signer, tmp_path):
    wk = well_known(
        public_url=PUBLIC,
        version="0.1.0",
        seed=signer.seed,
        capability=load_capability(),
        key_path=tmp_path / "wk-unused.key",
    )
    # aimarket_hub.validator._basic_well_known_check requires exactly these two.
    assert isinstance(wk["name"], str) and wk["name"]
    assert wk["manifest_url"] == f"{PUBLIC}/ai-market/v2/manifest"
    assert wk["signer_public_key"] == signer.public_key_b64
    assert wk["protocol_version"] == PROTOCOL_VERSION


def test_manifest_signature_verifies_with_the_hubs_own_canonical(signer, tmp_path):
    """The whole point of importing the formula rather than rewriting it."""
    m = _manifest(signer, tmp_path)
    verifier = oracle_signer(signer.seed, key_path=tmp_path / "verifier-unused.key")
    assert verifier.verify_manifest_signature(m, signer.public_key_b64)


def test_manifest_and_pack_are_signed_by_ONE_identity(signer, tmp_path):
    """Two keypairs would make the manifest advertise one key while capability.json and the
    pack signature advertise another — a verifier following the chain stops there."""
    m = _manifest(signer, tmp_path)
    assert m["signature"]["public_key"] == signer.public_key_b64


def test_borrowing_the_seed_creates_no_second_key_file_and_leaks_no_env(signer, tmp_path):
    target = tmp_path / "must-not-exist.key"
    before = os.environ.get("ORACLE_SIGNING_SEED_B64")
    oracle_signer(signer.seed, key_path=target)
    assert not target.exists(), "the env seed path must never touch a key file"
    assert os.environ.get("ORACLE_SIGNING_SEED_B64") == before, (
        "a leaked seed env var would silently re-key any oracle_core Signer built later"
    )


def test_tampering_with_a_tool_invalidates_the_signature(signer, tmp_path):
    m = _manifest(signer, tmp_path)
    verifier = oracle_signer(signer.seed, key_path=tmp_path / "v2-unused.key")
    m["tools"][0]["price_per_call_usd"] = 0.0
    assert not verifier.verify_manifest_signature(m, signer.public_key_b64), (
        "the canonical hashes tools, so a repriced row must not survive"
    )


def test_tool_row_declares_an_integer_latency(signer, tmp_path):
    """`p50_latency_ms` is `integer` in the published manifest schema — a float made the hub
    reject a whole manifest and index none of its capabilities. The row comes from
    oracle_core.Capability.tool(), which is why this holds without us coercing anything."""
    row = _manifest(signer, tmp_path)["tools"][0]
    assert isinstance(row["p50_latency_ms"], int)
    assert row["capability_id"] and row["product_id"] and row["name"]


# ── the routes ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / "agent.key"))
    monkeypatch.setenv("BASANOS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BASANOS_PUBLIC_URL", PUBLIC)
    import importlib

    import agent

    importlib.reload(agent)
    with TestClient(agent.app) as c:
        yield c, agent


def test_routes_serve_a_verifiable_pair(client):
    c, agent = client
    wk = c.get("/.well-known/ai-market.json")
    assert wk.status_code == 200
    body = wk.json()
    assert body["manifest_url"].endswith("/ai-market/v2/manifest")

    man = c.get("/ai-market/v2/manifest")
    assert man.status_code == 200
    m = man.json()
    verifier = oracle_signer(agent.SIGNER.seed, key_path=agent.DATA_DIR / "v-unused.key")
    assert verifier.verify_manifest_signature(m, agent.SIGNER.public_key_b64)
    assert body["signer_public_key"] == m["signature"]["public_key"]


def test_invoke_is_rate_limited(client):
    """A scan walks up to 200 files through every detector plus the graph pass, so an
    unbounded /invoke is a free denial-of-service the moment this node is in a public
    catalogue — which is exactly what federating it does."""
    c, agent = client
    agent._invoke_hits.clear()
    payload = {
        "product_id": agent.PRODUCT_ID,
        "capability_id": agent.CAPABILITY_ID,
        "input": {"roots": ["fixtures"]},
    }
    codes = [
        c.post("/invoke", json=payload).status_code
        for _ in range(agent.INVOKE_RATE_MAX + 2)
    ]
    assert codes.count(200) == agent.INVOKE_RATE_MAX, codes
    assert codes[-1] == 429
    agent._invoke_hits.clear()
