from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

import agent
from basanos.intel.ingest import ingest_into
from basanos.intel.sources import fetch_raw, intel_enabled
from basanos.intel.store import KnowledgeStore


def test_intel_routes_without_fetching_when_disabled():
    with TestClient(agent.app) as client:
        summary = client.get("/intel").json()
        assert summary["intel_enabled"] is False
        posted = client.post("/intel", json={})
    assert posted.status_code == 200
    assert posted.json()["reason"] == "intel_disabled"


def test_fetch_raw_noops_when_intel_off():
    from basanos.intel.sources import default_feeds

    assert intel_enabled() is False
    feed = default_feeds()[0]
    items = asyncio.run(fetch_raw(feed))
    assert items == []


def test_ingest_into_disabled(tmp_path):
    store = KnowledgeStore(str(tmp_path))
    result = asyncio.run(ingest_into(store))
    assert result["ingested"] == 0
    assert result["reason"] == "intel_disabled"
