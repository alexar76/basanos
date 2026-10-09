from __future__ import annotations

from fastapi.testclient import TestClient

import agent
from basanos.signing import ProviderSigner


def test_symlink_sources_are_not_read(tmp_path, monkeypatch):
    monkeypatch.setenv("BASANOS_CONTRACT_ROOT", str(tmp_path))
    # A symlink pointing at /etc/passwd must not be walked.
    (tmp_path / "acex" / "contracts" / "evm" / "src").mkdir(parents=True)
    target = tmp_path / "secret.sol"
    target.write_text("pragma solidity 0.8.28;\ncontract X { address a = tx.origin; }\n")
    link = tmp_path / "acex" / "contracts" / "evm" / "src" / "X.sol"
    link.symlink_to(target)
    from basanos.scanner import collect_sources, resolve_roots

    files = collect_sources(resolve_roots(["acex"]))
    assert files == []


def test_health_headers_deny_framing():
    with TestClient(agent.app) as client:
        response = client.get("/health")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_signer_rejects_replaced_file(tmp_path, monkeypatch):
    key = tmp_path / "provider.key"
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    ProviderSigner()
    assert key.is_file()
