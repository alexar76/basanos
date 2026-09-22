"""Branch coverage for detectors, intel fetch, ingest, scanner, and the API edge."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import agent
import validate_manifest
from basanos.detectors import run_detectors
from basanos.intel.ingest import ingest_into
from basanos.intel.sources import (
    ThreatFeed,
    _extract_items,
    default_feeds,
    fetch_raw,
    intel_enabled,
    source_digest,
)
from basanos.intel.store import KnowledgeStore
from basanos.inventory import repo_root, resolve_roots
from basanos.limits import FORBIDDEN_PACK_KEYS
from basanos.pack import build_pack
from basanos.scanner import collect_sources, git_head, scan, tree_digest


def test_block_and_line_comments_and_guarded_reentrancy():
    src = """
pragma solidity 0.8.28;
/* tx.origin
   ignored */
contract G is ReentrancyGuard {
    function withdraw() external nonReentrant {
        (bool ok,) = msg.sender.call{value: 1}("");
        balances[msg.sender] = 0; // write after call is locked
        require(ok);
    }
}
"""
    codes = {f["detector_id"] for f in run_detectors(src, "G.sol")}
    assert "reentrancy.value_call_unguarded" not in codes
    assert "auth.tx_origin" not in codes


def test_inline_block_comment_and_unknown_detector_order():
    src = "pragma solidity 0.8.28; /* secret */ contract C { address a = tx.origin; }\n"
    findings = run_detectors(src, "C.sol", order=["does-not-exist", "auth.tx_origin"])
    assert any(f["detector_id"] == "auth.tx_origin" for f in findings)


def test_entropy_blockhash_vdf_and_timestamp_seed():
    src = """
pragma solidity 0.8.28;
contract Rng {
    function seed() external view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp % 7, blockhash(1)));
    }
}
"""
    ids = {f["detector_id"] for f in run_detectors(src, "Rng.sol")}
    assert "entropy.blockhash" in ids
    assert "entropy.timestamp_seed" in ids


def test_unchecked_call_delegate_skipped_and_success_window():
    src = """
pragma solidity 0.8.28;
contract C {
    function a(address t, bytes memory d) external {
        t.delegatecall(d);
    }
    function b(address t) external {
        (bool success,) = t.call("");
        require(success);
    }
    function c(address t) external {
        t.call("");
    }
}
"""
    ids = {f["detector_id"] for f in run_detectors(src, "C.sol")}
    assert "call.delegatecall" in ids
    assert "call.unchecked" in ids


def test_ecrecover_openzeppelin_and_raw():
    oz = """
pragma solidity 0.8.28;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
contract S { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { ecrecover(h,v,r,s); } }
"""
    raw = """
pragma solidity 0.8.28;
contract S { function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { ecrecover(h,v,r,s); } }
"""
    assert run_detectors(oz, "Oz.sol") == [] or "sig.raw_ecrecover" not in {
        f["detector_id"] for f in run_detectors(oz, "Oz.sol")
    }
    assert "sig.raw_ecrecover" in {f["detector_id"] for f in run_detectors(raw, "Raw.sol")}


def test_oracle_twap_language_skips_spot():
    src = """
pragma solidity 0.8.28;
contract O {
    function p() external view returns (uint256) {
        (uint112 r0, uint112 r1,) = getReserves();
        return twap(r0, r1);
    }
}
"""
    assert "oracle.spot_without_twap" not in {f["detector_id"] for f in run_detectors(src, "O.sol")}


def test_intel_prod_fail_closed_and_explicit_prod_opt_in(monkeypatch):
    monkeypatch.setenv("BASANOS_THREAT_INTEL", "1")
    monkeypatch.setenv("AIFACTORY_PROD", "1")
    monkeypatch.delenv("BASANOS_THREAT_INTEL_PROD", raising=False)
    assert intel_enabled() is False
    monkeypatch.setenv("BASANOS_THREAT_INTEL_PROD", "1")
    assert intel_enabled() is True


def test_extract_items_osv_and_ghsa_and_unknown():
    osv = _extract_items(
        "osv",
        {
            "vulns": [
                {
                    "id": "OSV-1",
                    "summary": "Reentrancy",
                    "details": "SWC-107",
                    "published": "2024-01-01",
                    "aliases": ["CVE-1"],
                    "references": [{"url": "https://osv.dev/vulnerability/OSV-1"}],
                }
            ]
        },
    )
    assert osv[0]["title"] == "Reentrancy"
    ghsa = _extract_items(
        "ghsa",
        [
            {
                "ghsa_id": "GHSA-x",
                "cve_id": "CVE-2",
                "summary": "tx.origin",
                "html_url": "https://github.com/advisories/GHSA-x",
                "published_at": "2024-02-02",
                "description": "SWC-115",
            },
            "skip-me",
        ],
    )
    assert ghsa[0]["identifiers"][0] == "GHSA-x"
    assert _extract_items("nope", {}) == []
    assert source_digest({"a": 1})


def test_fetch_raw_posts_osv_and_gets_ghsa(monkeypatch):
    monkeypatch.setenv("BASANOS_THREAT_INTEL", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test")

    class DummyClient:
        def __init__(self, *args, **kwargs):
            self.headers = kwargs.get("headers") or {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None):
            assert "osv.dev" in url
            return httpx.Response(
                200,
                json={"vulns": [{"id": "OSV-9", "summary": "Reentrancy vault", "details": "x"}]},
                request=httpx.Request("POST", url),
            )

        async def get(self, url):
            assert "api.github.com" in url
            assert self.headers.get("Authorization") == "Bearer ghs_test"
            return httpx.Response(
                200,
                json=[{"ghsa_id": "GHSA-z", "summary": "delegatecall", "html_url": "https://x"}],
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("basanos.intel.sources.httpx.AsyncClient", DummyClient)
    feeds = default_feeds()
    osv = next(f for f in feeds if f.kind == "osv")
    ghsa = next(f for f in feeds if f.kind == "ghsa")
    assert asyncio.run(fetch_raw(osv))[0]["title"]
    assert asyncio.run(fetch_raw(ghsa))[0]["identifiers"][0] == "GHSA-z"


def test_fetch_raw_http_error_returns_empty(monkeypatch):
    monkeypatch.setenv("BASANOS_THREAT_INTEL", "1")

    class Boom:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None):
            raise httpx.ConnectError("nope")

        async def get(self, url):
            raise httpx.ConnectError("nope")

    monkeypatch.setattr("basanos.intel.sources.httpx.AsyncClient", Boom)
    assert asyncio.run(fetch_raw(default_feeds()[0])) == []


def test_custom_github_repos_and_host_filter(monkeypatch):
    monkeypatch.setenv("BASANOS_INTEL_GITHUB_REPOS", "OpenZeppelin/openzeppelin-contracts,bad,../evil")
    feeds = default_feeds()
    assert any(f.feed_id.startswith("ghsa:OpenZeppelin/") for f in feeds)
    evil = ThreatFeed("x", "https://evil.example/x", "ghsa")
    assert asyncio.run(fetch_raw(evil)) == []


def test_ingest_into_enabled_maps_and_skips(monkeypatch, tmp_path):
    monkeypatch.setenv("BASANOS_THREAT_INTEL", "1")

    async def fake_fetch(feed):
        if feed.kind == "osv":
            return [
                {
                    "title": "Reentrancy in token vault",
                    "text": "Classic SWC-107",
                    "url": "https://osv.dev/1",
                    "identifiers": ["OSV-1"],
                }
            ]
        return [{"title": "A weather report", "text": "It rained.", "url": "https://x"}]

    monkeypatch.setattr("basanos.intel.ingest.fetch_raw", fake_fetch)
    store = KnowledgeStore(str(tmp_path))
    result = asyncio.run(ingest_into(store))
    assert result["reason"] == "ok"
    assert result["ingested"] >= 1
    assert result["scanned"] >= 1


def test_store_loads_junk_and_records_outcomes(tmp_path):
    cards = tmp_path / "knowledge_cards.jsonl"
    cards.write_text(
        "\nnot-json\n"
        + json.dumps(
            {
                "card_id": "card-1",
                "source": "osv-oz",
                "title": "Reentrancy",
                "url": "https://x",
                "published": "",
                "summary": "SWC-107",
                "mapped_categories": ["reentrancy"],
                "identifiers": [],
                "weight": 1.0,
                "ingested_at": "not-a-date",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "learning_state.json").write_text("{not json", encoding="utf-8")
    store = KnowledgeStore(str(tmp_path))
    store.record_outcome("reentrancy", "vault", "finding")
    store.record_outcome("reentrancy", "vault", "no_finding")
    store.record_outcome("not-a-category", "vault", "finding")
    assert store.summary()["cards_total"] == 1
    ordered = store.order_detectors(["pragma.floating", "reentrancy.value_call_unguarded"], "vault")
    assert "reentrancy.value_call_unguarded" in ordered


def test_scanner_empty_inventory_and_unreadable_source(tmp_path, monkeypatch):
    monkeypatch.setenv("BASANOS_CONTRACT_ROOT", str(tmp_path))
    (tmp_path / "acex" / "contracts" / "evm" / "src").mkdir(parents=True)
    empty = scan(root_names=["acex"])
    # NO_SUBJECT, not FAIL: nothing was read, so the pack judges nobody's code. FAIL used
    # to be returned here, which is an accusation about Solidity BASANOS never opened —
    # and it was what a fresh clone produced from the README's own example, because the
    # default roots name monorepo paths. PASS would be the worse lie of the two.
    assert empty["verdict"] == "NO_SUBJECT"
    assert any(f["detector_id"] == "inventory.empty" for f in empty["findings"])
    assert empty["handling"]["worst_severity"] == "info", (
        "an empty read is an operator-input problem, not a severity about a subject"
    )
    bad = tmp_path / "acex" / "contracts" / "evm" / "src" / "Bad.sol"
    bad.write_bytes(b"\xff\xfe not utf8")
    pack = scan(root_names=["acex"])
    assert all(f["detector_id"] != "inventory.empty" for f in pack["findings"])
    assert git_head(tmp_path) == ""


def test_tree_digest_and_symlink_file_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("BASANOS_CONTRACT_ROOT", str(tmp_path))
    real = tmp_path / "acex" / "contracts" / "evm" / "src"
    real.mkdir(parents=True)
    sol = real / "A.sol"
    sol.write_text("pragma solidity 0.8.28;\ncontract A {}\n", encoding="utf-8")
    link = real / "Link.sol"
    link.symlink_to(sol)
    digest = tree_digest([sol], tmp_path)
    assert len(digest) == 64
    files = collect_sources(resolve_roots(["acex"]))
    assert sol.resolve() in [p.resolve() for p in files]
    assert all(p.name != "Link.sol" for p in files)


def test_repo_root_falls_back_to_satellite_when_parent_has_no_contracts(tmp_path, monkeypatch):
    monkeypatch.delenv("BASANOS_CONTRACT_ROOT", raising=False)
    monkeypatch.setattr("basanos.inventory.satellite_root", lambda: tmp_path)
    assert repo_root() == tmp_path


def test_build_pack_refuses_leaked_forbidden_key(monkeypatch):
    monkeypatch.setattr(
        "basanos.pack.FORBIDDEN_PACK_KEYS",
        FORBIDDEN_PACK_KEYS | {"verdict"},
    )
    with pytest.raises(RuntimeError, match="must not contain"):
        build_pack(
            commit_sha="a" * 40,
            tree_digest="b" * 64,
            files=[],
            findings=[],
            detector_order=[],
            intel={},
        )


def test_root_redirect_invalid_length_and_intel_json():
    with TestClient(agent.app) as client:
        home = client.get("/", follow_redirects=False)
        assert home.status_code == 200
        html = home.text
        assert "BASANOS" in html
        assert "three" in html
        assert "./stone.js" in html
        assert "Not HEPHAESTUS" not in html
        assert "not MOMUS" not in html
        stone = client.get("/stone.js")
        assert stone.status_code == 200
        assert b"UnrealBloomPass" in stone.content
        assert "javascript" in stone.headers["content-type"]
        bad_len = client.post("/invoke", content=b"{}", headers={"content-length": "nope"})
        assert bad_len.status_code == 413
        ingest = client.post(
            "/invoke",
            json={
                "product_id": "basanos",
                "capability_id": "agent.security.contract-assurance@v1",
                "input": {"roots": ["sound"], "ingest_intel": True},
            },
        )
        assert ingest.status_code == 200
        bad_intel = client.post(
            "/intel",
            content=b'{"x":1,"x":2}',
            headers={"content-type": "application/json"},
        )
        assert bad_intel.status_code == 400


def test_root_falls_back_to_ui_when_landing_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "UI_DIR", tmp_path)
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    with TestClient(agent.app) as client:
        redirect = client.get("/", follow_redirects=False)
        missing_stone = client.get("/stone.js")
    assert redirect.status_code == 307
    assert redirect.headers["location"] == "/ui/"
    assert missing_stone.status_code == 404


def test_validate_manifest_guards(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(validate_manifest, "MANIFEST", Path("capability.json"))
    with pytest.raises(SystemExit):
        validate_manifest.read_manifest()
    Path("capability.json").write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicate"):
        validate_manifest.read_manifest()
    Path("capability.json").write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit, match="one JSON object"):
        validate_manifest.read_manifest()
    with pytest.raises(SystemExit):
        validate_manifest.finite_number({"price_per_call_usd": True}, "price_per_call_usd", minimum=0, maximum=1)
    with pytest.raises(SystemExit):
        validate_manifest.finite_number({"price_per_call_usd": "x"}, "price_per_call_usd", minimum=0, maximum=1)
    with pytest.raises(SystemExit):
        validate_manifest.finite_number({"price_per_call_usd": 1e9}, "price_per_call_usd", minimum=0, maximum=1)
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url(1)
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url("http://example.com:notaport/")
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url("ftp://x")
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url("http://user:pass@127.0.0.1:9470/")
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url("http://127.0.0.1:9470/?q=1")
    with pytest.raises(SystemExit):
        validate_manifest.validate_invoke_url("http://example.com/invoke")
    validate_manifest.validate_invoke_url("http://127.0.0.1:9470/invoke")
    Path("capability.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit, match="missing"):
        validate_manifest.main()
    data = {
        "product_id": "bad id",
        "capability_id": "nope",
        "name": "",
        "invoke_url": "http://127.0.0.1:9470/invoke",
        "publisher_id": "tx-consumed:x",
        "provider_pubkey": "AAA",
        "price_per_call_usd": 0.02,
        "input_schema": {"type": "array"},
        "output_schema": {"type": "object"},
    }
    Path("capability.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit):
        validate_manifest.main()
    data["product_id"] = "basanos"
    data["capability_id"] = "agent.security.contract-assurance@v1"
    data["name"] = "BASANOS"
    data["publisher_id"] = "community"
    data["provider_pubkey"] = "not-base64!!"
    data["input_schema"] = {"type": "object"}
    Path("capability.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit, match="base64"):
        validate_manifest.main()
    data["provider_pubkey"] = "AAAA"
    Path("capability.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit, match="32"):
        validate_manifest.main()
