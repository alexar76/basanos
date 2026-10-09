from __future__ import annotations

from pathlib import Path

from basanos.detectors import run_detectors
from basanos.intel.store import KnowledgeStore
from basanos.ir import cei_inverted, parse_functions
from basanos.memos import MemoStore

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(name: str) -> set[str]:
    path = FIXTURES / name
    return {f["detector_id"] for f in run_detectors(path.read_text(encoding="utf-8"), name)}


def test_ir_parses_withdraw_without_false_cei():
    src = (FIXTURES / "sound" / "SoundVault.sol").read_text(encoding="utf-8")
    fns = {fn.name: fn for fn in parse_functions(src)}
    assert "withdraw" in fns
    assert cei_inverted(fns["withdraw"]) is False
    assert cei_inverted(fns["deposit"]) is False


def test_unguarded_mint_and_user_delegate_and_packed_and_loop():
    assert "auth.privileged_unguarded" in _codes("UnguardedMint.sol")
    assert "call.delegatecall_user_target" in _codes("UserDelegate.sol")
    assert "sig.encode_packed_hash" in _codes("PackedHash.sol")
    assert "call.value_in_loop" in _codes("PayoutLoop.sol")


def test_sound_vault_still_has_no_high_findings():
    findings = run_detectors(
        (FIXTURES / "sound" / "SoundVault.sol").read_text(encoding="utf-8"),
        "SoundVault.sol",
    )
    assert all(f["severity"] in {"info", "low"} for f in findings)


def test_memos_boost_repeated_category(tmp_path):
    memos = MemoStore(str(tmp_path / "memos"))
    store = KnowledgeStore(str(tmp_path / "intel"))
    for _ in range(4):
        memos.record(
            kind="vault",
            category="reentrancy",
            detector_id="reentrancy.value_call_unguarded",
            hit=True,
            path="V.sol",
            title="CEI inverted",
        )
    lessons = memos.distill_lessons(min_hits=3)
    assert lessons and lessons[0]["category"] == "reentrancy"
    boosts = memos.boost_map("vault")
    assert boosts["reentrancy"] > 0
    ordered = store.order_detectors(
        ["pragma.floating", "reentrancy.value_call_unguarded"],
        "vault",
        memo_boosts=boosts,
    )
    assert ordered[0] == "reentrancy.value_call_unguarded"
    recalled = memos.recall("vault")
    assert recalled and recalled[0].category == "reentrancy"


def test_memo_store_loads_skips_junk_and_record_scan(tmp_path):
    path = tmp_path / "memos.jsonl"
    path.write_text(
        "not-json\n"
        + '{"memo_id":"x","kind":"amm","category":"not-a-cat","detector_id":"z","hit":true,"path":"","title":"t"}\n',
        encoding="utf-8",
    )
    store = MemoStore(str(tmp_path))
    assert store.summary()["memos_total"] == 0
    assert store.record(kind="amm", category="nope", detector_id="z", hit=True, path="", title="") is None
    store.record_scan(
        "amm",
        [{"detector_id": "oracle.spot_without_twap", "category": "oracle", "title": "spot"}],
        detector_ids=["oracle.spot_without_twap", "pragma.floating"],
    )
    assert store.summary()["hits"] >= 1
    assert store.recall("weather") == []
