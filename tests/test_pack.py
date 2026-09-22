from __future__ import annotations

from basanos.limits import FORBIDDEN_PACK_KEYS
from basanos.pack import build_pack, verdict_for
from basanos.scanner import scan


def test_sound_fixtures_pass_without_forbidden_keys():
    pack = scan(root_names=["sound"])
    assert pack["verdict"] == "PASS"
    assert pack["basanos_report_digest"]
    assert pack["commit"]["tree_digest"]
    assert FORBIDDEN_PACK_KEYS.isdisjoint(pack)
    assert "scoreBps" not in pack
    assert "scoreBps" in " ".join(pack["limits"]["not_in_scope"])
    assert any("AgentAuditPool" in item for item in pack["limits"]["not_in_scope"])


def test_bad_fixtures_fail():
    pack = scan(root_names=["fixtures"])
    assert pack["verdict"] == "FAIL"
    assert pack["findings"]


def test_unknown_root_is_rejected():
    try:
        scan(root_names=["/etc"])
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("arbitrary paths must be rejected")


def test_verdict_ladder():
    assert verdict_for([]) == "PASS"
    assert verdict_for([{"severity": "low"}]) == "PASS"
    assert verdict_for([{"severity": "medium"}]) == "REVIEW"
    assert verdict_for([{"severity": "high"}]) == "FAIL"
    assert verdict_for([{"severity": "critical"}]) == "FAIL"


def test_build_pack_refuses_forbidden_keys():
    pack = build_pack(
        commit_sha="a" * 40,
        tree_digest="b" * 64,
        files=["x.sol"],
        findings=[],
        detector_order=[],
        intel={"cards_total": 0},
    )
    assert pack["verdict"] == "PASS"
    assert "basanos_report_digest" in pack


# ── 2026-08: an empty read is its own outcome ──────────────────────────────────


def test_empty_subject_is_neither_pass_nor_fail():
    """`build_pack` with no files must not grade a subject it never had.

    FAIL accused code BASANOS never opened; PASS would have certified it. Both are lies in
    a signed artifact, and the FAIL case was reachable from the README's own quick-start on
    a fresh clone.
    """
    pack = build_pack(
        commit_sha="0" * 40,
        tree_digest="d",
        files=[],
        findings=[],
        detector_order=[],
        intel={},
    )
    assert pack["verdict"] == "NO_SUBJECT"
    assert "judges nothing" in pack["handling"]["summary"]
    assert any("roots" in a for a in pack["handling"]["operator_actions"])


def test_a_real_subject_is_still_graded_normally():
    pack = build_pack(
        commit_sha="0" * 40,
        tree_digest="d",
        files=["A.sol"],
        findings=[{"severity": "high", "detector_id": "x", "swc": ""}],
        detector_order=[],
        intel={},
    )
    assert pack["verdict"] == "FAIL"


def test_capability_manifest_declares_every_verdict_the_code_can_emit():
    """The published manifest is a contract with Hub consumers.

    `validate_manifest.py` checks the manifest's SHAPE, not whether its enums still match
    the code — so adding the NO_SUBJECT verdict silently made a pack that the manifest's own
    output schema rejects. Pin the two together.
    """
    import json
    from pathlib import Path

    from basanos.handling import _VERDICT_ACTIONS

    manifest = json.loads(
        (Path(__file__).resolve().parents[1] / "capability.json").read_text(encoding="utf-8")
    )
    declared = set(manifest["output_schema"]["properties"]["verdict"]["enum"])
    emittable = set(_VERDICT_ACTIONS)
    assert declared == emittable, (
        f"manifest declares {sorted(declared)} but the code can emit {sorted(emittable)}"
    )
