from __future__ import annotations

from basanos.handling import (
    ACKNOWLEDGE_HOURS,
    CVD_DAYS,
    MUST_NOT,
    STANDARDS,
    cwe_for,
    handling_for,
    stamp_findings,
)
from basanos.limits import FORBIDDEN_PACK_KEYS
from basanos.pack import build_pack, verdict_for
from basanos.scanner import scan


def test_swc_maps_to_cwe():
    assert cwe_for("SWC-107") == "CWE-841"
    assert cwe_for("swc-105") == "CWE-284"
    assert cwe_for("") == ""


def test_fail_pack_recommends_containment_and_forbids_coverage():
    pack = scan(root_names=["fixtures"])
    assert pack["verdict"] == "FAIL"
    handling = pack["handling"]
    assert handling["role"] == "recommend-only"
    assert handling["acknowledge_hours"] == ACKNOWLEDGE_HOURS
    assert handling["cvd_days"] == CVD_DAYS
    assert handling["candidates"] is True
    assert handling["nist_phase"] == "containment"
    joined = " ".join(handling["operator_actions"])
    assert "coverListing" in joined
    assert "Do not deploy" in joined or "do not call" in joined.lower()
    assert "72 hours" in joined
    assert "90-day" in joined
    assert "exploit" in joined.lower()
    must_not = " ".join(handling["must_not"])
    assert "coverListing" in must_not
    assert "proof-of-concept" in must_not
    assert FORBIDDEN_PACK_KEYS.isdisjoint(handling)
    assert FORBIDDEN_PACK_KEYS.isdisjoint(pack)
    for finding in pack["findings"]:
        if finding.get("swc") == "SWC-107":
            assert finding.get("cwe") == "CWE-841"
            assert finding.get("nist_phase") == "containment"


def test_pass_pack_does_not_require_containment():
    pack = scan(root_names=["sound"])
    assert pack["verdict"] == "PASS"
    handling = pack["handling"]
    assert handling["nist_phase"] == "post-incident"
    joined = " ".join(handling["operator_actions"]).lower()
    assert "pause" not in joined
    assert "coverlisting" in joined  # still does not authorize coverage
    assert "ISO/IEC 29147:2018" in STANDARDS
    assert "ISO/IEC 30111:2019" in handling["standards"]


def test_worst_severity_does_not_drop_when_later_findings_are_weaker():
    handling = handling_for(
        "FAIL",
        [{"severity": "critical", "swc": "SWC-105"}, {"severity": "low", "swc": "SWC-103"}],
    )
    assert handling["worst_severity"] == "critical"
    assert handling["nist_phase"] == "containment"


def test_review_playbook_is_verification_not_containment():
    handling = handling_for("REVIEW", [{"severity": "medium", "swc": "SWC-104"}])
    assert handling["nist_phase"] == "detection-analysis"
    assert handling["worst_severity"] == "medium"
    assert any("Verify privately" in step for step in handling["operator_actions"])
    stamped = stamp_findings([{"severity": "medium", "swc": "SWC-104"}])
    assert stamped[0]["cwe"] == "CWE-252"
    assert verdict_for(stamped) == "REVIEW"


def test_handling_is_inside_the_signed_body():
    pack = build_pack(
        commit_sha="a" * 40,
        tree_digest="b" * 64,
        files=["x.sol"],
        findings=[{"severity": "critical", "swc": "SWC-105", "title": "drain"}],
        detector_order=[],
        intel={},
    )
    assert pack["verdict"] == "FAIL"
    assert pack["handling"]["summary"]
    assert any("pause" in item.lower() for item in MUST_NOT)
    assert "approve" not in pack["handling"]
    assert "reject" not in pack["handling"]
    assert "decision" not in pack["handling"]
