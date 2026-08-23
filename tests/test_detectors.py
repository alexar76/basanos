from __future__ import annotations

from pathlib import Path

from basanos.detectors import run_detectors

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(path: Path) -> set[str]:
    return {f["detector_id"] for f in run_detectors(path.read_text(encoding="utf-8"), path.name)}


def test_sound_vault_has_no_high_findings():
    findings = run_detectors(
        (FIXTURES / "sound" / "SoundVault.sol").read_text(encoding="utf-8"),
        "SoundVault.sol",
    )
    assert all(f["severity"] in {"info", "low"} for f in findings)


def test_unguarded_drain_flags_reentrancy():
    assert "reentrancy.value_call_unguarded" in _codes(FIXTURES / "UnguardedDrain.sol")


def test_tx_origin_and_selfdestruct_and_secret_and_spot():
    assert "auth.tx_origin" in _codes(FIXTURES / "TxOriginWallet.sol")
    assert "lifecycle.selfdestruct" in _codes(FIXTURES / "Boom.sol")
    assert "secret.hardcoded_word" in _codes(FIXTURES / "HiddenKey.sol")
    assert "oracle.spot_without_twap" in _codes(FIXTURES / "SpotOracle.sol")


def test_comments_do_not_trigger_tx_origin():
    src = "// tx.origin is mentioned in a comment\npragma solidity 0.8.28;\ncontract C { }\n"
    assert run_detectors(src, "C.sol") == []


# ── 2026-08: the two classes a hand audit of ACEX found and BASANOS did not ────
#
# Measured before these existed: a scan of the pre-fix ACEX tree — which held two
# exploitable criticals — reported eight findings, all `pragma.floating`. These pin the
# detectors that close that gap, and the authorization/non-authorization split in the IR
# that they (and `auth.privileged_unguarded`) depend on.

_DEAD_ALLOWLIST = """
pragma solidity 0.8.28;
contract Amm {
    address public owner;
    mapping(address => bool) public marketMakers;
    mapping(address => bool) public auditors;
    mapping(bytes32 => uint256) public pools;

    function setMarketMaker(address mm, bool ok) external { marketMakers[mm] = ok; }
    function setAuditor(address a, bool ok) external { auditors[a] = ok; }
    function recordAudit(bytes32 id) external {
        if (!auditors[msg.sender]) revert();
        pools[id] = 1;
    }
}
"""


def test_dead_allowlist_is_reported():
    """`marketMakers` has a setter and is never read in a condition; `auditors` is read."""
    from basanos.detectors import run_detectors

    dead = [
        f["title"]
        for f in run_detectors(_DEAD_ALLOWLIST, "Amm.sol")
        if f["detector_id"] == "auth.declared_but_unenforced"
    ]
    assert any("marketMakers" in t for t in dead), "a write-only allow-list must be reported"
    assert not any("auditors" in t for t in dead), (
        "auditors IS enforced (read in a revert condition) — flagging it would be noise"
    )


_CLAIM = """
pragma solidity 0.8.28;
contract Registry {
    mapping(bytes32 => address) public listings;
    mapping(bytes32 => uint256) public prices;
    modifier onlyRegistry() { _; }

    function applyForListing(bytes32 id) external { listings[id] = msg.sender; }
    function gated(bytes32 id) external onlyRegistry { prices[id] = 1; }
    function selfChecked(bytes32 id) external {
        if (listings[id] != msg.sender) revert();
        prices[id] = 2;
    }
    function reentrancyOnly(bytes32 id) external nonReentrant { prices[id] = 3; }
}
"""


def test_unauthenticated_state_claim_respects_real_gates():
    from basanos.detectors import run_detectors

    flagged = {
        f["title"].split()[0]
        for f in run_detectors(_CLAIM, "Registry.sol")
        if f["detector_id"] == "access.unauthenticated_state_claim"
    }
    assert "applyForListing" in flagged, "open first-come claim must be reported"
    assert "gated" not in flagged, "a custom onlyX modifier is an authorization gate"
    assert "selfChecked" not in flagged, "an in-body msg.sender check is authorization"
    assert "reentrancyOnly" in flagged, (
        "nonReentrant restricts WHEN, not WHO — it must not read as authorization"
    )


def test_ir_separates_authorization_from_reentrancy_guards():
    """The bug this fixes cut both ways: `nonReentrant` counted as an access gate (false
    negatives on privileged functions) while `onlyRegistry` counted as none (false
    positives on gated ones)."""
    from basanos.ir import parse_functions

    fns = {f.name: f for f in parse_functions(_CLAIM)}
    assert fns["gated"].guarded is True
    assert fns["selfChecked"].guarded is True
    assert fns["reentrancyOnly"].guarded is False
    assert fns["reentrancyOnly"].has_any_modifier is True
    assert fns["reentrancyOnly"].nonauth_modifiers_only is True
    assert fns["applyForListing"].has_any_modifier is False
