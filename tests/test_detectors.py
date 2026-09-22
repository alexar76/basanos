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


_FIXED_PACK = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract FixedPack {
    mapping(uint256 => bytes32) public commitments;

    function seed(uint256 roundId, bytes32 bh, bytes32 platonRandom) external {
        commitments[roundId] = keccak256(abi.encodePacked(roundId, bh, platonRandom));
    }
}
"""

_DYNAMIC_PACK = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract DynamicPack {
    function id(string memory a, bytes memory b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}
"""

_OPAQUE_PACK = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract OpaquePack {
    function id() external view returns (bytes32) {
        return keccak256(abi.encodePacked(outside.left(), outside.right()));
    }
}
"""


def _packed(source: str) -> list[dict]:
    return [
        f for f in run_detectors(source, "Pack.sol")
        if f["detector_id"] == "sig.encode_packed_hash"
    ]


def test_fixed_width_packing_cannot_collide_and_is_not_reported():
    # (uint256, bytes32, bytes32) has exactly one encoding — SWC-133 needs two dynamics.
    assert _packed(_FIXED_PACK) == []


def test_two_dynamic_arguments_are_still_a_medium():
    findings = _packed(_DYNAMIC_PACK)
    assert [f["severity"] for f in findings] == ["medium"]
    assert findings[0]["swc"] == "SWC-133"


def test_untypeable_arguments_are_reported_as_a_low_not_a_medium():
    findings = _packed(_OPAQUE_PACK)
    assert [f["severity"] for f in findings] == ["low"]
    assert "could not be typed" in findings[0]["detail"]


def test_function_findings_point_at_the_real_source_line():
    source = "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity 0.8.28;",
            "",
            "contract Claim {",
            "    mapping(uint256 => uint256) public settledAt;",
            "",
            "    // A long comment block, because comment lines are stripped before",
            "    // the function head is parsed and used to be counted out of the",
            "    // line numbering entirely.",
            "",
            "    function settle(uint256 roundId) external {",
            "        settledAt[roundId] = block.timestamp;",
            "    }",
            "}",
        ]
    )
    findings = [
        f for f in run_detectors(source, "Claim.sol")
        if f["detector_id"] == "access.unauthenticated_state_claim"
    ]
    assert findings, "expected the unauthenticated claim finding"
    assert source.splitlines()[findings[0]["line"] - 1].strip().startswith("function settle")


_LAND_GRAB = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Grab {
    struct Listing { address agentWallet; }
    mapping(bytes32 => Listing) public listings;

    function applyForListing(bytes32 listingId) external {
        if (listings[listingId].agentWallet != address(0)) revert("exists");
        listings[listingId] = Listing({agentWallet: msg.sender});
    }
}
"""

_TRANSITION = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Transition {
    enum Status { None, Drawing, Settled }
    struct Round { Status status; }
    mapping(uint256 => Round) internal _rounds;
    mapping(uint256 => uint64) public settledAt;

    function fulfillDraw(uint256 roundId) external {
        Round storage r = _rounds[roundId];
        if (r.status != Status.Drawing) revert("wrong status");
        settledAt[roundId] = uint64(block.timestamp);
    }
}
"""


def _claims(source: str) -> list[dict]:
    return [
        f for f in run_detectors(source, "Claim.sol")
        if f["detector_id"] == "access.unauthenticated_state_claim"
    ]


def test_first_writer_owns_the_slot_stays_a_medium():
    # The write needs an EMPTY slot — ACEX's real applyForListing squat.
    findings = _claims(_LAND_GRAB)
    assert [f["severity"] for f in findings] == ["medium"]


def test_state_machine_transition_is_a_low_not_a_medium():
    # The write needs a status only a privileged path can set.
    findings = _claims(_TRANSITION)
    assert [f["severity"] for f in findings] == ["low"]
    assert "state guard" in findings[0]["title"]


def test_one_finding_per_function_even_when_two_slots_are_claimed():
    source = _LAND_GRAB.replace(
        "        listings[listingId] = Listing({agentWallet: msg.sender});",
        "        listings[listingId] = Listing({agentWallet: msg.sender});\n"
        "        claimedAt[listingId] = block.timestamp;",
    ).replace(
        "    mapping(bytes32 => Listing) public listings;",
        "    mapping(bytes32 => Listing) public listings;\n"
        "    mapping(bytes32 => uint256) public claimedAt;",
    )
    findings = _claims(source)
    assert len(findings) == 1
    assert "listings[" in findings[0]["title"] and "claimedAt[" in findings[0]["title"]


_BLOCKHASH_LOTTERY = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract NaiveDraw {
    function winner(uint256 n) external view returns (uint256) {
        return uint256(blockhash(block.number - 1)) % n;
    }
}
"""

_BLOCKHASH_LIVENESS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Expiry {
    mapping(uint256 => uint64) internal _seedBlock;

    function expired(uint256 roundId) external view returns (bool) {
        return blockhash(_seedBlock[roundId]) == bytes32(0);
    }
}
"""

_BLOCKHASH_BOUND = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Bound {
    address public oracleSigner;

    function draw(uint64 seedBlock, bytes32 beaconRandom) external view returns (uint256) {
        bytes32 bh = blockhash(seedBlock);
        require(bh != bytes32(0), "expired");
        return uint256(keccak256(abi.encode(bh, beaconRandom, oracleSigner)));
    }
}
"""


def _entropy_findings(source: str) -> list[dict]:
    return [
        f for f in run_detectors(source, "Draw.sol")
        if f["detector_id"] == "entropy.blockhash"
    ]


def test_blockhash_as_sole_entropy_is_a_medium():
    # Nothing in the file binds the draw to an oracle, VDF or beacon.
    assert [f["severity"] for f in _entropy_findings(_BLOCKHASH_LOTTERY)] == ["medium"]


def test_blockhash_availability_check_is_not_an_entropy_finding():
    # `blockhash(b) == 0` is the 256-block expiry idiom; the value is never used.
    assert _entropy_findings(_BLOCKHASH_LIVENESS) == []


def test_blockhash_bound_to_a_beacon_stays_an_advisory_low():
    findings = _entropy_findings(_BLOCKHASH_BOUND)
    assert [f["severity"] for f in findings] == ["low"]
