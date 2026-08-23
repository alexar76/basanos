"""Cross-contract layer.

Measured origin: a hand audit of this ecosystem's ACEX contracts found two exploitable
criticals; a full single-file BASANOS scan of the same tree reported eight findings, all
`pragma.floating`. Both criticals were cross-contract, so no per-file detector could pose
the question. These tests pin the shapes that layer must recognise — and, just as
importantly, the ones it must stay quiet about.
"""

from __future__ import annotations

from basanos.xcontract import contract_facts, run_cross_detectors

# The ACEX vault shape, reduced: one balance, two privileged writers, mutated through a
# storage pointer (which is how real Solidity does it, and what a naive write tracker
# misses entirely).
VAULT = """
pragma solidity 0.8.28;
contract Vault {
    struct Position { uint256 usdcBalance; uint256 lockedForNotes; }
    mapping(bytes32 => Position) public positions;
    address public registry;
    address public lendingPool;

    modifier onlyRegistry() { _; }
    modifier onlyLendingPool() { _; }

    function _credit(bytes32 id, uint256 amount) internal {
        positions[id].usdcBalance += amount;
    }
    function depositCollateral(bytes32 id, uint256 amount) external { _credit(id, amount); }
    function creditCollateral(bytes32 id, uint256 amount) external onlyRegistry {
        _credit(id, amount);
    }
    function lockForNote(bytes32 id, uint256 amount) external onlyRegistry {
        Position storage p = positions[id];
        p.usdcBalance -= amount;
        p.lockedForNotes += amount;
    }
    function seizeTo(bytes32 id, uint256 amount) external onlyLendingPool {
        Position storage p = positions[id];
        p.usdcBalance -= amount;
    }
}
"""

# One authority plus an open deposit — the ordinary shape. Must NOT fire.
SINGLE_AUTHORITY = """
pragma solidity 0.8.28;
contract Simple {
    mapping(address => uint256) public balances;
    modifier onlyOwner() { _; }
    function deposit(uint256 a) external { balances[msg.sender] += a; }
    function sweep(address to, uint256 a) external onlyOwner { balances[to] -= a; }
}
"""

# The ACEX oracle shape, reduced: A prices from B's state, and anyone can write it.
AMM_AND_READER = """
pragma solidity 0.8.28;
contract Amm {
    mapping(address => uint256) public pools;
    function createPool(address token, uint256 amt) external { pools[token] = amt; }
}
contract Reader {
    Amm public amm;
    mapping(bytes32 => uint256) public baseline;
    function capture(bytes32 id, address token) external {
        baseline[id] = amm.pools(token);
    }
}
"""

GATED_AMM_AND_READER = AMM_AND_READER.replace(
    "function createPool(address token, uint256 amt) external {",
    "modifier onlyOwner() { _; }\n    function createPool(address token, uint256 amt) external onlyOwner {",
)


def _ids(source: str) -> list[str]:
    return [f["detector_id"] for f in run_cross_detectors([("X.sol", source)])]


def _titles(source: str) -> list[str]:
    return [f["title"] for f in run_cross_detectors([("X.sol", source)])]


def test_storage_alias_writes_are_attributed_to_the_mapping():
    """`Position storage p = positions[id]; p.usdcBalance -= a;` is a write to `positions`."""
    (vault,) = contract_facts(VAULT, "Vault.sol")
    writers = vault.writers_of("positions")
    assert "onlyRegistry" in writers
    assert "onlyLendingPool" in writers, "a storage-pointer write must not be invisible"
    assert "lockForNote" in writers["onlyRegistry"]
    assert "seizeTo" in writers["onlyLendingPool"]


def test_writes_through_an_internal_helper_belong_to_the_public_caller():
    """`_credit` is where the write is; the authority sits on whoever may call it."""
    (vault,) = contract_facts(VAULT, "Vault.sol")
    writers = vault.writers_of("positions")
    assert "depositCollateral" in writers[""], "an ungated public writer must be visible"
    assert "creditCollateral" in writers["onlyRegistry"]


def test_two_privileged_authorities_on_one_slot_is_reported():
    assert "xcontract.multi_authority_state" in _ids(VAULT)
    assert any("positions" in t for t in _titles(VAULT))


def test_one_authority_plus_an_open_deposit_is_not_reported():
    """Otherwise every ERC20-ish contract in existence fires and the signal is worthless."""
    assert "xcontract.multi_authority_state" not in _ids(SINGLE_AUTHORITY)


def test_reading_state_anyone_can_write_is_reported():
    ids = _ids(AMM_AND_READER)
    assert "xcontract.trusts_open_external_state" in ids
    title = next(t for t in _titles(AMM_AND_READER) if "pools" in t)
    assert "createPool" in title and "Reader" in title


def test_the_same_read_is_quiet_once_the_writer_is_gated():
    assert "xcontract.trusts_open_external_state" not in _ids(GATED_AMM_AND_READER)


def test_findings_carry_the_fields_a_pack_requires():
    for finding in run_cross_detectors([("X.sol", VAULT), ("Y.sol", AMM_AND_READER)]):
        for key in ("detector_id", "category", "severity", "title", "detail", "path", "line"):
            assert finding.get(key) not in (None, ""), f"{key} missing from {finding}"
        assert finding["category"] == "cross-contract"


def test_unparseable_source_does_not_break_the_pass():
    """A scan must degrade, not crash: an empty pack claims nothing, a crashed one lies."""
    assert run_cross_detectors([("bad.sol", "contract Broken { function f( {")]) == []
    assert run_cross_detectors([]) == []


def test_interface_only_file_yields_no_authority_claims():
    iface = "pragma solidity 0.8.28;\ninterface IThing { function f(bytes32 id) external; }"
    assert run_cross_detectors([("I.sol", iface)]) == []
