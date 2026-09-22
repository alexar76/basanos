"""What BASANOS will and will not claim.

These strings are part of every Assurance Pack. A pack that omitted them would
look like a catalog admission or an insurance quote — which is how the
``auditor`` word got overloaded in the first place.
"""

from __future__ import annotations

IN_SCOPE = (
    "static Solidity source at a pinned commit / tree digest",
    "function-body IR (brace-matched CEI, access, upgrade, hash, loops)",
    "closed detector set — memos and intel may only reorder it",
    "whole-tree contract graph: per-contract state, who may write each slot, and which "
    "contract reads which other contract's state (cross-contract shape, not proof)",
    "allowlisted public advisories as detector *attention* only",
    "local scan memos (Metis-style recall) that boost known families",
)

NOT_IN_SCOPE = (
    "runtime / live-federation probes — that is MOMUS",
    "Hub catalogue admit/reject — that is THEMIS",
    "on-chain USDC cover, scoreBps, TWAP default slash — that is AgentAuditPool",
    "capability-chain compose/price/run — that is HEPHAESTUS",
    "formal verification, fuzzing, or a substitute for a $80k firm PDF",
    # Learned the hard way: a hand audit of this ecosystem's own ACEX contracts found two
    # criticals — the same USDC pledged to a lending pool AND to a bond series across two
    # contracts, and a default whose beneficiary could cause it — while a BASANOS scan of
    # that exact tree reported nothing but a floating pragma. A pack that does not say this
    # reads as "sound" when it only means "no known pattern matched".
    "PROVING a cross-contract accounting invariant. There is now a whole-tree pass "
    "(basanos/xcontract.py) that finds the SHAPE — one slot mutated by two authorities, a "
    "value read from state anyone may write — and says which invariant to check. It does "
    "not verify that the invariant holds, and it follows storage aliases and one level of "
    "internal calls, not arbitrary indirection",
    "ECONOMIC incentive flaws (who profits from a state transition, whether the party a "
    "mechanism protects against can trigger it) — severity here is pattern risk, not payoff",
    "whether a value is economically meaningful (a floor in raw token units may be dust)",
    "executing bytecode, fetching URLs found in source, or compiling with solc",
    "emitting scoreBps or calling coverListing",
    "executing containment, pause, slash, or public disclosure — the pack only recommends (ISO/IEC 29147 / 30111)",
)

# Keys that must never appear on a pack. Tests lock this.
FORBIDDEN_PACK_KEYS = frozenset(
    {
        "scoreBps",
        "score_bps",
        "coverListing",
        "cover_listing",
        "approve",
        "reject",
        "decision",
    }
)
