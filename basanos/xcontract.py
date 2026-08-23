"""Cross-contract layer — the one BASANOS did not have.

Every detector in :mod:`basanos.detectors` reads a single file. That was measured against
this ecosystem's own ACEX contracts: a hand audit found two exploitable criticals there
and a full BASANOS scan of the same tree reported eight findings, all `pragma.floating`.
Both criticals were invisible for the same structural reason — they lived *between*
contracts:

* one USDC balance in ``AgentCollateralVault`` was the LTV basis ``AgentLendingPool``
  lent against **and** the pot ``AgentListingRegistry`` locked behind bonds, each through
  its own gated entry point. Neither file is wrong on its own;
* ``AgentAuditPool`` read ``PulseAMM``'s reserves as a price oracle while ``PulseAMM``
  let *any* caller create the pool that defines it.

So this module builds a small whole-tree model — contracts, their state, who may write
each slot, and which contracts read which other contract's state — and runs detectors
over *that*. It is a graph heuristic, not an invariant prover: it says "two authorities
mutate one balance, go check they cannot invalidate each other", which is exactly the
question a human auditor asks and a regex cannot pose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from basanos.ir import parse_functions
from basanos.models import finding_dict

#: `contract|library|interface Name ... {`
_CONTRACT = re.compile(r"\b(contract|library|interface)\s+(\w+)[^{]*\{")
#: A state declaration: `mapping(...) [vis] name;` or `Type [vis] name;`
_STATE_MAPPING = re.compile(
    r"mapping\s*\([^;]*?\)\s*(public|private|internal)?\s*(\w+)\s*;", re.DOTALL
)
#: A typed reference to another contract held as state: `PulseAMM public pulseAmm;`
_TYPED_REF = re.compile(r"^\s*([A-Z]\w+)\s+(?:public|private|internal|immutable|\s)*?(\w+)\s*;", re.M)
#: `only<Something>` — the authorization gate convention.
_GATE = re.compile(r"\b(only\w+)\b")
_SENDER_CHECK = re.compile(r"msg\.sender[^;\n]*(==|!=)|(==|!=)[^;\n]*msg\.sender")
#: `name[...]` / `name[...].field` on the left of a single `=`, `+=` or `-=`.
_WRITE = re.compile(r"\b(\w+)\s*\[[^\]]*\]\s*(?:\.\s*\w+\s*)?(?:[-+*/]?)=[^=]")
#: A plain `=` to a slot — DEFINING it, not adjusting it. The distinction carries weight:
#: whoever first defines `pools[token]` fixes that market forever (and `active` blocks
#: re-creation), while a swap that moves `reserveShare` by `+=` is the ordinary, expected
#: motion an AMM exists to perform. Treating both as equally alarming would mean every
#: AMM-priced integration fires HIGH forever, and a permanent finding is a muted one.
_DEFINE = re.compile(r"\b(\w+)\s*\[[^\]]*\]\s*(?:\.\s*\w+\s*)?=[^=]")
#: `CollateralPosition storage p = positions[id];` — idiomatic Solidity, and the reason a
#: naive write tracker is blind to most real mutation: every later `p.field = …` is a write
#: to `positions`. ACEX's vault mutates its collateral this way in `lockForNote` and
#: `seizeTo`, so without this the two privileged writers of one balance were invisible.
_STORAGE_ALIAS = re.compile(r"\b\w+\s+storage\s+(\w+)\s*=\s*(\w+)\s*\[")
#: A write through such an alias: `p.usdcBalance -= amount;` or `p = …`.
_ALIAS_WRITE = re.compile(r"\b(\w+)\s*(?:\.\s*\w+\s*)?(?:[-+*/]?)=[^=]")

#: A plain internal call: `_credit(...)`.
_INTERNAL_CALL = re.compile(r"(?<![.\w])(_\w+)\s*\(")
#: `someRef.getter(` — a read of another contract's state through its accessor.
_EXTERNAL_READ = re.compile(r"\b(\w+)\s*\.\s*(\w+)\s*\(")

#: Bound so a pathological tree cannot turn the graph pass into a CPU sink.
MAX_CONTRACTS = 200


@dataclass
class FnFacts:
    name: str
    visibility: str
    gate: str  # "onlyX" | "sender-check" | "" (open)
    writes: set[str] = field(default_factory=set)
    defines: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    reads_external: set[tuple[str, str]] = field(default_factory=set)  # (ref, member)
    line: int = 1


@dataclass
class ContractFacts:
    name: str
    path: str
    line: int
    state: set[str] = field(default_factory=set)
    refs: dict[str, str] = field(default_factory=dict)  # var name -> contract type
    fns: dict[str, FnFacts] = field(default_factory=dict)

    def writers_of(self, var: str) -> dict[str, set[str]]:
        """gate -> {function names} for every external/public writer of ``var``.

        Writes made through an internal helper count for the public function that calls it
        — that is where the authority actually sits (``depositCollateral`` and
        ``creditCollateral`` both reach ``positions`` through ``_credit``).
        """
        out: dict[str, set[str]] = {}
        for fn in self.fns.values():
            if fn.visibility not in {"external", "public"}:
                continue
            effective = set(fn.writes)
            for callee in fn.calls:
                target = self.fns.get(callee)
                if target is not None:
                    effective |= target.writes
            if var in effective:
                out.setdefault(fn.gate, set()).add(fn.name)
        return out


def _contract_slices(source: str) -> list[tuple[str, int, str]]:
    """(name, line, body) for each top-level contract/library/interface."""
    out: list[tuple[str, int, str]] = []
    for match in _CONTRACT.finditer(source):
        name = match.group(2)
        start = match.end() - 1
        depth = 0
        for i in range(start, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    out.append((name, source[: match.start()].count("\n") + 1, source[start : i + 1]))
                    break
        if len(out) >= MAX_CONTRACTS:
            break
    return out


def contract_facts(source: str, path: str) -> list[ContractFacts]:
    facts: list[ContractFacts] = []
    for name, line, body in _contract_slices(source):
        c = ContractFacts(name=name, path=path, line=line)
        for m in _STATE_MAPPING.finditer(body):
            c.state.add(m.group(2))
        for m in _TYPED_REF.finditer(body):
            type_name, var = m.group(1), m.group(2)
            if type_name in {"function", "return", "if", "for", "while"}:
                continue
            c.refs[var] = type_name
        for fn in parse_functions(body):
            gate = ""
            gm = _GATE.search(fn.rest)
            if gm:
                gate = gm.group(1)
            elif _SENDER_CHECK.search(fn.body):
                gate = "sender-check"
            f = FnFacts(
                name=fn.name, visibility=fn.visibility, gate=gate, line=fn.line
            )
            aliases = {
                m.group(1): m.group(2) for m in _STORAGE_ALIAS.finditer(fn.body)
            }
            for line_text in fn.body.splitlines():
                for wm in _WRITE.finditer(line_text):
                    f.writes.add(wm.group(1))
                for dm in _DEFINE.finditer(line_text):
                    f.defines.add(dm.group(1))
                for cm in _INTERNAL_CALL.finditer(line_text):
                    f.calls.add(cm.group(1))
                for rm in _EXTERNAL_READ.finditer(line_text):
                    f.reads_external.add((rm.group(1), rm.group(2)))
                if aliases:
                    for am in _ALIAS_WRITE.finditer(line_text):
                        target = aliases.get(am.group(1))
                        if target:
                            f.writes.add(target)
            c.fns[fn.name] = f
        facts.append(c)
    return facts


# ──────────────────────────── cross-contract detectors ────────────────────────


def multi_authority_state(all_facts: list[ContractFacts]) -> list[dict[str, Any]]:
    """One slot, two different privileged writers.

    The ACEX shape: ``AgentCollateralVault.positions`` was written under ``onlyRegistry``
    (``creditCollateral`` / ``lockForNote``) and under ``onlyLendingPool`` (``seizeTo``),
    while the lending pool separately read it as its LTV basis. Each writer was correct in
    isolation; together, the registry could move collateral out from under a live loan.

    Two *named* gates are required, so the ordinary "public deposit + admin sweep" shape
    does not fire.
    """
    findings: list[dict[str, Any]] = []
    for c in all_facts:
        for var in sorted(c.state):
            writers = c.writers_of(var)
            named = {g: fns for g, fns in writers.items() if g.startswith("only")}
            if len(named) < 2:
                continue
            open_writers = sorted(writers.get("", set()))
            detail_gates = "; ".join(
                f"{gate} → {', '.join(sorted(fns))}" for gate, fns in sorted(named.items())
            )
            extra = (
                f" Also writable with no gate by: {', '.join(open_writers)}."
                if open_writers
                else ""
            )
            findings.append(
                finding_dict(
                    detector_id="xcontract.multi_authority_state",
                    category="cross-contract",
                    severity="medium",
                    title=(
                        f"{c.name}.{var} is mutated by {len(named)} different "
                        "authorities"
                    ),
                    detail=(
                        f"{detail_gates}.{extra} If another contract reads `{var}` as an "
                        "accounting basis (a balance, collateral, or supply it lends or "
                        "pays against), confirm that neither authority can invalidate a "
                        "claim the other already granted — that is the invariant, and it "
                        "is not visible in any single file."
                    ),
                    path=c.path,
                    line=c.line,
                    swc="SWC-105",
                )
            )
    return findings


def externally_read_open_state(all_facts: list[ContractFacts]) -> list[dict[str, Any]]:
    """Contract A trusts a value that anyone may write in contract B.

    The ACEX shape: ``AgentAuditPool`` read ``pulseAmm.pools(...)`` reserves as the price
    that decides a default (which slashes staked USDC), while ``PulseAMM.createPool`` was
    callable by anyone — so whoever created the pool first defined the oracle forever.
    """
    by_name = {c.name: c for c in all_facts}
    findings: list[dict[str, Any]] = []
    for reader in all_facts:
        for fn in reader.fns.values():
            for ref, member in sorted(fn.reads_external):
                target_type = reader.refs.get(ref)
                if not target_type:
                    continue
                target = by_name.get(target_type)
                if target is None or member not in target.state:
                    continue
                writers = target.writers_of(member)
                open_fns = sorted(writers.get("", set()))
                if not open_fns:
                    continue
                # HIGH when an ungated caller DEFINES the slot (first writer owns it, and
                # nothing later can reassign), MEDIUM when they only move an existing value
                # — which is what an AMM swap is, and what a TWAP or spot re-check exists to
                # absorb. Same finding, honest severity.
                defines_it = sorted(
                    name
                    for name in open_fns
                    if member in target.fns[name].defines
                )
                severity = "high" if defines_it else "medium"
                shape = (
                    f"`{', '.join(defines_it)}` DEFINES that slot, so the first caller owns "
                    "it and no later call can reassign it. "
                    if defines_it
                    else "The ungated callers update an existing value rather than defining "
                    "it, which is ordinary market motion — the risk is manipulation, not capture. "
                )
                findings.append(
                    finding_dict(
                        detector_id="xcontract.trusts_open_external_state",
                        category="cross-contract",
                        severity=severity,
                        title=(
                            f"{reader.name}.{fn.name} reads {target_type}.{member}, which "
                            f"{', '.join(open_fns)} can write with no gate"
                        ),
                        detail=(
                            f"`{reader.name}` consumes `{target_type}.{member}` while "
                            f"`{target_type}.{', '.join(open_fns)}` is externally callable "
                            f"with no authorization gate and no msg.sender check. {shape}"
                            f"Whatever `{reader.name}` decides from that value, an arbitrary "
                            "caller influences. If it prices, scores, or settles anything, "
                            "treat the value as attacker-supplied until proven otherwise."
                        ),
                        path=reader.path,
                        line=fn.line,
                        swc="SWC-105",
                    )
                )
    return findings


CROSS_DETECTORS = (
    ("xcontract.multi_authority_state", multi_authority_state),
    ("xcontract.trusts_open_external_state", externally_read_open_state),
)


def run_cross_detectors(sources: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """``sources`` is [(relative_path, text)]. Returns findings across the whole tree."""
    all_facts: list[ContractFacts] = []
    for path, text in sources:
        try:
            all_facts.extend(contract_facts(text, path))
        except (re.error, RecursionError, ValueError):
            continue
        if len(all_facts) >= MAX_CONTRACTS:
            break
    findings: list[dict[str, Any]] = []
    for _, run in CROSS_DETECTORS:
        findings.extend(run(all_facts))
    return findings
