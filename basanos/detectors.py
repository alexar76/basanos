"""Closed detector set. Internet intel may reorder these; it cannot add one."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from basanos.ir import (
    cei_inverted,
    delegatecall_target_is_argument,
    iter_code_lines,
    parse_functions,
)
from basanos.models import finding_dict

DETECTOR_CATEGORIES = (
    "reentrancy",
    "access-control",
    "oracle",
    "entropy",
    "delegatecall",
    "selfdestruct",
    "tx-origin",
    "pragma",
    "unchecked-call",
    "secret",
    "dead-guard",
)

SKIP_DIR_NAMES = frozenset(
    {"lib", "node_modules", "out", "cache", ".git", "broadcast", "artifacts"}
)

_CALL_VALUE = re.compile(r"\.call\s*\{[^}]*value\s*:")
_EXTERNAL_CALL = re.compile(r"\.(call|delegatecall|staticcall)\s*[\({]")
_TX_ORIGIN = re.compile(r"\btx\.origin\b")
_SELFDESTRUCT = re.compile(r"\b(selfdestruct|suicide)\s*\(")
_DELEGATE = re.compile(r"\.delegatecall\s*\(")
_BLOCKHASH = re.compile(r"\bblockhash\s*\(")
_TIMESTAMP_SEED = re.compile(r"\b(block\.timestamp|block\.number)\b")
_PRAGMA_FLOAT = re.compile(r"pragma\s+solidity\s+[\^>=]")
_PRIVATE_HEX = re.compile(
    r"\b(bytes32|uint256)\s+(private|internal)\s+\w+\s*=\s*0x[a-fA-F0-9]{64}\b"
)
_ECRECOVER = re.compile(r"\becrecover\s*\(")

#: `mapping(address => bool) [public|private|internal] name;` — the shape an allow-list takes.
_BOOL_MAP_DECL = re.compile(
    r"mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*(?:public|private|internal\s+)?\s*(\w+)\s*;"
)
#: Names that promise a gate. Only these are judged, so an ordinary bool map is not noise.
_GATE_NAME = re.compile(
    r"(?i)(allow|white|black|deny|auth|operator|admin|owner|maker|minter|keeper|"
    r"trusted|permitted|approved|auditor|guardian|relayer|signer)"
)
#: A read that gates control flow.
_GUARD_CONTEXT = re.compile(r"\b(require|revert|if|assert)\b|&&|\|\||!")
#: A caller check, as opposed to merely passing msg.sender somewhere.
_SENDER_COMPARED = re.compile(r"msg\.sender[^;]*(==|!=)|(==|!=)[^;]*msg\.sender")
#: `map[key] = …` / `map[key] += …` / `map[key].field = …` — a claim on a slot.
def _claim_write(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(name)}\s*\[[^\]]+\]\s*(?:\.\s*\w+\s*)?(?:\+)?=[^=]")


@dataclass(frozen=True)
class Detector:
    detector_id: str
    category: str
    run: Callable[[str, str], list[dict]]


def _joined(source: str) -> str:
    return "\n".join(code for _, code in iter_code_lines(source))


def _hits(pattern: re.Pattern[str], source: str, path: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for lineno, code in iter_code_lines(source):
        if pattern.search(code):
            found.append((lineno, code.strip()[:180]))
    return found


def _reentrancy(source: str, path: str) -> list[dict]:
    """Flag a value-call that is followed by a state write in the same function (classic CEI inversion)."""
    text = _joined(source)
    if "ReentrancyGuard" in text or "nonReentrant" in text:
        return []
    findings: list[dict] = []
    for fn in parse_functions(source):
        if not cei_inverted(fn):
            continue
        findings.append(
            finding_dict(
                detector_id="reentrancy.value_call_unguarded",
                category="reentrancy",
                severity="high",
                title="value-call followed by a state write (CEI inverted)",
                detail=f"{fn.name}: .call{{value:…}} is followed by an assignment, and no ReentrancyGuard is named.",
                path=path,
                line=fn.line,
                swc="SWC-107",
            )
        )
    return findings


def _tx_origin(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="auth.tx_origin",
            category="tx-origin",
            severity="high",
            title="tx.origin used in source",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-115",
        )
        for line, snippet in _hits(_TX_ORIGIN, source, path)
    ]


def _selfdestruct(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="lifecycle.selfdestruct",
            category="selfdestruct",
            severity="high",
            title="selfdestruct/suicide present",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-106",
        )
        for line, snippet in _hits(_SELFDESTRUCT, source, path)
    ]


def _delegatecall(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="call.delegatecall",
            category="delegatecall",
            severity="medium",
            title="delegatecall present — confirm the target is not caller-controlled",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-112",
        )
        for line, snippet in _hits(_DELEGATE, source, path)
    ]


def _entropy(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    text = _joined(source)
    has_vdf_or_oracle = bool(
        re.search(r"\b(VDF|vrf|VRF|oracle|ORACLE_SIGNER|blockhash)\b", text)
    )
    for line, snippet in _hits(_BLOCKHASH, source, path):
        findings.append(
            finding_dict(
                detector_id="entropy.blockhash",
                category="entropy",
                severity="medium" if not has_vdf_or_oracle else "low",
                title="blockhash used — confirm it is bound to an oracle/VDF, not used as sole entropy",
                detail=snippet,
                path=path,
                line=line,
                swc="SWC-120",
            )
        )
    # A naked timestamp used as a seed-like expression (modulo / xor) is worse than a deadline.
    for line, snippet in _hits(_TIMESTAMP_SEED, source, path):
        if re.search(r"(%|\^|keccak|hash)", snippet):
            findings.append(
                finding_dict(
                    detector_id="entropy.timestamp_seed",
                    category="entropy",
                    severity="medium",
                    title="block.timestamp/number mixed into a hash or modulo",
                    detail=snippet,
                    path=path,
                    line=line,
                    swc="SWC-120",
                )
            )
    return findings


def _pragma(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="pragma.floating",
            category="pragma",
            severity="low",
            title="floating solidity pragma",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-103",
        )
        for line, snippet in _hits(_PRAGMA_FLOAT, source, path)
    ]


def _unchecked_call(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    lines = list(iter_code_lines(source))
    for idx, (lineno, code) in enumerate(lines):
        if not _EXTERNAL_CALL.search(code) or "delegatecall" in code:
            continue
        window = " ".join(c for _, c in lines[idx : idx + 4])
        if "require(" in window or "success" in window or "SafeERC20" in window:
            continue
        if ".call(" in code or ".call{" in code:
            findings.append(
                finding_dict(
                    detector_id="call.unchecked",
                    category="unchecked-call",
                    severity="medium",
                    title="low-level call without an immediate success check",
                    detail=code.strip()[:180],
                    path=path,
                    line=lineno,
                    swc="SWC-104",
                )
            )
    return findings


def _secrets(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="secret.hardcoded_word",
            category="secret",
            severity="critical",
            title="64-hex word assigned to a private/internal integer — looks like a key",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-123",
        )
        for line, snippet in _hits(_PRIVATE_HEX, source, path)
    ]


def _ecrecover(source: str, path: str) -> list[dict]:
    text = _joined(source)
    if not _ECRECOVER.search(text):
        return []
    if "ECDSA" in text or "OpenZeppelin" in source or "@openzeppelin" in source:
        return []
    line = next((n for n, c in iter_code_lines(source) if _ECRECOVER.search(c)), 0)
    return [
        finding_dict(
            detector_id="sig.raw_ecrecover",
            category="access-control",
            severity="medium",
            title="raw ecrecover without OpenZeppelin ECDSA",
            detail="s-value malleability is on the caller unless a wrapper is used.",
            path=path,
            line=line,
            swc="SWC-117",
        )
    ]


def _oracle_spot(source: str, path: str) -> list[dict]:
    """Flag a spot-price read used as if it were a baseline, without TWAP language nearby."""
    text = _joined(source)
    if not re.search(r"\b(getReserves|slot0|latestRoundData|spotPrice)\s*\(", text):
        return []
    if re.search(r"\b(TWAP|twap|observe|cumulative)\b", text):
        return []
    line = next(
        (
            n
            for n, c in iter_code_lines(source)
            if re.search(r"\b(getReserves|slot0|latestRoundData|spotPrice)\s*\(", c)
        ),
        0,
    )
    return [
        finding_dict(
            detector_id="oracle.spot_without_twap",
            category="oracle",
            severity="high",
            title="spot-price primitive without TWAP/observe language",
            detail="A reserves/slot0/latestRoundData read is not accompanied by a TWAP window.",
            path=path,
            line=line,
            swc="",
        )
    ]


def _privileged_unguarded(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    for fn in parse_functions(source):
        if fn.visibility not in {"external", "public"}:
            continue
        if not fn.is_privileged_name or fn.is_user_flow or fn.guarded:
            continue
        findings.append(
            finding_dict(
                detector_id="auth.privileged_unguarded",
                category="access-control",
                severity="high",
                title=f"{fn.name} is externally callable without an access modifier",
                detail="mint/burn/upgrade/initialize/pause/owner setters must be gated.",
                path=path,
                line=fn.line,
                swc="SWC-105",
            )
        )
    return findings


def _arbitrary_delegatecall(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    for fn in parse_functions(source):
        if not delegatecall_target_is_argument(fn):
            continue
        findings.append(
            finding_dict(
                detector_id="call.delegatecall_user_target",
                category="delegatecall",
                severity="critical",
                title=f"{fn.name}: delegatecall target looks caller-controlled",
                detail="A function argument appears next to .delegatecall — confirm the target cannot be set by msg.sender.",
                path=path,
                line=fn.line,
                swc="SWC-112",
            )
        )
    return findings


def _encode_packed_hash(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="sig.encode_packed_hash",
            category="access-control",
            severity="medium",
            title="keccak256(abi.encodePacked(...)) — adjacent dynamic types can collide",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-133",
        )
        for line, snippet in _hits(re.compile(r"keccak256\s*\(\s*abi\.encodePacked\s*\("), source, path)
    ]


def _transfer_send(source: str, path: str) -> list[dict]:
    return [
        finding_dict(
            detector_id="call.transfer_send",
            category="unchecked-call",
            severity="medium",
            title="address.transfer/send — 2300 gas stipend breaks some receivers",
            detail=snippet,
            path=path,
            line=line,
            swc="SWC-134",
        )
        for line, snippet in _hits(re.compile(r"\.(transfer|send)\s*\("), source, path)
    ]


def _value_call_in_loop(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    for fn in parse_functions(source):
        if "for (" not in fn.body and "for(" not in fn.body:
            continue
        if not _CALL_VALUE.search(fn.body) and ".transfer(" not in fn.body:
            continue
        findings.append(
            finding_dict(
                detector_id="call.value_in_loop",
                category="unchecked-call",
                severity="medium",
                title=f"{fn.name}: value transfer inside a loop",
                detail="A failing receiver can grief the whole payout; prefer pull-payments.",
                path=path,
                line=fn.line,
                swc="SWC-128",
            )
        )
    return findings



def _dead_guard(source: str, path: str) -> list[dict]:
    """An allow-list that is written but never read.

    PulseAMM declared `mapping(address => bool) marketMakers`, exposed an onlyOwner setter
    for it, and never consulted it: `createPool` was open to anyone, so the first caller for
    a share token fixed the pool — and therefore the price the audit pool reads as its
    oracle — forever. The registry carried the same dead `pulseMarketMakers`. Writing to a
    gate that nothing enforces is worse than having no gate, because the operator believes
    the door is locked.
    """
    findings: list[dict] = []
    joined = _joined(source)
    for match in _BOOL_MAP_DECL.finditer(joined):
        name = match.group(1)
        if not _GATE_NAME.search(name):
            continue
        reads_that_gate = 0
        for _, code in iter_code_lines(source):
            if f"{name}[" not in code:
                continue
            if _claim_write(name).search(code):
                continue  # this occurrence is a write
            if _GUARD_CONTEXT.search(code):
                reads_that_gate += 1
        if reads_that_gate:
            continue
        findings.append(
            finding_dict(
                detector_id="auth.declared_but_unenforced",
                category="dead-guard",
                severity="high",
                title=f"{name} is an allow-list that is written but never enforced",
                detail=(
                    f"`{name}` is assigned (a setter exists) but never read in a "
                    "require/if/revert condition, so it gates nothing. Either enforce it on "
                    "the functions it was meant to protect, or delete it — a setter for a "
                    "gate that does not exist reads to an operator as protection."
                ),
                path=path,
                line=_index_to_line_in(source, name),
                swc="SWC-105",
            )
        )
    return findings


def _unauthenticated_state_claim(source: str, path: str) -> list[dict]:
    """An open function that claims a mapping slot keyed by a caller-supplied id.

    Whoever writes first owns the slot, and nothing later can reassign it. In ACEX this was
    `createPool` (first caller defines the oracle pool for a CapShare, permanently),
    `applyForListing` (first caller becomes a listing's agentWallet, with no eviction path)
    and `observeSharePrice` (any caller writes the price the TWAP later weights).
    """
    findings: list[dict] = []
    maps = {m.group(1) for m in re.finditer(r"mapping\s*\([^)]*\)\s*(?:public|private|internal\s+)?\s*(\w+)\s*;", _joined(source))}
    for fn in parse_functions(source):
        if fn.visibility not in {"external", "public"}:
            continue
        if fn.guarded or fn.is_privileged_name:
            continue
        if _SENDER_COMPARED.search(fn.body):
            continue  # the function does its own caller check
        ids = {a for a in fn.arg_names if a}
        if not ids:
            continue
        for name in sorted(maps):
            write = _claim_write(name)
            for line in fn.body.splitlines():
                m = write.search(line)
                if not m:
                    continue
                key = line[line.index("[", m.start()) + 1 : line.index("]", m.start())]
                if not any(i in key for i in ids):
                    continue
                findings.append(
                    finding_dict(
                        detector_id="access.unauthenticated_state_claim",
                        category="access-control",
                        severity="medium",
                        title=f"{fn.name} lets any caller claim {name}[<caller-supplied id>]",
                        detail=(
                            f"`{fn.name}` is externally callable with no modifier and no "
                            f"msg.sender comparison, and writes `{name}` at a key taken from "
                            "its arguments. Confirm that the first writer SHOULD own that "
                            "slot forever, and that there is a way to release or reassign it."
                        ),
                        path=path,
                        line=fn.line,
                        swc="SWC-105",
                    )
                )
                break
    return findings


def _index_to_line_in(source: str, needle: str) -> int:
    idx = source.find(needle)
    return source[:idx].count("\n") + 1 if idx >= 0 else 1


DETECTORS: tuple[Detector, ...] = (
    Detector("auth.declared_but_unenforced", "dead-guard", _dead_guard),
    Detector("access.unauthenticated_state_claim", "access-control", _unauthenticated_state_claim),
    Detector("reentrancy.value_call_unguarded", "reentrancy", _reentrancy),
    Detector("auth.tx_origin", "tx-origin", _tx_origin),
    Detector("auth.privileged_unguarded", "access-control", _privileged_unguarded),
    Detector("lifecycle.selfdestruct", "selfdestruct", _selfdestruct),
    Detector("call.delegatecall", "delegatecall", _delegatecall),
    Detector("call.delegatecall_user_target", "delegatecall", _arbitrary_delegatecall),
    Detector("entropy.blockhash", "entropy", _entropy),
    Detector("pragma.floating", "pragma", _pragma),
    Detector("call.unchecked", "unchecked-call", _unchecked_call),
    Detector("call.transfer_send", "unchecked-call", _transfer_send),
    Detector("call.value_in_loop", "unchecked-call", _value_call_in_loop),
    Detector("secret.hardcoded_word", "secret", _secrets),
    Detector("sig.raw_ecrecover", "access-control", _ecrecover),
    Detector("sig.encode_packed_hash", "access-control", _encode_packed_hash),
    Detector("oracle.spot_without_twap", "oracle", _oracle_spot),
)


def run_detectors(source: str, path: str, *, order: list[str] | None = None) -> list[dict]:
    by_id = {d.detector_id: d for d in DETECTORS}
    sequence = order or [d.detector_id for d in DETECTORS]
    findings: list[dict] = []
    seen: set[str] = set()
    for detector_id in sequence:
        det = by_id.get(detector_id)
        if det is None or detector_id in seen:
            continue
        seen.add(detector_id)
        findings.extend(det.run(source, path))
    for det in DETECTORS:
        if det.detector_id not in seen:
            findings.extend(det.run(source, path))
    return findings
