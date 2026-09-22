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


_BLOCKHASH_LIVENESS = re.compile(
    r"blockhash\s*\([^)]*\)\s*[=!]=\s*(?:bytes32\s*\(\s*0\s*\)|0x0+|0)(?!\w)"
    r"|(?:bytes32\s*\(\s*0\s*\)|0x0+|\b0)\s*[=!]=\s*blockhash\s*\("
)


def _entropy(source: str, path: str) -> list[dict]:
    findings: list[dict] = []
    text = _joined(source)
    # `blockhash` was in this alternation, so its own presence always satisfied the
    # "is it bound to something" test and the medium branch could never fire: a
    # contract using blockhash as its ONLY entropy was reported at the same severity
    # as one that mixes in a signed beacon.
    # Word-bounded, case-sensitive tokens missed this ecosystem's own names —
    # `ChronosVDF`, `onchainVdf`, `oracleSigner` all failed `\bVDF\b` / `\boracle\b`,
    # which is why `blockhash` itself was in the list as a stand-in.
    has_vdf_or_oracle = bool(
        re.search(r"vdf|vrf|oracle|beacon|ecrecover|signer", text, re.IGNORECASE)
    )
    for line, snippet in _hits(_BLOCKHASH, source, path):
        # `blockhash(b) == 0` is the 256-block expiry idiom — the value is never used,
        # only its availability, so there is no entropy binding to confirm. The lottery's
        # `cancelRound` reads exactly this way and produced an advisory about randomness
        # it does not derive.
        if _BLOCKHASH_LIVENESS.search(snippet) and not re.search(
            r"=\s*blockhash\s*\(|blockhash\s*\([^)]*\)\s*[,)]", snippet
        ):
            continue
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


_ENCODE_PACKED = re.compile(r"keccak256\s*\(\s*abi\.encodePacked\s*\(")
_DECL = re.compile(
    r"\b(string|bytes\d*|u?int\d*|address|bool|[A-Z]\w*)\s*(\[[^\]]*\])?\s*"
    r"(?:memory|calldata|storage|payable|public|private|internal|immutable|constant|indexed)?\s*"
    r"\b(\w+)\s*[,;=)]"
)
_FIXED_LITERAL = re.compile(r"^(?:0x[0-9a-fA-F]+|\d[\d_]*|true|false|type\(|uint\d*\(|int\d*\(|bytes\d+\(|address\()")
_DYNAMIC_LITERAL = re.compile("^(?:\"|'|bytes\\s*\\(|string\\s*\\(|abi\\.encode)")


def _declared_types(source: str) -> dict[str, str]:
    """name → declared solidity type, from params, state vars and locals in this file.

    Enough typing to answer the only question SWC-133 asks: are two *dynamic* values
    packed next to each other? Unknown names stay unknown rather than being guessed.
    """
    types: dict[str, str] = {}
    for match in _DECL.finditer(_joined(source)):
        base, array, name = match.group(1), match.group(2), match.group(3)
        if name in {"memory", "calldata", "storage", "returns", "public", "private"}:
            continue
        types.setdefault(name, f"{base}{array or ''}")
    return types


def _is_dynamic(type_name: str) -> bool:
    return type_name.endswith("[]") or type_name in {"string", "bytes"}


def _split_args(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        args.append("".join(current).strip())
    return args


def _packed_arg_text(text: str, open_paren: int) -> str:
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
    return text[open_paren + 1 :]


def _classify_packed_args(args: list[str], types: dict[str, str]) -> tuple[int, int]:
    """(dynamic, untypeable) counts for one encodePacked argument list."""
    dynamic = unknown = 0
    for arg in args:
        if _DYNAMIC_LITERAL.match(arg):
            dynamic += 1
            continue
        if _FIXED_LITERAL.match(arg):
            continue
        name = re.match(r"^[A-Za-z_]\w*", arg)
        declared = types.get(name.group(0)) if name else None
        if declared is None:
            unknown += 1
        elif _is_dynamic(declared):
            dynamic += 1
    return dynamic, unknown


def _encode_packed_hash(source: str, path: str) -> list[dict]:
    """SWC-133 needs TWO adjacent dynamic values — not merely an encodePacked call.

    Flagging every `keccak256(abi.encodePacked(...))` reported two mediums against this
    monorepo's own lottery for `(bytes32)` and `(uint256, bytes32, bytes32)`, which cannot
    collide: fixed-width arguments have exactly one encoding. Mediums that a human must
    dismiss every scan train an operator to dismiss the real ones too, so the packing is
    now typed from the file's own declarations, and anything untypeable is reported as the
    `low` "confirm this yourself" it actually is.
    """
    types = _declared_types(source)
    findings: list[dict] = []
    for lineno, code in iter_code_lines(source):
        for match in _ENCODE_PACKED.finditer(code):
            packed_open = code.find("(", match.end() - 1)
            args = _split_args(_packed_arg_text(code, packed_open if packed_open >= 0 else match.end() - 1))
            dynamic, unknown = _classify_packed_args(args, types)
            if dynamic >= 2:
                findings.append(
                    finding_dict(
                        detector_id="sig.encode_packed_hash",
                        category="access-control",
                        severity="medium",
                        title="keccak256(abi.encodePacked(...)) — adjacent dynamic types can collide",
                        detail=(
                            f"{dynamic} dynamic arguments are packed without a separator: "
                            f"{code.strip()[:160]}"
                        ),
                        path=path,
                        line=lineno,
                        swc="SWC-133",
                    )
                )
            elif unknown >= 2:
                findings.append(
                    finding_dict(
                        detector_id="sig.encode_packed_hash",
                        category="access-control",
                        severity="low",
                        title="keccak256(abi.encodePacked(...)) — argument types not resolvable here",
                        detail=(
                            f"{unknown} arguments could not be typed from this file. If two or "
                            f"more are dynamic (string / bytes / array), the hash can collide: "
                            f"{code.strip()[:160]}"
                        ),
                        path=path,
                        line=lineno,
                        swc="SWC-133",
                    )
                )
    return findings


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
        claimed: list[str] = []
        for name in sorted(maps):
            write = _claim_write(name)
            for line in fn.body.splitlines():
                m = write.search(line)
                if not m:
                    continue
                key = line[line.index("[", m.start()) + 1 : line.index("]", m.start())]
                if not any(i in key for i in ids):
                    continue
                claimed.append(name)
                break
        if not claimed:
            continue
        gated = _state_machine_gated(fn.body, ids)
        slots = ", ".join(f"{name}[<caller-supplied id>]" for name in claimed)
        # One finding per function, not per mapping: `fulfillDraw` writing two round
        # slots used to emit two identical-looking mediums on the same line.
        findings.append(
            finding_dict(
                detector_id="access.unauthenticated_state_claim",
                category="access-control",
                # A permissionless state-machine transition (revert unless the round is
                # already in a specific status) is not a first-writer land grab, and a
                # medium that a human dismisses every scan teaches them to dismiss the
                # real ones. It stays reported, at the severity it deserves.
                severity="low" if gated else "medium",
                title=(
                    f"{fn.name} writes {slots} behind a state guard"
                    if gated
                    else f"{fn.name} lets any caller claim {slots}"
                ),
                detail=(
                    f"`{fn.name}` is externally callable with no modifier and no "
                    f"msg.sender comparison, and writes {slots} at a key taken from "
                    "its arguments. "
                    + (
                        "It reverts unless prior state at that key allows the write, so "
                        "the claim is bounded by the state machine — confirm every status "
                        "path into it is privileged."
                        if gated
                        else "Confirm that the first writer SHOULD own that slot forever, "
                        "and that there is a way to release or reassign it."
                    )
                ),
                path=path,
                line=fn.line,
                swc="SWC-105",
            )
        )
    return findings


# `Round storage r = _rounds[roundId];` and `Listing memory L = registry.getListing(id);`
# are the same thing for this question: an alias for state selected by the caller's key.
_KEYED_ALIAS_BIND = re.compile(r"\b[\w.]+\s+(?:storage|memory)\s+(\w+)\s*=\s*([^;]+);")
_EMPTY = r"(?:address\s*\(\s*0\s*\)|bytes32\s*\(\s*0\s*\)|0x0+|0)"
_MUST_BE_EMPTY = re.compile(rf"!=\s*{_EMPTY}(?!\w)")
_MUST_EXIST = re.compile(rf"==\s*{_EMPTY}(?!\w)")
_ENUM_COMPARE = re.compile(r"[=!]=\s*(?:\w+\.)+[A-Z]\w*")
_REVERTS = re.compile(r"\brevert\b")
_REQUIRES = re.compile(r"\brequire\s*\(")


def _state_machine_gated(body: str, ids: set[str]) -> bool:
    """True when the write needs prior non-default state at the caller-supplied key.

    The distinction the severity turns on:
      * `if (listings[id].agentWallet != address(0)) revert` — the write needs an EMPTY
        slot. That is ACEX's real `applyForListing` squat: first writer owns it forever.
      * `if (r.status != Status.Drawing) revert` — the write needs a status only a
        privileged path can set. That is the lottery's permissionless settlement.
    Both revert on prior state, so polarity is what separates a land grab from a
    transition — and `require` states the passing condition, so it inverts.
    """
    aliases = {
        m.group(1)
        for m in _KEYED_ALIAS_BIND.finditer(body)
        if any(re.search(rf"\b{re.escape(ident)}\b", m.group(2)) for ident in ids)
    }
    gated = False
    for line in body.splitlines():
        is_require = bool(_REQUIRES.search(line))
        if not is_require and not _REVERTS.search(line):
            continue
        touches_key = any(
            re.search(rf"\b{re.escape(alias)}\s*[.\[]", line) for alias in aliases
        ) or any(re.search(rf"\[\s*{re.escape(ident)}\s*\]", line) for ident in ids)
        if not touches_key:
            continue
        if _ENUM_COMPARE.search(line):
            gated = True
            continue
        needs_empty = bool(_MUST_BE_EMPTY.search(line)) if not is_require else bool(
            _MUST_EXIST.search(line)
        )
        if needs_empty:
            return False  # land grab evidence wins over any transition guard
        if _MUST_EXIST.search(line) or (is_require and _MUST_BE_EMPTY.search(line)):
            gated = True
    return gated


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
