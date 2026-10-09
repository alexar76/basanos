"""Lightweight Solidity IR — function bodies with brace matching, no solc."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

_FUNC_HEAD = re.compile(
    r"\bfunction\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?P<rest>[^{;]*)\{",
    re.MULTILINE,
)
#: Modifiers that gate WHO may call. `only<Something>` is the near-universal Solidity
#: convention, so it is matched structurally instead of by a list of known names — the old
#: hard-coded list did not know `onlyRegistry`, `onlyVault`, `onlyLendingPool` or any other
#: project-specific gate, and reported correctly-gated functions as unguarded.
_AUTH_MODIFIER = re.compile(
    r"\b(only\w+|initializer|reinitializer|requiresAuth|authorized|restricted|permissioned)\b"
)

#: Modifiers that gate WHEN or HOW a call runs — never who. These used to sit in the same
#: list as `onlyOwner`, which made the guard test a false-negative machine: a privileged
#: function carrying nothing but `nonReentrant` was judged "gated".
_NONAUTH_MODIFIER = re.compile(
    r"\b(nonReentrant|whenNotPaused|whenPaused|payable|virtual|override|pure|view)\b"
)

#: A caller check written in the body instead of as a modifier — `borrow` in ACEX does
#: `if (L.agentWallet != msg.sender) revert Unauthorized();`. That is authorization too.
_SENDER_CHECK = re.compile(r"msg\.sender[^;\n]*(==|!=)|(==|!=)[^;\n]*msg\.sender")

_MODIFIER = re.compile(
    r"\b(only\w+|nonReentrant|whenNotPaused|whenPaused|initializer|reinitializer|"
    r"requiresAuth|authorized|restricted|permissioned)\b"
)
_VALUE_CALL = re.compile(r"\.call\s*\{[^}]*value\s*:")
_DELEGATE = re.compile(r"\.delegatecall\s*\(")
_STATE_WRITE = re.compile(
    r"\b(?:balances|allowance|owner|_owner|_balances|_shares|_totalSupply|totalSupply)\s*\["
)
_ASSIGN = re.compile(r"\b\w[\w.]*\s*=(?!=)")
_PRIVILEGED_NAME = re.compile(
    r"^(setOwner|transferOwnership|mint|burn|upgradeTo|upgradeToAndCall|initialize|"
    r"_authorizeUpgrade|pause|unpause|sweep|drain|rescue|setOracle|setPrice)$",
    re.IGNORECASE,
)
_USER_FLOW = re.compile(r"^(deposit|withdraw|transfer|approve|transferFrom|balanceOf)$", re.IGNORECASE)


def iter_code_lines(source: str) -> Iterator[tuple[int, str]]:
    """Yield (lineno, code) skipping // and /* */ comments."""
    in_block = False
    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw
        if in_block:
            end = line.find("*/")
            if end < 0:
                continue
            line = line[end + 2 :]
            in_block = False
        out: list[str] = []
        i = 0
        while i < len(line):
            if line.startswith("/*", i):
                end = line.find("*/", i + 2)
                if end < 0:
                    in_block = True
                    break
                i = end + 2
                continue
            if line.startswith("//", i):
                break
            out.append(line[i])
            i += 1
        code = "".join(out).rstrip()
        if code.strip():
            yield lineno, code


@dataclass(frozen=True)
class FunctionIR:
    name: str
    args: str
    rest: str
    body: str
    line: int
    visibility: str

    @property
    def modifiers(self) -> str:
        return self.rest

    @property
    def guarded(self) -> bool:
        """Is there an AUTHORIZATION gate on this function?

        Deliberately narrower than "has a modifier": `nonReentrant` and `whenNotPaused`
        restrict when a call may run, not who may make it, so counting them here hid
        privileged functions that nothing authorized.
        """
        return bool(
            _AUTH_MODIFIER.search(self.rest)
            or _SENDER_CHECK.search(self.body)
        )

    @property
    def has_any_modifier(self) -> bool:
        """Any modifier at all, authorization or not."""
        return bool(_MODIFIER.search(self.rest))

    @property
    def nonauth_modifiers_only(self) -> bool:
        """Carries a modifier, but none of them decide WHO may call — the shape that used
        to read as safe."""
        return bool(_NONAUTH_MODIFIER.search(self.rest)) and not self.guarded

    @property
    def is_privileged_name(self) -> bool:
        return bool(_PRIVILEGED_NAME.match(self.name))

    @property
    def is_user_flow(self) -> bool:
        return bool(_USER_FLOW.match(self.name))

    @property
    def arg_names(self) -> list[str]:
        names: list[str] = []
        for part in self.args.split(","):
            toks = part.strip().split()
            if toks:
                names.append(toks[-1].lstrip("_"))
        return names


def _index_to_line(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _source_line(joined: str, index: int, line_map: list[int]) -> int:
    """Translate an offset in comment-stripped code back to its file line."""
    ordinal = _index_to_line(joined, index)
    if 1 <= ordinal <= len(line_map):
        return line_map[ordinal - 1]
    return ordinal


def _extract_body(src: str, brace_open: int) -> tuple[str, int]:
    depth = 0
    i = brace_open
    while i < len(src):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[brace_open + 1 : i], i
        i += 1
    return src[brace_open + 1 :], len(src)


def joined_code(source: str) -> tuple[str, list[int]]:
    """Comment-stripped code, plus a map from joined line ordinal to source line.

    `iter_code_lines` drops blank and comment-only lines, so counting newlines in the
    joined text answers "which code line", not "which line of the file". Reporting the
    former put every function-level finding tens of lines above the real code (in this
    monorepo, `fulfillDraw` at source line 452 was reported at 253) — an operator
    following a pack landed in an unrelated function.
    """
    pairs = list(iter_code_lines(source))
    return "\n".join(code for _, code in pairs), [lineno for lineno, _ in pairs]


def parse_functions(source: str) -> list[FunctionIR]:
    joined, line_map = joined_code(source)
    out: list[FunctionIR] = []
    for match in _FUNC_HEAD.finditer(joined):
        body, _end = _extract_body(joined, match.end() - 1)
        rest = match.group("rest")
        vis = "internal"
        for token in ("external", "public", "internal", "private"):
            if token in rest.split():
                vis = token
                break
        out.append(
            FunctionIR(
                name=match.group("name"),
                args=match.group("args"),
                rest=rest,
                body=body,
                line=_source_line(joined, match.start(), line_map),
                visibility=vis,
            )
        )
    return out


def cei_inverted(fn: FunctionIR) -> bool:
    """True when a value-call is followed by a storage write in the same function."""
    match = _VALUE_CALL.search(fn.body)
    if not match:
        return False
    after = fn.body[match.end() :]
    return bool(_STATE_WRITE.search(after) or _ASSIGN.search(after))


def delegatecall_target_is_argument(fn: FunctionIR) -> bool:
    if not _DELEGATE.search(fn.body):
        return False
    args = set(fn.arg_names)
    if not args:
        return False
    for call in _DELEGATE.finditer(fn.body):
        window = fn.body[max(0, call.start() - 80) : call.end() + 40]
        if any(re.search(rf"\b{re.escape(name)}\b", window) for name in args):
            return True
    return False
