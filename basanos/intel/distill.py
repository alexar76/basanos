"""Raw advisory → KnowledgeCard. Deterministic keyword map; no LLM required.

A hostile advisory that says "ignore your rules" cannot add a detector, change a
verdict threshold, or mint scoreBps. It can only map onto the closed category set.
"""

from __future__ import annotations

import re
from typing import Any

from basanos.intel.cards import DETECTOR_CATEGORIES, KnowledgeCard

_KEYWORDS = {
    "reentrancy": ("reentrancy", "re-entrancy", "swc-107", "checks-effects"),
    "access-control": ("access control", "missing onlyowner", "unauthorized", "privilege", "ecrecover"),
    "oracle": ("oracle", "twap", "spot price", "flash loan", "reserves"),
    "entropy": ("weak randomness", "blockhash", "timestamp", "swc-120", "predictable"),
    "delegatecall": ("delegatecall", "swc-112", "untrusted callee"),
    "selfdestruct": ("selfdestruct", "suicide", "swc-106"),
    "tx-origin": ("tx.origin", "swc-115"),
    "pragma": ("floating pragma", "swc-103", "compiler version"),
    "unchecked-call": ("unchecked call", "swc-104", "return value"),
    "secret": ("private key", "hardcoded secret", "exposed key"),
}

_INJECTION = re.compile(
    r"(ignore (previous|all) instructions|you are now|system prompt|exfiltrat)",
    re.IGNORECASE,
)


def looks_like_injection(text: str) -> bool:
    return bool(_INJECTION.search(text or ""))


def _deterministic_map(blob: str) -> list[str]:
    lower = blob.casefold()
    cats = [cat for cat, words in _KEYWORDS.items() if any(w in lower for w in words)]
    return [c for c in cats if c in DETECTOR_CATEGORIES]


def distill(item: dict[str, Any], *, source: str) -> KnowledgeCard | None:
    title = str(item.get("title") or "")[:200]
    text = str(item.get("text") or "")[:4000]
    url = str(item.get("url") or "")[:500]
    if looks_like_injection(f"{title}\n{text}"):
        # Keep the card only if the *rest* of the text still maps; never trust extra categories.
        text = title
    cats = _deterministic_map(f"{title} {text}")
    card = KnowledgeCard(
        card_id=KnowledgeCard.make_id(source, url, title),
        source=source,
        title=title,
        url=url,
        published=str(item.get("published") or "")[:40],
        summary=text[:400],
        mapped_categories=cats,
        identifiers=[str(i) for i in (item.get("identifiers") or []) if i][:12],
    ).sanitized()
    return card if card.is_actionable() else None
