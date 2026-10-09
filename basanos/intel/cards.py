from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from basanos.detectors import DETECTOR_CATEGORIES

DETECTOR_CATEGORIES = DETECTOR_CATEGORIES  # re-export for intel callers


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class KnowledgeCard:
    card_id: str
    source: str
    title: str
    url: str
    published: str
    summary: str
    mapped_categories: list[str]
    identifiers: list[str] = field(default_factory=list)
    weight: float = 1.0
    ingested_at: str = field(default_factory=_now_z)

    @staticmethod
    def make_id(source: str, url: str, title: str) -> str:
        return "card-" + hashlib.sha256(f"{source}|{url}|{title}".encode()).hexdigest()[:20]

    def sanitized(self) -> "KnowledgeCard":
        self.title = (self.title or "")[:200]
        self.summary = (self.summary or "")[:600]
        self.url = (self.url or "")[:500]
        self.mapped_categories = [
            c for c in (self.mapped_categories or []) if c in DETECTOR_CATEGORIES
        ][: len(DETECTOR_CATEGORIES)]
        self.identifiers = [str(i)[:40] for i in (self.identifiers or [])][:12]
        self.weight = max(0.0, min(3.0, float(self.weight or 1.0)))
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_actionable(self) -> bool:
        return bool(self.mapped_categories)
