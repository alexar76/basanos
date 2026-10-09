"""Scan memos — Metis-style long-term memory for detector attention.

A memo is DATA: contract-kind + detector outcome. Recalled memos may boost a
closed category in UCB1. They cannot add a detector, change a verdict ladder,
or emit scoreBps. Distilled lessons are compact counts, not free-form prompts.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from basanos.detectors import DETECTOR_CATEGORIES

_MAX_MEMOS = 4000
_LESSON_MIN = 3


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


@dataclass
class Memo:
    memo_id: str
    kind: str
    category: str
    detector_id: str
    hit: bool
    path: str
    title: str
    ingested_at: str = field(default_factory=_now_z)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MemoStore:
    """JSONL memory + TF-IDF recall (same shape as Metis VectorMemory, local to BASANOS)."""

    def __init__(self, data_dir: str) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "memos.jsonl"
        self._memos: list[Memo] = []
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if d.get("category") not in DETECTOR_CATEGORIES:
                    continue
                self._memos.append(
                    Memo(
                        memo_id=str(d.get("memo_id") or "")[:80],
                        kind=str(d.get("kind") or "generic")[:40],
                        category=str(d["category"]),
                        detector_id=str(d.get("detector_id") or "")[:80],
                        hit=bool(d.get("hit")),
                        path=str(d.get("path") or "")[:200],
                        title=str(d.get("title") or "")[:200],
                        ingested_at=str(d.get("ingested_at") or _now_z())[:40],
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        if len(self._memos) > _MAX_MEMOS:
            self._memos = self._memos[-_MAX_MEMOS:]

    def record(
        self,
        *,
        kind: str,
        category: str,
        detector_id: str,
        hit: bool,
        path: str,
        title: str,
    ) -> Memo | None:
        if category not in DETECTOR_CATEGORIES:
            return None
        memo = Memo(
            memo_id=f"m-{len(self._memos)+1}-{int(time.time())}",
            kind=kind[:40],
            category=category,
            detector_id=detector_id[:80],
            hit=hit,
            path=path[:200],
            title=title[:200],
        )
        self._memos.append(memo)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(memo.to_dict(), ensure_ascii=False) + "\n")
        return memo

    def record_scan(self, kind: str, findings: list[dict[str, Any]], *, detector_ids: list[str]) -> None:
        hit_ids = {str(f.get("detector_id") or "") for f in findings}
        hit_cats = {str(f.get("category") or "") for f in findings}
        by_id_title = {
            str(f.get("detector_id") or ""): str(f.get("title") or "")[:200] for f in findings
        }
        from basanos.detectors import DETECTORS

        cat_of = {d.detector_id: d.category for d in DETECTORS}
        for detector_id in detector_ids:
            cat = cat_of.get(detector_id, "")
            hit = detector_id in hit_ids or cat in hit_cats
            self.record(
                kind=kind,
                category=cat or "pragma",
                detector_id=detector_id,
                hit=hit and detector_id in hit_ids,
                path="",
                title=by_id_title.get(detector_id, ""),
            )

    def recall(self, kind: str, *, limit: int = 8) -> list[Memo]:
        query = _tokenize(kind)
        scored: list[tuple[float, Memo]] = []
        for memo in self._memos:
            if not memo.hit:
                continue
            tokens = _tokenize(f"{memo.kind} {memo.category} {memo.detector_id} {memo.title}")
            overlap = len(query & tokens) if query else (1 if memo.kind == kind else 0)
            if memo.kind == kind:
                overlap += 2
            if overlap <= 0:
                continue
            scored.append((float(overlap), memo))
        scored.sort(key=lambda x: x[0], reverse=True)
        seen: set[str] = set()
        out: list[Memo] = []
        for _score, memo in scored:
            key = f"{memo.category}|{memo.detector_id}"
            if key in seen:
                continue
            seen.add(key)
            out.append(memo)
            if len(out) >= limit:
                break
        return out

    def boost_map(self, kind: str) -> dict[str, float]:
        """Extra UCB alpha from repeated hits on this contract kind. Capped."""
        boosts: dict[str, float] = {}
        for memo in self._memos:
            if not memo.hit:
                continue
            if memo.kind != kind and kind != "generic":
                continue
            boosts[memo.category] = min(3.0, boosts.get(memo.category, 0.0) + 0.35)
        return boosts

    def distill_lessons(self, *, min_hits: int = _LESSON_MIN) -> list[dict[str, Any]]:
        counts: dict[tuple[str, str], int] = {}
        for memo in self._memos:
            if not memo.hit:
                continue
            key = (memo.kind, memo.category)
            counts[key] = counts.get(key, 0) + 1
        lessons = [
            {
                "kind": kind,
                "category": cat,
                "hits": n,
                "lesson": f"{kind} contracts repeatedly trip {cat} — scan that family first",
            }
            for (kind, cat), n in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
            if n >= min_hits
        ]
        return lessons[:12]

    def summary(self) -> dict[str, Any]:
        hits = sum(1 for m in self._memos if m.hit)
        return {
            "memos_total": len(self._memos),
            "hits": hits,
            "lessons": self.distill_lessons(),
            "exploration": round(math.sqrt(1.0 / (1.0 + hits)), 4),
        }
