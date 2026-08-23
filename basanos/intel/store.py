"""UCB1 over (detector-category, contract-kind). Intel steers attention only."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from basanos.intel.cards import DETECTOR_CATEGORIES, KnowledgeCard

_UCB_C = 1.4
_EXT_PRIOR_CAP = 3.0
_CARD_HALF_LIFE_DAYS = 30.0


def _now() -> float:
    return time.time()


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class _Arm:
    alpha: float = 1.0
    beta: float = 1.0

    @property
    def n(self) -> float:
        return self.alpha + self.beta


class KnowledgeStore:
    def __init__(self, data_dir: str) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._cards_path = self._dir / "knowledge_cards.jsonl"
        self._outcomes_path = self._dir / "learning_state.json"
        self._cards: dict[str, KnowledgeCard] = {}
        self._arms: dict[str, _Arm] = {}
        self._load()

    def _load(self) -> None:
        if self._cards_path.is_file():
            for line in self._cards_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    self._cards[d["card_id"]] = KnowledgeCard(
                        **{k: v for k, v in d.items() if k in KnowledgeCard.__dataclass_fields__}
                    )
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        if self._outcomes_path.is_file():
            try:
                state = json.loads(self._outcomes_path.read_text(encoding="utf-8"))
                for k, v in (state.get("arms") or {}).items():
                    self._arms[k] = _Arm(
                        alpha=float(v.get("alpha", 1.0)), beta=float(v.get("beta", 1.0))
                    )
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

    def _persist_arms(self) -> None:
        state = {
            "updated_at": _now_z(),
            "arms": {k: {"alpha": a.alpha, "beta": a.beta} for k, a in self._arms.items()},
        }
        self._outcomes_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    @staticmethod
    def _key(category: str, target_kind: str) -> str:
        return f"{category}|{target_kind}"

    def _arm(self, category: str, target_kind: str) -> _Arm:
        return self._arms.setdefault(self._key(category, target_kind), _Arm())

    def record_outcome(self, category: str, target_kind: str, outcome: str, *, weight: float = 1.0) -> None:
        if category not in DETECTOR_CATEGORIES:
            return
        arm = self._arm(category, target_kind)
        if outcome == "finding":
            arm.alpha += weight
        elif outcome == "no_finding":
            arm.beta += weight
        self._persist_arms()

    def ingest_card(self, card: KnowledgeCard) -> bool:
        if not card.is_actionable() or card.card_id in self._cards:
            return False
        self._cards[card.card_id] = card
        with self._cards_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(card.to_dict(), ensure_ascii=False) + "\n")
        return True

    def _external_boost(self, category: str) -> float:
        boost = 0.0
        now = _now()
        for card in self._cards.values():
            if category not in card.mapped_categories:
                continue
            try:
                ingested = time.mktime(time.strptime(card.ingested_at, "%Y-%m-%dT%H:%M:%SZ"))
            except (ValueError, TypeError):
                ingested = now
            age_days = max(0.0, (now - ingested) / 86400.0)
            decay = 0.5 ** (age_days / _CARD_HALF_LIFE_DAYS)
            boost += card.weight * decay
        return min(_EXT_PRIOR_CAP, boost)

    def score(self, category: str, target_kind: str, *, extra_alpha: float = 0.0) -> float:
        arm = self._arm(category, target_kind)
        alpha_eff = arm.alpha + self._external_boost(category) + max(0.0, extra_alpha)
        mean = alpha_eff / (alpha_eff + arm.beta)
        total = sum(a.n for a in self._arms.values()) + 1.0
        exploration = _UCB_C * math.sqrt(math.log(total + 1.0) / arm.n)
        return mean + exploration

    def order_detectors(
        self,
        detector_ids: list[str],
        target_kind: str,
        *,
        memo_boosts: dict[str, float] | None = None,
    ) -> list[str]:
        from basanos.detectors import DETECTORS

        cat_of = {d.detector_id: d.category for d in DETECTORS}
        boosts = memo_boosts or {}

        def key(did: str) -> float:
            cat = cat_of.get(did, "pragma")
            return self.score(cat, target_kind, extra_alpha=boosts.get(cat, 0.0))

        return sorted(detector_ids, key=key, reverse=True)

    def summary(self, top_n: int = 8) -> dict[str, Any]:
        cards = sorted(self._cards.values(), key=lambda c: c.ingested_at, reverse=True)
        cat_scores = {
            cat: round(self.score(cat, "generic"), 4) for cat in DETECTOR_CATEGORIES
        }
        return {
            "cards_total": len(self._cards),
            "recent_cards": [c.to_dict() for c in cards[:top_n]],
            "category_scores": cat_scores,
            "learned_pairs": len(self._arms),
        }
