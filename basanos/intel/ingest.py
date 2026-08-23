"""Pull allowlisted feeds into the knowledge store. Intel is attention, not new detectors."""

from __future__ import annotations

from typing import Any

from basanos.intel.distill import distill
from basanos.intel.sources import default_feeds, fetch_raw, intel_enabled
from basanos.intel.store import KnowledgeStore


async def ingest_into(store: KnowledgeStore) -> dict[str, Any]:
    if not intel_enabled():
        return {"ingested": 0, "reason": "intel_disabled", "cards_total": store.summary()["cards_total"]}
    added = 0
    scanned = 0
    for feed in default_feeds():
        items = await fetch_raw(feed)
        scanned += len(items)
        for item in items:
            card = distill(item, source=feed.feed_id)
            if card and store.ingest_card(card):
                added += 1
    return {
        "ingested": added,
        "scanned": scanned,
        "cards_total": store.summary()["cards_total"],
        "reason": "ok",
    }
