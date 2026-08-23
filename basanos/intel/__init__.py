"""Distilled advisory cards. Fetched text is DATA, never instructions."""

from __future__ import annotations

from basanos.intel.cards import DETECTOR_CATEGORIES, KnowledgeCard
from basanos.intel.sources import FEED_ALLOWLIST, ThreatFeed, default_feeds, intel_enabled

__all__ = [
    "DETECTOR_CATEGORIES",
    "KnowledgeCard",
    "FEED_ALLOWLIST",
    "ThreatFeed",
    "default_feeds",
    "intel_enabled",
]
