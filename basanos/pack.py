"""Assurance Pack — the only BASANOS product.

A pack is a signed statement about Solidity at a specific tree digest. It is
not a Hub admission, not a red-team finding against a live host, and not an
on-chain insurance quote.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from basanos.handling import handling_for, stamp_findings
from basanos.limits import FORBIDDEN_PACK_KEYS, IN_SCOPE, NOT_IN_SCOPE

PACK_VERSION = "1.0.0"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def pack_digest(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verdict_for(findings: list[dict[str, Any]]) -> str:
    ranks = [SEVERITY_RANK.get(str(f.get("severity") or "info"), 0) for f in findings]
    worst = max(ranks, default=0)
    if worst >= 3:
        return "FAIL"
    if worst >= 2:
        return "REVIEW"
    return "PASS"


def build_pack(
    *,
    commit_sha: str,
    tree_digest: str,
    files: list[str],
    findings: list[dict[str, Any]],
    detector_order: list[str],
    intel: dict[str, Any],
) -> dict[str, Any]:
    stamped = stamp_findings(findings)
    # An empty subject is its own outcome. `verdict_for` ranks severities and cannot know
    # the difference between "read 40 files, found nothing bad" (PASS) and "read nothing"
    # — and conflating those in either direction is a lie in a signed artifact.
    verdict = "NO_SUBJECT" if not files else verdict_for(stamped)
    body = {
        "pack_version": PACK_VERSION,
        "verdict": verdict,
        "commit": {"sha": commit_sha, "tree_digest": tree_digest},
        "subject": {"file_count": len(files), "files": files[:MAX_FILES_IN_PACK]},
        "findings": stamped,
        "handling": handling_for(verdict, stamped),
        "limits": {"in_scope": list(IN_SCOPE), "not_in_scope": list(NOT_IN_SCOPE)},
        "learning": {
            "detector_order": detector_order,
            "intel_cards": int(intel.get("cards_total") or 0),
            "memos_total": int(intel.get("memos_total") or 0),
            "lessons": list(intel.get("lessons") or [])[:8],
            "recalled_memos": list(intel.get("recalled_memos") or [])[:8],
            "rule": "memos and intel reorder detectors; they cannot add detectors or emit scoreBps",
        },
    }
    digest = pack_digest(body)
    pack = {**body, "basanos_report_digest": digest}
    leaked = FORBIDDEN_PACK_KEYS.intersection(pack)
    if leaked:
        raise RuntimeError(f"assurance pack must not contain {sorted(leaked)}")
    return pack


MAX_FILES_IN_PACK = 80
