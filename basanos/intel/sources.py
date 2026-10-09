"""Allowlisted threat feeds. No arbitrary URL. Opt-in. Fail-closed in prod."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

FEED_ALLOWLIST = {
    "api.osv.dev",
    "api.github.com",
}


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def intel_enabled() -> bool:
    if not _truthy(os.environ.get("BASANOS_THREAT_INTEL")):
        return False
    if _truthy(os.environ.get("AIFACTORY_PROD")) and not _truthy(
        os.environ.get("BASANOS_THREAT_INTEL_PROD")
    ):
        return False
    return True


@dataclass
class ThreatFeed:
    feed_id: str
    url: str
    kind: str  # "osv" | "ghsa"
    body: dict[str, Any] | None = None

    def host_ok(self) -> bool:
        host = (urlparse(self.url).hostname or "").lower()
        return host in FEED_ALLOWLIST


_DEFAULT_GITHUB_REPOS = (
    "OpenZeppelin/openzeppelin-contracts",
    "foundry-rs/foundry",
    "transmissions11/solmate",
    "Uniswap/v4-core",
    "aave/aave-v3-core",
    "alexar76/acex",
    "alexar76/aicom",
)


def default_feeds() -> list[ThreatFeed]:
    feeds = [
        ThreatFeed(
            "osv-oz",
            "https://api.osv.dev/v1/query",
            "osv",
            {"package": {"ecosystem": "npm", "name": "@openzeppelin/contracts"}},
        ),
        ThreatFeed(
            "osv-solmate",
            "https://api.osv.dev/v1/query",
            "osv",
            {"package": {"ecosystem": "npm", "name": "solmate"}},
        ),
        ThreatFeed(
            "ghsa-reviewed",
            "https://api.github.com/advisories?per_page=25&type=reviewed",
            "ghsa",
        ),
    ]
    repos = [
        r.strip()
        for r in (
            os.environ.get("BASANOS_INTEL_GITHUB_REPOS") or ",".join(_DEFAULT_GITHUB_REPOS)
        ).split(",")
        if r.strip()
    ]
    for repo in repos:
        if "/" in repo and ".." not in repo:
            feeds.append(
                ThreatFeed(
                    f"ghsa:{repo}",
                    f"https://api.github.com/repos/{repo}/security-advisories?per_page=25",
                    "ghsa",
                )
            )
    return [f for f in feeds if f.host_ok()]


def source_digest(item: dict[str, Any]) -> str:
    canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


async def fetch_raw(feed: ThreatFeed, *, timeout_s: float = 15.0, max_items: int = 25) -> list[dict[str, Any]]:
    if not feed.host_ok() or not intel_enabled():
        return []
    headers: dict[str, str] = {"User-Agent": "aimarket-basanos/0.1"}
    host = (urlparse(feed.url).hostname or "").lower()
    if host == "api.github.com":
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("BASANOS_GITHUB_TOKEN") or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=False, headers=headers) as client:
            if feed.kind == "osv":
                r = await client.post(feed.url, json=feed.body or {})
            else:
                r = await client.get(feed.url)
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError):
        return []
    return _extract_items(feed.kind, data)[:max_items]


def _extract_items(kind: str, data: Any) -> list[dict[str, Any]]:
    if kind == "osv" and isinstance(data, dict):
        return [
            {
                "title": (v.get("summary") or v.get("id") or "")[:200],
                "url": next((r.get("url") for r in (v.get("references") or []) if isinstance(r, dict)), "")
                or f"https://osv.dev/vulnerability/{v.get('id','')}",
                "identifiers": [v.get("id", "")] + list(v.get("aliases") or [])[:8],
                "published": str(v.get("published") or "")[:40],
                "text": (v.get("details") or v.get("summary") or "")[:4000],
            }
            for v in (data.get("vulns") or [])
            if isinstance(v, dict)
        ]
    if kind == "ghsa" and isinstance(data, list):
        items = []
        for v in data:
            if not isinstance(v, dict):
                continue
            items.append(
                {
                    "title": (v.get("summary") or v.get("ghsa_id") or "")[:200],
                    "url": v.get("html_url") or "",
                    "identifiers": [v.get("ghsa_id") or "", v.get("cve_id") or ""],
                    "published": str(v.get("published_at") or "")[:40],
                    "text": (v.get("description") or v.get("summary") or "")[:4000],
                }
            )
        return items
    return []
