"""Ecosystem contract roots BASANOS is allowed to walk.

Callers name a *root id*, never an absolute path. That keeps /invoke from becoming
a local-file read primitive.
"""

from __future__ import annotations

import os
from pathlib import Path

MAX_FILES = 200
MAX_FILE_BYTES = 512_000

# Names a caller may pass. Values are relative to the discovered repo root.
ROOT_IDS: dict[str, tuple[str, ...]] = {
    "acex": ("acex/contracts/evm/src",),
    "lottery": ("lottery/contracts/src",),
    "core": ("contracts/evm/src",),
    "zk": ("contracts/zk/verifier",),
    "fixtures": ("tests/fixtures",),
    "sound": ("tests/fixtures/sound",),
}

DEFAULT_ROOT_IDS = ("acex", "lottery", "core", "zk")
SKIP_DIR_NAMES = frozenset(
    {"lib", "node_modules", "out", "cache", ".git", "broadcast", "artifacts", "__pycache__"}
)


def satellite_root() -> Path:
    return Path(__file__).resolve().parents[1]


def repo_root() -> Path:
    """Monorepo root when BASANOS lives inside aicom/; otherwise the satellite checkout."""
    override = os.getenv("BASANOS_CONTRACT_ROOT", "").strip()
    if override:
        return Path(override).resolve()
    sat = satellite_root()
    parent = sat.parent
    if (parent / "acex" / "contracts").is_dir() or (parent / "lottery" / "contracts").is_dir():
        return parent
    return sat


def resolve_roots(names: list[str] | None) -> list[Path]:
    wanted = [n.strip() for n in (names or []) if n.strip()] or list(DEFAULT_ROOT_IDS)
    unknown = [n for n in wanted if n not in ROOT_IDS]
    if unknown:
        raise ValueError(f"unknown contract roots: {', '.join(unknown)}")
    base = repo_root()
    sat = satellite_root()
    out: list[Path] = []
    for name in wanted:
        for rel in ROOT_IDS[name]:
            # `fixtures` / `sound` are BASANOS's OWN test corpus, so they resolve against
            # the satellite FIRST. Preferring `base` meant that inside the aicom monorepo
            # they pointed at the monorepo's unrelated `tests/fixtures` (0 Solidity files)
            # and the detector fixtures were never opened — three tests asserted FAIL and
            # got it from "no sources found", passing while exercising nothing. Standalone
            # (GitHub CI) they happened to be right, so the suite meant two different
            # things depending on where it ran.
            if name in {"fixtures", "sound"}:
                candidate = sat / rel
                if not candidate.is_dir():
                    candidate = base / rel
            else:
                candidate = base / rel
            if candidate.is_dir():
                out.append(candidate.resolve())
    return out


def kind_for(path: Path) -> str:
    name = path.name.lower()
    mapping = (
        ("auditpool", "audit-pool"),
        ("audit", "audit-pool"),
        ("amm", "amm"),
        ("vault", "vault"),
        ("registry", "registry"),
        ("lottery", "lottery"),
        ("vdf", "lottery"),
        ("chronos", "lottery"),
        ("escrow", "escrow"),
        ("nft", "nft"),
        ("note", "token"),
        ("share", "token"),
        ("distributor", "distributor"),
        ("bounty", "settlement"),
    )
    for needle, kind in mapping:
        if needle in name:
            return kind
    return "generic"
