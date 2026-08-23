"""Walk allowlisted Solidity roots, run the closed detector set, emit a pack."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from basanos.detectors import DETECTORS, SKIP_DIR_NAMES, run_detectors
from basanos.inventory import (
    MAX_FILE_BYTES,
    MAX_FILES,
    kind_for,
    repo_root,
    resolve_roots,
)
from basanos.pack import build_pack
from basanos.xcontract import CROSS_DETECTORS, run_cross_detectors


def git_head(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    sha = (proc.stdout or "").strip()
    return sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha.lower()) else ""


def _is_safe_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        return False
    if info.st_size <= 0 or info.st_size > MAX_FILE_BYTES:
        return False
    return path.suffix == ".sol"


def collect_sources(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and d != "test"]
            for name in filenames:
                path = Path(dirpath) / name
                if _is_safe_file(path):
                    files.append(path)
                if len(files) >= MAX_FILES:
                    return files
    return files


def tree_digest(files: list[Path], base: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(files, key=lambda p: str(p)):
        rel = path.relative_to(base).as_posix() if path.is_relative_to(base) else path.name
        h.update(rel.encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\n")
    return h.hexdigest()


def scan(
    *,
    root_names: list[str] | None = None,
    store: Any | None = None,
    memos: Any | None = None,
) -> dict[str, Any]:
    base = repo_root()
    roots = resolve_roots(root_names)
    files = collect_sources(roots)
    rel_files: list[str] = []
    sources_for_graph: list[tuple[str, str]] = []
    findings: list[dict[str, Any]] = []
    ids = [d.detector_id for d in DETECTORS]
    order = ids
    if store is not None:
        generic_boost = memos.boost_map("generic") if memos is not None else {}
        order = store.order_detectors(ids, "generic", memo_boosts=generic_boost)

    for path in files:
        kind = kind_for(path)
        boosts = memos.boost_map(kind) if memos is not None else {}
        if store is not None:
            ordered = store.order_detectors(ids, kind, memo_boosts=boosts)
        else:
            ordered = order
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        rel = path.relative_to(base).as_posix() if path.is_relative_to(base) else path.name
        rel_files.append(rel)
        sources_for_graph.append((rel, source))
        file_findings = run_detectors(source, rel, order=ordered)
        findings.extend(file_findings)
        if store is not None:
            cats = {f["category"] for f in file_findings}
            for detector in DETECTORS:
                outcome = "finding" if detector.category in cats else "no_finding"
                store.record_outcome(detector.category, kind, outcome)
        if memos is not None:
            for finding in file_findings:
                memos.record(
                    kind=kind,
                    category=str(finding.get("category") or "pragma"),
                    detector_id=str(finding.get("detector_id") or ""),
                    hit=True,
                    path=rel,
                    title=str(finding.get("title") or ""),
                )

    # Whole-tree pass. The per-file detectors above cannot see an invariant that spans two
    # contracts, which is exactly where this ecosystem's own worst Solidity bugs lived — see
    # basanos/xcontract.py. It runs last so it observes every file the scan admitted.
    findings.extend(run_cross_detectors(sources_for_graph))

    digest = tree_digest(files, base) if files else hashlib.sha256(b"empty").hexdigest()
    commit = git_head(base)
    if not files:
        findings.append(
            {
                "detector_id": "inventory.empty",
                "category": "pragma",
                # `severity` in a pack means "how bad is the SUBJECT's code". Nothing was
                # read, so there is no subject to grade — the NO_SUBJECT verdict carries
                # the signal instead of a `high` that inflates every severity statistic.
                "severity": "info",
                "title": "no Solidity sources under the requested roots",
                "detail": (
                    "BASANOS cannot attest a commit it did not read. Ask for a root that "
                    "exists here (`fixtures` always does), or point BASANOS_CONTRACT_ROOT at "
                    "the checkout you want scanned. The default roots name monorepo paths."
                ),
                "path": "",
                "line": 0,
                "swc": "",
            }
        )
    intel = store.summary() if store is not None else {"cards_total": 0}
    if memos is not None:
        summary = memos.summary()
        intel["memos_total"] = summary["memos_total"]
        intel["lessons"] = summary["lessons"]
        recalled = memos.recall("generic") or (memos.recall(kind_for(files[0])) if files else [])
        intel["recalled_memos"] = [
            {
                "kind": m.kind,
                "category": m.category,
                "detector_id": m.detector_id,
                "title": m.title,
            }
            for m in recalled
        ]
    return build_pack(
        commit_sha=commit,
        tree_digest=digest,
        files=rel_files,
        findings=findings,
        detector_order=order + [cid for cid, _ in CROSS_DETECTORS],
        intel=intel,
    )
