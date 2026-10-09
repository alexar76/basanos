"""What an operator should do when a pack is not clean.

Aligned with ISO/IEC 29147 (disclosure), ISO/IEC 30111 (vendor handling),
NIST SP 800-61 (incident response), and CERT/CC coordinated disclosure.

BASANOS only *recommends*. It never pauses a contract, never slashes, never
calls coverListing, and never publishes an exploit. Findings are static-analysis
*candidates* until a human verifies them (ISO/IEC 30111 verification stage).
"""

from __future__ import annotations

from typing import Any

STANDARDS = (
    "ISO/IEC 29147:2018",
    "ISO/IEC 30111:2019",
    "NIST SP 800-61r2",
    "FIRST PSIRT Services Framework",
    "CERT/CC Coordinated Vulnerability Disclosure",
)

# Acknowledge / CVD windows already used in the factory SECURITY.md.
ACKNOWLEDGE_HOURS = 72
CVD_DAYS = 90

MUST_NOT = (
    "emit scoreBps or call coverListing",
    "auto-pause, slash, or send on-chain transactions",
    "publish an exploit or proof-of-concept before a fix or CVD expiry",
    "admit or reject a Hub listing — that is THEMIS",
    "probe a live host — that is MOMUS",
)

# SWC Registry → CWE. Classification only; not a CVSS vector.
SWC_TO_CWE = {
    "SWC-103": "CWE-664",
    "SWC-104": "CWE-252",
    "SWC-105": "CWE-284",
    "SWC-106": "CWE-284",
    "SWC-107": "CWE-841",
    "SWC-112": "CWE-829",
    "SWC-115": "CWE-477",
    "SWC-117": "CWE-347",
    "SWC-120": "CWE-330",
    "SWC-123": "CWE-123",
    "SWC-128": "CWE-400",
    "SWC-133": "CWE-327",
    "SWC-134": "CWE-691",
}

# Qualitative labels match CVSS 3.1 ratings. No numeric vector: detectors
# do not observe Attack Vector / Complexity / Privileges / User Interaction.
_SEVERITY_NIST = {
    "critical": "containment",
    "high": "containment",
    "medium": "detection-analysis",
    "low": "post-incident",
    "info": "post-incident",
}

_VERDICT_ACTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "PASS": (
        "No medium-or-worse candidate on this digest. Still not insurance.",
        (
            "Record the pack digest against the commit / tree.",
            "Park low/info items on the backlog; they do not block a ship decision.",
            "A human auditor may still decline AgentAuditPool.coverListing — this pack does not authorize coverage.",
        ),
    ),
    "REVIEW": (
        "Medium candidates. ISO/IEC 30111 verification before any coverage.",
        (
            "Do not call coverListing until a human confirms or dismisses each medium finding.",
            "Verify privately: reproduce or reject the candidate. Do not publish a proof-of-concept.",
            "Schedule remediation, land a patch, re-scan the new commit with BASANOS.",
            "Disclose only after the fix, after dismissal, or when the 90-day CVD window expires (ISO/IEC 29147).",
        ),
    ),
    # A scan that found no Solidity is not a judgement about a subject. Calling it FAIL
    # said "this code is dangerous" about code BASANOS never opened — and it is what a
    # first-time reader of the README got, because the documented example names monorepo
    # roots that do not exist in a standalone clone. PASS would be the worse lie, so the
    # honest answer is a fourth outcome that is neither clean nor an accusation.
    "NO_SUBJECT": (
        "No Solidity was read, so this pack judges nothing. Not a clean bill.",
        (
            "Check the `roots` you asked for: run `fixtures` to see the shape of a real pack, "
            "or set BASANOS_CONTRACT_ROOT to the checkout you want scanned.",
            "Do not record this digest as assurance for anything — it attests an empty read.",
            "A human auditor and AgentAuditPool.coverListing are unaffected: nothing was claimed.",
        ),
    ),
    "FAIL": (
        "High or critical candidates. Contain this digest. Coordinated disclosure. No coverage.",
        (
            "Do not deploy this tree and do not call AgentAuditPool.coverListing while FAIL stands.",
            "NIST SP 800-61 containment: stop production use of this digest.",
            "If the contract is already live and has a pause or circuit-breaker, pause on the owner path you already control. BASANOS will not send that transaction.",
            "Notify operators on a private channel. Do not open a public issue. Acknowledge within 72 hours (ISO/IEC 29147).",
            "Patch, re-scan the new commit, then public write-up only after the fix or the 90-day CVD window.",
            "Do not attach an exploit, payload, or reproduction procedure to any public artifact.",
        ),
    ),
}


def cwe_for(swc: str) -> str:
    return SWC_TO_CWE.get(str(swc or "").strip().upper(), "")


def stamp_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stamped: list[dict[str, Any]] = []
    for raw in findings:
        item = dict(raw)
        swc = str(item.get("swc") or "")
        cwe = cwe_for(swc)
        if cwe:
            item["cwe"] = cwe
        item["nist_phase"] = _SEVERITY_NIST.get(str(item.get("severity") or "info"), "detection-analysis")
        stamped.append(item)
    return stamped


def handling_for(verdict: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary, actions = _VERDICT_ACTIONS.get(verdict, _VERDICT_ACTIONS["REVIEW"])
    worst = "info"
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for finding in findings:
        sev = str(finding.get("severity") or "info")
        if rank.get(sev, 0) > rank.get(worst, 0):
            worst = sev
    return {
        "standards": list(STANDARDS),
        "role": "recommend-only",
        "acknowledge_hours": ACKNOWLEDGE_HOURS,
        "cvd_days": CVD_DAYS,
        "worst_severity": worst,
        "nist_phase": _SEVERITY_NIST.get(worst, "detection-analysis"),
        "summary": summary,
        "operator_actions": list(actions),
        "must_not": list(MUST_NOT),
        "candidates": True,
    }
