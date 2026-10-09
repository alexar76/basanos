from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = {
    "en": ROOT / "README.md",
    "ru": ROOT / "docs" / "README.ru.md",
    "es": ROOT / "docs" / "README.es.md",
    "fr": ROOT / "docs" / "README.fr.md",
    "zh": ROOT / "docs" / "README.zh.md",
}


def test_five_language_docs_draw_the_layer_split():
    for lang, path in DOCS.items():
        assert path.is_file(), lang
        text = path.read_text(encoding="utf-8")
        for token in (
            "AgentAuditPool",
            "MOMUS",
            "THEMIS",
            "HEPHAESTUS",
            "agent.security.contract-assurance@v1",
            "scoreBps",
        ):
            assert token in text, (lang, token)


def test_security_doc_matches_boundaries():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for token in ("65", "SSRF", "Ed25519", "allowlist", "BASANOS_THREAT_INTEL", "29147", "30111", "72", "90"):
        assert token in security


def test_landing_does_not_claim_insurance():
    landing = (ROOT / "docs" / "landing" / "index.html").read_text(encoding="utf-8")
    assert "coverListing" not in landing
    assert "AgentAuditPool" in landing
    assert "Assurance Pack" in landing
    assert "three" in landing
    assert "./stone.js" in landing
    assert "Not HEPHAESTUS" not in landing
    assert "not MOMUS" not in landing
    assert "not THEMIS" not in landing
    console = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "Not HEPHAESTUS" not in console
    assert "three" in console
    assert "/stone.js" in console
    assert "Assurance Pack" in console
    stone = (ROOT / "docs" / "landing" / "stone.js").read_text(encoding="utf-8")
    assert "UnrealBloomPass" in stone
    assert "OutputPass" in stone
    assert "DodecahedronGeometry" in stone
    # the composer viewport must not be re-scaled by three's pixel ratio
    assert "setPixelRatio(1)" in stone
    assert "coverListing" not in stone
