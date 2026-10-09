from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

import configure_provider
import validate_manifest
from basanos.signing import ProviderSigner

ROOT = Path(__file__).resolve().parents[1]


def test_configure_and_validate_manifest(tmp_path, monkeypatch):
    manifest = tmp_path / "capability.json"
    manifest.write_text((ROOT / "capability.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / ".aimarket/provider.key"))
    assert configure_provider.main() == 0
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(data["provider_pubkey"]) == 44
    assert validate_manifest.main() == 0
    assert not manifest.with_suffix(".json.tmp").exists()


def test_configure_cleans_temp_on_replace_failure(tmp_path, monkeypatch):
    manifest = tmp_path / "capability.json"
    manifest.write_text((ROOT / "capability.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / ".aimarket/provider.key"))
    original_replace = Path.replace

    def broken_replace(self, target):
        if self.name == "capability.json.tmp":
            raise OSError("simulated atomic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", broken_replace)
    with pytest.raises(OSError, match="simulated"):
        configure_provider.main()
    assert not manifest.with_suffix(".json.tmp").exists()


def test_provider_identity_is_persistent_and_private(tmp_path, monkeypatch):
    key = tmp_path / "identity" / "provider.key"
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    first = ProviderSigner()
    second = ProviderSigner()
    assert first.public_key_b64 == second.public_key_b64
    assert stat.S_IMODE(key.stat().st_mode) == 0o600


@pytest.mark.parametrize("content", [b"short", b"x" * 33])
def test_corrupted_provider_identity_fails_closed(tmp_path, monkeypatch, content):
    key = tmp_path / "provider.key"
    key.write_bytes(content)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    with pytest.raises(RuntimeError, match="corrupted"):
        ProviderSigner()


def test_provider_identity_rejects_symlink(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_bytes(b"x" * 32)
    key = tmp_path / "provider.key"
    key.symlink_to(target)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(key))
    with pytest.raises(RuntimeError, match="regular file"):
        ProviderSigner()


def test_provider_identity_rejects_symlink_parent(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(linked / "provider.key"))
    with pytest.raises(RuntimeError, match="directory"):
        ProviderSigner()
