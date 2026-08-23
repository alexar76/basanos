from __future__ import annotations

import json
import os
from pathlib import Path

from basanos.signing import ProviderSigner


def main() -> int:
    signer = ProviderSigner()
    path = Path("capability.json")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["provider_pubkey"] = signer.public_key_b64
    temporary = path.with_suffix(".json.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    print(f"provider identity ready: {signer.public_key_b64}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
