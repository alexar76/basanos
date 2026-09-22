from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Identity + learning dir must exist before agent.py constructs the signer/store.
_TEST_DIR = tempfile.TemporaryDirectory(prefix="basanos-tests-")
os.environ["AIMARKET_PROVIDER_IDENTITY_FILE"] = str(Path(_TEST_DIR.name) / "provider.key")
os.environ["BASANOS_DATA_DIR"] = str(Path(_TEST_DIR.name) / "data")
os.environ.pop("BASANOS_THREAT_INTEL", None)
os.environ.pop("AIFACTORY_PROD", None)
