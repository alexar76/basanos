"""AIMarket federation surface — the two GETs a hub crawler needs to index this node.

BASANOS served only ``/invoke``, which makes it an *agent* but not a *peer*: the hub's
crawler discovers nodes through ``GET /.well-known/ai-market.json`` → a **signed** manifest,
and anything it cannot discover never reaches the federated catalogue. Downstream that is
not cosmetic — ``signal-hunt`` holds no node list at all, it derives its sources from
``tool["source_hub"]`` in that catalogue, and the LOGOS assistant answers from the same live
capability list. A node outside the catalogue is invisible to both.

Nothing here formats a document by hand. Both come from ``oracle_core.Protocol``, the same
code the federated oracles use, because the manifest signature is over the **hub's** canonical
form and that form has teeth: when the hub grew a fifth ``by_hub_hash`` field, "every oracle
manifest failed with 'Invalid manifest signature' and no oracle could federate at all", and
``oracle_core.signing`` still carries the note that a sixth field must be mirrored "the same
day". A satellite that reimplements the layout signs itself out of the federation on the next
protocol bump; one that delegates gets the fix with a dependency bump. ``aimarket-oracle-core``
0.3.0 on PyPI is byte-identical to the monorepo copy, so this is the same code either way.

One identity, not two. ``oracle_core.Signer`` keeps a 64-byte key file (seed ‖ pubkey) while
this satellite's :class:`~basanos.signing.ProviderSigner` keeps 32 (seed only), so the same
path cannot be shared — each rejects the other's size as corrupt. Rather than mint a second
keypair (which would make the manifest advertise one key while ``capability.json`` and the
pack signature advertise another, breaking the chain a verifier follows), the seed is handed
over in memory through ``ORACLE_SIGNING_SEED_B64``. No second key file is created.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "v2"
#: oracle_core reads the seed from here before it ever looks at a key file.
_SEED_ENV = "ORACLE_SIGNING_SEED_B64"

#: Declared, not measured: BASANOS keeps no latency metrics. The manifest schema declares
#: `p50_latency_ms` as an integer, and oracle_core coerces it for the same reason — a float
#: made a whole manifest unindexable once.
DECLARED_P50_MS = 1200
DECLARED_SUCCESS_RATE = 0.99
CATEGORIES = ("security", "solidity", "assurance")


def load_capability(path: str | Path | None = None) -> dict[str, Any]:
    """The committed capability descriptor this node publishes."""
    target = Path(path) if path else Path(__file__).resolve().parents[1] / "capability.json"
    return json.loads(target.read_text(encoding="utf-8"))


def oracle_signer(seed: bytes, *, key_path: str | Path | None = None):
    """An ``oracle_core`` Signer that IS this node — no second keypair, no new file.

    The seed goes in through the environment because that branch runs before
    ``_ensure_keypair``, so ``key_path`` is never read or written. It still points inside our
    own data dir rather than at oracle_core's default, so that if a future release does touch
    the file, it lands somewhere we own instead of somewhere we do not.
    """
    from oracle_core.signing import Signer

    previous = os.environ.get(_SEED_ENV)
    os.environ[_SEED_ENV] = base64.b64encode(seed).decode()
    try:
        # The Signer copies the seed in __init__, so restoring the env immediately is safe —
        # and leaving it set would silently re-key any other Signer built later.
        return Signer(key_path=str(key_path or "data/basanos_manifest_key_unused"))
    finally:
        if previous is None:
            os.environ.pop(_SEED_ENV, None)
        else:
            os.environ[_SEED_ENV] = previous


def _protocol(*, public_url: str, version: str, seed: bytes,
              capability: dict[str, Any], key_path: str | Path | None = None):
    """An ``oracle_core.Protocol`` describing this one capability.

    ``handler`` is required by the dataclass but never invoked: only ``well_known()`` and
    ``manifest()`` are used from here, and ``/invoke`` stays this satellite's own route with
    its own rate limit and pack signing.
    """
    from oracle_core import Capability, OracleSpec
    from oracle_core.protocol import Protocol

    unused = str(key_path or "data/basanos_manifest_key_unused")
    cap = Capability(
        capability_id=capability["capability_id"],
        description=capability["description"],
        handler=lambda _payload: {},
        product_id=capability["product_id"],
        input_schema=capability["input_schema"],
        output_schema=capability["output_schema"],
        price_per_call_usd=capability["price_per_call_usd"],
        p50_latency_ms=DECLARED_P50_MS,
        success_rate_30d=DECLARED_SUCCESS_RATE,
    )
    spec = OracleSpec(
        name=capability["name"],
        product_id=capability["product_id"],
        description=capability["description"],
        public_url=public_url.rstrip("/"),
        categories=list(CATEGORIES),
        capabilities=[cap],
        signing_key_path=unused,
        version=version,
    )
    return Protocol(spec, signer=oracle_signer(seed, key_path=unused))


def well_known(*, public_url: str, version: str, seed: bytes,
               capability: dict[str, Any], key_path: str | Path | None = None) -> dict[str, Any]:
    """``GET /.well-known/ai-market.json`` — the crawler's entry point."""
    return _protocol(
        public_url=public_url, version=version, seed=seed,
        capability=capability, key_path=key_path,
    ).well_known()


def manifest(*, public_url: str, version: str, seed: bytes,
             capability: dict[str, Any], key_path: str | Path | None = None) -> dict[str, Any]:
    """``GET /ai-market/v2/manifest`` — signed with this node's own identity."""
    return _protocol(
        public_url=public_url, version=version, seed=seed,
        capability=capability, key_path=key_path,
    ).manifest()
