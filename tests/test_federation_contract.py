"""The contract the Hub actually speaks, pinned.

Both of these were broken in production while every other test was green, and both fail the
same way: a listed, priced capability that answers the Hub with an error the buyer sees as a
502 — or, worse, is never listed at all and simply never earns.
"""

from __future__ import annotations

import json
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent  # noqa: E402

CLIENT = TestClient(agent.app)
BODY = {
    "product_id": "basanos",
    "capability_id": "agent.security.contract-assurance@v1",
    "input": {"roots": []},
    # The Hub always sends this fourth key (aimarket-hub api.py builds
    # {"capability_id", "input", "product_id", "source_hub"}).
    "source_hub": "https://modelmarket.dev",
}


def test_the_federation_invoke_path_is_served():
    """`oracle_core.Protocol.well_known()` derives mcp_endpoint as
    f"{base}/ai-market/v2/invoke" and cannot be told otherwise, so this is the ONLY path a
    hub-routed call ever lands on. Serving just /invoke meant a 404 for every buyer."""
    response = CLIENT.post("/ai-market/v2/invoke", json=BODY)
    assert response.status_code == 200, response.text
    assert response.headers.get("X-Provider-Signature")
    assert response.json()["result"]["verdict"] in ("PASS", "REVIEW", "FAIL", "NO_SUBJECT")


def test_both_paths_reach_the_same_handler():
    own = CLIENT.post("/invoke", json=BODY)
    federated = CLIENT.post("/ai-market/v2/invoke", json=BODY)
    assert own.status_code == federated.status_code == 200
    assert own.json()["result"]["verdict"] == federated.json()["result"]["verdict"]


def test_source_hub_is_accepted_not_rejected():
    """InvokeEnvelope forbids extra keys, so an unknown `source_hub` was a 422."""
    assert CLIENT.post("/invoke", json=BODY).status_code == 200


def test_a_genuinely_unknown_key_is_still_refused():
    """Accepting `source_hub` must not turn the envelope permissive."""
    response = CLIENT.post("/invoke", json=dict(BODY, surprise="x"))
    assert response.status_code == 422


def test_the_well_known_never_advertises_loopback():
    """A loopback manifest_url is rejected by the Hub crawler (_url_is_safe blocks
    127.0.0.0/8), so the node is crawled and indexed with zero capabilities — reachable,
    trusted, signed, and unsellable."""
    doc = CLIENT.get("/.well-known/ai-market.json").json()
    for field in ("manifest_url", "mcp_endpoint"):
        value = str(doc.get(field, ""))
        if os.getenv("BASANOS_PUBLIC_URL"):
            assert "127.0.0.1" not in value and "localhost" not in value, field


def test_the_committed_capability_json_pins_no_provider_key():
    """configure_provider.py stamps whatever identity the machine holds, so a committed
    provider_pubkey is a developer laptop's key. Production's pin belongs in the Hub's
    federation_seeds.json, read from the running container."""
    doc = json.loads((open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "capability.json"))).read())
    assert "provider_pubkey" not in doc, (
        "a provider key is committed again — it will be the laptop's, and a supply-published "
        "invoke verified against it fails with staked USDC on the line")
