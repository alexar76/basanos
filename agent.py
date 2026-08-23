from __future__ import annotations

import hmac
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from basanos import CAPABILITY_ID, PRODUCT_ID, __version__
from basanos.intel.ingest import ingest_into
from basanos.intel.sources import intel_enabled
from basanos.intel.store import KnowledgeStore
from basanos.memos import MemoStore
from basanos.models import InvokeEnvelope
from basanos.scanner import scan
from basanos.signing import ProviderSigner

MAX_INVOKE_BYTES = 65_536
ROOT = Path(__file__).resolve().parent
UI_DIR = ROOT / "frontend"
DATA_DIR = Path(os.getenv("BASANOS_DATA_DIR", str(ROOT / "data")))

SIGNER = ProviderSigner()
STORE = KnowledgeStore(str(DATA_DIR / "intel"))
MEMOS = MemoStore(str(DATA_DIR / "memos"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="BASANOS",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@app.middleware("http")
async def request_boundary(request: Request, call_next):
    response = None
    if request.method == "POST" and request.url.path in {"/invoke", "/intel"}:
        raw_length = request.headers.get("content-length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0 or length > MAX_INVOKE_BYTES:
            response = JSONResponse(
                {"detail": f"request body must be 0-{MAX_INVOKE_BYTES} bytes"},
                status_code=413,
            )
    if response is None:
        response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/", response_model=None)
def root():
    for candidate in (UI_DIR / "landing.html", ROOT / "docs" / "landing" / "index.html"):
        if candidate.is_file():
            return FileResponse(candidate, media_type="text/html; charset=utf-8")
    return RedirectResponse(url="/ui/", status_code=307)


@app.get("/stone.js", response_model=None)
def stone_module():
    for candidate in (UI_DIR / "stone.js", ROOT / "docs" / "landing" / "stone.js"):
        if candidate.is_file():
            return FileResponse(candidate, media_type="text/javascript; charset=utf-8")
    return JSONResponse({"detail": "missing"}, status_code=404)


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "agent": PRODUCT_ID,
        "kind": "tool",
        "version": __version__,
        "capability_id": CAPABILITY_ID,
        "provider_pubkey": SIGNER.public_key_b64,
        "intel_enabled": intel_enabled(),
        "role": "contract-assurance",
        "not": ["AgentAuditPool", "MOMUS", "THEMIS", "HEPHAESTUS"],
    }


@app.post("/invoke")
async def invoke(raw_request: Request, request: InvokeEnvelope) -> JSONResponse:
    if not hmac.compare_digest(request.product_id, PRODUCT_ID):
        return JSONResponse({"detail": "product_id does not match this provider"}, status_code=400)
    if not hmac.compare_digest(request.capability_id, CAPABILITY_ID):
        return JSONResponse({"detail": "capability_id does not match this provider"}, status_code=400)

    try:
        raw_envelope = json.loads(await raw_request.body(), object_pairs_hook=_unique_object)
        input_payload = raw_envelope["input"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return JSONResponse({"detail": "request must contain unambiguous JSON"}, status_code=400)

    payload = request.input
    if payload.ingest_intel:
        await ingest_into(STORE)
    try:
        pack = scan(root_names=payload.roots, store=STORE, memos=MEMOS)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse(
        {"success": True, "result": pack},
        headers={
            "X-Provider-Signature": SIGNER.sign_result(
                pack,
                capability_id=CAPABILITY_ID,
                product_id=PRODUCT_ID,
                input_payload=input_payload,
            )
        },
    )


@app.get("/intel")
def intel_summary() -> dict:
    return {"intel_enabled": intel_enabled(), **STORE.summary()}


@app.get("/memos")
def memos_summary() -> dict:
    return MEMOS.summary()


@app.post("/intel")
async def intel_ingest(raw_request: Request) -> JSONResponse:
    try:
        json.loads(await raw_request.body() or b"{}", object_pairs_hook=_unique_object)
    except (ValueError, json.JSONDecodeError):
        return JSONResponse({"detail": "request must contain unambiguous JSON"}, status_code=400)
    result = await ingest_into(STORE)
    return JSONResponse(result)


if UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "9470")))
