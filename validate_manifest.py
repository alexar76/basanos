from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

MANIFEST = Path("capability.json")
MAX_MANIFEST_BYTES = 65_536
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
CAPABILITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*@[vV]\d+")
PUBLISHER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
RESERVED_PUBLISHER_PREFIXES = ("tx-consumed:", "unverified-dev-credit")


def fail(message: str) -> None:
    raise SystemExit(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"capability.json contains duplicate key: {key}")
        result[key] = value
    return result


def read_manifest() -> dict:
    try:
        info = MANIFEST.lstat()
    except OSError as exc:
        fail(f"cannot inspect capability.json: {exc}")
    if MANIFEST.is_symlink() or not MANIFEST.is_file():
        fail("capability.json must be a regular file, not a link")
    if info.st_size > MAX_MANIFEST_BYTES:
        fail(f"capability.json exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        fail(f"capability.json is not valid bounded UTF-8 JSON: {exc}")
    if not isinstance(data, dict):
        fail("capability.json must contain one JSON object")
    return data


def finite_number(data: dict, key: str, *, minimum: float, maximum: float) -> float:
    value = data.get(key)
    if isinstance(value, bool):
        fail(f"{key} must be a finite number between {minimum} and {maximum}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        fail(f"{key} must be a finite number between {minimum} and {maximum}")
    if not math.isfinite(number) or not minimum <= number <= maximum:
        fail(f"{key} must be a finite number between {minimum} and {maximum}")
    return number


def validate_invoke_url(raw: object) -> None:
    if not isinstance(raw, str):
        fail("invoke_url must be an absolute http(s) URL")
    try:
        url = urlsplit(raw.strip())
        _ = url.port
    except ValueError as exc:
        fail(f"invoke_url is malformed: {exc}")
    if url.scheme not in {"http", "https"} or not url.hostname:
        fail("invoke_url must be an absolute http(s) URL")
    if url.username or url.password:
        fail("invoke_url must not contain credentials")
    if url.query or url.fragment:
        fail("invoke_url must not contain a query string or fragment")
    hostname = url.hostname.casefold()
    is_loopback = hostname == "localhost"
    try:
        is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if url.scheme != "https" and not is_loopback:
        fail("public invoke_url must use HTTPS; HTTP is allowed only for loopback development")


def main() -> int:
    data = read_manifest()
    required = (
        "product_id",
        "capability_id",
        "name",
        "invoke_url",
        "publisher_id",
        "provider_pubkey",
        "price_per_call_usd",
        "input_schema",
        "output_schema",
    )
    missing = [key for key in required if data.get(key) in (None, "")]
    if missing:
        fail(f"missing required fields: {', '.join(missing)}")
    if not isinstance(data["product_id"], str) or not SAFE_ID.fullmatch(data["product_id"]):
        fail("product_id must be alphanumeric (dots, dashes, underscores allowed), max 128 chars")
    if not isinstance(data["capability_id"], str) or not CAPABILITY_ID.fullmatch(data["capability_id"]):
        fail("capability_id must look like my.tool@v1")
    if not isinstance(data["name"], str) or not 1 <= len(data["name"].strip()) <= 128:
        fail("name must contain 1-128 characters")
    publisher_id = data["publisher_id"]
    if not isinstance(publisher_id, str) or not PUBLISHER_ID.fullmatch(publisher_id):
        fail("publisher_id must be a stable 1-128 character identifier")
    if publisher_id.startswith(RESERVED_PUBLISHER_PREFIXES):
        fail("publisher_id uses a reserved Hub bookkeeping prefix")
    validate_invoke_url(data["invoke_url"])
    finite_number(data, "price_per_call_usd", minimum=0.0, maximum=1_000.0)
    for key in ("input_schema", "output_schema"):
        schema = data[key]
        if not isinstance(schema, dict) or schema.get("type") != "object":
            fail(f"{key} must be a JSON object schema")
    try:
        provider_key = base64.b64decode(str(data["provider_pubkey"]), validate=True)
    except (ValueError, binascii.Error):
        fail("provider_pubkey must be canonical base64")
    if len(provider_key) != 32:
        fail("provider_pubkey must encode exactly 32 Ed25519 public-key bytes")
    print("capability.json is structurally ready for AIMarket Hub publish")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
