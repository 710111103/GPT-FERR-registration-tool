from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

from mitmproxy import http

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core.static_asset_cache import StaticAssetStore, eligible_request

CACHE_ROOT = Path(os.environ["TURB_STATIC_CACHE_DIR"])
STORE = StaticAssetStore(
    CACHE_ROOT,
    ttl=int(os.getenv("TURB_STATIC_CACHE_TTL", "86400")),
    max_item_bytes=int(os.getenv("TURB_STATIC_CACHE_MAX_ITEM", str(8 * 1024 * 1024))),
    max_total_bytes=int(os.getenv("TURB_STATIC_CACHE_MAX_TOTAL", str(512 * 1024 * 1024))),
)
WAIT_SECONDS = max(0.0, min(2.0, int(os.getenv("TURB_STATIC_CACHE_WAIT_MS", "600")) / 1000))
METRICS_PATH = os.getenv("TURB_STATIC_CACHE_METRICS", "")
METRICS = Counter()


def _metrics() -> None:
    if not METRICS_PATH:
        return
    path = Path(METRICS_PATH)
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".part")
    try:
        tmp.write_text(json.dumps(dict(METRICS)), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass
    finally:
        tmp.unlink(missing_ok=True)


def _hit(flow: http.HTTPFlow, cached: tuple[bytes, dict], *, waited: bool) -> None:
    body, headers = cached
    flow.response = http.Response.make(200, body, headers)
    flow.response.headers["x-turb-static-cache"] = "HIT"
    METRICS["hits"] += 1
    METRICS["bytes_saved"] += len(body)
    if waited:
        METRICS["waiter_hits"] += 1
    _metrics()


async def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    if not eligible_request(url, flow.request.method, flow.request.headers):
        return
    # 哈希静态资源无需身份凭据；缓存候选不携带 Cookie 回源。
    flow.request.headers.pop("cookie", None)
    try:
        cached = STORE.load(url)
        if cached:
            _hit(flow, cached, waited=False)
            return
        METRICS["misses"] += 1
        token = STORE.claim(url)
        if token:
            flow.metadata["static_cache_owner"] = token
            flow.metadata["static_cache_url"] = url
            METRICS["owner_misses"] += 1
            return
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            await asyncio.sleep(min(0.05, deadline - time.monotonic()))
            cached = STORE.load(url)
            if cached:
                _hit(flow, cached, waited=True)
                return
            _, _, flight = STORE._paths(url)
            if not flight.exists():
                break
        METRICS["waiter_timeouts"] += 1
        _metrics()
    except Exception:
        METRICS["errors"] += 1
        token = flow.metadata.pop("static_cache_owner", None)
        if token:
            STORE.release(url, token)


def responseheaders(flow: http.HTTPFlow) -> None:
    token = flow.metadata.get("static_cache_owner")
    if not token or not flow.response:
        return
    try:
        content_length = int(flow.response.headers.get("content-length", "0") or 0)
        if content_length > STORE.max_item_bytes:
            flow.response.stream = True
            METRICS["oversize"] += 1
            STORE.release(flow.metadata.pop("static_cache_url"), flow.metadata.pop("static_cache_owner"))
    except (TypeError, ValueError):
        pass


def response(flow: http.HTTPFlow) -> None:
    token = flow.metadata.pop("static_cache_owner", None)
    if not token:
        return
    url = flow.metadata.pop("static_cache_url", flow.request.pretty_url)
    try:
        body = flow.response.content if flow.response else b""
        if flow.response and STORE.store(url, flow.response.status_code, flow.response.headers, body):
            METRICS["recorded"] += 1
            METRICS["recorded_bytes"] += len(body or b"")
        else:
            METRICS["rejected"] += 1
    except Exception:
        METRICS["errors"] += 1
    finally:
        STORE.release(url, token)
        _metrics()


def error(flow: http.HTTPFlow) -> None:
    token = flow.metadata.pop("static_cache_owner", None)
    if token:
        STORE.release(flow.metadata.pop("static_cache_url", flow.request.pretty_url), token)
        METRICS["owner_failures"] += 1
        _metrics()


def done() -> None:
    _metrics()
