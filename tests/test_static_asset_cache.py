from __future__ import annotations

import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.static_asset_cache import StaticAssetStore, eligible_request, eligible_response

URL = "https://chatgpt.com/cdn/assets/root-fy7gddts.css"
HEADERS = {"content-type": "text/css", "cache-control": "public, max-age=2592000"}


def test_cache_only_accepts_public_versioned_assets():
    assert eligible_request(URL, "GET", {"Cookie": "private=1"})
    assert not eligible_request(URL, "POST", {})
    assert not eligible_request(URL, "GET", {"Authorization": "Bearer secret"})
    assert not eligible_request(URL, "GET", {"Range": "bytes=0-10"})
    assert not eligible_request(URL + "?token=secret", "GET", {})
    for path in ("/backend-api/me", "/api/auth/session", "/cdn-cgi/challenge-platform/x.js", "/sentinel/sdk.js", "/cdn/assets/root.css"):
        assert not eligible_request("https://chatgpt.com" + path, "GET", {})
    assert not eligible_request("https://evil.example/cdn/assets/root-fy7gddts.css", "GET", {})
    assert eligible_response(URL, 200, HEADERS, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "cache-control": "public, max-age=3600"}, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "cache-control": "max-age=2592000"}, b"body", 1000)
    assert eligible_response(URL, 200, {**HEADERS, "set-cookie": "__cf_bm=edge; HttpOnly; Secure; Path=/"}, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "set-cookie": "__Secure-next-auth.session-token=secret; Secure"}, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "vary": "Cookie"}, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "cache-control": "private, max-age=31536000, immutable"}, b"body", 1000)
    assert not eligible_response(URL, 200, {**HEADERS, "content-type": "text/html"}, b"body", 1000)
    assert not eligible_response(URL, 302, HEADERS, b"body", 1000)
    assert not eligible_response(URL, 200, HEADERS, b"12345", 4)


def test_atomic_store_validates_body_and_expires():
    with tempfile.TemporaryDirectory() as tmp:
        store = StaticAssetStore(tmp, ttl=60)
        assert store.store(URL, 200, HEADERS, b"style { color: red }")
        body, headers = store.load(URL)
        assert body == b"style { color: red }"
        assert set(headers) == {"content-type", "cache-control"}
        body_path, meta_path, _ = store._paths(URL)
        assert not list(Path(tmp).rglob("*.part"))
        body_path.write_bytes(b"corrupt")
        assert store.load(URL) is None
        assert store.store(URL, 200, HEADERS, b"fresh")
        assert store.load(URL)[0] == b"fresh"
        store.ttl = 1
        import json
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["stored_at"] -= 10
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        assert store.load(URL) is None


def test_cross_instance_flight_allows_one_owner_and_waiter_hit():
    with tempfile.TemporaryDirectory() as tmp:
        stores = [StaticAssetStore(tmp) for _ in range(3)]
        barrier = threading.Barrier(3)
        owner_count = 0

        def worker(store):
            nonlocal owner_count
            barrier.wait(timeout=2)
            token = store.claim(URL)
            if token:
                owner_count += 1
                time.sleep(0.1)
                store.store(URL, 200, HEADERS, b"cached")
                store.release(URL, token)
            else:
                deadline = time.monotonic() + 0.5
                while store.load(URL) is None and time.monotonic() < deadline:
                    time.sleep(0.01)
            return store.load(URL)[0]

        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(worker, stores)) == [b"cached"] * 3
        assert owner_count == 1


def test_stale_flight_recovery_and_token_safe_release():
    with tempfile.TemporaryDirectory() as tmp:
        store = StaticAssetStore(tmp)
        first = store.claim(URL)
        assert first and store.claim(URL) is None
        _, _, flight = store._paths(URL)
        past = time.time() - 60
        import os
        os.utime(flight, (past, past))
        second = store.claim(URL, lease_seconds=30)
        assert second and second != first
        store.release(URL, first)
        assert flight.exists()
        store.release(URL, second)
        assert not flight.exists()


def test_mitmproxy_addon_singleflight_waits_without_blocking_other_flows(monkeypatch):
    import asyncio
    import importlib.util
    import os
    import sys
    from types import SimpleNamespace

    class Response:
        def __init__(self, body):
            self.status_code = 200
            self.headers = dict(HEADERS)
            self.content = body
            self.stream = False

        @classmethod
        def make(cls, status, body, headers):
            out = cls(body)
            out.status_code = status
            out.headers = dict(headers)
            return out

    def flow(url=URL, headers=None):
        return SimpleNamespace(
            request=SimpleNamespace(pretty_url=url, method="GET", headers=headers or {}),
            response=None, metadata={},
        )

    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("TURB_STATIC_CACHE_DIR", tmp)
        monkeypatch.setenv("TURB_STATIC_CACHE_WAIT_MS", "350")
        monkeypatch.setitem(sys.modules, "mitmproxy", SimpleNamespace(http=SimpleNamespace(HTTPFlow=object, Response=Response)))
        path = Path(__file__).resolve().parent.parent / "tools" / "static_asset_cache_addon.py"
        spec = importlib.util.spec_from_file_location("static_asset_addon_test", path)
        addon = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(addon)

        async def exercise():
            owner = flow(headers={"cookie": "session=private"})
            await addon.request(owner)
            assert "cookie" not in owner.request.headers
            assert owner.metadata.get("static_cache_owner")
            waiter = flow()
            unrelated = flow("https://chatgpt.com/api/auth/session")
            pending = asyncio.create_task(addon.request(waiter))
            await asyncio.wait_for(addon.request(unrelated), timeout=0.1)
            assert unrelated.response is None
            await asyncio.sleep(0.05)
            owner.response = Response(b"shared asset")
            addon.response(owner)
            await asyncio.wait_for(pending, timeout=0.3)
            assert waiter.response.content == b"shared asset"
            assert addon.METRICS["owner_misses"] == 1
            assert addon.METRICS["waiter_hits"] == 1

        asyncio.run(exercise())
