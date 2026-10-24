from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_PREFIXES = {
    "chatgpt.com": ("/cdn/assets/", "/_next/static/"),
    "auth-cdn.oaistatic.com": ("/assets/",),
    "cdn.oaistatic.com": ("/assets/",),
}
_DENIED_PARTS = (
    "/api/", "/backend-api/", "/backend-anon/", "/oauth", "/authorize",
    "/login", "/logout", "/email-verification", "/about-you", "/cdn-cgi/",
    "/sentinel/", "/ces/", "/awe/", "/challenge", "/captcha", "/turnstile",
    "/statsig", "/featuregate", "/rum", "/telemetry", "/beacon",
)
_TYPES = {
    ".js": ("application/javascript", "text/javascript"),
    ".mjs": ("application/javascript", "text/javascript"),
    ".css": ("text/css",),
    ".woff2": ("font/woff2", "application/font-woff2"),
    ".woff": ("font/woff", "application/font-woff"),
    ".svg": ("image/svg+xml",),
    ".png": ("image/png",),
    ".webp": ("image/webp",),
}
_SAFE_HEADERS = {"content-type", "cache-control", "etag", "last-modified", "access-control-allow-origin", "cross-origin-resource-policy"}
_VERSIONED = re.compile(r"(?:^|[-_.])[a-z0-9]{8,}(?=\.[a-z0-9]+$|[-_.])", re.IGNORECASE)


def cache_key(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    authority = host + (f":{parts.port}" if parts.port and parts.port != 443 else "")
    canonical = urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, ""))
    return hashlib.sha256(("static-v3\n" + canonical).encode("utf-8")).hexdigest(), canonical


def eligible_request(url: str, method: str, headers: dict) -> bool:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path.lower()
        if parts.scheme.lower() != "https" or method.upper() != "GET" or parts.query:
            return False
        if host not in _ALLOWED_PREFIXES or not any(path.startswith(p) for p in _ALLOWED_PREFIXES[host]):
            return False
        if any(part in path for part in _DENIED_PARTS):
            return False
        request_headers = {str(k).lower() for k in headers}
        if "authorization" in request_headers or "range" in request_headers:
            return False
        suffix = Path(path).suffix
        if suffix not in _TYPES or not _VERSIONED.search(Path(path).name):
            return False
        return True
    except (ValueError, TypeError):
        return False


def eligible_response(url: str, status: int, headers: dict, body: bytes, max_item_bytes: int) -> bool:
    if status != 200 or not body or len(body) > max_item_bytes:
        return False
    normalized = {str(k).lower(): str(v) for k, v in headers.items()}
    set_cookie = normalized.get("set-cookie", "")
    if "www-authenticate" in normalized:
        return False
    if set_cookie:
        # 公共静态资源也可能顺带刷新 Cloudflare 边缘 Cookie；不保存/重放这些头。
        # 若出现任何业务 Session Cookie，整条响应仍拒绝入缓存。
        cookie_names = {
            match.group(1).lower()
            for match in re.finditer(r"(?:^|,\s*)([!#$%&'*+.^_`|~0-9a-z-]+)=", set_cookie, re.IGNORECASE)
        }
        if not cookie_names or not cookie_names.issubset({"__cf_bm", "_cfuvid"}):
            return False
    mime = normalized.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime not in _TYPES.get(Path(urlsplit(url).path.lower()).suffix, ()):
        return False
    cache_control = normalized.get("cache-control", "").lower()
    directives = {part.strip() for part in cache_control.split(",")}
    if "public" not in directives or any(token in directives for token in ("private", "no-store", "no-cache")):
        return False
    max_age = re.search(r"(?:^|,)\s*max-age\s*=\s*(\d+)(?:\s*,|\s*$)", cache_control)
    if not max_age or int(max_age.group(1)) < 86400:
        return False
    vary = normalized.get("vary", "").strip().lower()
    if vary and set(part.strip() for part in vary.split(",")) != {"accept-encoding"}:
        return False
    return True


class StaticAssetStore:
    def __init__(self, root: str | Path, *, ttl: int = 86400, max_item_bytes: int = 8 * 1024 * 1024, max_total_bytes: int = 512 * 1024 * 1024):
        self.root = Path(root)
        self.ttl = max(1, ttl)
        self.max_item_bytes = max(1024, max_item_bytes)
        self.max_total_bytes = max(self.max_item_bytes, max_total_bytes)
        self.root.mkdir(parents=True, exist_ok=True)
        self._next_cleanup = 0.0

    def _paths(self, url: str) -> tuple[Path, Path, Path]:
        key, _ = cache_key(url)
        folder = self.root / key[:2]
        return folder / (key + ".body"), folder / (key + ".json"), folder / (key + ".flight")

    def load(self, url: str) -> tuple[bytes, dict] | None:
        body_path, meta_path, _ = self._paths(url)
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("version") != 3 or meta.get("url") != cache_key(url)[1]:
                return None
            if time.time() - float(meta["stored_at"]) > self.ttl:
                return None
            body = body_path.read_bytes()
            if len(body) != meta["size"] or len(body) > self.max_item_bytes:
                return None
            if hashlib.sha256(body).hexdigest() != meta["digest"]:
                return None
            return body, dict(meta["headers"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def store(self, url: str, status: int, headers: dict, body: bytes) -> bool:
        if not eligible_request(url, "GET", {}) or not eligible_response(url, status, headers, body, self.max_item_bytes):
            return False
        if self.load(url) is not None:
            return True
        body_path, meta_path, _ = self._paths(url)
        body_path.parent.mkdir(parents=True, exist_ok=True)
        token = uuid.uuid4().hex
        body_tmp = body_path.with_name(body_path.name + "." + token + ".part")
        meta_tmp = meta_path.with_name(meta_path.name + "." + token + ".part")
        normalized = {str(k).lower(): str(v) for k, v in headers.items()}
        meta = {
            "version": 3, "url": cache_key(url)[1], "size": len(body),
            "digest": hashlib.sha256(body).hexdigest(), "stored_at": time.time(),
            "headers": {k: v for k, v in normalized.items() if k in _SAFE_HEADERS},
        }
        try:
            body_tmp.write_bytes(body)
            meta_tmp.write_text(json.dumps(meta), encoding="utf-8")
            os.replace(body_tmp, body_path)
            os.replace(meta_tmp, meta_path)
            self.cleanup()
            return True
        finally:
            body_tmp.unlink(missing_ok=True)
            meta_tmp.unlink(missing_ok=True)

    def claim(self, url: str, lease_seconds: float = 30) -> str | None:
        _, _, flight = self._paths(url)
        flight.parent.mkdir(parents=True, exist_ok=True)
        token = uuid.uuid4().hex
        try:
            fd = os.open(flight, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            try:
                if time.time() - flight.stat().st_mtime < lease_seconds:
                    return None
                flight.unlink(missing_ok=True)
            except OSError:
                return None
            try:
                fd = os.open(flight, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                return None
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token)
        return token

    def release(self, url: str, token: str) -> None:
        _, _, flight = self._paths(url)
        try:
            if flight.read_text(encoding="utf-8") == token:
                flight.unlink(missing_ok=True)
        except OSError:
            pass

    def cleanup(self) -> None:
        now = time.time()
        if now < self._next_cleanup:
            return
        self._next_cleanup = now + 900
        entries = []
        scanned = 0
        for meta_path in self.root.glob("*/*.json"):
            scanned += 1
            if scanned > 2000:
                break
            body_path = meta_path.with_suffix(".body")
            try:
                mtime = meta_path.stat().st_mtime
                size = body_path.stat().st_size
                if now - mtime > self.ttl or size > self.max_item_bytes:
                    meta_path.unlink(missing_ok=True)
                    body_path.unlink(missing_ok=True)
                else:
                    entries.append((mtime, size, meta_path, body_path))
            except OSError:
                meta_path.unlink(missing_ok=True)
        total = sum(entry[1] for entry in entries)
        for _, size, meta_path, body_path in sorted(entries):
            if total <= self.max_total_bytes:
                break
            meta_path.unlink(missing_ok=True)
            body_path.unlink(missing_ok=True)
            total -= size
