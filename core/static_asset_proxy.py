from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parent.parent


@dataclass
class StaticAssetProxy:
    process: subprocess.Popen
    port: int
    metrics_path: Path
    _final_snapshot: dict | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def snapshot(self) -> dict:
        if self._final_snapshot is not None:
            return dict(self._final_snapshot)
        try:
            return json.loads(self.metrics_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self._final_snapshot = self.snapshot()
        self.metrics_path.unlink(missing_ok=True)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_static_asset_proxy(upstream_proxy: str) -> StaticAssetProxy:
    from config import browser as cfg

    runtime = ROOT / ".static-cache-venv" / "Scripts" / "mitmdump.exe"
    addon = ROOT / "tools" / "static_asset_cache_addon.py"
    if not runtime.is_file():
        raise RuntimeError(f"静态缓存运行时不存在: {runtime}")
    port = _free_port()
    cache_dir = ROOT / str(getattr(cfg, "STATIC_ASSET_CACHE_DIR", ".static-asset-cache-v3"))
    cache_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = cache_dir / ("metrics-" + uuid.uuid4().hex + ".json")
    env = os.environ.copy()
    env.update({
        "TURB_STATIC_CACHE_DIR": str(cache_dir),
        "TURB_STATIC_CACHE_METRICS": str(metrics_path),
        "TURB_STATIC_CACHE_TTL": str(getattr(cfg, "STATIC_ASSET_CACHE_TTL_SECONDS", 86400)),
        "TURB_STATIC_CACHE_MAX_ITEM": str(getattr(cfg, "STATIC_ASSET_CACHE_MAX_ITEM_BYTES", 8 * 1024 * 1024)),
        "TURB_STATIC_CACHE_MAX_TOTAL": str(getattr(cfg, "STATIC_ASSET_CACHE_MAX_TOTAL_BYTES", 512 * 1024 * 1024)),
        "TURB_STATIC_CACHE_WAIT_MS": str(getattr(cfg, "STATIC_ASSET_CACHE_WAIT_TIMEOUT_MS", 600)),
    })
    parsed = urlsplit(upstream_proxy)
    if not parsed.scheme or not parsed.hostname or not parsed.port:
        raise RuntimeError("静态缓存上游代理格式无效")
    upstream_server = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    command = [
        str(runtime), "--quiet", "--listen-host", "127.0.0.1", "--listen-port", str(port),
        "--mode", f"upstream:{upstream_server}", "--set", "connection_strategy=lazy",
        "-s", str(addon),
    ]
    if parsed.username is not None:
        command.extend(["--upstream-auth", f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"])
    process = subprocess.Popen(command, cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = StaticAssetProxy(process=process, port=port, metrics_path=metrics_path)
    deadline = time.time() + 12
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"静态缓存代理启动失败，退出码={process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                logger.info("[静态缓存] 已启动：port=%s upstream=%s", port, upstream_proxy.split("@")[-1])
                return proxy
        except OSError:
            time.sleep(0.2)
    proxy.stop()
    raise RuntimeError("静态缓存代理启动超时")
