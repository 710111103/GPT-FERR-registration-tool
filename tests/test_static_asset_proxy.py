from pathlib import Path
from types import SimpleNamespace

from core.static_asset_proxy import StaticAssetProxy, _free_port


class FakeProcess:
    def __init__(self):
        self.terminated = 0
        self.killed = 0
        self.waited = []
        self.running = True

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.terminated += 1
        self.running = False

    def kill(self):
        self.killed += 1
        self.running = False

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return 0


def test_free_port_is_bindable():
    port = _free_port()
    assert isinstance(port, int) and port > 0


def test_proxy_stop_is_idempotent_and_preserves_metrics(tmp_path):
    metrics = tmp_path / "metrics.json"
    metrics.write_text('{"hits":3,"bytes_saved":42}', encoding="utf-8")
    process = FakeProcess()
    proxy = StaticAssetProxy(process=process, port=12345, metrics_path=metrics)
    assert proxy.snapshot()["hits"] == 3
    proxy.stop()
    proxy.stop()
    assert process.terminated == 1
    assert proxy.snapshot() == {"hits": 3, "bytes_saved": 42}
    assert not metrics.exists()


def test_ant_cleanup_always_stops_cache_proxy(monkeypatch):
    from core import antbrowser_driver

    cache = SimpleNamespace(stop=lambda: setattr(cache, "stopped", True), stopped=False)
    opened = SimpleNamespace(raw={"ephemeral": False, "static_asset_proxy": cache})
    antbrowser_driver.cleanup_ant_profile(opened)
    assert cache.stopped is True
