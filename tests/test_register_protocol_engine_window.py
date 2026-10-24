import subprocess

from core import register_protocol_engine as engine


def test_protocol_bridge_is_hidden_on_windows(monkeypatch, tmp_path):
    bridge = tmp_path / "bridge.py"
    bridge.write_text("pass", encoding="utf-8")
    seen = {}

    class Result:
        stdout = '{"ok": true}'
        stderr = ""
        returncode = 0

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return Result()

    monkeypatch.setattr(engine, "_BRIDGE", bridge)
    monkeypatch.setattr(engine, "_PROTO_DIR", tmp_path)
    monkeypatch.setattr(engine.subprocess, "run", fake_run)
    monkeypatch.setattr(engine.os, "name", "nt")
    assert engine._run_bridge({"mode": "check"}, 1)["ok"] is True
    assert seen["creationflags"] == subprocess.CREATE_NO_WINDOW
    assert seen["capture_output"] is True


def test_protocol_bridge_has_no_creation_flag_off_windows(monkeypatch, tmp_path):
    bridge = tmp_path / "bridge.py"
    bridge.write_text("pass", encoding="utf-8")
    seen = {}

    class Result:
        stdout = '{"ok": true}'
        stderr = ""
        returncode = 0

    monkeypatch.setattr(engine, "_BRIDGE", bridge)
    monkeypatch.setattr(engine, "_PROTO_DIR", tmp_path)
    monkeypatch.setattr(engine.subprocess, "run", lambda *a, **kw: (seen.update(kw) or Result()))
    monkeypatch.setattr(engine.os, "name", "posix")
    assert engine._run_bridge({"mode": "check"}, 1)["ok"] is True
    assert seen["creationflags"] == 0
