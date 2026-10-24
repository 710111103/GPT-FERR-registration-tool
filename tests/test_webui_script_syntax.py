"""Catch template-literal syntax failures that blank the entire account table."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest


def test_index_inline_javascript_parses(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js not installed")
    html = (Path(__file__).resolve().parents[1] / "webui" / "templates" / "index.html").read_text(encoding="utf-8")
    scripts = re.findall(r"<script(?:\s[^>]*)?>([\s\S]*?)</script>", html, flags=re.I)
    assert scripts
    for index, script in enumerate(scripts):
        if script.strip():
            target = tmp_path / f"inline-{index}.js"
            target.write_text(script, encoding="utf-8")
            result = subprocess.run([node, "--check", str(target)], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
