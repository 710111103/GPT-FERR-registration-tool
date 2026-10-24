from pathlib import Path
import importlib.util
import sys


PROTO = Path(__file__).resolve().parents[1] / "vendor" / "gpt-register-tool" / "协议"


def _load_http_client():
    sys.path.insert(0, str(PROTO))
    try:
        spec = importlib.util.spec_from_file_location("oss_http_client_compat", PROTO / "http_client.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def test_unsupported_chrome_profile_falls_back_to_installed_default():
    module = _load_http_client()
    if not module._HAS_CFFI:
        return
    from curl_cffi.requests.impersonate import DEFAULT_CHROME
    assert module.resolve_cffi_impersonate("chrome152") == str(DEFAULT_CHROME)


def test_supported_profile_is_preserved():
    module = _load_http_client()
    assert module.resolve_cffi_impersonate("chrome136") == "chrome136"


def test_claimed_chrome_version_stays_152_while_tls_profile_is_supported():
    source = (PROTO / "fingerprint.py").read_text(encoding="utf-8")
    assert '"impersonate": "chrome136"' in source
    assert '"ver": "152"' in source
    assert '"ua_ver": "152.0.0.0"' in source
