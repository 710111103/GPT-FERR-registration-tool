"""Route configured headless browser jobs through isolated Ant profiles."""
from __future__ import annotations


def registration_driver(mode: str) -> str:
    from config import cloakbrowser, roxybrowser
    mode = str(mode or "").strip().lower()
    if mode in ("roxy", "roxybrowser", "fingerprint", "browser") and roxybrowser.ROXY_OPEN_HEADLESS:
        return "ant"
    if mode in ("cloak", "cloakbrowser") and cloakbrowser.CLOAK_HEADLESS:
        return "ant"
    return mode


def oauth_driver(mode: str) -> str:
    return registration_driver(mode)
