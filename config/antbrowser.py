# -*- coding: utf-8 -*-
"""Ant Browser 本地自动化配置。"""
from config.env_loader import env_str, apply_env_overrides
from config import browser as _browser_cfg
ANT_API_BASE: str = env_str("ANT_API_BASE", "http://127.0.0.1:19876")
ANT_PROFILE_ID: str = env_str("ANT_PROFILE_ID", "")
ANT_LAUNCH_CODE: str = env_str("ANT_LAUNCH_CODE", "")
ANT_HEADLESS: bool = False
ANT_AUTO_CREATE: bool = True
ANT_DELETE_AFTER_RUN: bool = True
ANT_KEEP_BROWSER_OPEN: bool = True
STATIC_ASSET_CACHE_ENABLED: bool = _browser_cfg.STATIC_ASSET_CACHE_ENABLED
STATIC_ASSET_CACHE_DIR: str = _browser_cfg.STATIC_ASSET_CACHE_DIR
apply_env_overrides(globals(), {"ANT_API_BASE": "str", "ANT_PROFILE_ID": "str", "ANT_LAUNCH_CODE": "str", "ANT_HEADLESS": "bool", "ANT_AUTO_CREATE": "bool", "ANT_DELETE_AFTER_RUN": "bool", "ANT_KEEP_BROWSER_OPEN": "bool"})

