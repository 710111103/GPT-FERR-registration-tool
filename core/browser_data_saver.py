# -*- coding: utf-8 -*-
"""浏览器注册流程的省流量资源拦截。

省流量模式只拦截 Roxy/Cloak 本地指纹浏览器中的可选页面资源和配置中明确指定的
URL，默认不拦截 document/核心 script/stylesheet/xhr/fetch/websocket，避免影响登录、
验证码和 session 写入。Playwright 可以按资源类型和 URL glob 精确拦截；Selenium/Roxy
通过 Chrome CDP 的 URL glob 拦截常见扩展名资源及配置的 URL。Browser Use/Skyvern
云端浏览器不安装本模块的拦截器。
"""
from __future__ import annotations

import logging
import threading
from collections import Counter
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

from config import browser as _cfg

logger = logging.getLogger(__name__)


# Playwright 的 Request.resource_type 枚举。这里保留常用类型，未知值不会导致
# 注册流程失败；用户可以在配置中填写多个值，每行一个。
_RESOURCE_TYPE_ALIASES = {
    "images": "image",
    "img": "image",
    "videos": "media",
    "video": "media",
    "audio": "media",
    "fonts": "font",
    "tracks": "texttrack",
    "track": "texttrack",
}
_KNOWN_RESOURCE_TYPES = {
    "document",
    "stylesheet",
    "image",
    "media",
    "font",
    "script",
    "texttrack",
    "xhr",
    "fetch",
    "eventsource",
    "websocket",
    "manifest",
    "other",
}

# Selenium/CDP 没有通过 Network.setBlockedURLs 暴露 resourceType 过滤器，只能按
# URL glob 过滤。因此只列常见静态资源后缀，不把整个 third-party 域名拦掉。
_URL_EXTENSIONS_BY_TYPE = {
    "image": (
        ".apng", ".avif", ".bmp", ".gif", ".ico", ".jfif", ".jpeg", ".jpg",
        ".png", ".svg", ".webp",
    ),
    "media": (
        ".3gp", ".avi", ".flac", ".m4a", ".m4v", ".mkv", ".mov", ".mp3",
        ".mp4", ".mpeg", ".ogg", ".wav", ".webm",
    ),
    "font": (".eot", ".otf", ".ttf", ".woff", ".woff2"),
    "manifest": (".webmanifest", "/manifest.json"),
    "texttrack": (".vtt", ".srt"),
    # 下面几类不是默认值，但允许高级配置使用；开启前应确认页面不依赖它们。
    "stylesheet": (".css",),
    "script": (".js", ".mjs"),
}

# 登录风控/验证挑战可能把验证码图片、challenge 资源标为 image。Playwright 路由
# 可以按 URL 例外放行这些资源；Selenium/CDP 的 URL 黑名单没有例外规则，只能依赖
# 这类资源通常不使用常见静态后缀，遇到验证码异常时应关闭模式排查。
# 仅保留真实的验证码与风控域名特征，绝不能包含普通页面路径词（如 verification / verify），
# 否则会导致 auth.openai.com/email-verification 下的所有静态图片与字体全部绕过拦截。
_CHALLENGE_KEYWORDS = (
    "captcha", "challenge-platform", "arkose", "hcaptcha", "recaptcha", "turnstile",
)


def _as_items(value: Any, *, lower: bool = True) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.replace(",", "\n").splitlines()
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = [value]
    result = [str(item or "").strip() for item in raw if str(item or "").strip()]
    return [item.lower() for item in result] if lower else result


def configured_resource_types() -> list[str]:
    """读取并规范化省流量拦截类型；无效类型被忽略。"""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", ("image", "media"))
    result: list[str] = []
    for item in _as_items(raw, lower=True):
        item = _RESOURCE_TYPE_ALIASES.get(item, item)
        if item in _KNOWN_RESOURCE_TYPES and item not in result:
            result.append(item)
    return result


def configured_url_patterns() -> list[str]:
    """读取并规范化额外 URL glob 规则；空项去重，保留配置顺序。"""
    raw = getattr(_cfg, "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", ())
    result: list[str] = []
    # URL path 可能区分大小写，不能像 resource_type 一样统一转小写。
    for item in _as_items(raw, lower=False):
        if item not in result:
            result.append(item)
    return result


def _is_challenge_url(url: str) -> bool:
    lower = str(url or "").lower()
    return any(keyword in lower for keyword in _CHALLENGE_KEYWORDS)


def _infer_resource_type(url: str) -> str:
    """Selenium 的 CDP 事件缺少 type 时，按 URL 后缀做保守推断。"""
    try:
        path = urlsplit(str(url or "")).path.lower()
    except Exception:
        path = str(url or "").lower().split("?", 1)[0].split("#", 1)[0]
    for resource_type, extensions in _URL_EXTENSIONS_BY_TYPE.items():
        if any(path.endswith(extension) for extension in extensions):
            return resource_type
    return "other"


class BrowserDataSaver:
    """给一个浏览器会话安装可选资源拦截器。"""

    def __init__(self, *, label: str = "Browser"):
        self.label = str(label or "Browser")
        self.enabled = bool(getattr(_cfg, "BROWSER_DATA_SAVER_MODE", False))
        self.resource_types = configured_resource_types() if self.enabled else []
        self.url_patterns = configured_url_patterns() if self.enabled else []
        self.blocked_count = 0
        self.blocked_by_type: Counter[str] = Counter()
        self.blocked_by_url_pattern: Counter[str] = Counter()
        self._lock = threading.RLock()
        self._context: Any | None = None
        self._driver: Any | None = None
        self._route_handler: Any | None = None
        self._blocked_playwright_requests: set[int] = set()
        self._selenium_patterns: list[str] = []
        self._installed = False
        self._stopped = False
        self._block_all_mode = False
        self._session_only_mode = False
        self.method = "disabled"

    def session_only(self) -> None:
        """On ChatGPT, retain only OAuth documents, challenges, and auth APIs."""
        if not self.enabled:
            return
        with self._lock:
            self._session_only_mode = True
        logger.info(
            "[%s] 省流量模式已切换为 session-only：ChatGPT 仅放行文档、风控挑战和 /api/auth/*",
            self.label,
        )

    def block_all(self) -> None:
        """注册或核心会话完成后彻底封锁所有外网流量（仅放行 about:blank）。"""
        with self._lock:
            self._block_all_mode = True
        logger.info("[%s] 省流量模式已切换为全局封锁状态，阻断后续所有外网流量", self.label)

    def _matching_url_pattern(self, url: str) -> str | None:
        """返回第一个命中的 URL glob；规则匹配大小写按 URL 原文执行。"""
        text = str(url or "")
        if not text:
            return None
        for pattern in self.url_patterns:
            try:
                if fnmatchcase(text, pattern):
                    return pattern
            except Exception:
                continue
        return None

    def _should_block(self, resource_type: str, url: str) -> bool:
        if self._stopped:
            return False
        if self._block_all_mode:
            raw_url = str(url or "").lower()
            return not (raw_url.startswith("about:") or raw_url.startswith("data:"))
        if not self.enabled:
            return False
        if self._session_only_mode:
            raw_url = str(url or "")
            try:
                parsed = urlsplit(raw_url)
                host = parsed.hostname or ""
                path = parsed.path or "/"
            except Exception:
                host = ""
                path = "/"
            if host == "chatgpt.com" or host.endswith(".chatgpt.com"):
                normalized_type = _RESOURCE_TYPE_ALIASES.get(
                    str(resource_type or "").lower(), str(resource_type or "").lower()
                )
                if normalized_type == "document" or path.startswith("/api/auth/") or _is_challenge_url(raw_url):
                    return False
                return True
        # 始终拦截巨大的 SourceMap 文件（.js.map / .css.map / *.map），CDP 会自动拉取造成大量流量浪费
        raw_url = str(url or "")
        clean_url = raw_url.split("?", 1)[0].split("#", 1)[0].lower()
        if clean_url.endswith(".map") or clean_url.endswith(".js.map") or clean_url.endswith(".css.map"):
            return True

        resource_type = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "").lower(), str(resource_type or "").lower())
        matched_url_pattern = self._matching_url_pattern(url)
        # 命中明确配置的 URL 拦截黑名单规则（如 RUM、未登录不需要的聊天 SPA chunks、统计上报等），直接拦截
        if matched_url_pattern is not None:
            return True
        if resource_type not in self.resource_types:
            return False
        # 验证挑战资源优先放行；普通页面图片/媒体仍然拦截。
        if _is_challenge_url(url):
            return False
        return True

    def _record_blocked(
        self,
        resource_type: str,
        *,
        request: Any | None = None,
        url_pattern: str | None = None,
    ) -> None:
        normalized = _RESOURCE_TYPE_ALIASES.get(str(resource_type or "other").lower(), str(resource_type or "other").lower())
        with self._lock:
            self.blocked_count += 1
            self.blocked_by_type[normalized or "other"] += 1
            if url_pattern:
                self.blocked_by_url_pattern[str(url_pattern)] += 1
            if request is not None:
                self._blocked_playwright_requests.add(id(request))

    def was_playwright_blocked(self, request: Any) -> bool:
        """供 Playwright 流量统计器排除 route.abort() 产生的伪上传字节。"""
        with self._lock:
            key = id(request)
            if key not in self._blocked_playwright_requests:
                return False
            self._blocked_playwright_requests.remove(key)
            return True

    def install_playwright(self, context: Any) -> "BrowserDataSaver":
        """在 BrowserContext 上按 resource_type 拦截请求。"""
        if not self.enabled:
            return self
        if not self.resource_types and not self.url_patterns:
            logger.info("[%s] 省流量模式已开启，但未配置可拦截资源类型或 URL 规则", self.label)
            return self
        try:
            def _handle_route(route: Any) -> None:
                try:
                    request = route.request
                    resource_type = getattr(request, "resource_type", "")
                    url = getattr(request, "url", "")
                    if self._should_block(resource_type, url):
                        self._record_blocked(
                            resource_type,
                            request=request,
                            url_pattern=self._matching_url_pattern(url),
                        )
                        try:
                            route.abort("blockedbyclient")
                        except TypeError:
                            # 兼容极旧的 Playwright route.abort() 签名。
                            route.abort()
                        return
                    route.continue_()
                except Exception as exc:
                    # 拦截器不能阻断注册主流程；处理异常时尽量放行请求。
                    logger.debug("[%s] 省流量路由处理失败，尝试放行：%s", self.label, exc)
                    try:
                        route.continue_()
                    except Exception:
                        pass

            context.route("**/*", _handle_route)
            self._context = context
            self._route_handler = _handle_route
            self._installed = True
            self.method = "playwright.context.route"
            logger.info(
                "[%s] 省流量模式已启用：拦截资源类型=%s，URL规则=%s（验证码/challenge 相关 URL 放行）",
                self.label,
                ",".join(self.resource_types) or "-",
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] 安装 Playwright 省流量拦截失败，继续不拦截：%s: %s", self.label, type(exc).__name__, exc)
        return self

    def install_selenium(self, driver: Any) -> "BrowserDataSaver":
        """通过 Chrome CDP Network.setBlockedURLs 安装 URL 后缀和 URL glob 拦截。"""
        if not self.enabled:
            return self
        patterns: list[str] = []
        for resource_type in self.resource_types:
            for extension in _URL_EXTENSIONS_BY_TYPE.get(resource_type, ()):
                # 省略 scheme/host，匹配带 query/hash 的同类资源 URL。
                patterns.append(f"*{extension}*")
        # CDP 的 URL matcher 使用 * 作为通配符；将 Playwright 规则中的 **
        # 收窄成单个 *，即可兼容跨路径 URL 的 CDP 匹配。
        patterns.extend(pattern.replace("**", "*") for pattern in self.url_patterns)
        # 去重并保持配置/扩展名顺序，便于日志和测试稳定。
        patterns = list(dict.fromkeys(patterns))
        if not patterns:
            logger.info("[%s] 省流量模式已开启，但 Selenium 没有可用 URL 规则", self.label)
            return self
        try:
            # 某些情况下流量统计器没有成功初始化，仍需单独开启 Network 域。
            try:
                driver.execute_cdp_cmd("Network.enable", {})
            except Exception:
                pass
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": patterns})
            self._driver = driver
            self._selenium_patterns = patterns
            self._installed = True
            self.method = "selenium.cdp.Network.setBlockedURLs"
            logger.info(
                "[%s] 省流量模式已启用：按 URL 拦截资源类型=%s，类型规则=%s 条，URL规则=%s 条（Selenium URL 规则不支持 challenge 例外）",
                self.label,
                ",".join(self.resource_types) or "-",
                sum(len(_URL_EXTENSIONS_BY_TYPE.get(resource_type, ())) for resource_type in self.resource_types),
                len(self.url_patterns),
            )
        except Exception as exc:
            logger.warning("[%s] 安装 Selenium 省流量拦截失败，继续不拦截：%s: %s", self.label, type(exc).__name__, exc)
        return self

    def observe_cdp_event(self, method: str, params: dict[str, Any], request: dict[str, Any] | None = None) -> bool:
        """让 Selenium 流量统计器识别 CDP inspector 拦截事件。

        返回 True 表示这是本省流量规则拦截的请求，统计器应跳过它的请求头估算，
        因为该请求实际上没有发到网络。
        """
        if not self.enabled or method != "Network.loadingFailed":
            return False
        if str(params.get("blockedReason") or "").lower() != "inspector":
            return False
        request = request or {}
        url = str(request.get("url") or "")
        resource_type = str(request.get("resourceType") or "").strip().lower() or _infer_resource_type(url)
        resource_type = _RESOURCE_TYPE_ALIASES.get(resource_type, resource_type)
        if self._selenium_patterns:
            if not url or not any(fnmatchcase(url, pattern) for pattern in self._selenium_patterns):
                return False
        # 保留未调用 install_selenium() 时的资源类型事件兼容性；正常安装成功后
        # 总会有 URL 规则，走上面的精确分支。
        elif resource_type not in self.resource_types:
            return False
        self._record_blocked(resource_type, url_pattern=self._matching_url_pattern(url))
        return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "data_saver_enabled": bool(self.enabled),
                "data_saver_method": self.method,
                "data_saver_blocked_resource_types": list(self.resource_types),
                "data_saver_blocked_url_patterns": list(self.url_patterns),
                "data_saver_blocked_count": int(self.blocked_count),
                "data_saver_session_only": bool(self._session_only_mode),
                "data_saver_blocked_by_type": dict(sorted(self.blocked_by_type.items())),
                "data_saver_blocked_by_url_pattern": dict(sorted(self.blocked_by_url_pattern.items())),
            }

    def stop(self) -> None:
        """移除 Playwright 路由；CDP URL 规则随浏览器会话结束。"""
        if self._stopped:
            return
        self._stopped = True
        if self._context is not None and self._route_handler is not None:
            try:
                self._context.unroute("**/*", self._route_handler)
            except Exception:
                pass
        self._route_handler = None
        self._context = None
        self._driver = None
        self._blocked_playwright_requests.clear()


__all__ = ["BrowserDataSaver", "configured_resource_types", "configured_url_patterns"]
