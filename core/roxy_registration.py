# -*- coding: utf-8 -*-
"""通过 RoxyBrowser 指纹浏览器 + Selenium 执行 ChatGPT 注册。"""
from __future__ import annotations

import logging
import random
import string
import time
import uuid
from pathlib import Path
from typing import Callable

from config import roxybrowser as _cfg
from config import twofa as _twofa_cfg
from core.account_export import save_account_data, post_register_dwell
from core.browser_data_saver import BrowserDataSaver
from core.browser_traffic import SeleniumTrafficTracker
from core.email_provider import acquire_email_after_input, wait_for_otp, resolve_email_source
from core.humanize import delay as human_delay
from core.roxybrowser_client import RoxyBrowserClient, RoxyOpenResult

logger = logging.getLogger(__name__)


def _enable_performance_logging(options) -> None:
    """尽量开启 Chrome performance log；不支持时不阻断注册。"""
    try:
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    except Exception as exc:
        logger.debug("[Roxy] 当前 Selenium 选项不支持 performance log：%s", exc)


def _log_prefix(driver=None) -> str:
    """按当前浏览器实现返回注册日志前缀。

    CloakBrowser 复用 Roxy 的页面操作函数；这些共享函数必须跟随实际 driver
    输出 `[Cloak注册]`，避免 Cloak 流程里混入 `[Roxy注册]` 日志。
    """
    try:
        explicit = str(getattr(driver, "_registration_log_prefix", "") or "").strip()
        if explicit:
            return explicit
        if driver is not None and driver.__class__.__name__ == "CloakSeleniumDriver":
            return "[Cloak注册]"
    except Exception:
        pass
    return "[Roxy注册]"


def _build_driver(opened: RoxyOpenResult):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    if opened.debugger_address:
        logger.info("[Roxy] Selenium 连接 debuggerAddress=%s", opened.debugger_address)
        options = Options()
        # 页面里长轮询/风控脚本偶尔会让 driver.get 等到超时；eager 只等 DOMContentLoaded。
        options.page_load_strategy = "eager"
        _enable_performance_logging(options)
        options.add_experimental_option("debuggerAddress", opened.debugger_address)
        driver_path = ""
        try:
            raw_data = opened.raw.get("data") if isinstance(opened.raw, dict) else {}
            if isinstance(raw_data, dict):
                driver_path = str(raw_data.get("driver") or raw_data.get("driverPath") or raw_data.get("driver_path") or "").strip()
        except Exception:
            driver_path = ""
        if driver_path:
            logger.info("[Roxy] 使用 Roxy chromedriver=%s", driver_path)
            driver = webdriver.Chrome(service=Service(executable_path=driver_path), options=options)
        else:
            driver = webdriver.Chrome(options=options)
        _apply_browser_automation_mask(driver)
        return driver

    if opened.webdriver_url:
        logger.info("[Roxy] Selenium 连接 webdriver_url=%s", opened.webdriver_url)
        options = Options()
        options.page_load_strategy = "eager"
        _enable_performance_logging(options)
        driver = RemoteWebDriver(command_executor=opened.webdriver_url, options=options)
        _apply_browser_automation_mask(driver)
        return driver

    raise RuntimeError("Roxy 未返回可连接的 Selenium 地址")


def _center_browser_window(driver) -> None:
    """把可见的 Roxy 窗口移动到 Windows 主屏工作区中央。"""
    if bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False)):
        return
    try:
        import platform
        if platform.system().lower() != "windows":
            return
        import ctypes

        class _Rect(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        work_area = _Rect()
        if not ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0):
            raise OSError("无法读取 Windows 工作区")
        size = driver.get_window_size()
        width = max(1, int(size.get("width") or 1))
        height = max(1, int(size.get("height") or 1))
        x = int(work_area.left + max(0, (work_area.right - work_area.left - width) // 2))
        y = int(work_area.top + max(0, (work_area.bottom - work_area.top - height) // 2))
        driver.set_window_position(x, y)
        logger.info("[Roxy] 浏览器窗口已居中：x=%s y=%s width=%s height=%s", x, y, width, height)
    except Exception as exc:
        logger.warning("[Roxy] 浏览器窗口居中失败，继续执行：%s", exc)


def _wait(driver, timeout: int | None = None):
    from selenium.webdriver.support.ui import WebDriverWait
    return WebDriverWait(driver, timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))


def _safe_get(driver, url: str, *, timeout: int = 45, attempts: int = 2, accept_hosts: tuple[str, ...] = ()) -> None:
    """带容错的页面跳转。

    Roxy/Chrome 150 偶发 `Timed out receiving message from renderer`，实际页面可能已经可用。
    这里超时后先 `window.stop()`，只要当前 URL/DOM 已进入目标页就继续；否则重试一次。
    """
    from selenium.common.exceptions import TimeoutException, WebDriverException
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    except ImportError:
        PlaywrightTimeoutError = ()

    last_exc: Exception | None = None
    old_timeout = int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
    hosts = tuple(h.lower() for h in (accept_hosts or ()))
    for attempt in range(1, max(1, attempts) + 1):
        try:
            try:
                driver.set_page_load_timeout(max(10, int(timeout)))
                driver.set_script_timeout(8)
            except Exception:
                pass
            driver.get(url)
            return
        except (TimeoutException, PlaywrightTimeoutError, Exception) as exc:
            last_exc = exc
            logger.warning(
                "%s 页面加载超时或异常，检查 DOM 元素：url=%s attempt=%s/%s error=%s",
                _log_prefix(driver), url, attempt, attempts, str(exc).splitlines()[0] if str(exc) else type(exc).__name__,
            )
            time.sleep(1.0)
            try:
                current = str(driver.current_url or "").lower()
            except Exception:
                current = ""
            native_navigation_state = getattr(driver, "navigation_state_native", None)
            if callable(native_navigation_state):
                navigation_state = native_navigation_state()
                ready = "native"
                has_elements = bool(navigation_state.get("has_elements"))
            else:
                try:
                    ready = str(driver.execute_script("return document.readyState || ''") or "")
                    # 必须检查交互元素；只有 body 时中止加载会造成 SPA 白屏。
                    has_elements = bool(driver.execute_script("return !!document.querySelector('input, button, a[role=button]')"))
                except Exception:
                    ready = ""
                    has_elements = False
            target_ok = any(h in current for h in hosts) if hosts else (url.split("/", 3)[2].lower() in current)
            if target_ok and has_elements:
                if not callable(native_navigation_state):
                    try:
                        driver.execute_script("window.stop();")
                    except Exception:
                        pass
                logger.info(
                    "%s 页面加载虽超时但交互元素已渲染，继续流程：current=%s readyState=%s",
                    _log_prefix(driver), current[:180], ready or "-",
                )
                return
            if attempt < attempts:
                try:
                    driver.get("about:blank")
                except Exception:
                    pass
                time.sleep(1.5 * attempt)
                continue
        except WebDriverException as exc:
            last_exc = exc
            if attempt < attempts:
                logger.warning("%s 页面跳转失败，准备重试：url=%s attempt=%s/%s error=%s", _log_prefix(driver), url, attempt, attempts, exc)
                time.sleep(1.5 * attempt)
                continue
            raise
        finally:
            try:
                driver.set_page_load_timeout(old_timeout)
            except Exception:
                pass
    raise last_exc or RuntimeError(f"页面跳转失败: {url}")


def _visible(el) -> bool:
    try:
        return el.is_displayed() and el.is_enabled()
    except Exception:
        return False


def _browser_actions_enabled() -> bool:
    try:
        from config import humanize as _hcfg
        return bool(getattr(_hcfg, "ENABLE_HUMANIZE_BROWSER_ACTIONS", True))
    except Exception:
        return True


def _apply_browser_automation_mask(driver) -> None:
    """连接 Selenium 后尽量降低明显自动化特征；失败不影响主流程。"""
    if not _browser_actions_enabled():
        return
    try:
        script = r"""
        Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => undefined});
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) window.chrome.runtime = {};
        const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
        if (originalQuery) {
          window.navigator.permissions.query = (parameters) => (
            parameters && parameters.name === 'notifications'
              ? Promise.resolve({ state: Notification.permission })
              : originalQuery(parameters)
          );
        }
        """
        if hasattr(driver, "execute_cdp_cmd"):
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": script})
        try:
            driver.execute_script(script)
        except Exception:
            pass
        logger.info("%s 已注入浏览器自动化特征弱化脚本", _log_prefix(driver))
    except Exception as exc:
        logger.debug("%s 注入自动化特征弱化脚本失败：%s", _log_prefix(driver), exc)


def _human_scroll_to(driver, el) -> None:
    try:
        block = random.choice(["center", "nearest", "center"])
        driver.execute_script("arguments[0].scrollIntoView({block: arguments[1], inline:'nearest'});", el, block)
        if _browser_actions_enabled():
            time.sleep(random.uniform(0.08, 0.35))
            # 轻微滚动抖动，避免每次都精准居中。
            driver.execute_script("window.scrollBy(0, arguments[0]);", random.randint(-90, 90))
            time.sleep(random.uniform(0.05, 0.22))
            driver.execute_script("arguments[0].scrollIntoView({block:'center', inline:'nearest'});", el)
    except Exception:
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass


def _human_click(driver, el, *, label: str = "") -> None:
    """快速人工化点击。

    之前用 ActionChains 在 Roxy/Chrome 150 上偶发卡住 1-2 分钟，导致邮箱提交很慢。
    这里改为 CDP 派发鼠标事件；没有 CDP 时再用 JS/原生 click 兜底。
    """
    _human_scroll_to(driver, el)
    # 如果是 Playwright 原生元素/包含 locator，直接用 locator 点击，最稳定且不会卡在 CDP/JS 序列化中
    loc = getattr(el, "locator", None)
    if loc is not None:
        try:
            if not _browser_actions_enabled():
                loc.click(timeout=8000)
            else:
                human_delay("click")
                loc.click(timeout=8000)
            return
        except Exception:
            pass

    if not _browser_actions_enabled():
        time.sleep(0.2)
        try:
            el.click()
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", el)
            except Exception:
                pass
        return
    try:
        human_delay("click")
        # AntBrowser / Playwright 原生 Locator 支持真实用户级点击，优先调用原生点击
        if hasattr(el, "click") and callable(el.click) and hasattr(el, "locator"):
            try:
                el.click()
                return
            except Exception:
                pass
        point = driver.execute_script(r"""
        const el = arguments[0];
        const r = el.getBoundingClientRect();
        const x = r.left + r.width * (0.30 + Math.random() * 0.40);
        const y = r.top + r.height * (0.35 + Math.random() * 0.30);
        return {x, y, w:r.width, h:r.height};
        """, el) or {}
        x = float(point.get("x") or 0)
        y = float(point.get("y") or 0)
        if hasattr(driver, "execute_cdp_cmd") and x > 0 and y > 0:
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
            time.sleep(random.uniform(0.05, 0.22))
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
            time.sleep(random.uniform(0.035, 0.13))
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})
        else:
            driver.execute_script(r"""
            const el = arguments[0];
            el.dispatchEvent(new PointerEvent('pointerdown', {bubbles:true, cancelable:true, pointerType:'mouse'}));
            el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
            el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
            el.click();
            """, el)
    except Exception as exc:
        logger.debug("%s 人工化点击失败，回退 el.click label=%s err=%s", _log_prefix(driver), label, exc)
        time.sleep(random.uniform(0.12, 0.45))
        try:
            driver.execute_script("arguments[0].click();", el)
        except Exception:
            el.click()


def _human_type_text(driver, el, value: str, *, clear: bool = True) -> None:
    """按字符/小段输入，触发真实 key events；失败时回退 JS setter。"""
    if not _browser_actions_enabled():
        if clear:
            try:
                el.clear()
            except Exception:
                pass
        el.send_keys(value)
        return
    try:
        _human_scroll_to(driver, el)
        try:
            _human_click(driver, el, label="input_focus")
        except Exception:
            driver.execute_script("arguments[0].focus();", el)
        if clear:
            from selenium.webdriver.common.keys import Keys
            mod = Keys.COMMAND
            try:
                import platform
                if platform.system().lower() != "darwin":
                    mod = Keys.CONTROL
            except Exception:
                pass
            try:
                el.send_keys(mod, "a")
                time.sleep(random.uniform(0.04, 0.16))
                el.send_keys(Keys.BACKSPACE)
            except Exception:
                try:
                    el.clear()
                except Exception:
                    pass
        text = str(value)
        i = 0
        while i < len(text):
            # 邮箱/密码整体仍逐字符，但偶尔 2 字符一组，节奏更自然。
            step = 2 if random.random() < 0.12 and i + 1 < len(text) else 1
            el.send_keys(text[i:i + step])
            i += step
            human_delay("keystroke")
            if i < len(text) and random.random() < 0.08:
                human_delay("typing_pause")
        driver.execute_script(
            "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            el,
        )
        current_val = str(driver.execute_script("return arguments[0].value;", el) or "")
        if current_val != str(value):
            logger.debug("%s 输入后值未匹配(当前=%r, 期望=%r)，调用 JS setter 兜底", _log_prefix(driver), current_val, value)
            _set_element_value(driver, el, value)
    except Exception as exc:
        logger.debug("%s 人工化输入失败，回退 JS setter err=%s", _log_prefix(driver), exc)
        _set_element_value(driver, el, value)


def _page_warmup(driver, *, reason: str = "") -> None:
    if not _browser_actions_enabled():
        return
    try:
        human_delay("page_warmup")
        if hasattr(driver, "execute_cdp_cmd"):
            driver.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": "mouseMoved",
                "x": random.randint(80, 360),
                "y": random.randint(80, 260),
            })
    except Exception:
        pass


def _find_any(driver, selectors: list[str], timeout: int | None = None):
    from selenium.webdriver.common.by import By

    end = time.time() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last = None
    while time.time() < end:
        for selector in selectors:
            try:
                by = By.XPATH if selector.startswith("//") else By.CSS_SELECTOR
                items = driver.find_elements(by, selector)
                for item in items:
                    if _visible(item):
                        return item
            except Exception as exc:
                last = exc
        time.sleep(0.4)
    raise RuntimeError(f"找不到页面元素: {selectors}; last={last}")


def _click_any(driver, selectors: list[str], timeout: int | None = None) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_click(driver, el, label="click_any")


def _type_any(driver, selectors: list[str], value: str, timeout: int | None = None, clear: bool = True) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_type_text(driver, el, value, clear=clear)


_EMAIL_INPUT_SELECTORS = [
    "input[type='email']",
    "input[name='email']",
    "input[name='username']",
    "input#email-input",
    "input[autocomplete='email']",
]


def _email_entry_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const attrText = el => [
          el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
          el.getAttribute('data-auth-provider'), el.getAttribute('href'), el.getAttribute('action'),
          el.getAttribute('formaction'), el.getAttribute('value')
        ].filter(Boolean).join(' ').toLowerCase();
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''
        })).slice(0, 30);
        const actions = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
          .filter(visible).map(el => ({tag: el.tagName, type: el.getAttribute('type') || '', attrs: attrText(el)})).slice(0, 40);
        return {url: location.href, title: document.title, readyState: document.readyState,
          inputCount: document.querySelectorAll('input').length,
          actionCount: document.querySelectorAll('button,a,[role=button]').length,
          frameCount: document.querySelectorAll('iframe').length,
          bodyPresent: !!document.body, inputs, actions};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _find_visible_email_input_js(driver):
    page = getattr(driver, "page", None)
    if page is not None:
        try:
            selectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[name="username"]',
                'input[name="identifier"]',
                'input#email-input',
                'input[autocomplete*="email"]',
                'input[placeholder*="email" i]',
                'input[aria-label*="email" i]',
                'input[type="text"][name*="email" i]',
                'input[type="text"][id*="email" i]',
            ]
            for sel in selectors:
                matches = page.locator(sel)
                for index in range(min(matches.count(), 30)):
                    loc = matches.nth(index)
                    try:
                        if loc.is_visible(timeout=300) and loc.is_enabled(timeout=300) and loc.is_editable(timeout=300):
                            from core.antbrowser_driver import AntBrowserElement
                            return AntBrowserElement(page, locator=loc)
                    except Exception:
                        # A detached/hidden duplicate must not hide another live input.
                        continue
        except Exception:
            pass

    return driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const selectors = [
      'input[type="email"]',
      'input[name="email"]',
      'input[name="username"]',
      'input[name="identifier"]',
      'input#email-input',
      'input[autocomplete*="email"]',
      'input[placeholder*="email" i]',
      'input[aria-label*="email" i]',
      'input[type="text"][name*="email" i]',
      'input[type="text"][id*="email" i]'
    ];
    for (const sel of selectors) {
      const el = [...document.querySelectorAll(sel)].find(visible);
      if (el) return el;
    }
    return null;
    """)


def _is_oauth_consent_like(driver) -> bool:
    """检测是否已到 OAuth 授权/consent 页。这里不能再点任何邮箱分支或全局提交按钮。"""
    try:
        return bool(driver.execute_script(r"""
        const url = String(location.href || '').toLowerCase();
        if (/oauth|authorize|consent/.test(url) && !/login|signup|identifier|email-verification/.test(url)) return true;
        const formsWithEmail = [...document.querySelectorAll('form')]
          .some(form => form.querySelector('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]'));
        if (formsWithEmail) return false;
        const actions = [...document.querySelectorAll('button,a,[role="button"],input[type="submit"],input[type="button"]')]
          .map(el => [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('href'),
            el.getAttribute('formaction'), el.value, el.className].filter(Boolean).join(' ').toLowerCase())
          .join(' ');
        return /oauth|authorize|consent|grant|allow/.test(actions) && !/email|username/.test(actions);
        """))
    except Exception:
        return False


def _is_external_idp_url(url: str) -> bool:
    u = str(url or '').lower()
    return any(x in u for x in (
        'accounts.google.', 'google.com/o/oauth', 'appleid.apple.', 'login.microsoftonline.',
        'login.live.', 'github.com/login/oauth', 'facebook.com/', 'saml', 'sso'
    ))


def _assert_not_external_idp(driver, label: str = '') -> None:
    try:
        current = str(driver.current_url or '')
    except Exception:
        current = ''
    if _is_external_idp_url(current):
        raise RuntimeError(f"误入第三方账号授权页（{label}）：{current}")


def _click_email_entry_option(driver) -> bool:
    """进入邮箱登录入口。

    优先使用 DOM 技术属性；新版 ChatGPT 欢迎页的“登录”按钮可能没有
    email/provider 等属性，因此再使用严格的多语言登录文案白名单。
    文案匹配只接受完整短文本，并继续排除第三方 IdP，避免误点 Google/Apple。
    """
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，跳过邮箱入口兜底点击", _log_prefix(driver))
        return False
    target = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const attrText = el => {
      const own = [
        el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
        el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
        el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'), el.getAttribute('href'), el.getAttribute('action'),
        el.getAttribute('formaction'), el.getAttribute('value'), el.getAttribute('aria-label'), el.className
      ].filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' ')).join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
    const good = /(^|[^a-z])(email|mail|username|passwordless|otp|magic)([^a-z]|$)/;
    const loginLabels = new Set([
      'log in', 'login', 'sign in',
      '登录', '登入', '登錄',
      'ログイン', 'サインイン',
      'đăng nhập', 'iniciar sesión', 'connexion', 'anmelden'
    ]);
    const normalizeText = el => String(el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '')
      .replace(/\s+/g, ' ').trim().toLowerCase();
    const all = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')]
      .filter(visible)
      .map(el => ({el, attrs: attrText(el), text: normalizeText(el), hasLogo: !!el.querySelector('img,svg,use')}))
      .filter(x => !bad.test(x.attrs) && !x.hasLogo);
    const technical = all.filter(x => good.test(x.attrs));
    const candidates = technical.length ? technical : all.filter(x => loginLabels.has(x.text));
    if (candidates.length !== 1) return null;
    candidates[0].el.scrollIntoView({block:'center'});
    return candidates[0].el;
    """)
    if target:
        _human_click(driver, target, label="email_entry")
        return True
    return False


def _check_and_solve_cloudflare(driver, timeout: float = 20.0) -> bool:
    """通用 Cloudflare 质询 / Turnstile 检测与点击过盾。
    支持在邮箱输入页、OTP 页、重新发送按钮、资料页等各个阶段通用调用。
    若检测到质询并处理返回 True，未检测到返回 False。
    """
    page = getattr(driver, "page", None)
    cf_keywords = (
        "chờ một chút", "just a moment", "moment please", "checking your browser",
        "cloudflare", "しばらくお待ちください", "un momento", "un instant", "bitte warten",
        "подождите", "稍等", "请稍候", "セキュリティ検証", "security verification", "ray id"
    )

    def _is_cf_page() -> tuple[bool, str]:
        title = ""
        if page is not None:
            try:
                title = (page.title() or "").lower()
            except Exception:
                pass
        if not title:
            try:
                title = str(getattr(driver, "title", "") or "").lower()
            except Exception:
                pass
        if any(w in title for w in cf_keywords):
            return True, title
        try:
            body_snippet = str(driver.execute_script("return (document.body?.innerText || '').slice(0, 500);") or "").lower()
            if any(w in body_snippet for w in cf_keywords):
                return True, title or "body_cf_text"
        except Exception:
            pass
        return False, ""

    is_cf, detected_title = _is_cf_page()
    if not is_cf:
        return False

    logger.info("%s 检测到 Cloudflare 质询/等待页（title=%s），尝试通过并等待...", _log_prefix(driver), detected_title)
    end = time.time() + timeout
    while time.time() < end:
        _check_manual_stop()
        if page is not None:
            try:
                for frame in page.frames:
                    if any(k in frame.url.lower() for k in ("cloudflare", "challenge", "turnstile")):
                        box = frame.locator('input[type="checkbox"], .ctp-checkbox-label, #challenge-stage, span.mark, div.ctp-checkbox-container').first
                        if box.count() > 0 and box.is_visible(timeout=800):
                            box.click(timeout=2000)
                            logger.info("%s 已点击 Cloudflare iframe 质询复选框", _log_prefix(driver))
                            time.sleep(2.0)
                            break
                main_box = page.locator('iframe[src*="cloudflare" i], iframe[src*="turnstile" i], .cf-turnstile').first
                if main_box.count() > 0 and main_box.is_visible(timeout=800):
                    main_box.click(timeout=2000)
                    logger.info("%s 已尝试点击主页面 Cloudflare 区域", _log_prefix(driver))
                    time.sleep(2.0)
            except Exception:
                pass

        time.sleep(1.0)
        still_cf, _ = _is_cf_page()
        if not still_cf:
            logger.info("%s Cloudflare 质询已通过", _log_prefix(driver))
            return True

    logger.warning("%s Cloudflare 质询等待（%.1fs），页面可能仍处于质询状态", _log_prefix(driver), timeout)
    return True


class _LoginPasswordPageReached(RuntimeError):
    """The login flow advanced while an email field was being awaited."""


def _wait_for_email_input(driver, timeout: int | None = None):
    """进入邮箱登录/注册方式并返回已找到的可见邮箱输入框。"""
    # 默认流程仍给慢代理至少 45 秒；调用方显式传入较短时限时必须尊重，
    # 否则 AT 刷新设置的 15~30 秒会被这里偷偷抬回 45 秒。
    if timeout is None:
        wait_sec = max(45, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90))
    else:
        wait_sec = max(10, int(timeout))
    manual_wait = bool(getattr(driver, "_manual_challenge_wait", False))
    if manual_wait:
        wait_sec = max(wait_sec, int(getattr(driver, "_manual_challenge_timeout", 300)))
    end = time.time() + wait_sec
    next_challenge_log = 0.0
    progress = getattr(driver, "_challenge_progress", None)
    last_state = None
    clicked_email_option = False
    logged_challenge = False
    cf_start_time = None
    page = getattr(driver, "page", None)
    while time.time() < end:
        _check_manual_stop()

        # A slow navigation may leave an old challenge title while the password
        # form is already visible.  Never spend the full challenge timeout
        # waiting for another email input on an advanced login page.
        if "/log-in/password" in str(getattr(driver, "current_url", "") or "").lower():
            logger.info("%s 已进入登录密码页，不再等待邮箱框", _log_prefix(driver))
            raise _LoginPasswordPageReached("已进入登录密码页")

        # 1. 优先使用原生 page.title() 检查是否处于 Cloudflare 质询，避免在质询中执行复杂 JS 卡死
        page_title = ""
        if page is not None:
            try:
                page_title = (page.title() or "").lower()
            except Exception:
                page_title = ""

        is_cf = any(w in page_title for w in (
            "chờ một chút", "just a moment", "moment please", "checking your browser",
            "cloudflare", "しばらくお待ちください", "un momento", "un instant", "bitte warten",
            "подождите", "稍等", "请稍候"
        ))
        if is_cf:
            if not logged_challenge:
                logger.info("%s 检测到 Cloudflare 质询/等待页（%s），等待自动通过或尝试点击...", _log_prefix(driver), page_title)
                logged_challenge = True
                cf_start_time = time.time()

            # 尝试点击 Turnstile 验证复选框
            if manual_wait and time.time() >= next_challenge_log:
                message = f"Waiting for manual browser challenge; window remains open (~{max(0, int(end - time.time()))}s left)"
                logger.info("%s %s", _log_prefix(driver), message)
                if callable(progress):
                    progress(message)
                next_challenge_log = time.time() + 30
            if page is not None and not manual_wait:
                try:
                    for frame in page.frames:
                        if any(k in frame.url.lower() for k in ("cloudflare", "challenge", "turnstile")):
                            box = frame.locator('input[type="checkbox"], .ctp-checkbox-label, #challenge-stage, span.mark').first
                            if box.count() > 0 and box.is_visible(timeout=800):
                                box.click(timeout=2000)
                                logger.info("%s 已尝试点击 Cloudflare 质询复选框", _log_prefix(driver))
                                time.sleep(2.0)
                                break
                except Exception:
                    pass

            # The visible browser may still be waiting for a human challenge.  Do not
            # abort after 35s while the overall input deadline still has time left.
            # Challenge timeout means login is unverified, not that the password is wrong.
            if cf_start_time and time.time() >= end:
                raise RuntimeError("Cloudflare 验证页等待超时；密码尚未验证")

            time.sleep(1.0)
            continue
        elif logged_challenge:
            logger.info("%s Cloudflare 质询已通过，继续寻找邮箱输入框", _log_prefix(driver))
            logged_challenge = False
            cf_start_time = None

        el = _find_visible_email_input_js(driver)
        if el:
            return el
        last_state = _email_entry_state(driver)
        title = str(last_state.get("title") or "").lower()
        if any(w in title for w in (
            "chờ một chút", "just a moment", "moment please", "checking your browser",
            "cloudflare", "しばらくお待ちください", "un momento", "un instant", "bitte warten",
            "подождите", "稍等", "请稍候"
        )):
            if not logged_challenge:
                logger.info("%s 检测到 Cloudflare 质询/等待页（%s），等待自动通过...", _log_prefix(driver), last_state.get("title"))
                logged_challenge = True
                cf_start_time = time.time()
            if manual_wait and time.time() >= next_challenge_log:
                message = f"Waiting for manual browser challenge; window remains open (~{max(0, int(end - time.time()))}s left)"
                logger.info("%s %s", _log_prefix(driver), message)
                if callable(progress):
                    progress(message)
                next_challenge_log = time.time() + 30
            time.sleep(1.0)
            continue
        if logged_challenge and manual_wait and time.time() >= next_challenge_log:
            message = f"Waiting for manual browser challenge; window remains open (~{max(0, int(end - time.time()))}s left)"
            logger.info("%s %s", _log_prefix(driver), message)
            if callable(progress):
                progress(message)
            next_challenge_log = time.time() + 30
        if not clicked_email_option and _click_email_entry_option(driver):
            clicked_email_option = True
            time.sleep(1.0)
            _assert_not_external_idp(driver, "点击邮箱入口后")
            continue
        time.sleep(0.5)
    if logged_challenge:
        raise RuntimeError("Cloudflare 验证页等待超时；密码尚未验证")
    raise RuntimeError(f"邮箱登录入口未就绪或未被识别；尚未提交邮箱，未验证密码，state={last_state}")


def _type_email_address(driver, email: str, timeout: int | None = None) -> None:
    """进入邮箱登录/注册方式并填写邮箱。全程不依赖页面可见文字。"""
    el = _wait_for_email_input(driver, timeout=timeout)
    _human_type_text(driver, el, email, clear=True)


def _submit_nearest_form_for_active_input(driver) -> bool:
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，禁止执行邮箱提交", _log_prefix(driver))
        return False
    result = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[name="identifier"],input[autocomplete*="email"],input[placeholder*="email" i],input[aria-label*="email" i]')]
      .find(visible);
    if (!input) return {ok:false, reason:'missing_email_input'};
    const value = String(input.value || '').trim();
    if (!value || !value.includes('@')) return {ok:false, reason:'email_value_not_ready', value};
    const form = input.closest('form');
    if (!form) return {ok:false, reason:'missing_form'};

    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|sso|saml|idp|provider|authorize|consent|grant|allow/;
    const attrText = el => {
      const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
        el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
        el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
        .filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' '))
        .join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const inputRect = input.getBoundingClientRect();
    const formId = form.getAttribute('id') || '';
    const scopedButtons = [
      ...form.querySelectorAll('button,input[type="submit"]'),
      ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
    ].filter((el, idx, arr) => arr.indexOf(el) === idx);
    const rawButtons = scopedButtons
      .filter(visible)
      .map((el, idx) => {
        const r = el.getBoundingClientRect();
        const attrs = attrText(el);
        const hasLogo = !!el.querySelector('img,svg,use');
        const isBad = bad.test(attrs) || hasLogo;
        const belowInput = r.top >= inputRect.bottom - 10;
        const distance = Math.max(0, r.top - inputRect.bottom) + Math.abs((r.left + r.right) / 2 - (inputRect.left + inputRect.right) / 2) / 10;
        const cls = String(el.className || '').toLowerCase();
        const type = String(el.getAttribute('type') || '').toLowerCase();
        // ChatGPT 新版邮箱页的主按钮形如：
        // <button class="... btn-primary ... w-full ..." type="submit"><div>続行</div></button>
        // 优先选择同 form 下的 primary submit，而不是因为多个按钮距离接近误判歧义。
        const isPrimarySubmit = (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && type === 'submit'
          && (/\bbtn-primary\b/.test(cls) || /\b_primary_/.test(cls) || /\bw-full\b/.test(cls));
        const score = (isPrimarySubmit ? 1000 : 0) + (type === 'submit' ? 100 : 0) - distance;
        return {el, idx, attrs, isBad, hasLogo, belowInput, distance, score, isPrimarySubmit, tag: el.tagName, type};
      });
    const safe = rawButtons.filter(x => !x.isBad && x.belowInput)
      .sort((a,b) => b.score - a.score || a.distance - b.distance || a.idx - b.idx);
    if (!safe.length) {
      return {ok:false, reason:'no_safe_submit', buttons: rawButtons.map(x => ({idx:x.idx, isBad:x.isBad, hasLogo:x.hasLogo, belowInput:x.belowInput, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    // 多个安全按钮时，若没有明确 primary submit，且距离接近，才认为页面歧义。
    if (!safe[0].isPrimarySubmit && safe.length > 1 && Math.abs(safe[0].distance - safe[1].distance) < 8) {
      return {ok:false, reason:'ambiguous_submit', buttons: safe.slice(0,3).map(x => ({idx:x.idx, distance:x.distance, score:x.score, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
    }
    const target = safe[0].el;
    target.scrollIntoView({block:'center'});
    window.__roxy_email_submit_debug = {at: Date.now(), targetAttrs: safe[0].attrs.slice(0,240), buttonCount: rawButtons.length, primary:safe[0].isPrimarySubmit};
    return {ok:true, reason:safe[0].isPrimarySubmit ? 'primary_submit' : 'safe_submit', target, targetAttrs:safe[0].attrs.slice(0,160), primary:safe[0].isPrimarySubmit};
    """) or {}
    if result.get("ok"):
        target = result.get("target")
        if target:
            _human_click(driver, target, label="email_submit")
        else:
            logger.warning("%s 邮箱提交未返回目标元素，回退 requestSubmit", _log_prefix(driver))
            driver.execute_script("document.querySelector('form')?.requestSubmit?.();")
        logger.info("%s 邮箱表单安全提交：%s", _log_prefix(driver), result)
        time.sleep(0.8)
        _assert_not_external_idp(driver, "提交邮箱后")
        return True
    logger.warning("%s 未执行邮箱提交：%s", _log_prefix(driver), result)
    return False


def _current_email_input_value(driver) -> str:
    try:
        state = _email_input_value_state(driver)
        for item in state.get("inputs") or []:
            value = str(item.get("value") or "").strip()
            if "@" in value:
                return value
    except Exception:
        pass
    return ""


def _stabilize_email_input_before_submit(driver, email: str) -> dict:
    """提交前把 DOM value / React 受控状态 / blur-change 状态统一稳定下来。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[name="identifier"],input[autocomplete*="email"],input[placeholder*="email" i],input[aria-label*="email" i]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.scrollIntoView({block:'center', inline:'nearest'});
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;

        // 让 React/表单校验尽量收到完整输入链路。
        try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:email})); } catch (_) {}
        try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();

        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        return {
          ok:true,
          value: input.value,
          active: document.activeElement === input,
          hasForm: !!form,
          hasSubmit: !!submit,
          submitDisabled: submit ? (!!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true') : null,
          url: location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_form_stable(driver, email: str) -> dict:
    """第一次提交就按“补交成功”的方式执行：稳定 value 后 Enter + DOM click。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
        const editable = el => visible(el) && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(editable);
        if (!input) return {ok:false, reason:'missing_email_input'};
        if (!email || !email.includes('@')) return {ok:false, reason:'empty_email', value: email};

        const form = input.closest('form');
        if (!form) return {ok:false, reason:'missing_form'};

        const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
        const attrText = el => {
          const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
            el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
            .filter(Boolean).join(' ');
          const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
            .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
              x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
              .filter(Boolean).join(' '))
            .join(' ');
          return `${own} ${desc}`.toLowerCase();
        };

        const formId = form.getAttribute('id') || '';
        const buttons = [
          ...form.querySelectorAll('button,input[type="submit"]'),
          ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
        ].filter((el, idx, arr) => arr.indexOf(el) === idx)
          .filter(el => visible(el) && !bad.test(attrText(el)) && !el.querySelector('img,svg,use'));
        const submit = buttons.find(el => (el.getAttribute('type') || '').toLowerCase() === 'submit') || buttons[0] || null;
        if (!submit) return {ok:false, reason:'missing_safe_submit'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.scrollIntoView({block:'center', inline:'nearest'});
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        try { input.dispatchEvent(new InputEvent('beforeinput', {bubbles:true, cancelable:true, inputType:'insertText', data:email})); } catch (_) {}
        try { input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email})); } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();

        submit.scrollIntoView({block:'center', inline:'nearest'});

        // 不要在 execute_script 同步执行 submit.click()：
        // ChromeDriver 会等前端 submit/navigation，Roxy/Chrome 150 上可能卡到 page/script timeout。
        // setTimeout 让 Selenium 先返回，点击在页面事件循环里异步发生，和补交逻辑一致。
        setTimeout(() => {
          try {
            input.focus();
            input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keypress', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            if (submit && !submit.disabled) submit.click();
            else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);

        window.__roxy_email_submit_debug = {
          at: Date.now(),
          mode: 'stable_async_enter_click',
          value: input.value,
          submitAttrs: attrText(submit).slice(0, 240)
        };
        return {
          ok:true,
          reason:'stable_async_enter_click',
          value: input.value,
          submitDisabled: !!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          submitAttrs: attrText(submit).slice(0, 180),
          url: location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_step(driver, email: str | None = None) -> None:
    # 邮箱提交前再次清理可能异步弹出的 Cookie / 同意浮层
    _maybe_accept(driver)
    # 不再优先走浏览器内 NextAuth fetch：
    # Roxy/Chrome 150 下 execute_async_script + fetch 偶发卡到 script timeout；
    # 实测 UI 首次提交后若停在 /auth/login?email=...，由 _recover_email_submit_if_stuck 补交表单更稳定。
    email_value = str(email or _current_email_input_value(driver) or "").strip()
    stable = _stabilize_email_input_before_submit(driver, email_value)
    logger.info("%s 邮箱提交前状态稳定：%s", _log_prefix(driver), stable)
    time.sleep(random.uniform(0.8, 1.8) if _browser_actions_enabled() else 0.4)

    native_submit = getattr(driver, "submit_email_native", None)
    if callable(native_submit):
        result = native_submit(email_value)
        logger.info("%s 邮箱原生表单提交：%s", _log_prefix(driver), result)
        if not result.get("ok"):
            reason = str(result.get("reason") or "email_submit_not_confirmed")
            if reason == "navigation_error":
                raise RuntimeError(f"[navigation_error] 邮箱提交触发浏览器导航失败: {result}")
            raise RuntimeError(f"邮箱提交未确认页面迁移: {result}")
        time.sleep(1.0)
        _assert_not_external_idp(driver, "原生表单提交邮箱后")
        return

    stable_submit = _submit_email_form_stable(driver, email_value)
    if stable_submit.get("ok"):
        logger.info("%s 邮箱稳定表单提交：%s", _log_prefix(driver), stable_submit)
        time.sleep(1.0)
        _assert_not_external_idp(driver, "稳定表单提交邮箱后")
        return
    logger.warning("%s 邮箱稳定表单提交失败，回退 UI 点击提交：%s", _log_prefix(driver), stable_submit)
    if _submit_nearest_form_for_active_input(driver):
        return
    raise RuntimeError(f"无法提交邮箱步骤（拒绝按页面文字或首个 submit 兜底，避免误点第三方登录），state={_email_entry_state(driver)}")


def _recover_email_submit_if_stuck(driver, email: str) -> dict:
    """邮箱提交后停在 /auth/login?email= 且输入框被清空时，补一次原生表单提交。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[name="identifier"],input[autocomplete*="email"],input[placeholder*="email" i],input[aria-label*="email" i]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        input.dispatchEvent(new InputEvent('input', {bubbles:true, inputType:'insertText', data:email}));
        input.dispatchEvent(new Event('change', {bubbles:true}));
        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        setTimeout(() => {
          try {
            input.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            input.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, cancelable:true, key:'Enter', code:'Enter'}));
            if (submit && !submit.disabled) submit.click();
            else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);
        return {ok:true, reason:'resubmitted_email_form', value: input.value, hasForm: !!form, hasSubmit: !!submit};
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _is_invalid_authorize_page(driver) -> bool:
    """检测是否进入了 OpenAI 授权失败页（Invalid authorize request 错误 JSON 或报错页面）。"""
    try:
        curr = str(getattr(driver, "current_url", "") or "").lower()
        if "authorize" in curr or "api/accounts" in curr or "invalid_request" in curr:
            body_text = str(driver.execute_script("return document.body ? (document.body.innerText || document.body.textContent || '') : '';") or "").lower()
            if "invalid authorize request" in body_text or "invalid_request" in body_text or "error" in body_text and "message" in body_text:
                return True
    except Exception:
        pass
    return False


def _submit_email_via_browser_nextauth(driver, email: str) -> dict:
    """在 Roxy 浏览器上下文里调用 ChatGPT NextAuth signin。

    UI submit 在 Roxy/Chrome 150 上会偶发只跳到 `/auth/login?email=...` 后停住。
    这里改走浏览器页面内 fetch，仍使用当前 Roxy 浏览器的 cookie / 指纹环境，
    拿到 auth.openai.com authorize URL 后让浏览器内部 SPA 跳转（绝不能用 driver.get 硬导航，
    否则会丢失 Referer 和会话状态导致 OpenAI 报错 Invalid authorize request）。
    """
    try:
        current = str(getattr(driver, "current_url", "") or "")
        if "chatgpt.com" not in current:
            return {"ok": False, "reason": "not_on_chatgpt", "url": current[:180]}
    except Exception:
        current = ""

    did = str(uuid.uuid4())
    auth_log_id = str(uuid.uuid4())
    old_script_timeout = int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)
    try:
        try:
            driver.set_script_timeout(25)
        except Exception:
            pass
        result = driver.execute_async_script(r"""
        const email = String(arguments[0] || '').trim();
        const did = String(arguments[1] || '');
        const authLogId = String(arguments[2] || '');
        const done = arguments[arguments.length - 1];
        (async () => {
          try {
            const csrfResp = await fetch('/api/auth/csrf', {
              method: 'GET',
              credentials: 'include',
              headers: {
                'accept': 'application/json',
                'cache-control': 'no-cache',
                'pragma': 'no-cache'
              }
            });
            const csrfText = await csrfResp.text();
            let csrfData = {};
            try { csrfData = JSON.parse(csrfText); } catch (_) {}
            const csrfToken = csrfData.csrfToken || '';
            if (!csrfResp.ok || !csrfToken) {
              done({ok:false, stage:'csrf', status:csrfResp.status, body:csrfText.slice(0, 500)});
              return;
            }

            const q = new URLSearchParams({
              prompt: 'login',
              'ext-oai-did': did,
              auth_session_logging_id: authLogId,
              'ext-passkey-client-capabilities': '11111',
              screen_hint: 'login_or_signup',
              login_hint: email
            });
            const body = new URLSearchParams({
              callbackUrl: 'https://chatgpt.com/',
              csrfToken,
              json: 'true'
            });
            const resp = await fetch('/api/auth/signin/openai?' + q.toString(), {
              method: 'POST',
              credentials: 'include',
              headers: {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'cache-control': 'no-cache',
                'pragma': 'no-cache'
              },
              body: body.toString()
            });
            const text = await resp.text();
            let data = {};
            try { data = JSON.parse(text); } catch (_) {}
            let url = data.url || '';
            if (!resp.ok || !url) {
              done({ok:false, stage:'signin', status:resp.status, body:text.slice(0, 700)});
              return;
            }

            try {
              const u = new URL(url, location.href);
              if (!u.searchParams.get('screen_hint')) u.searchParams.set('screen_hint', 'login_or_signup');
              if (!u.searchParams.get('login_hint')) u.searchParams.set('login_hint', email);
              if (!u.searchParams.get('ext-oai-did')) u.searchParams.set('ext-oai-did', did);
              if (!u.searchParams.get('auth_session_logging_id')) u.searchParams.set('auth_session_logging_id', authLogId);
              url = u.toString();
            } catch (_) {}
            setTimeout(() => {
              try { window.location.assign(url); } catch (_) { location.href = url; }
            }, 100);
            done({ok:true, stage:'redirect', url:url.slice(0, 260)});
          } catch (e) {
            done({ok:false, stage:'exception', error:String(e && (e.stack || e.message) || e).slice(0, 700)});
          }
        })();
        """, email, did, auth_log_id) or {}
        return result if isinstance(result, dict) else {"ok": False, "reason": "invalid_result", "result": str(result)[:300]}
    except Exception as exc:
        msg = str(exc)
        # 如果是因为页面发生跳转导致执行上下文被销毁，说明已成功触发重定向
        if "Execution context was destroyed" in msg or "navigation" in msg.lower():
            logger.info("%s NextAuth 提交时页面已开始跳转：%s", _log_prefix(driver), msg[:160])
            return {"ok": True, "reason": "navigation_started"}
        # 如果是 script timeout，尝试检查页面是否已经开始跳转到 auth.openai.com
        try:
            curr = str(getattr(driver, "current_url", "") or "")
            if "auth.openai.com" in curr:
                logger.info("%s NextAuth 虽超时但页面已成功跳转到 auth.openai.com: %s", _log_prefix(driver), curr[:150])
                return {"ok": True, "reason": "navigated_to_auth"}
        except Exception:
            pass
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            driver.set_script_timeout(old_script_timeout)
        except Exception:
            pass


def _email_input_value_state(driver) -> dict:
    """读取当前可见邮箱框状态，用于提交后确认是否真的进入下一步。"""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[name="identifier"],input[autocomplete*="email"],input[placeholder*="email" i],input[aria-label*="email" i]')]
          .filter(visible)
          .map(el => ({type: el.getAttribute('type') || '', name: el.name || '', id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''}));
        return {url: location.href, inputs};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_login_page_still_present(driver) -> bool:
    state = _email_input_value_state(driver)
    return bool(state.get("inputs"))


def _wait_email_submit_next_state(driver, email: str, timeout: int = 18) -> str:
    """邮箱提交后等待进入 password / otp / logged_in；仍停留邮箱页则返回 email_page。

    Cloak/Playwright 路径里，点击 submit 后页面经常先发生一次 SPA 导航：
    `chatgpt.com/auth/login?email=...`，同时 React 会短暂把 email input 清空。
    旧逻辑一看到空 input 就立刻返回 `email_cleared`，导致在真正跳到
    `auth.openai.com/...` 前过早重填，形成“提交 -> 清空 -> 重填”的循环。
    这里对 email_cleared 做去抖：只记录并继续观察几秒；若期间进入
    password/otp/login_password/logged_in 则按真实状态返回，持续清空才让上层重试。
    """
    end = time.time() + timeout
    last = None
    cleared_seen_at: float | None = None
    cleared_last_log_at = 0.0
    cleared_recover_done = False
    empty_login_seen_at: float | None = None
    expected_email = str(email or "").strip().lower()
    start_time = time.time()
    max_hard_deadline = start_time + 40.0
    # Used by both the input-present and input-absent branches.  Previously it
    # was assigned only after _email_input_value_state() returned inputs, so a
    # login?email page with no visible input raised UnboundLocalError.
    debounce = 4.0
    while time.time() < min(end, max_hard_deadline):
        native_state_reader = getattr(driver, "email_submit_state_native", None)
        if callable(native_state_reader):
            native = native_state_reader(expected_email)
            native_state = str(native.get("state") or "unknown")
            last = native
            if native_state in ("otp", "password", "login_password", "logged_in"):
                return native_state
            if native_state == "navigation_error":
                raise RuntimeError(f"[navigation_error] 邮箱提交后浏览器导航失败: {native}")
            inputs = native.get("inputs") or []
            url = str(native.get("url") or "")
            if native_state == "email_cleared":
                now = time.time()
                if cleared_seen_at is None:
                    cleared_seen_at = now
                if now - cleared_seen_at >= (3.0 if "email=" in url else 4.0):
                    return "email_cleared"
            else:
                cleared_seen_at = None
            time.sleep(0.8)
            continue

        if _has_access_token(driver):
            return "logged_in"
        if _is_login_password_page(driver):
            return "login_password"
        if _is_email_verification_page(driver):
            return "otp"
        if _is_signup_password_page(driver):
            return "password"

        if _is_invalid_authorize_page(driver):
            logger.warning("%s 页面检测到 Invalid authorize request，重新打开 /auth/login 恢复流程", _log_prefix(driver))
            try:
                driver.get("https://chatgpt.com/auth/login")
                time.sleep(1.5)
            except Exception:
                pass
            return "email_cleared"

        current_url = str(getattr(driver, "current_url", "") or "")
        if "auth.openai.com" in current_url:
            if _is_email_verification_page(driver):
                return "otp"
            if _is_login_password_page(driver):
                return "login_password"
            if _is_signup_password_page(driver):
                return "password"
            if "authorize" in current_url or "oauth" in current_url or "/api/accounts" in current_url:
                if end - time.time() < 10 and time.time() + 15 <= max_hard_deadline:
                    end = time.time() + 15
                    logger.info("%s 正在跳转 auth.openai.com 授权页，延长等待：url=%s", _log_prefix(driver), current_url[:150])

        state = _email_input_value_state(driver)
        last = state
        inputs = state.get("inputs") or []
        url = str(state.get("url") or "")
        debounce = 3.0 if ("/auth/login" in url and "email=" in url) else 4.0
        lower_url = url.strip().lower()
        state_error = str(state.get("error") or "").lower()
        if (not lower_url or lower_url == "about:blank" or lower_url.startswith("chrome-error://")
                or "target page, context or browser has been closed" in state_error
                or "browser has been closed" in state_error):
            raise RuntimeError(f"[navigation_error] 邮箱提交后浏览器导航失败: {state}")
        if inputs:
            empty_login_seen_at = None
            values = [str(i.get("value") or "") for i in inputs]
            has_blank = any(v == "" for v in values)
            has_expected = any(v.strip().lower() == expected_email for v in values)
            if has_blank and not has_expected:
                now = time.time()
                if cleared_seen_at is None:
                    cleared_seen_at = now
                if now - cleared_last_log_at > 1.0:
                    logger.info(
                        "%s 邮箱提交后检测到输入框清空，准备流转：elapsed=%.1fs debounce=%.1fs url=%s",
                        _log_prefix(driver), now - cleared_seen_at, debounce, url[:180],
                    )
                    cleared_last_log_at = now
                if (
                    not cleared_recover_done
                    and "/auth/login" in url
                    and "email=" in url
                    and now - cleared_seen_at >= 1.5
                ):
                    cleared_recover_done = True
                    rec = _recover_email_submit_if_stuck(driver, email)
                    logger.info("%s 邮箱提交后停留在 login?email，补交原生表单：%s，继续等待跳转", _log_prefix(driver), rec)
                    # 重置清空计时器，给补交的表单足够时间完成向 auth.openai.com 的跳转，避免立即判定失败重填
                    cleared_seen_at = now
                    time.sleep(1.0)
                    continue
                if now - cleared_seen_at >= debounce:
                    return "email_cleared"
            else:
                cleared_seen_at = None
            # 仍是当前邮箱页，继续短等。
        else:
            url = str(state.get("url") or "")
            if "/auth/login" in url and "email=" in url:
                now = time.time()
                if empty_login_seen_at is None:
                    empty_login_seen_at = now
                if not cleared_recover_done and now - empty_login_seen_at >= 2.5:
                    cleared_recover_done = True
                    logger.info(
                        "%s 邮箱提交后停在无输入框 login?email，补交原生表单：url=%s",
                        _log_prefix(driver), url[:180],
                    )
                    rec = _recover_email_submit_if_stuck(driver, email)
                    logger.info("%s login?email 补交结果：%s，继续等待跳转", _log_prefix(driver), rec)
                    empty_login_seen_at = now
                    time.sleep(1.0)
                    continue
                if now - empty_login_seen_at >= (debounce + 2.0):
                    return "email_cleared"
            else:
                empty_login_seen_at = None
        time.sleep(0.8)
    logger.info("%s 邮箱提交后等待下一步超时，最后邮箱页状态=%s", _log_prefix(driver), last)
    current_url = str(getattr(driver, "current_url", "") or "")
    if "auth.openai.com" in current_url:
        if _is_invalid_authorize_page(driver):
            logger.warning("%s 超时检测到 Invalid authorize request，重新打开登录页", _log_prefix(driver))
            try:
                driver.get("https://chatgpt.com/auth/login")
                time.sleep(1.5)
            except Exception:
                pass
            return "email_cleared"
        if _is_email_verification_page(driver):
            return "otp"
        if _is_signup_password_page(driver):
            return "password"
        if _is_login_password_page(driver):
            return "login_password"
        if "authorize" in current_url or "/api/accounts" in current_url:
            # 已到 OpenAI 授权端点说明邮箱提交成功。住宅代理上该文档和挑战资源
            # 经常需要 20 秒以上才渲染；此时重载 ChatGPT 登录页会重复下载整套 SPA。
            auth_end = time.time() + 45.0
            while time.time() < auth_end:
                time.sleep(1.0)
                if _is_invalid_authorize_page(driver):
                    logger.warning("%s 等待中检测到 Invalid authorize request，重新打开登录页", _log_prefix(driver))
                    try:
                        driver.get("https://chatgpt.com/auth/login")
                        time.sleep(1.5)
                    except Exception:
                        pass
                    return "email_cleared"
                if _is_email_verification_page(driver):
                    return "otp"
                if _is_signup_password_page(driver):
                    return "password"
                if _is_login_password_page(driver):
                    return "login_password"
            return "unknown"
    return "email_page" if _is_email_login_page_still_present(driver) else "unknown"


def _submit_email_and_wait_next(
    driver,
    email: str | None,
    attempts: int = 3,
    email_supplier: Callable[[], str] | None = None,
    allow_login_password: bool = False,
) -> str:
    """填写并提交邮箱，必须确认进入 password/otp/logged_in 才返回。"""
    last_state = None
    current_email = str(email or "").strip()
    configured_attempts = int(getattr(driver, "_email_submit_attempts", attempts) or attempts)
    attempts = max(1, min(int(attempts), configured_attempts))
    input_wait_timeout = max(10, min(45, int(getattr(driver, "_email_input_wait_timeout", 45) or 45)))
    for attempt in range(1, attempts + 1):
        # 优先检查页面是否已经自行流转到下一步（例如上一轮提交后慢代理延迟跳转）
        if _is_email_verification_page(driver):
            logger.info("%s 页面已进入邮箱验证码页，直接继续下一步", _log_prefix(driver))
            return "otp"
        if _is_signup_password_page(driver):
            logger.info("%s 页面已进入设置密码页，直接继续下一步", _log_prefix(driver))
            return "password"
        if _is_login_password_page(driver):
            if allow_login_password:
                logger.info("%s 页面已进入登录密码页（允许登录流程）：login_password", _log_prefix(driver))
                return "login_password"
            raise RuntimeError(f"邮箱提交后进入登录密码页，按已注册/不可用邮箱处理并停用: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
        if _has_access_token(driver):
            return "logged_in"

        if current_email:
            try:
                _type_email_address(driver, current_email, timeout=input_wait_timeout)
            except _LoginPasswordPageReached:
                if allow_login_password:
                    return "login_password"
                raise
        else:
            # 先确认页面已有可用输入框，再领取邮箱；不能把领取动作放在页面导航之前。
            email_input = _wait_for_email_input(driver, timeout=input_wait_timeout)
            if email_supplier is None:
                raise RuntimeError("已找到邮箱输入框，但未提供邮箱分配器")
            current_email = str(email_supplier() or "").strip()
            if not current_email:
                raise RuntimeError("邮箱分配器返回了空邮箱地址")
            _human_type_text(driver, email_input, current_email, clear=True)
        state = _email_input_value_state(driver)
        last_state = state
        values = [str(i.get("value") or "") for i in (state.get("inputs") or [])]
        if not any(v.strip().lower() == current_email.lower() for v in values):
            logger.warning("%s 邮箱写入校验失败，准备重试：attempt=%s/%s state=%s", _log_prefix(driver), attempt, attempts, state)
            time.sleep(0.8)
            continue
        logger.info("%s 已填写邮箱并校验通过：%s", _log_prefix(driver), current_email)
        human_delay("form")
        _submit_email_step(driver, current_email)
        logger.info("%s 已提交邮箱，等待进入密码页或验证码页（%s/%s）", _log_prefix(driver), attempt, attempts)
        state_name = _wait_email_submit_next_state(driver, current_email, timeout=20)
        if state_name == "login_password":
            if allow_login_password:
                logger.info("%s 邮箱提交后进入登录密码页（允许登录流程）：%s", _log_prefix(driver), state_name)
                return state_name
            raise RuntimeError(f"邮箱提交后进入登录密码页，按已注册/不可用邮箱处理并停用: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
        if state_name in ("password", "otp", "logged_in"):
            logger.info("%s 邮箱提交后已进入下一步：%s", _log_prefix(driver), state_name)
            return state_name
        logger.warning("%s 邮箱提交后仍未进入下一步：%s，准备重填重试 state=%s", _log_prefix(driver), state_name, _email_input_value_state(driver))
        current_url = str(getattr(driver, "current_url", "") or "")
        recoverable_unknown = state_name == "unknown" and "/auth/login" in current_url and "email=" in current_url
        if state_name in ("email_cleared", "email_page") or recoverable_unknown:
            nextauth = _submit_email_via_browser_nextauth(driver, current_email)
            logger.info("%s UI 提交停留在邮箱页，NextAuth 补交结果：%s", _log_prefix(driver), nextauth)
            # 如果补交时或补交后页面正在发生跳转（如 execution context destroyed），给其一定时间完成跳转
            recovered_state = _wait_email_submit_next_state(driver, current_email, timeout=20)
            if recovered_state in ("password", "otp", "logged_in"):
                logger.info("%s 邮箱流转后已进入下一步：%s", _log_prefix(driver), recovered_state)
                return recovered_state
        if attempt < attempts:
            # login?email 页面偶尔会留下空 DOM。继续在该上下文执行 evaluate 可能让
            # Playwright 长时间等待浏览器响应；重新导航会创建新的文档上下文。
            logger.info("%s 当前登录页未渲染输入框，重新加载登录页后重试", _log_prefix(driver))
            _safe_get(
                driver,
                "https://chatgpt.com/auth/login",
                timeout=35,
                attempts=1,
                accept_hosts=("chatgpt.com", "auth.openai.com"),
            )
            _maybe_accept(driver)
        time.sleep(1.0)
    raise RuntimeError(f"email_submit_stalled: 邮箱提交后未进入密码页或邮箱验证码页，最后状态={last_state}")


def _type_otp(driver, code: str, timeout: int = 20) -> None:
    code = str(code or "").strip()
    if not code:
        raise ValueError("OTP 验证码不能为空")

    _check_and_solve_cloudflare(driver, timeout=10.0)

    end = time.time() + max(5, timeout)
    last_reason = ""
    while time.time() < end:
        current_url = str(getattr(driver, "current_url", "") or "").strip()
        lower_url = current_url.lower()
        if not lower_url or lower_url == "about:blank" or lower_url.startswith("chrome-error://"):
            raise RuntimeError(f"[navigation_error] OTP 页面浏览器导航失败: url={current_url or '<empty>'}")
        _check_and_solve_cloudflare(driver, timeout=3.0)
        # 1. 优先使用 Playwright 原生动作填入，确保 React 状态同步
        if hasattr(driver, "page") and getattr(driver, "page", None) is not None:
            try:
                page = driver.page
                # 检查单输入框
                single_loc = page.locator(
                    'input[autocomplete="one-time-code"], input[name="code"], input[name="otp"], '
                    'input[inputmode="numeric"]:not([maxlength="1"]), input[aria-label*="code" i], '
                    'input[placeholder*="code" i], input[type="tel"]:not([maxlength="1"])'
                ).first
                if single_loc.count() and single_loc.is_visible(timeout=800):
                    single_loc.focus()
                    time.sleep(random.uniform(0.12, 0.28))
                    try:
                        single_loc.press_sequentially(code, delay=random.randint(80, 180))
                    except Exception:
                        single_loc.fill(code, timeout=3000)
                    # 提交优先点击原生验证按钮；若无显式按钮才按 Enter，切勿同时回车又点击导致并发重复提交引发 400 Route Error
                    submitted = False
                    try:
                        submit_btn = page.locator('button[value="validate"], button[type="submit"]:not([value="resend"])').first
                        if submit_btn.count() and submit_btn.is_visible(timeout=800):
                            time.sleep(random.uniform(0.18, 0.45))
                            submit_btn.click(timeout=3000)
                            submitted = True
                    except Exception:
                        pass
                    if not submitted:
                        try:
                            page.keyboard.press("Enter")
                        except Exception:
                            pass
                    logger.info("[OTP] 已通过 Playwright 人性化按键填入验证码: %s", code)
                    return

                # 检查 6 格分格输入框
                box_loc = page.locator(
                    'input[maxlength="1"], input[data-index], input[aria-label*="digit" i], '
                    'input[aria-label*="character" i], input[name*="code" i][maxlength="1"]'
                )
                b_count = box_loc.count()
                if b_count >= len(code):
                    for idx, ch in enumerate(code):
                        box = box_loc.nth(idx)
                        box.focus()
                        time.sleep(random.uniform(0.08, 0.18))
                        try:
                            box.press_sequentially(ch, delay=random.randint(60, 140))
                        except Exception:
                            box.fill(ch, timeout=1000)
                    submitted = False
                    try:
                        submit_btn = page.locator('button[value="validate"], button[type="submit"]:not([value="resend"])').first
                        if submit_btn.count() and submit_btn.is_visible(timeout=800):
                            time.sleep(random.uniform(0.25, 0.55))
                            submit_btn.click(timeout=3000)
                            submitted = True
                    except Exception:
                        pass
                    if not submitted:
                        try:
                            page.keyboard.press("Enter")
                        except Exception:
                            pass
                    logger.info("[OTP] 已通过 Playwright 原生分格输入验证码: %s (boxes=%s)", code, b_count)
                    return
            except Exception as p_exc:
                last_reason = f"playwright_err: {p_exc}"
                logger.debug("[OTP] Playwright 原生填入重试中: %s", p_exc)

        # 2. 页面内 JS 极速执行填入
        try:
            fast_res = driver.execute_script(r"""
            const code = String(arguments[0] || '').trim();
            if (!code) return {ok: false, reason: 'empty_code'};
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
              && !el.disabled && !el.readOnly;
            const inputs = [...document.querySelectorAll('input')].filter(visible);

            const setVal = (el, val) => {
              const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
              if (setter) setter.call(el, val); else el.value = val;
              el.dispatchEvent(new InputEvent('input', {bubbles: true, data: val}));
              el.dispatchEvent(new Event('change', {bubbles: true}));
            };

            // 1. 尝试单输入框
            const single = inputs.find(el => {
              const attrs = `${el.name} ${el.id} ${el.autocomplete} ${el.inputMode} ${el.getAttribute('aria-label') || ''} ${el.placeholder || ''}`.toLowerCase();
              return (attrs.includes('one-time-code') || attrs.includes('code') || attrs.includes('otp')) && el.maxLength !== 1;
            });
            if (single) {
              single.focus();
              setVal(single, code);
              try {
                single.dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, key:'Enter', code:'Enter'}));
                single.dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, key:'Enter', code:'Enter'}));
              } catch (_) {}
              try {
                const btn = document.querySelector('button[value="validate"], button[type="submit"]:not([value="resend"])');
                if (btn) {
                  btn.click();
                } else if (single.form) {
                  single.form.requestSubmit ? single.form.requestSubmit() : single.form.submit();
                }
              } catch (_) {}
              return {ok: true, mode: 'single'};
            }

            // 2. 尝试分格输入框（如 6 位分开的 input）
            const codeInputs = inputs.filter(el => {
              const attrs = `${el.name} ${el.id} ${el.autocomplete} ${el.inputMode} ${el.getAttribute('aria-label') || ''} ${el.type}`.toLowerCase();
              return attrs.includes('numeric') || attrs.includes('one-time') || attrs.includes('code') || attrs.includes('otp') || attrs.includes('digit') || el.maxLength === 1;
            });
            if (codeInputs.length >= code.length) {
              for (let i = 0; i < code.length; i++) {
                codeInputs[i].focus();
                setVal(codeInputs[i], code[i]);
              }
              try {
                codeInputs[codeInputs.length - 1].dispatchEvent(new KeyboardEvent('keydown', {bubbles:true, key:'Enter', code:'Enter'}));
                codeInputs[codeInputs.length - 1].dispatchEvent(new KeyboardEvent('keyup', {bubbles:true, key:'Enter', code:'Enter'}));
              } catch (_) {}
              try {
                const btn = document.querySelector('button[value="validate"], button[type="submit"]:not([value="resend"])');
                if (btn) {
                  btn.click();
                } else if (codeInputs[0].form) {
                  codeInputs[0].form.requestSubmit ? codeInputs[0].form.requestSubmit() : codeInputs[0].form.submit();
                }
              } catch (_) {}
              return {ok: true, mode: 'multi', count: codeInputs.length};
            }
            return {ok: false, inputsCount: inputs.length};
            """, code)
            if isinstance(fast_res, dict) and fast_res.get("ok"):
                logger.info("[OTP] 已通过页面脚本快速填入验证码: mode=%s", fast_res.get("mode"))
                return
            last_reason = f"fast_res: {fast_res}"
        except Exception as exc:
            last_reason = f"script_err: {exc}"
            logger.debug("[OTP] 脚本快速填入跳过: %s", exc)

        time.sleep(1.0)

    # 3. 超时前最后尝试 Selenium 查找
    from selenium.webdriver.common.by import By
    try:
        for selector in [
            "input[autocomplete='one-time-code']",
            "input[name='code']",
            "input[name='otp']",
            "input[inputmode='numeric']",
            "input[type='tel']",
        ]:
            els = [e for e in driver.find_elements(By.CSS_SELECTOR, selector) if _visible(e)]
            if len(els) == 1:
                _human_type_text(driver, els[0], code, clear=True)
                return
    except Exception:
        pass

    page_state = _email_otp_page_state(driver)
    current_url = str(getattr(driver, "current_url", "") or "")
    logger.error("[OTP] 找不到 OTP 输入框: url=%s, last_reason=%s, state=%s", current_url, last_reason, page_state)
    raise RuntimeError(f"找不到 OTP 输入框: url={current_url}")


def _email_otp_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', inputmode: el.getAttribute('inputmode') || '',
          ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const buttons = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', value: el.getAttribute('value') || '',
          action: el.getAttribute('data-dd-action-name') || '', aria: el.getAttribute('aria-label') || '',
          disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120)
        }));
        const errors = [...document.querySelectorAll('.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[aria-invalid="true"] + *,[class*="error"]')]
          .filter(visible).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean);
        return {url: location.href, title: document.title, inputs, buttons, errors, text: (document.body?.innerText || '').slice(0, 1200)};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, 'current_url', ''), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_verification_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return False
    if 'email-verification' in url:
        return True
    state = _email_otp_page_state(driver)
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete','inputmode')) for i in (state.get('inputs') or [])).lower()
    return 'one-time-code' in attrs or 'otp' in attrs or 'code' in attrs


def _clear_otp_inputs(driver) -> None:
    try:
        driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).filter(el => {
          const attrs = [el.type, el.name, el.id, el.autocomplete, el.inputMode, el.getAttribute('aria-label')].join(' ').toLowerCase();
          return /one-time|otp|code|numeric|tel/.test(attrs);
        });
        for (const el of inputs) {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(el, ''); else el.value = '';
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """)
    except Exception:
        pass


def _click_resend_email_otp(driver, timeout: int = 20) -> dict:
    """点击重新发送邮箱验证码。优先按 DOM 属性识别，文本仅兜底。"""
    _check_and_solve_cloudflare(driver, timeout=10.0)
    # 如果是 AntBrowserSeleniumDriver (Playwright)，直接使用原生 locator 进行点击
    page = getattr(driver, "page", None)
    if page is not None:
        try:
            resend_loc = page.locator(
                'button[value="resend"], button[name="intent"][value="resend"], '
                'button:has-text("resend"), button:has-text("重新发送"), '
                'button:has-text("再送信"), button:has-text("Gửi lại")'
            ).first
            if resend_loc.count() and resend_loc.is_visible(timeout=2000):
                text = (resend_loc.inner_text() or "resend").strip()
                resend_loc.click(timeout=5000)
                logger.info("%s[OTP] 已通过原生 locator 点击重新发送验证码按钮：%s", _log_prefix(driver), text)
                time.sleep(1.5)
                return {"ok": True, "text": text}
        except Exception as exc:
            message = str(exc).lower()
            if "execution context was destroyed" in message or "navigation" in message:
                logger.info("%s[OTP] 重发点击已触发页面跳转，继续等待新验证码", _log_prefix(driver))
                return {"ok": True, "text": "resend", "reason": "navigation_after_click"}
            logger.debug("%s[OTP] 原生 locator 查找重发按钮未命中，回退 JS：%s", _log_prefix(driver), exc)

    end = time.time() + timeout
    last = None
    while time.time() < end:
        _check_and_solve_cloudflare(driver, timeout=3.0)
        try:
            # 直接在 JS 内部执行 click，避免将 DOM ElementHandle 传回 Python 后因 handle 无效导致卡死
            clicked = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')].filter(visible);
            const attrHit = candidates.find(el => {
              if (!enabled(el)) return false;
              const attrs = [el.id, el.getAttribute('name'), el.getAttribute('value'), el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .join(' ').toLowerCase();
              const name = String(el.getAttribute('name') || '').toLowerCase();
              const value = String(el.getAttribute('value') || '').toLowerCase();
              if (name === 'intent' && value === 'resend') return true;
              return /resend|send.*new|new.*code|again/.test(attrs);
            });
            const target = attrHit || candidates.find(el => enabled(el) && /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重新发送电子邮件|重发|再次发送|再送信|新しい|届かない|gửi\s*lại/.test((el.innerText || el.textContent || '').toLowerCase()));
            if (target) {
              const text = (target.innerText || target.value || target.getAttribute('data-dd-action-name') || '').trim();
              target.scrollIntoView({block: 'center'});
              target.dispatchEvent(new PointerEvent('pointerdown', {bubbles:true, cancelable:true, pointerType:'mouse'}));
              target.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
              target.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
              target.click();
              return {ok: true, text: text || 'resend'};
            }
            return null;
            """)
            if isinstance(clicked, dict) and clicked.get("ok"):
                text = clicked.get("text") or "-"
                logger.info("%s[OTP] 已点击重新发送验证码按钮：%s", _log_prefix(driver), text)
                time.sleep(random.uniform(1.1, 2.4) if _browser_actions_enabled() else 1.5)
                return {"ok": True, "text": text}
        except Exception as exc:
            last = exc
        time.sleep(0.5)
    logger.warning("%s[OTP] 重新发送验证码按钮未找到或未就绪，继续等待验证码流转", _log_prefix(driver))
    return {"ok": False, "reason": "resend_button_not_found"}


def _recover_email_otp_http_500(driver, email: str) -> bool:
    """Rebuild the auth document after Chromium lands on auth.openai.com HTTP 500."""
    state = _email_otp_page_state(driver)
    current_url = str(getattr(driver, "current_url", "") or "").lower()
    text = " ".join((
        str(state.get("title") or ""),
        str(state.get("text") or ""),
        " ".join(str(item) for item in (state.get("errors") or [])),
    )).lower()
    is_http_500 = "http error 500" in text or (
        current_url.startswith("chrome-error://") and "500" in text
    )
    if not is_http_500:
        return False

    logger.warning("%s[OTP] 重发后 auth.openai.com 返回 HTTP 500，重建同一邮箱的认证会话", _log_prefix(driver))
    _safe_get(
        driver,
        "https://chatgpt.com/auth/login",
        timeout=35,
        attempts=2,
        accept_hosts=("chatgpt.com", "auth.openai.com"),
    )
    _maybe_accept(driver)
    next_state = _submit_email_and_wait_next(driver, email, attempts=2)
    if next_state not in ("password", "otp"):
        raise RuntimeError(f"HTTP 500 后重建认证会话未进入密码/验证码页: state={next_state}")
    _fill_password_page_if_present(driver, email, timeout=20)
    if not _is_email_verification_page(driver):
        raise RuntimeError(f"HTTP 500 后重建认证会话未进入验证码页: url={getattr(driver, 'current_url', '')}")
    logger.info("%s[OTP] HTTP 500 后已重建验证码页，等待新验证码", _log_prefix(driver))
    return True


def _wait_after_email_otp_submit(driver, timeout: int = 30) -> str:
    """提交 OTP 后等待页面离开验证码页。

    返回:
      - 'accepted': 页面已离开邮箱验证码页（成功流转到资料页或登录态）
      - 'invalid': 页面有明确错误标记（aria-invalid、错误提示文案等）
      - 'pending': 超时后页面仍停留在验证码页（未跳转，可触发显式提交按钮重试）
    """
    _check_and_solve_cloudflare(driver, timeout=6.0)
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        time.sleep(0.5)
        _check_and_solve_cloudflare(driver, timeout=2.0)
        if not _is_email_verification_page(driver):
            return 'accepted'
        last = _email_otp_page_state(driver)
        # 检查是否遭遇 OpenAI Remix 页面异常（Route Error / 400 Invalid content type）
        body_text = str(last.get('text') or '').lower()
        if any(err_kw in body_text for err_kw in ('route error', 'invalid content type', 'đã xảy ra lỗi', 'something went wrong', 'an unknown error occurred')):
            page = getattr(driver, "page", None)
            if page is not None:
                try:
                    retry_btn = page.locator(
                        'button:has-text("Try again"), button:has-text("Thử lại"), '
                        'button:has-text("再試行"), button:has-text("重试"), button[action="Try again"]'
                    ).first
                    if retry_btn.count() and retry_btn.is_visible(timeout=500):
                        retry_btn.click(timeout=2000)
                        logger.info("%s[OTP] 检测到 Remix 路由错误，已点击“重试”按钮", _log_prefix(driver))
                        time.sleep(2.0)
                except Exception:
                    pass

        invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or []))
        if invalid or (last.get('errors') or []):
            return 'invalid'
    if _is_email_verification_page(driver):
        has_error_mark = bool(last.get('errors')) or any(
            str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or [])
        )
        if has_error_mark:
            logger.warning("%s[OTP] 提交后仍停留验证码页且存在错误标记，按验证码无效处理 snapshot=%s", _log_prefix(driver), last)
            return 'invalid'
        logger.warning(
            "%s[OTP] 提交后 %ss 仍在验证码页（未跳转），返回 pending snapshot=%s",
            _log_prefix(driver), timeout, last
        )
        return 'pending'
    return 'accepted'


def _click_continue(driver) -> None:
    page = getattr(driver, "page", None)
    if page is not None:
        try:
            submit_loc = page.locator(
                'button[value="validate"], button[data-dd-action-name="Continue"], '
                'button[data-dd-action-name="continue"], button[type="submit"]:not([value="resend"]), '
                'button:has-text("Continue"), button:has-text("Tiếp tục"), button:has-text("続行"), button:has-text("继续")'
            ).first
            if submit_loc.count() and submit_loc.is_visible(timeout=1000):
                submit_loc.click(timeout=5000)
                logger.info("%s[OTP] 已通过原生 locator 点击继续/验证按钮", _log_prefix(driver))
                return
        except Exception:
            pass

    _click_any(driver, [
        "button[value='validate']",
        "button[type='submit']:not([value='resend'])",
        "//button[@data-dd-action-name='Continue']",
        "//button[@data-dd-action-name='continue']",
        "//button[@data-login-web-auth-control='true' and @type='submit']",
        "//button[contains(., 'Continue')]",
        "//button[contains(., '続行')]",
        "//button[contains(., 'Tiếp tục')]",
        "//button[contains(., '继续')]",
        "//button[contains(., 'Sign up')]",
        "//button[contains(., 'Create')]",
        "//button[contains(., 'Next')]",
    ], timeout=20)


def _maybe_accept(driver) -> None:
    """自动关闭/接受 Cookie 与 Consent 弹窗，支持多语言出口与通用 DOM 兜底。"""
    # 1. 优先通过 JS 快速定位并点击 cookie 容器内部的“接受/全部接受”按钮，或直接隐藏遮挡层
    try:
        driver.execute_script(r"""
        try {
          const cookieKeywords = /cookie|consent|onetrust/i;
          const acceptKeywords = /chấp nhận|accept|agree|同意|aceptar|accepter|akzeptieren|принять|aceitar|accetta|동의|allow all|accept all/i;
          const badKeywords = /google|apple|microsoft|phone|số điện thoại/i;
          // 查找所有可能的 cookie 弹层容器
          const containers = [...document.querySelectorAll('#onetrust-banner-sdk, [id*="cookie" i], [class*="cookie" i], [aria-label*="cookie" i]')];
          for (const c of containers) {
            const btns = [...c.querySelectorAll('button, a[role="button"]')];
            const acceptBtn = btns.find(b => acceptKeywords.test(b.innerText || b.textContent || '') && !badKeywords.test(b.innerText || ''));
            if (acceptBtn) {
              acceptBtn.click();
              return true;
            }
          }
          // 兜底直接找页面上文本匹配的独立 accept 按钮
          const allBtns = [...document.querySelectorAll('button')];
          const directAccept = allBtns.find(b => {
            const txt = (b.innerText || b.textContent || '').trim();
            return acceptKeywords.test(txt) && !badKeywords.test(txt) && txt.length < 35 && !b.querySelector('svg, img');
          });
          if (directAccept) {
            directAccept.click();
            return true;
          }
        } catch (_) {}
        return false;
        """)
    except Exception:
        pass

    # 2. 针对 Playwright / Selenium 的常规选择器点击
    for selectors in ([
        "button#onetrust-accept-btn-handler",
        "button[data-testid='cookie-accept']",
        "button[data-testid='accept-cookies']",
        "//button[contains(., 'Chấp nhận')]",
        "//button[contains(., 'Accept')]",
        "//button[contains(., '同意')]",
        "//button[contains(., 'Agree')]",
        "//button[contains(., 'Aceptar')]",
        "//button[contains(., 'Accepter')]",
        "//button[contains(., 'Akzeptieren')]",
    ],):
        try:
            _click_any(driver, selectors, timeout=2)
            time.sleep(0.3)
        except Exception:
            pass


def _page_snapshot(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const inputs = [...document.querySelectorAll('input,select,textarea')].map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
          autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
          value: el.value || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).filter(x => x.visible).slice(0, 30);
        const buttons = [...document.querySelectorAll('button,a[role=button],input[type=submit]')].map(el => ({
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
          type: el.getAttribute('type') || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
          disabled: !!el.disabled
        })).filter(x => x.visible).slice(0, 30);
        const widgets = [...document.querySelectorAll('[role=spinbutton], .react-aria-Select, [data-testid="hidden-select-container"] select')].map(el => ({
          tag: el.tagName, role: el.getAttribute('role') || '', dataType: el.getAttribute('data-type') || '',
          aria: el.getAttribute('aria-label') || '', text: (el.innerText || el.textContent || '').trim().slice(0, 80),
          visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, title: document.title, text: (document.body?.innerText || '').slice(0, 2000), inputs, buttons, widgets};
        """) or {}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "url": getattr(driver, 'current_url', '')}


def _has_access_token(driver) -> bool:
    try:
        result = driver.execute_async_script(r"""
        const done = arguments[0];
        fetch('https://chatgpt.com/api/auth/session', {credentials:'include'})
          .then(r => r.json()).then(j => done(Boolean(j && j.accessToken)))
          .catch(() => done(false));
        """)
        return bool(result)
    except Exception:
        return False


def _is_profile_like(snapshot: dict) -> bool:
    """资料页识别：兼容 about-you/profile；年龄/生日控件可能不是 input，而是 React Aria widget。"""
    url = str(snapshot.get('url') or '').lower()
    inputs = snapshot.get('inputs') or []
    widgets = snapshot.get('widgets') or []
    attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('name', 'id', 'placeholder', 'autocomplete', 'aria', 'type')).lower()
        for i in inputs
    )
    widget_attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('role', 'dataType', 'aria', 'text', 'tag')).lower()
        for i in widgets
    )
    has_profile_url = any(x in url for x in ('about-you', 'profile', 'signup/profile', 'create-account/profile'))
    has_name_field = (
        'autocomplete name' in attrs
        or ' name ' in f' {attrs} '
        or 'fullname' in attrs
        or 'full_name' in attrs
        or 'firstname' in attrs
        or 'lastname' in attrs
    )
    has_age_or_birth_field = any(x in f' {attrs} {widget_attrs} ' for x in (
        ' age', '-age', '_age', 'birth', 'birthday', 'birthdate',
        ' month', '-month', '_month', 'data-type month',
        ' day', '-day', '_day', 'data-type day',
        ' year', '-year', '_year', 'data-type year',
        'spinbutton', 'react-aria-select', 'type number',
    ))
    # about-you/profile URL 本身已经足够强；部分新版页面会用无 name 的 React Aria 控件。
    return has_profile_url and (has_name_field or has_age_or_birth_field or bool(inputs) or bool(widgets))


def _set_element_value(driver, el, value: str) -> None:
    """兼容 React 受控输入框：用原生 setter 设置值并派发 input/change。"""
    driver.execute_script(r"""
    const el = arguments[0];
    if (!el) return false;
    const value = String(arguments[1]);
    const tag = (el.tagName || '').toLowerCase();
    el.scrollIntoView({block:'center'});
    el.focus();
    if (tag === 'select') {
      el.value = value;
    } else {
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, value);
      else el.value = value;
    }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    el.blur();
    """, el, value)


def _select_or_type(driver, selectors: list[str], value: str, timeout: int = 3) -> bool:
    try:
        el = _find_any(driver, selectors, timeout=timeout)
    except Exception:
        return False
    try:
        tag = (el.tag_name or '').lower()
        if tag == 'select':
            if el.__class__.__name__ == 'CloakElement':
                driver.execute_script(r"""
                const el = arguments[0], value = String(arguments[1]);
                const n = parseInt(value, 10);
                const opts = [...el.options];
                const match = opts.find(o => o.value === value)
                  || opts.find(o => (o.textContent || '').trim() === value)
                  || opts[Math.max(0, n - 1)];
                if (match) el.value = match.value; else el.value = value;
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
                """, el, str(value))
            else:
                from selenium.webdriver.support.ui import Select
                sel = Select(el)
                try:
                    sel.select_by_value(str(int(value)))
                except Exception:
                    try:
                        sel.select_by_visible_text(str(int(value)))
                    except Exception:
                        # 月份 select 可能是 0-based，也可能是 1-based；先 value/text，不行再 index。
                        sel.select_by_index(max(0, int(value)-1))
                driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles:true}));", el)
        else:
            _human_type_text(driver, el, str(value), clear=True)
        return True
    except Exception as exc:
        logger.debug('%s 填写字段失败 selectors=%s value=%s err=%s', _log_prefix(driver), selectors, value, exc)
        return False


def _fill_birthday_or_age(driver, birthday: str, age: int) -> str | None:
    """填写 about-you 的年龄/生日控件。

    参考 FlowPilot：优先处理直接年龄 input；否则兼容 hidden birthday/date、原生年月日
    select/input、React Aria hidden native select、role=spinbutton[data-type=year/month/day]。
    返回 age / birthday / ymd / react_select / spinbutton / None。
    """
    y, m, d = birthday.split('-')
    result = driver.execute_script(r"""
    const birthday = String(arguments[0]);
    const year = String(arguments[1]);
    const month = String(Number(arguments[2]));
    const month2 = String(arguments[2]).padStart(2, '0');
    const day = String(Number(arguments[3]));
    const day2 = String(arguments[3]).padStart(2, '0');
    const age = String(arguments[4]);
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const setValue = (el, value) => {
      if (!el) return false;
      el.scrollIntoView?.({block:'center'});
      el.focus?.();
      const tag = (el.tagName || '').toLowerCase();
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype
        : tag === 'select' ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, String(value)); else el.value = String(value);
      if (tag === 'select') {
        [...el.options].forEach(opt => { opt.selected = String(opt.value) === String(value); });
      }
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      el.blur?.();
      return true;
    };
    const ageInput = [...document.querySelectorAll('input[name="age"], input#age, input[id$="-age"], input[type="number"]')]
      .find(visible);
    if (ageInput && setValue(ageInput, age)) return {ok:true, mode:'age'};

    const dateInput = [...document.querySelectorAll('input[name="birthdate"], input[type="date"], input[name="birthday"]')]
      .find(el => visible(el) || String(el.getAttribute('type') || '').toLowerCase() === 'date');
    if (dateInput && setValue(dateInput, birthday)) return {ok:true, mode:'birthday'};

    const setFirst = (selectors, values) => {
      for (const sel of selectors) {
        for (const el of [...document.querySelectorAll(sel)]) {
          if (!visible(el)) continue;
          for (const val of values) {
            if (el.tagName === 'SELECT') {
              const has = [...el.options].some(o => String(o.value) === String(val) || String(o.textContent || '').trim() === String(val));
              if (!has) continue;
            }
            if (setValue(el, val)) return true;
          }
        }
      }
      return false;
    };
    const yOk = setFirst(['select[name="year"]','input[name="year"]','select[id*="year"]','input[id*="year"]'], [year]);
    const mOk = setFirst(['select[name="month"]','input[name="month"]','select[id*="month"]','input[id*="month"]'], [month, month2]);
    const dOk = setFirst(['select[name="day"]','input[name="day"]','select[id*="day"]','input[id*="day"]'], [day, day2]);
    if (yOk && mOk && dOk) {
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'ymd'};
    }

    // React Aria Select 通常有 hidden native select；不依赖标签文字，按 option 数值范围和 DOM 顺序推断年/月/日。
    const selects = [...document.querySelectorAll('[data-testid="hidden-select-container"] select, .react-aria-Select select, select')]
      .filter(el => !el.disabled);
    const nums = sel => [...sel.options].map(o => Number(o.value)).filter(Number.isFinite);
    const maxNum = sel => Math.max(...nums(sel), -Infinity);
    const minNum = sel => Math.min(...nums(sel), Infinity);
    const hasOption = (sel, val) => [...sel.options].some(o => String(o.value) === String(val));
    const yearSelects = selects.filter(sel => hasOption(sel, year) && maxNum(sel) > 1900);
    const smallSelects = selects.filter(sel => !yearSelects.includes(sel));
    const monthSelects = smallSelects.filter(sel => (hasOption(sel, month) || hasOption(sel, month2)) && minNum(sel) <= 1 && maxNum(sel) <= 12);
    const daySelects = smallSelects.filter(sel => (hasOption(sel, day) || hasOption(sel, day2)) && maxNum(sel) >= 28);
    if (yearSelects.length && monthSelects.length && daySelects.length) {
      const ys = yearSelects[0];
      let ms = monthSelects[0];
      let ds = daySelects.find(x => x !== ms) || daySelects[0];
      setValue(ys, year);
      setValue(ms, hasOption(ms, month) ? month : month2);
      setValue(ds, hasOption(ds, day) ? day : day2);
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'react_select'};
    }

    const spinYear = document.querySelector('[role="spinbutton"][data-type="year"]');
    const spinMonth = document.querySelector('[role="spinbutton"][data-type="month"]');
    const spinDay = document.querySelector('[role="spinbutton"][data-type="day"]');
    if (spinYear && spinMonth && spinDay) return {ok:false, mode:'spinbutton_needed'};
    return {ok:false, mode:'missing'};
    """, birthday, y, m, d, str(age)) or {}
    if result.get('ok'):
        return str(result.get('mode') or 'birthday')
    if result.get('mode') != 'spinbutton_needed':
        return None

    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        mod = Keys.COMMAND
        try:
            import platform
            if platform.system().lower() != 'darwin':
                mod = Keys.CONTROL
        except Exception:
            pass
        for selector, value in [
            ('[role="spinbutton"][data-type="year"]', y),
            ('[role="spinbutton"][data-type="month"]', str(m).zfill(2)),
            ('[role="spinbutton"][data-type="day"]', str(d).zfill(2)),
        ]:
            el = driver.find_element(By.CSS_SELECTOR, selector)
            driver.execute_script("arguments[0].scrollIntoView({block:'center'}); arguments[0].focus();", el)
            time.sleep(0.1)
            el.send_keys(mod, 'a')
            time.sleep(0.05)
            el.send_keys(str(value))
            time.sleep(0.1)
            driver.execute_script("arguments[0].dispatchEvent(new Event('input', {bubbles:true})); arguments[0].dispatchEvent(new Event('change', {bubbles:true})); arguments[0].blur();", el)
        driver.execute_script(r"""
        const hidden = document.querySelector('input[name="birthday"]');
        if (hidden) {
          const value = arguments[0];
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(hidden, value); else hidden.value = value;
          hidden.dispatchEvent(new Event('input', {bubbles:true}));
          hidden.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """, birthday)
        return 'spinbutton'
    except Exception as exc:
        logger.debug('%s spinbutton 生日填写失败：%s', _log_prefix(driver), exc)
        return None


def _generate_roxy_password() -> str:
    """参考 FlowPilot 密码策略：8~64 位，含大小写、数字、符号。"""
    upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    lower = 'abcdefghjkmnpqrstuvwxyz'
    digits = '23456789'
    symbols = '!@#$%^&*?_-+=' 
    groups = [upper, lower, digits, symbols]
    all_chars = ''.join(groups)
    chars = [random.choice(g) for g in groups]
    while len(chars) < 14:
        chars.append(random.choice(all_chars))
    random.shuffle(chars)
    return ''.join(chars)


def _registration_password() -> str:
    try:
        from config import register as _register_cfg
        configured = str(getattr(_register_cfg, 'REGISTER_PASSWORD', '') or '').strip()
        if configured:
            return configured
    except Exception:
        pass
    return _generate_roxy_password()


def _password_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', visible: visible(el), value: el.type === 'password' ? '<password>' : (el.value || '')
        })).slice(0, 30);
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const buttons = [...document.querySelectorAll('button,input[type="submit"]')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          disabled: !!el.disabled, visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, inputs, forms, buttons};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_signup_password_page(driver) -> bool:
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    if any(x in url for x in ('/create-account/password', '/u/signup/password', '/signup/password')):
        return True
    if '/log-in/password' in url:
        return False
    inputs = state.get('inputs') or []
    return any(
        i.get('visible') and (
            str(i.get('type') or '').lower() == 'password'
            or 'password' in str(i.get('name') or '').lower()
            or str(i.get('autocomplete') or '').lower() == 'new-password'
        )
        for i in inputs
    )


def _is_login_password_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if any(x in url for x in ('/log-in/password', '/login/password', '/reauth')):
        return True
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    if any(x in url for x in ('/log-in/password', '/login/password', '/reauth')):
        return True
    inputs = state.get('inputs') or []
    has_current_pw_input = any(
        i.get('visible') and (
            str(i.get('autocomplete') or '').lower() == 'current-password'
            or 'current-password' in str(i.get('name') or '').lower()
        )
        for i in inputs
    )
    if has_current_pw_input:
        return True
    try:
        page_source = str(driver.page_source or '')
        markers = (
            'まず本人確認', '本人確認を行います', '現在のパスワード',
            'パスワードをお忘れですか', 'current password', 'forgot password',
            '输入当前密码', '当前密码', '忘记密码',
        )
        if any(m in page_source for m in markers):
            return True
    except Exception:
        pass
    return False


def _click_forgot_password_if_present(driver) -> dict:
    """在要求输入当前密码/确认密码的页面点击「忘记密码」，重新向邮箱发验证码。"""
    try:
        native_target = getattr(driver, 'forgot_password_target_native', None)
        result = native_target() if callable(native_target) else driver.execute_script(r"""
        const visible = el => {
          if (!el) return false;
          const rects = el.getClientRects();
          return !!(el.offsetWidth || el.offsetHeight || (rects && rects.length))
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        };
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('a,button,[role="link"],[role="button"],input[type="submit"]')].filter(el => visible(el) && enabled(el));
        const isForgot = el => {
          const href = String(el.getAttribute('href') || '').toLowerCase();
          const attrs = [
            href, el.id, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          const raw = String(el.textContent || el.getAttribute('value') || '').toLowerCase();
          return (
            href.includes('reset-password') ||
            attrs.includes('reset-password') ||
            attrs.includes('forgot-password') ||
            attrs.includes('forgot_password') ||
            text.includes('forgotpassword') ||
            text.includes('passwordforgot') ||
            text.includes('パスワードをお忘れですか') ||
            text.includes('パスワードをお忘れ') ||
            text.includes('忘记密码') ||
            text.includes('忘記密碼') ||
            text.includes('找回密码') ||
            text.includes('重置密码') ||
            (raw.includes('パスワード') && raw.includes('忘れ'))
          );
        };
        const btn = candidates.find(isForgot);
        if (!btn) return {ok: false, reason: 'missing_forgot_password_link'};
        btn.scrollIntoView({block: 'center'});
        return {
          ok: true,
          reason: 'forgot_password_target',
          button: btn,
          href: btn.getAttribute('href') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {'ok': False, 'reason': 'empty_result'}
        if result.get('ok') and result.get('button'):
            _human_click(driver, result.get('button'), label='forgot_password')
            result['reason'] = 'clicked_forgot_password'
            result.pop('button', None)
            time_end = time.time() + 6.0
            while time.time() < time_end:
                try:
                    cur_url = str(driver.current_url or '').lower()
                    if '/reset-password' in cur_url or 'reset' in cur_url:
                        clicked_continue = False
                        page = getattr(driver, 'page', None)
                        if page is not None:
                            try:
                                submit = page.locator('button[type="submit"],input[type="submit"]').first
                                if submit.count() and submit.is_visible(timeout=1000) and submit.is_enabled(timeout=1000):
                                    submit.click(timeout=5000)
                                    clicked_continue = True
                            except Exception as native_exc:
                                logger.debug("%s reset-password 原生 Continue 点击失败：%s", _log_prefix(driver), native_exc)
                        if not clicked_continue:
                            driver.execute_script(r"""
                        const visible = el => {
                          if (!el) return false;
                          const rects = el.getClientRects();
                          return !!(el.offsetWidth || el.offsetHeight || (rects && rects.length))
                            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
                        };
                        const btns = [...document.querySelectorAll('button[type="submit"],button,input[type="submit"]')].filter(visible);
                        for (const b of btns) {
                            const t = (b.textContent || b.value || '').trim().toLowerCase();
                            if (t.includes('continue') || t.includes('続行') || t.includes('继续') || t.includes('送信')) {
                                b.click();
                                break;
                            }
                        }
                            """)
                        break
                except Exception:
                    pass
                time.sleep(0.4)
        return result
    except Exception as exc:
        return {'ok': False, 'reason': f'{type(exc).__name__}: {exc}'}


def _click_passwordless_signup_if_present(driver) -> dict:
    """
    新版注册/登录流在 password 页可能默认要求密码。
    如果页面提供“使用一次性验证码”按钮，优先点击进入邮箱 OTP 页面。
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')].filter(el => visible(el) && enabled(el));
        const isPasswordlessOtp = el => {
          const name = String(el.getAttribute('name') || '').toLowerCase();
          const value = String(el.getAttribute('value') || '').toLowerCase();
          const attrs = [
            el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className, el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          return (
            (name === 'intent' && value.includes('passwordless') && value.includes('send_otp')) ||
            (name === 'intent' && value.includes('passwordless') && value.includes('otp')) ||
            (name === 'intent' && value === 'passwordless_signup_send_otp') ||
            (name === 'intent' && value === 'passwordless_login_send_otp') ||
            attrs.includes('passwordless_signup_send_otp') ||
            attrs.includes('passwordless_login_send_otp') ||
            /passwordless.*otp|otp.*passwordless|one[-_\s]?time.*code|code.*one[-_\s]?time/.test(attrs) ||
            text.includes('使用一次性验证码注册') ||
            text.includes('使用一次性验证码登录') ||
            text.includes('使用一次性验证码') ||
            text.includes('使用一次性驗證碼註冊') ||
            text.includes('使用一次性驗證碼登入') ||
            text.includes('一次性验证码') ||
            text.includes('一次性驗證碼') ||
            text.includes('メールでコード') ||
            text.includes('ワンタイムコード') ||
            text.includes('認証コード') ||
            text.includes('useonetimeregistrationcode') ||
            text.includes('useaone-timecodetosignup') ||
            text.includes('useaone-timecodetoregister') ||
            text.includes('useaone-timecodetologin') ||
            text.includes('continuewithaone-timecode') ||
            text.includes('loginwithaone-timecode') ||
            text.includes('signupwithaone-timecode') ||
            text.includes('one-timecode')
          );
        };
        const btn = candidates.find(isPasswordlessOtp);
        if (!btn) return {ok:false, reason:'missing_passwordless_button'};
        btn.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'passwordless_send_otp_target',
          button: btn,
          name: btn.getAttribute('name') || '',
          value: btn.getAttribute('value') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {"ok": False, "reason": "empty_result"}
        if result.get("ok") and result.get("button"):
            _human_click(driver, result.get("button"), label="passwordless_otp")
            result["reason"] = "clicked_passwordless_send_otp"
            result.pop("button", None)
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _click_continue_with_password_if_present(driver) -> dict:
    """在邮箱验证码页点击“使用密码继续”，进入 /create-account/password。"""
    try:
        native_target = getattr(driver, "continue_with_password_target_native", None)
        result = native_target() if callable(native_target) else driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('a,button,[role="link"],[role="button"]')].filter(el => visible(el) && enabled(el));
        const isPasswordCreate = el => {
          const href = String(el.getAttribute('href') || '').toLowerCase();
          if (href.includes('/log-in') || href.includes('login')) return false;
          const attrs = [
            href, el.id, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-login-web-auth-control'),
            el.getAttribute('data-dd-action-name'), el.className
          ].join(' ').toLowerCase();
          if (attrs.includes('/log-in')) return false;
          const text = norm(el.textContent || '');
          const rawText = String(el.textContent || '').toLowerCase();
          return (
            href.includes('/create-account/password') ||
            attrs.includes('/create-account/password') ||
            // 英文
            text.includes('continuewithpassword') ||
            text.includes('continuewithapassword') ||
            // 日文 (如: パスワードで続行, パスワードで続ける)
            text.includes('パスワードで続行') ||
            text.includes('パスワードで続ける') ||
            (rawText.includes('パスワード') && (rawText.includes('続行') || rawText.includes('次へ') || rawText.includes('続け'))) ||
            // 越南语 (如: Tiếp tục với mật khẩu)
            rawText.includes('mật khẩu') ||
            // 中文 (如: 使用密码继续, 通过密码继续)
            text.includes('使用密码继续') ||
            text.includes('密码继续') ||
            text.includes('通过密码继续') ||
            text.includes('以密碼繼續') ||
            // 韩文
            rawText.includes('비밀번호') ||
            // 德语 / 西班牙语 / 法语 / 葡萄牙语
            rawText.includes('passwort') ||
            rawText.includes('contraseña') ||
            rawText.includes('mot de passe') ||
            rawText.includes('senha')
          );
        };
        const btn = candidates.find(isPasswordCreate);
        if (!btn) return {ok:false, reason:'missing_continue_with_password'};
        btn.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'continue_with_password_target',
          button: btn,
          href: btn.getAttribute('href') || '',
          text: (btn.textContent || '').trim().slice(0, 80)
        };
        """) or {"ok": False, "reason": "empty_result"}
        if result.get("ok") and result.get("button"):
            _human_click(driver, result.get("button"), label="continue_with_password")
            result["reason"] = "clicked_continue_with_password"
            result.pop("button", None)
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _fill_password_page_if_present(driver, email: str, timeout: int = 25) -> str | None:
    """邮箱提交后兼容 create-account/password。返回本次设置的 OpenAI 账号密码；未遇到密码页返回 None。"""
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        if _is_email_verification_page(driver):
            # 邮箱验证码页刚加载时 DOM 和多语言组件可能仍在挂载，短等重试避免误判
            clicked = False
            for _attempt in range(5):
                result = _click_continue_with_password_if_present(driver)
                if result.get("ok"):
                    logger.info("%s 邮箱验证码页已点击“使用密码继续”：email=%s detail=%s", _log_prefix(driver), email, result)
                    time.sleep(1.0)
                    clicked = True
                    break
                time.sleep(0.8)
            if clicked:
                transition_end = time.time() + 12
                while time.time() < transition_end:
                    if _is_signup_password_page(driver):
                        break
                    if _has_access_token(driver):
                        return None
                    time.sleep(0.4)
                continue
            logger.info("%s 已在邮箱验证码页，未找到“使用密码继续”按钮：detail=%s", _log_prefix(driver), result)
            return None
        if _has_access_token(driver):
            return None
        last = _password_page_state(driver)
        is_signup_password = _is_signup_password_page(driver)
        is_login_password = _is_login_password_page(driver)
        if not (is_signup_password or is_login_password):
            time.sleep(0.5)
            continue
        passwordless = _click_passwordless_signup_if_present(driver) if is_login_password else {"ok": False, "reason": "signup_password_prefers_password"}
        if passwordless.get('ok'):
            logger.info("%s 检测到 password 页，已点击一次性验证码入口：email=%s detail=%s", _log_prefix(driver), email, passwordless)
            wait_end = time.time() + 20
            while time.time() < wait_end:
                if _is_email_verification_page(driver):
                    logger.info("%s 一次性验证码入口已进入邮箱验证码页", _log_prefix(driver))
                    return None
                if _has_access_token(driver):
                    logger.info("%s 一次性验证码入口后已检测到登录态", _log_prefix(driver))
                    return None
                time.sleep(0.5)
            logger.info("%s 已点击一次性验证码入口，未立即检测到 OTP 页，交给后续 OTP 阶段继续处理", _log_prefix(driver))
            return None
        if is_login_password:
            logger.warning("%s 当前处于登录密码页（/log-in/password），该邮箱在 OpenAI 已存在账号：email=%s", _log_prefix(driver), email)
            raise RuntimeError(f"该邮箱已在 OpenAI 存在账号（处于 /log-in/password），无法新建账号设置密码: {email}")
        password = _registration_password()
        logger.info("%s 准备填写密码（%s 位）：email=%s", _log_prefix(driver), len(password), email)
        native_targets = getattr(driver, "signup_password_targets_native", None)
        result = native_targets() if callable(native_targets) else None
        if not result or not result.get("ok"):
            result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && el.getAttribute('aria-disabled') !== 'true')
          .map((el, idx) => {
            const r = el.getBoundingClientRect();
            const ir = input.getBoundingClientRect();
            return {el, idx, below: r.top >= ir.bottom - 10, dist: Math.max(0, r.top - ir.bottom) + Math.abs((r.left+r.right-ir.left-ir.right)/2)/10};
          })
          .filter(x => x.below)
          .sort((a,b) => a.dist - b.dist || a.idx - b.idx);
        if (!buttons.length) return {ok:false, reason:'missing_submit'};
        buttons[0].el.scrollIntoView({block:'center'});
        return {ok:true, reason:'password_targets', input, button: buttons[0].el};
        """) or {}
        if not result.get('ok'):
            raise RuntimeError(f"密码页处理失败：{result} state={last}")
        _human_type_text(driver, result.get("input"), password, clear=True)
        # React/Auth0 会在 input/change 后异步校验密码强度并启用 Continue。
        # 之前输入完 0.4~1.4s 就点，偶发点在按钮还未真正可提交/事件未绑定完成时，页面无反应。
        human_delay("form", minimum=2.0, maximum=3.6)
        submit_result = native_targets() if callable(native_targets) else driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !!el && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const pass = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(el => visible(el) && !el.disabled && !el.readOnly);
        const form = pass ? pass.closest('form') : document.querySelector('form');
        const scope = form || document;
        const candidates = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')]
          .filter(el => visible(el) && enabled(el));
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const scored = candidates.map((el, idx) => {
          const attrs = [
            el.getAttribute('type'), el.getAttribute('data-dd-action-name'),
            el.getAttribute('data-login-web-auth-control'), el.getAttribute('aria-label'),
            el.getAttribute('name'), el.getAttribute('value'), el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          let score = 0;
          if ((el.getAttribute('type') || '').toLowerCase() === 'submit') score += 80;
          if ((el.getAttribute('data-dd-action-name') || '').toLowerCase() === 'continue') score += 90;
          if (String(el.getAttribute('data-login-web-auth-control') || '').toLowerCase() === 'true') score += 70;
          if (/continue|next|submit|create|続行|続ける|次へ|登録/.test(attrs) || /continue|next|submit|create|続行|続ける|次へ|登録/.test(text)) score += 50;
          return {el, idx, score};
        }).sort((a,b) => b.score - a.score || a.idx - b.idx);
        const target = scored[0]?.el;
        if (!target) return {ok:false, reason:'missing_enabled_submit'};
        target.scrollIntoView({block:'center'});
        return {
          ok:true,
          reason:'enabled_submit_target',
          button: target,
          text: (target.textContent || target.getAttribute('value') || '').trim().slice(0, 80),
          type: target.getAttribute('type') || '',
          dd: target.getAttribute('data-dd-action-name') || '',
          ariaDisabled: target.getAttribute('aria-disabled') || ''
        };
        """) or {}
        if not submit_result.get("ok") or not submit_result.get("button"):
            raise RuntimeError(f"密码页找不到可点击的 Continue 按钮：{submit_result} state={_password_page_state(driver)}")
        _human_click(driver, submit_result.get("button"), label="password_submit")
        logger.info("%s 已填写并点击密码页 Continue：detail=%s", _log_prefix(driver), {k: v for k, v in submit_result.items() if k != "button"})
        # 提交密码后通常进入邮箱验证码页，最多等一段时间。
        wait_end = time.time() + 20
        retried_submit = False
        while time.time() < wait_end:
            if _is_email_verification_page(driver):
                logger.info("%s 密码提交后已进入邮箱验证码页", _log_prefix(driver))
                return password
            if _has_access_token(driver):
                logger.info("%s 密码提交后已检测到登录态", _log_prefix(driver))
                return password
            if _is_login_password_page(driver):
                err_text = driver.execute_script(r"""
                const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                const els = [...document.querySelectorAll('[role="alert"], [class*="error" i], [id*="error" i], p, span')].filter(visible);
                for (const el of els) {
                  const t = (el.textContent || '').trim().toLowerCase();
                  if (t.includes('incorrect email address or password') || t.includes('password is incorrect') || t.includes('パスワードが正しくありません')) {
                    return el.textContent.trim();
                  }
                }
                return null;
                """)
                if err_text:
                    logger.warning("%s 登录密码页提示密码错误：detail=%r", _log_prefix(driver), err_text)
                    raise RuntimeError(f"该邮箱已在 OpenAI 注册且密码不匹配 (/log-in/password): {email} ({err_text})")
            if not retried_submit and time.time() > wait_end - 15 and (_is_signup_password_page(driver) or _is_login_password_page(driver)):
                retried_submit = True
                logger.info("%s 密码页点击后仍未跳转，等待后重试一次 Continue/Enter", _log_prefix(driver))
                human_delay("form", minimum=1.2, maximum=2.2)
                try:
                    btn = submit_result.get("button")
                    if btn and hasattr(btn, "click"):
                        btn.click()
                    else:
                        _click_continue(driver)
                except Exception:
                    try:
                        from selenium.webdriver.common.keys import Keys
                        driver.switch_to.active_element.send_keys(Keys.ENTER)
                    except Exception:
                        pass
            # React 导航期间 DOM 会短暂清空。旧逻辑把这个瞬态当成密码提交成功，
            # 上层随后可能仍在 /create-account/password 上填写 OTP。只有明确观察到
            # email-verification 或登录态才算完成；其余状态继续等到超时并报错。
            time.sleep(0.5)
        raise RuntimeError(
            f"密码已提交但未进入邮箱验证码页或登录态: "
            f"state={_password_page_state(driver)}"
        )
    logger.info("%s 未检测到密码页，继续后续流程 last=%s", _log_prefix(driver), last)
    return None


def _accept_profile_consents(driver) -> int:
    """about-you/profile 下出现韩国/日本个人信息同意协议时，默认全部勾选。

    不依赖可见文字；优先处理 allCheckboxes，再处理所有必选 consent checkbox。
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const isChecked = el => el.checked === true || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
        const mark = el => {
          if (!el || isChecked(el)) return false;
          const label = el.closest('label');
          try {
            (label && visible(label) ? label : el).scrollIntoView({block:'center'});
            (label && visible(label) ? label : el).click();
          } catch (_) {}
          if (!isChecked(el)) {
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
            if (setter) setter.call(el, true); else el.checked = true;
            el.dispatchEvent(new MouseEvent('click', {bubbles:true}));
            el.dispatchEvent(new Event('input', {bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
          }
          return isChecked(el);
        };
        const all = [...document.querySelectorAll('input[type="checkbox"]')]
          .filter(el => visible(el) || visible(el.closest('label')));
        if (!all.length) return {count:0, names:[]};
        const byName = name => all.find(el => String(el.name || '').toLowerCase() === name.toLowerCase());
        const ordered = [];
        const add = el => { if (el && !ordered.includes(el)) ordered.push(el); };
        add(byName('allCheckboxes'));
        for (const name of ['personalInfoConsent', 'thirdPartyConsent', 'overseasTransferConsent']) add(byName(name));
        for (const el of all) {
          const n = String(el.name || '').toLowerCase();
          const id = String(el.id || '').toLowerCase();
          if (/consent|checkbox|agree|required|personal|third|overseas/.test(`${n} ${id}`)) add(el);
        }
        // about-you/profile 页面里的 checkbox 基本都是必选 consent；剩余可见 checkbox 也全部勾选。
        for (const el of all) add(el);
        const clicked = [];
        for (const el of ordered) {
          if (mark(el)) clicked.push(el.name || el.id || 'checkbox');
        }
        return {count: clicked.length, names: clicked};
        """) or {}
        count = int(result.get('count') or 0)
        if count:
            logger.info("%s 已勾选 about-you/profile 同意协议复选框：%s", _log_prefix(driver), result.get('names'))
        return count
    except Exception as exc:
        logger.debug('%s 勾选 profile consent 失败：%s', _log_prefix(driver), exc)
        return 0


def _complete_profile_page(driver, name: str, birthday: str, timeout: int = 45) -> bool:
    """等待并完成姓名/生日页；若已经登录成功则返回 False，不把它当失败。"""
    end = time.time() + timeout
    y, m, d = birthday.split('-')
    from datetime import date
    today = date.today()
    age = today.year - int(y) - ((today.month, today.day) < (int(m), int(d)))
    last_snapshot = {}
    while time.time() < end:
        time.sleep(1)
        if _has_access_token(driver):
            logger.info('%s 已检测到登录态，资料页可能已跳过', _log_prefix(driver))
            return False
        snap = _page_snapshot(driver)
        last_snapshot = snap
        final_confirmation = _click_final_confirmation_if_present(driver)
        if final_confirmation.get("ok"):
            logger.info(
                "%s 已点击注册最终确认页按钮：%s",
                _log_prefix(driver), final_confirmation.get("reason"),
            )
            return True
        if not _is_profile_like(snap):
            logger.info('%s 等待资料页中：url=%s', _log_prefix(driver), snap.get('url'))
            continue

        logger.info('%s 检测到资料页，开始填写姓名生日：url=%s inputs=%s', _log_prefix(driver), snap.get('url'), snap.get('inputs'))
        name_ok = False
        # 常见单姓名字段
        for selectors in [
            ["input[name='name']", "input[name='fullName']", "input[name='full_name']", "input[autocomplete='name']"],
            ["input[placeholder*='Name']", "input[placeholder*='name']", "input[aria-label*='Name']", "input[aria-label*='name']"],
        ]:
            if _select_or_type(driver, selectors, name, timeout=3):
                logger.info("%s 已填写姓名字段：%s", _log_prefix(driver), name)
                name_ok = True
                break
        # 兼容 first/last 分开
        if not name_ok:
            parts = name.split(' ', 1)
            first = parts[0]
            last = parts[1] if len(parts) > 1 else 'User'
            first_ok = _select_or_type(driver, ["input[name='firstName']", "input[name='first_name']", "input[placeholder*='First']", "input[aria-label*='First']"], first, timeout=2)
            last_ok = _select_or_type(driver, ["input[name='lastName']", "input[name='last_name']", "input[placeholder*='Last']", "input[aria-label*='Last']"], last, timeout=2)
            name_ok = first_ok or last_ok

        birth_mode = _fill_birthday_or_age(driver, birthday, age)
        birth_ok = bool(birth_mode)
        if birth_ok:
            if birth_mode == 'age':
                logger.info("%s 已填写年龄字段：%s", _log_prefix(driver), age)
            else:
                logger.info("%s 已填写生日字段 mode=%s value=%s", _log_prefix(driver), birth_mode, birthday)

        if not name_ok or not birth_ok:
            logger.warning('%s 资料页字段未填完整 name_ok=%s birth_ok=%s snapshot=%s', _log_prefix(driver), name_ok, birth_ok, snap)
            continue

        _accept_profile_consents(driver)
        human_delay('form')
        for _ in range(3):
            if _click_if_enabled_submit(driver):
                logger.info('%s 已点击资料页提交按钮，等待 OAuth 跳转', _log_prefix(driver))
                return True
            time.sleep(1)
        logger.warning('%s 找不到可点击的资料页提交按钮 snapshot=%s', _log_prefix(driver), _page_snapshot(driver))
    raise RuntimeError(f'等待/填写资料页超时，最后页面：{last_snapshot}')


def _click_final_confirmation_if_present(driver) -> dict:
    """处理 OTP 后新版无表单的最终确认页，不依赖页面显示语言。"""
    try:
        result = driver.execute_script(r"""
        const host = String(location.hostname || '').toLowerCase();
        if (host !== 'auth.openai.com' && host !== 'chatgpt.com') {
          return {ok:false, reason:'unexpected_host', host};
        }
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => visible(el) && !el.disabled
          && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const editable = [...document.querySelectorAll('input,textarea,select')]
          .filter(el => visible(el) && !el.disabled && !el.readOnly && String(el.type || '').toLowerCase() !== 'hidden');
        if (editable.length) return {ok:false, reason:'editable_fields_present', count:editable.length};
        const dialogs = [...document.querySelectorAll('[role="dialog"],dialog,[aria-modal="true"]')].filter(visible);
        const scope = dialogs.find(el => el.querySelector('button,[role="button"],input[type="submit"]')) || document;
        const buttons = [...scope.querySelectorAll('button,[role="button"],input[type="submit"]')]
          .filter(enabled)
          .filter(el => {
            const text = [el.innerText, el.textContent, el.value, el.getAttribute('aria-label'), el.getAttribute('title')]
              .filter(Boolean).join(' ').trim().toLowerCase();
            return !/cookie|preference|privacy|details|詳細|详(?:情|细)/i.test(text);
          });
        const button = buttons.find(el => String(el.getAttribute('type') || '').toLowerCase() === 'submit')
          || (buttons.length === 1 ? buttons[0] : null);
        if (!button) return {ok:false, reason:'safe_button_count', count:buttons.length, dialogs:dialogs.length};
        button.scrollIntoView({block:'center', inline:'nearest'});
        button.click();
        return {ok:true, reason:scope === document ? 'single_safe_page_button_clicked' : 'dialog_primary_button_clicked'};
        """) or {}
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _click_if_enabled_submit(driver) -> bool:
    """提交资料页：优先 form.requestSubmit/button[type=submit]，不依赖按钮文字。"""
    try:
        target = driver.execute_script(r"""
        const visible = (el) => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const forms = [...document.querySelectorAll('form')].filter(visible);
        for (const form of forms) {
          const submit = form.querySelector('button[type="submit"], input[type="submit"]');
          if (submit && visible(submit)) {
            const isEnabled = !submit.disabled && String(submit.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            if (isEnabled) {
              submit.scrollIntoView({block:'center'});
              return submit;
            }
            // 提交按钮存在但处于禁用状态，说明表单验证未通过，不能提前触发提交
            return null;
          }
          if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return 'submitted_by_requestSubmit';
          }
        }
        const submitters = [...document.querySelectorAll('button[type="submit"], input[type="submit"]')]
          .filter(el => visible(el) && !el.disabled);
        if (submitters.length) {
          submitters[0].scrollIntoView({block:'center'});
          return submitters[0];
        }
        // 兜底：页面只有一个可点击 button 时点击它，但仍不读文字。
        const buttons = [...document.querySelectorAll('button:not([disabled])')].filter(visible);
        if (buttons.length === 1) {
          buttons[0].scrollIntoView({block:'center'});
          return buttons[0];
        }
        return null;
        """)
        if not target:
            return False
        if isinstance(target, str):
            return True
        _human_click(driver, target, label="profile_submit")
        return True
    except Exception:
        return False


def _read_chatgpt_session_once(driver) -> dict | None:
    """Read session in the current browser; log only status and safe diagnostics."""
    script = r"""
    const done = arguments[0];
    fetch('/api/auth/session', {credentials: 'include'})
      .then(async r => {
        const contentType = r.headers.get('content-type') || '';
        let data = {};
        if (contentType.toLowerCase().includes('application/json')) {
          try { data = await r.json(); } catch (_) {}
        }
        done({ok: r.ok, status: r.status, contentType: contentType.slice(0, 80),
              data: data && typeof data === 'object' ? data : {}});
      })
      .catch(e => done({ok: false, status: 0, errorType: e && e.name || 'FetchError'}));
    """
    result = driver.execute_async_script(script) or {}
    data = result.get("data") or {}
    if result.get("ok") and isinstance(data, dict) and data.get("accessToken"):
        logger.info("%s /api/auth/session status=%s accessToken=present", _log_prefix(driver), result.get("status"))
        return data
    # Do not log response bodies, cookies, tokens, e-mail, or query strings.
    status = result.get("status")
    error_type = result.get("errorType")
    logger.info("%s /api/auth/session status=%s content_type=%s token=absent error_type=%s",
                _log_prefix(driver), status, result.get("contentType"), error_type)
    return None


def _switch_to_chatgpt_window_if_any(driver) -> bool:
    """有些浏览器/适配层会在新窗口完成 callback；尝试切到已有 chatgpt.com 句柄。"""
    try:
        handles = list(getattr(driver, "window_handles", []) or [])
        current_handle = None
        try:
            current_handle = getattr(driver, "current_window_handle", None)
        except Exception:
            current_handle = None
        for handle in handles:
            try:
                driver.switch_to.window(handle)
                if "chatgpt.com" in str(getattr(driver, "current_url", "") or ""):
                    return True
            except Exception:
                continue
        if current_handle is not None:
            try:
                driver.switch_to.window(current_handle)
            except Exception:
                pass
    except Exception:
        pass
    return False


def _fetch_chatgpt_session(driver, timeout: int = 90, auto_jump_wait: int = 15) -> dict:
    """等待页面完成跳转并从 ChatGPT 页面内读取登录 session/accessToken。

    旧逻辑会在 auth.openai.com 上一直等到总超时，Cloak/部分 Chromium 场景下
    实际账号已创建成功但当前句柄 URL 没及时更新，导致白等 120 秒。现在只给
    自动跳转 `auto_jump_wait` 秒；超过后立即主动打开 chatgpt.com 读 session。
    """
    end = time.time() + timeout
    auto_jump_end = time.time() + max(3, int(auto_jump_wait or 15))
    last_data = None
    forced_chatgpt_open = False
    last_stage = None

    while time.time() < end:
        try:
            current = str(driver.current_url or '')
        except Exception:
            current = ''

        # Log only host and path. Query strings may contain OAuth codes and state.
        from urllib.parse import urlsplit
        parsed = urlsplit(current)
        stage = (parsed.hostname or "unknown", parsed.path[:100])
        if stage != last_stage:
            logger.info("%s session_wait host=%s path=%s", _log_prefix(driver), *stage)
            last_stage = stage
        if 'chatgpt.com' not in current:
            if _switch_to_chatgpt_window_if_any(driver):
                current = str(getattr(driver, "current_url", "") or "")
            else:
                if "auth.openai.com" in current:
                    confirmation = _click_final_confirmation_if_present(driver)
                    if confirmation.get("ok"):
                        logger.info("%s 已点击 OAuth 最终确认按钮，继续等待 callback", _log_prefix(driver))
                        time.sleep(2)
                        continue
            # 如果还在 auth.openai.com 并且尚未跳出，说明 OAuth 认证或重定向正在进行中，
            # 绝不能提前强制跳往 chatgpt.com（否则会截断 auth callback 并丢失 session cookies）。
            # 只有在非 auth.openai.com 页面且经过了充足时间后才尝试主动访问 chatgpt.com。
            if 'chatgpt.com' not in current and "auth.openai.com" not in current and time.time() >= auto_jump_end and not forced_chatgpt_open:
                try:
                    logger.info("%s 未在 %ss 内观察到当前窗口跳转 chatgpt.com，主动打开 ChatGPT 内读取 session", _log_prefix(driver), int(auto_jump_wait or 15))
                    _safe_get(driver, "https://chatgpt.com/", timeout=35, attempts=2, accept_hosts=("chatgpt.com",))
                    forced_chatgpt_open = True
                    time.sleep(3)
                    current = str(getattr(driver, "current_url", "") or "")
                except Exception as exc:
                    last_data = f"{type(exc).__name__}: {exc}"
            elif 'chatgpt.com' not in current:
                time.sleep(1)
                continue

        if 'chatgpt.com' in current:
            try:
                # 立即停止 ChatGPT 首页继续拉取庞大的 Next.js SPA、KaTeX、媒体与统计资源，节省 10~20MB 流量
                driver.execute_script("window.stop();")
            except Exception:
                pass
            try:
                data = _read_chatgpt_session_once(driver)
                if data:
                    try:
                        driver.execute_script("window.stop();")
                        driver.get("about:blank")
                    except Exception:
                        pass
                    return data
                last_data = "session 暂无 accessToken"
            except Exception as exc:
                message = str(exc).lower()
                if "targetclosed" in message or "target page, context or browser has been closed" in message:
                    raise RuntimeError("AntBrowser 页面上下文已关闭") from exc
                last_data = f"{type(exc).__name__}: {exc}"
        time.sleep(2)

    raise RuntimeError(f"等待 /api/auth/session accessToken 超时；最后页面={last_stage}；读取状态={str(last_data)[:120]}")


def _check_manual_stop() -> None:
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        return


def run_roxy_registration(
    email: str | None,
    name: str,
    birthday: str,
    proxy: str = None,
    otp_code: str = None,
    batch_dir: Path | None = None,
    on_email_acquired: Callable[[str], None] | None = None,
) -> dict:
    """Roxy 指纹浏览器自动化注册入口。"""
    if bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False)):
        from core.antbrowser_registration import run_ant_registration
        return run_ant_registration(email=email, name=name, birthday=birthday, proxy=proxy,
                                    otp_code=otp_code, batch_dir=batch_dir, on_email_acquired=on_email_acquired,
                                    force_headless=True)
    client = RoxyBrowserClient()
    # 必须先进入统一 try/finally：create 成功后即使 open/build driver 失败，也要回收临时环境。
    opened = None
    driver = None
    create_acknowledged = False
    openai_password: str | None = None
    traffic_tracker: SeleniumTrafficTracker | None = None
    data_saver: BrowserDataSaver | None = None
    network_traffic: dict | None = None

    def _traffic_checkpoint() -> None:
        if traffic_tracker is not None:
            try:
                traffic_tracker.checkpoint()
            except Exception as exc:
                logger.debug("[Roxy注册] 刷新浏览器流量统计失败：%s", exc)

    try:
        opened = client.open_profile()
        driver = _build_driver(opened)
        try:
            from core import registration_service as svc
            current_job_id = getattr(svc._THREAD_CTX, "job_id", None)
            if current_job_id is not None:
                svc.register_job_driver(current_job_id, driver)
        except Exception:
            pass
        try:
            traffic_tracker = SeleniumTrafficTracker(driver, label="Roxy")
        except Exception as exc:
            # 统计失败不应影响注册主流程。
            logger.warning("[Roxy注册] 初始化浏览器流量统计失败，继续注册：%s: %s", type(exc).__name__, str(exc)[:180])
        data_saver = BrowserDataSaver(label="Roxy")
        if traffic_tracker is not None:
            traffic_tracker.attach_data_saver(data_saver)
        data_saver.install_selenium(driver)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(_cfg.ROXY_SELENIUM_TIMEOUT))
        try:
            driver.set_script_timeout(12)
        except Exception:
            pass
        logger.info("[Roxy注册] 开始：%s，profile=%s", email, opened.profile_id)

        otp_after_ts = time.time()
        logger.info("[Roxy注册] 打开登录页：https://chatgpt.com/auth/login")
        _safe_get(
            driver,
            "https://chatgpt.com/auth/login",
            timeout=min(45, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)),
            attempts=2,
            accept_hosts=("chatgpt.com", "auth.openai.com"),
        )
        _traffic_checkpoint()
        human_delay("navigate")
        _page_warmup(driver, reason="login_page")
        logger.info("[Roxy注册] 登录页加载完成，准备填写邮箱")
        _maybe_accept(driver)
        _check_manual_stop()

        # 填邮箱。OpenAI UI 会随出口 IP/语言变化；这里只按 DOM 技术属性找邮箱入口，
        # 并排除 Google/Apple/Microsoft 等第三方入口，不依赖按钮可见文字。
        def _email_supplier_after_input() -> str:
            nonlocal email
            _check_manual_stop()
            email = acquire_email_after_input(email)
            if on_email_acquired:
                on_email_acquired(email)
            return email

        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=3,
            email_supplier=_email_supplier_after_input,
        )
        _traffic_checkpoint()
        _check_manual_stop()

        # 新版注册流如果邮箱后直接进入验证码页，也优先点击“使用密码继续”进入
        # /create-account/password，设置密码并把密码写入账号 extra.registration_password。
        openai_password = _fill_password_page_if_present(driver, email, timeout=25)
        _traffic_checkpoint()
        _check_manual_stop()

        current_otp = otp_code
        max_otp_attempts = 3
        for otp_attempt in range(1, max_otp_attempts + 1):
            if current_otp is None:
                logger.info("[Roxy注册][OTP] 等待验证码：%s（第 %s/%s 次）", email, otp_attempt, max_otp_attempts)
                try:
                    current_otp = wait_for_otp(email, after_ts=otp_after_ts)
                except Exception as exc:
                    from core.email_provider import reject_remail_after_otp_timeout
                    reject_remail_after_otp_timeout(email, exc)
                    if otp_attempt >= max_otp_attempts:
                        raise
                    # 兜底：OpenAI 重发验证码时常常是同一封邮件（时间戳不变），
                    # after_ts 过滤会把它当成旧邮件忽略。先宽松取最新一条验证码，
                    # 取到就直接用它重试提交，避免误点“重新发送”后死等。
                    fallback_otp = None
                    try:
                        fallback_otp = wait_for_otp(email, after_ts=0.0, max_wait=15, poll_interval=3)
                    except Exception:
                        fallback_otp = None
                    if fallback_otp:
                        logger.info(
                            "[Roxy注册][OTP] 取码接口超时但宽松取到最新验证码，直接重试提交：%s (fallback)",
                            fallback_otp,
                        )
                        current_otp = fallback_otp
                        continue
                    logger.warning(
                        "[Roxy注册][OTP] 一直未收到验证码，点击“重新发送电子邮件”后继续等待（下一轮 %s/%s）：%s: %s",
                        otp_attempt + 1,
                        max_otp_attempts,
                        type(exc).__name__,
                        str(exc)[:180],
                    )
                    otp_after_ts = time.time()
                    _click_resend_email_otp(driver, timeout=25)
                    human_delay("api")
                    current_otp = None
                    continue
            logger.info("[Roxy注册][OTP] 收到验证码：%s", current_otp)
            if _recover_email_otp_http_500(driver, email):
                otp_after_ts = time.time()
                current_otp = None
                continue
            _clear_otp_inputs(driver)
            _type_otp(driver, current_otp)
            logger.info("[Roxy注册][OTP] 已填写邮箱验证码")
            _check_manual_stop()
            human_delay("otp_input")
            try:
                _click_continue(driver)
                logger.info("[Roxy注册][OTP] 已提交邮箱验证码，等待资料页或登录态")
            except Exception as exc:
                logger.info("[Roxy注册][OTP] 未找到显式提交按钮，继续等待页面状态：%s", str(exc)[:120])

            outcome = _wait_after_email_otp_submit(driver, timeout=30)
            _traffic_checkpoint()
            if outcome == 'accepted':
                break
            if otp_attempt >= max_otp_attempts:
                raise RuntimeError("邮箱验证码连续错误/过期，已达到最大重试次数")
            logger.warning("[Roxy注册][OTP] 验证码错误/过期，准备重新发送并重新获取验证码（%s/%s）", otp_attempt + 1, max_otp_attempts)
            otp_after_ts = time.time()
            _click_resend_email_otp(driver, timeout=25)
            _traffic_checkpoint()
            human_delay("api")
            current_otp = None

        # about-you / profile 信息页：必须完成或确认已有登录态，不能静默跳过。
        logger.info("[Roxy注册] 开始等待资料页/登录态")
        _check_manual_stop()
        profile_submitted = _complete_profile_page(driver, name, birthday, timeout=60)
        _traffic_checkpoint()
        if profile_submitted:
            create_acknowledged = True
            # 给 OAuth 回调 / session cookie 写入一点时间。
            human_delay("post_auth")

        logger.info("[Roxy注册] 等待 ChatGPT 跳转并写入 session/accessToken")
        _check_manual_stop()
        session_info = _fetch_chatgpt_session(driver, timeout=120)
        _traffic_checkpoint()
        access_token = session_info["accessToken"]
        logger.info("[Roxy注册] 已拿到 accessToken：%s", email)
        _check_manual_stop()

        codex_auto = False
        try:
            from config import codex as _codex_cfg
            codex_auto = bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False))
        except Exception:
            codex_auto = False

        if not codex_auto:
            # 注册凭证已完整获取，跳过 Codex 时立即切往空白页并开启全局拦截，
            # 彻底阻断 ChatGPT 首页在后台下载数十个 SPA chunk / KaTeX / 媒体 / 统计（节约 8~12MB 流量）
            try:
                driver.execute_script("window.stop();")
                driver.get("about:blank")
            except Exception:
                pass
            if data_saver is not None:
                data_saver.block_all()

        totp_secret = None
        if _twofa_cfg.ENABLE_2FA:
            logger.info("[Roxy注册] 2FA 已启用，账号落库后由统一 2FA 服务在后台异步自动入队")

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg
            if bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False)):
                # 注册流程本身已创建 Roxy 一号一环境。这里不能再新建第二个 Roxy 环境；
                # 复用当前注册窗口，先清理 Cookie/session/localStorage/cache，再开始 Codex 授权。
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=True，复用当前注册 Roxy 窗口执行 Codex 授权，不创建新环境")
                _check_manual_stop()
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
                _traffic_checkpoint()
            else:
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=False，注册后跳过 Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        if codex_auto:
            try:
                driver.execute_script("window.stop();")
                driver.get("about:blank")
            except Exception:
                pass
            if data_saver is not None:
                data_saver.block_all()

        # 统计注册浏览器关闭前的完整会话；注册后停留期间的网络请求也计入。
        # 注册成功后立即收尾，不额外停留阻塞窗口
        _traffic_checkpoint()
        if traffic_tracker is not None:
            network_traffic = traffic_tracker.stop()
        if data_saver is not None:
            data_saver.stop()
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=proxy or None,
            batch_dir=batch_dir,
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "roxybrowser": {"profile_id": opened.profile_id, "open_result": opened.raw},
                "registration_password": openai_password,
                "codex": codex_result,
                "network_traffic": network_traffic,
            },
        )
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        return {
            "success": bool(codex_ok),
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "codex": codex_result,
            "network_traffic": network_traffic,
            "error": None if codex_ok else f"Codex 未完成: {codex_result.get('message')}",
        }
    except Exception as exc:
        if traffic_tracker is not None:
            try:
                network_traffic = traffic_tracker.stop()
            except Exception:
                pass
        if data_saver is not None:
            data_saver.stop()
        logger.error("[Roxy注册] 失败：%s: %s", type(exc).__name__, exc)
        logger.debug("[Roxy注册] 失败详情", exc_info=True)
        # 未确认创建前回收邮箱；确认后避免重复使用。
        try:
            if email:
                from core.email_provider import release_email
                release_status = getattr(exc, "email_release_status", "failed" if create_acknowledged else "available")
                release_email(email, status=release_status, note=f"Roxy注册失败: {str(exc)[:180]}")
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "network_traffic": network_traffic,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        }
    finally:
        if traffic_tracker is not None:
            try:
                traffic_tracker.stop()
            except Exception:
                pass
        if data_saver is not None:
            data_saver.stop()
        if driver and not bool(_cfg.ROXY_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
        try:
            from core import registration_service as svc
            current_job_id = getattr(svc._THREAD_CTX, "job_id", None)
            if current_job_id is not None:
                svc.unregister_job_driver(current_job_id)
        except Exception:
            pass
        if not bool(_cfg.ROXY_KEEP_BROWSER_OPEN):
            client.cleanup_profile(opened)
