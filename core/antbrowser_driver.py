# -*- coding: utf-8 -*-
"""AntBrowserBrowser 的 Selenium 风格轻量适配层。"""
from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from config import antbrowser as _cfg
import requests
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)


@dataclass
class AntBrowserOpenResult:
    profile_id: str = "antbrowser"
    raw: dict | None = None


class AntBrowserElement:
    def __init__(self, page, locator=None, handle=None):
        self.page = page
        self.locator = locator
        self.handle = handle

    def _handle(self):
        if self.handle is not None:
            return self.handle
        if self.locator is not None:
            try:
                self.handle = self.locator.element_handle(timeout=5000)
            except Exception:
                return None
            return self.handle
        return None

    def _eval(self, expression: str, arg: Any = None) -> Any:
        try:
            if self.locator is not None:
                try:
                    return self.locator.evaluate(expression, arg, timeout=3000)
                except TypeError:
                    return self.locator.evaluate(expression, arg)
            return self.handle.evaluate(expression, arg)
        except Exception as exc:
            msg = str(exc)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                return None
            raise

    def _eval_handle(self, expression: str, arg: Any = None) -> Any:
        try:
            h = self._handle()
            if h is None:
                return None
            return h.evaluate_handle(expression, arg)
        except Exception as exc:
            msg = str(exc)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                return None
            raise

    def is_displayed(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_visible(timeout=800))
            return bool(self.handle.evaluate("el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'"))
        except Exception:
            return False

    def is_enabled(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_enabled(timeout=800))
            return bool(self.handle.evaluate("el => !el.disabled && el.getAttribute('aria-disabled') !== 'true'"))
        except Exception:
            return False

    def click(self) -> None:
        try:
            if self.locator is not None:
                self.locator.click(timeout=8000)
                return
        except Exception:
            pass
        try:
            if self.handle is not None:
                self.handle.click(timeout=8000)
                return
        except Exception:
            pass
        # 兜底：派发原生事件
        try:
            self._eval("""el => {
                el.dispatchEvent(new PointerEvent('pointerdown', {bubbles:true, cancelable:true, pointerType:'mouse'}));
                el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
                el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
                el.click();
            }""")
        except Exception:
            pass

    def clear(self) -> None:
        try:
            if self.locator is not None:
                self.locator.fill("", timeout=5000)
                return
        except Exception:
            pass
        try:
            if self.handle is not None:
                self.handle.fill("", timeout=5000)
                return
        except Exception:
            pass
        try:
            self._eval("""el => {
                if ('value' in el) {
                    el.value = '';
                    el.dispatchEvent(new Event('input', {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                }
            }""")
        except Exception:
            try:
                self.page.keyboard.press("Control+A")
                self.page.keyboard.press("Backspace")
            except Exception:
                pass

    @property
    def tag_name(self) -> str:
        try:
            return str(self._eval("el => el.tagName.toLowerCase()") or "")
        except Exception:
            return ""

    def send_keys(self, *values: str) -> None:
        text = "".join(str(v or "") for v in values)
        lower = text.lower()
        if "\ue03d" in text or "\ue009" in text or "command" in lower or "control" in lower:
            try:
                self.page.keyboard.press("Control+A")
            except Exception:
                pass
            return

        if "\ue003" in text:
            try:
                self.page.keyboard.press("Backspace")
            except Exception:
                pass
            return

        if "\ue017" in text:
            try:
                self.page.keyboard.press("Delete")
            except Exception:
                pass
            return

        if "\ue007" in text or "\ue006" in text:
            try:
                self.page.keyboard.press("Enter")
            except Exception:
                pass
            return

        try:
            self.page.keyboard.type(text, delay=10)
        except Exception:
            try:
                if self.locator is not None:
                    self.locator.type(text, delay=10, timeout=5000)
                elif self.handle is not None:
                    self.handle.type(text, delay=10, timeout=5000)
            except Exception as exc:
                logger.debug("[AntBrowser] send_keys 输入异常: %s", exc)

    def get_attribute(self, name: str) -> str | None:
        try:
            if self.locator is not None:
                return self.locator.get_attribute(name, timeout=1000)
            return self.handle.get_attribute(name)
        except Exception:
            return None


class _SwitchTo:
    def __init__(self, driver: "AntBrowserSeleniumDriver"):
        self._driver = driver

    def window(self, handle: str) -> None:
        self._driver._switch_window(handle)


class AntBrowserSeleniumDriver:
    """只实现本项目 Roxy Selenium 流程实际用到的 WebDriver 子集。"""

    def __init__(self, browser: Any, context: Any | None, page: Any):
        self.browser = browser
        self.context = context
        self.page = page
        self._page_load_timeout_ms = int(getattr(_cfg, "ANT_SELENIUM_TIMEOUT", 90) or 90) * 1000
        self._script_timeout_ms = 30000
        self.switch_to = _SwitchTo(self)
        try:
            self.page.set_default_navigation_timeout(self._page_load_timeout_ms)
            self.page.set_default_timeout(10000)
        except Exception:
            pass

    def set_script_timeout(self, seconds: float) -> None:
        self._script_timeout_ms = max(1000, int(float(seconds) * 1000))

    @property
    def current_url(self) -> str:
        return str(getattr(self.page, "url", "") or "")

    @property
    def window_handles(self) -> list[str]:
        pages = self._pages()
        return [str(i) for i in range(len(pages))]

    def _pages(self) -> list[Any]:
        try:
            if self.context is not None:
                return list(self.context.pages)
        except Exception:
            pass
        try:
            contexts = list(getattr(self.browser, "contexts", []) or [])
            pages = []
            for ctx in contexts:
                pages.extend(list(getattr(ctx, "pages", []) or []))
            return pages or [self.page]
        except Exception:
            return [self.page]

    def _switch_window(self, handle: str) -> None:
        pages = self._pages()
        idx = int(handle)
        self.page = pages[idx]
        try:
            self.page.bring_to_front()
        except Exception:
            pass

    def set_page_load_timeout(self, seconds: int) -> None:
        self._page_load_timeout_ms = int(seconds) * 1000
        try:
            self.page.set_default_navigation_timeout(self._page_load_timeout_ms)
        except Exception:
            pass

    def email_submit_state_native(self, expected_email: str = "") -> dict:
        """Read post-submit auth state without page.evaluate during navigation."""
        try:
            url = self.current_url
        except Exception as exc:
            return {
                "url": "",
                "state": "navigation_error",
                "inputs": [],
                "error": f"page_closed: {type(exc).__name__}: {exc}",
            }
        result = {"url": url, "state": "unknown", "inputs": []}
        lower_url = str(url or "").strip().lower()
        if not lower_url or lower_url == "about:blank" or lower_url.startswith("chrome-error://"):
            result["state"] = "navigation_error"
            result["error"] = "browser_navigation_failed"
            return result

        selectors = {
            "otp": 'input[autocomplete="one-time-code"],input[name="code"],input[inputmode="numeric"][maxlength="6"]',
            "password": 'input[type="password"],input[name*="password" i]',
            "email": (
                'input[type="email"],input[name="email"],input[name="username"],'
                'input[name="identifier"],input[autocomplete*="email"]'
            ),
        }
        for kind, selector in selectors.items():
            try:
                locator = self.page.locator(selector)
                count = min(int(locator.count()), 10)
            except Exception as exc:
                message = str(exc).lower()
                if any(token in message for token in (
                    "targetclosed", "target page, context or browser has been closed", "page has been closed",
                )):
                    result["state"] = "navigation_error"
                result["error"] = f"{type(exc).__name__}: {exc}"
                return result
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if not candidate.is_visible(timeout=400):
                        continue
                    if kind == "otp":
                        result["state"] = "otp"
                        return result
                    if kind == "password":
                        autocomplete = (candidate.get_attribute("autocomplete", timeout=400) or "").lower()
                        result["state"] = "login_password" if autocomplete == "current-password" or "/log-in/" in url else "password"
                        return result
                    value = candidate.input_value(timeout=400)
                    result["inputs"].append({"type": "email", "value": value})
                except Exception:
                    continue

        if result["inputs"]:
            expected = str(expected_email or "").strip().lower()
            values = [str(item.get("value") or "").strip().lower() for item in result["inputs"]]
            result["state"] = "email_page" if expected in values else "email_cleared"
        return result

    def navigation_state_native(self) -> dict:
        """Return minimal navigation readiness without evaluating page JavaScript."""
        result = {"url": self.current_url, "has_elements": False}
        try:
            locator = self.page.locator('input,button,a[role="button"]')
            result["has_elements"] = int(locator.count()) > 0
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    def get(self, url: str) -> None:
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)
        except Exception as exc:
            msg = str(exc)
            if "Timeout" in msg or "timeout" in msg:
                curr = (self.page.url or "").lower()
                if any(h in curr for h in ("chatgpt.com", "openai.com", "auth0.com")):
                    logger.info("[AntBrowser] goto 等待 domcontentloaded 超时，但已导航至目标域 (%s)，放行继续由后续流程等待元素", curr)
                    return
            raise

    def submit_email_native(self, email: str) -> dict:
        """使用 Playwright 原生动作提交邮箱；只有观察到页面迁移才报告成功。"""
        expected = str(email or "").strip()
        input_loc = self.page.locator(
            'input[type="email"],input[name="email"],input[name="username"],input[name="identifier"],'
            'input[autocomplete*="email"],input[placeholder*="email" i],input[aria-label*="email" i]'
        ).first
        try:
            input_loc.wait_for(state="visible", timeout=5000)
            curr_val = input_loc.input_value(timeout=2000).strip()
            if curr_val.lower() != expected.lower():
                input_loc.fill(expected, timeout=5000)
            actual = input_loc.input_value(timeout=2000).strip()
        except Exception as exc:
            return {"ok": False, "reason": "email_input_unavailable", "error": f"{type(exc).__name__}: {exc}"}
        if actual.lower() != expected.lower():
            return {"ok": False, "reason": "email_value_not_confirmed", "actual": actual}

        try:
            input_loc.dispatch_event("input")
            input_loc.dispatch_event("change")
        except Exception:
            pass

        initial_url = self.current_url

        def wait_transition(action: str, timeout: float = 5.0) -> dict:
            deadline = time.monotonic() + timeout
            last = None
            while time.monotonic() < deadline:
                state = self.email_submit_state_native(expected)
                last = state
                name = str(state.get("state") or "unknown")
                current_url = str(state.get("url") or "")
                if name == "navigation_error":
                    return {"ok": False, "reason": "navigation_error", "action": action, "state": state}
                if name in ("otp", "password", "login_password", "logged_in"):
                    return {"ok": True, "reason": f"{action}_next_state", "state": state}
                if current_url and current_url != initial_url and name != "email_page":
                    return {"ok": True, "reason": f"{action}_navigation_started", "state": state}
                time.sleep(0.25)
            return {"ok": False, "reason": "email_submit_not_confirmed", "action": action, "state": last}

        candidates = []
        try:
            form = input_loc.locator("xpath=ancestor::form[1]")
            candidates.append(form.locator('button[type="submit"],input[type="submit"]').first)
        except Exception:
            pass
        candidates.append(self.page.locator(
            'button[type="submit"], button:has-text("Continue"), button:has-text("続行"), '
            'button:has-text("Tiếp tục"), button:has-text("继续")'
        ).first)

        click_errors = []
        attempted_buttons = 0
        for index, submit in enumerate(candidates):
            try:
                if not submit.count() or not submit.is_visible(timeout=1000) or not submit.is_enabled(timeout=1000):
                    continue
                attempted_buttons += 1
                submit.click(timeout=5000, no_wait_after=True)
                result = wait_transition(f"playwright_native_click_{index + 1}")
                if result.get("ok") or result.get("reason") == "navigation_error":
                    return result
                # The first global submit selector can resolve to a non-email action.
                # Continue trying the remaining form-scoped/localized candidates.
                click_errors.append(f"candidate_{index + 1}: no_transition")
            except Exception as exc:
                click_errors.append(f"candidate_{index + 1}: {type(exc).__name__}: {exc}")

        enter_error = ""
        try:
            input_loc.focus()
            input_loc.press("Enter", timeout=5000, no_wait_after=True)
            result = wait_transition("playwright_native_enter")
            if result.get("ok") or result.get("reason") == "navigation_error":
                return result
        except Exception as exc:
            enter_error = f"{type(exc).__name__}: {exc}"
            result = {"ok": False, "reason": "email_submit_action_failed"}

        request_submit_error = ""
        try:
            requested = input_loc.evaluate(
                """el => {
                    const form = el && el.closest ? el.closest('form') : null;
                    if (!form) return false;
                    if (typeof form.requestSubmit === 'function') form.requestSubmit();
                    else form.submit();
                    return true;
                }""",
                timeout=3000,
            )
            if requested:
                requested_result = wait_transition("playwright_native_request_submit", timeout=8.0)
                if requested_result.get("ok") or requested_result.get("reason") == "navigation_error":
                    return requested_result
                result = requested_result
        except Exception as exc:
            request_submit_error = f"{type(exc).__name__}: {exc}"

        result = dict(result or {})
        result.setdefault("ok", False)
        result["reason"] = "email_submit_not_confirmed"
        result["attempted_buttons"] = attempted_buttons
        if click_errors:
            result["click_errors"] = click_errors
        if enter_error:
            result["enter_error"] = enter_error
        if request_submit_error:
            result["request_submit_error"] = request_submit_error
        return result

    def signup_password_targets_native(self) -> dict:
        """返回密码创建页的原生 Locator 包装，避免 DOM 节点嵌套序列化。"""
        inputs = self.page.locator(
            'input[type="password"],input[name*="password" i],input[autocomplete="new-password"]'
        )
        input_loc = None
        for idx in range(min(int(inputs.count()), 20)):
            candidate = inputs.nth(idx)
            try:
                if candidate.is_visible(timeout=500) and candidate.is_enabled(timeout=500):
                    input_loc = candidate
                    break
            except Exception:
                continue
        if input_loc is None:
            return {"ok": False, "reason": "missing_password_input"}

        form = input_loc.locator("xpath=ancestor::form[1]")
        scope = form if form.count() else self.page
        submitters = scope.locator('button[type="submit"],input[type="submit"]')
        button_loc = None
        for idx in range(min(int(submitters.count()), 20)):
            candidate = submitters.nth(idx)
            try:
                if candidate.is_visible(timeout=500) and candidate.is_enabled(timeout=500):
                    button_loc = candidate
                    break
            except Exception:
                continue
        if button_loc is None:
            return {"ok": False, "reason": "missing_enabled_submit"}

        try:
            text = button_loc.inner_text(timeout=1000).strip()[:80]
        except Exception:
            text = ""
        return {
            "ok": True,
            "reason": "playwright_native_password_targets",
            "input": AntBrowserElement(self.page, locator=input_loc),
            "button": AntBrowserElement(self.page, locator=button_loc),
            "text": text,
        }

    def submit_login_password_native(self, password: str) -> dict:
        """Fill and submit the visible login password form, confirming the action was accepted."""
        inputs = self.page.locator(
            'input[type="password"],input[name*="password" i],input[autocomplete="current-password"]'
        )
        input_loc = None
        for idx in range(min(int(inputs.count()), 20)):
            candidate = inputs.nth(idx)
            try:
                if candidate.is_visible(timeout=500) and candidate.is_enabled(timeout=500) and candidate.is_editable(timeout=500):
                    input_loc = candidate
                    break
            except Exception:
                continue
        if input_loc is None:
            return {"ok": False, "reason": "missing_password_input"}
        try:
            input_loc.fill(str(password), timeout=5000)
            actual = input_loc.input_value(timeout=2000)
        except Exception as exc:
            return {"ok": False, "reason": "password_fill_failed", "error": f"{type(exc).__name__}: {exc}"}
        if actual != str(password):
            return {"ok": False, "reason": "password_value_not_confirmed", "length": len(actual or "")}

        initial_url = self.current_url
        form = input_loc.locator("xpath=ancestor::form[1]")
        scope = form if form.count() else self.page
        submitters = scope.locator('button[type="submit"],input[type="submit"]')
        last_error = ""
        for idx in range(min(int(submitters.count()), 20)):
            button = submitters.nth(idx)
            try:
                if not button.is_visible(timeout=500) or not button.is_enabled(timeout=500):
                    continue
                button.click(timeout=5000, no_wait_after=True)
                return {"ok": True, "reason": "password_native_click", "url_before": initial_url}
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        try:
            input_loc.press("Enter", timeout=5000, no_wait_after=True)
            return {"ok": True, "reason": "password_native_enter", "url_before": initial_url, "click_error": last_error}
        except Exception as exc:
            return {
                "ok": False,
                "reason": "password_submit_action_failed",
                "click_error": last_error,
                "enter_error": f"{type(exc).__name__}: {exc}",
            }

    def login_password_diagnostics_native(self) -> dict:
        """Return non-secret password-page diagnostics for retry/error classification."""
        result = {"url": self.current_url, "input_present": False, "input_length": 0, "submit_enabled": False, "messages": []}
        try:
            password = self.page.locator('input[type="password"],input[name*="password" i],input[autocomplete="current-password"]').first
            if password.count() and password.is_visible(timeout=500):
                result["input_present"] = True
                result["input_length"] = len(password.input_value(timeout=500) or "")
        except Exception as exc:
            result["input_error"] = f"{type(exc).__name__}: {exc}"
        try:
            submit = self.page.locator('button[type="submit"],input[type="submit"]').first
            if submit.count() and submit.is_visible(timeout=500):
                result["submit_enabled"] = bool(submit.is_enabled(timeout=500))
        except Exception as exc:
            result["submit_error"] = f"{type(exc).__name__}: {exc}"
        try:
            alerts = self.page.locator('[role="alert"], [aria-live="assertive"], [class*="error" i]')
            for idx in range(min(int(alerts.count()), 10)):
                item = alerts.nth(idx)
                if item.is_visible(timeout=300):
                    value = " ".join(str(item.inner_text(timeout=500) or "").split())[:240]
                    if value and value not in result["messages"]:
                        result["messages"].append(value)
        except Exception as exc:
            result["message_error"] = f"{type(exc).__name__}: {exc}"
        return result

    def retry_login_password_enter_native(self) -> dict:
        try:
            password = self.page.locator('input[type="password"],input[name*="password" i],input[autocomplete="current-password"]').first
            if not password.count() or not password.is_visible(timeout=1000):
                return {"ok": False, "reason": "missing_password_input"}
            password.press("Enter", timeout=5000, no_wait_after=True)
            return {"ok": True, "reason": "password_enter_retry"}
        except Exception as exc:
            return {"ok": False, "reason": "password_enter_retry_failed", "error": f"{type(exc).__name__}: {exc}"}

    def continue_with_password_target_native(self) -> dict:
        """返回验证码页的“使用密码继续”控件，保留可点击的 Playwright Locator。"""
        candidates = self.page.locator('a,button,[role="link"],[role="button"]')
        password_terms = (
            "continue with password", "continue with a password",
            "パスワードで続行", "パスワード", "mật khẩu",
            "使用密码继续", "密码继续", "通过密码继续", "以密碼繼續",
            "비밀번호", "passwort", "contraseña", "mot de passe", "senha",
        )
        for idx in range(min(int(candidates.count()), 40)):
            candidate = candidates.nth(idx)
            try:
                if not candidate.is_visible(timeout=300) or not candidate.is_enabled(timeout=300):
                    continue
                href = str(candidate.get_attribute("href", timeout=300) or "").strip()
                # 必须严格排除任何包含 /log-in 的登录密码链接，防止新注册误跳入登录页
                if "/log-in" in href.lower():
                    continue
                text = str(candidate.inner_text(timeout=500) or "").strip()
                normalized = " ".join(text.lower().split())
                if "/create-account/password" not in href.lower() and not any(
                    term in normalized for term in password_terms
                ):
                    continue
                return {
                    "ok": True,
                    "reason": "playwright_native_continue_with_password",
                    "button": AntBrowserElement(self.page, locator=candidate),
                    "href": href,
                    "text": text[:80],
                }
            except Exception:
                continue
        return {"ok": False, "reason": "missing_continue_with_password"}

    def forgot_password_target_native(self) -> dict:
        """Return the live forgot-password link without serializing a DOM node."""
        candidates = self.page.locator('a[href*="reset-password" i],a,button,[role="link"],[role="button"]')
        forgot_terms = (
            "forgot password", "password forgotten", "reset password",
            "パスワードをお忘れですか", "パスワードをお忘れ", "忘记密码",
            "忘記密碼", "找回密码", "重置密码",
        )
        for idx in range(min(int(candidates.count()), 60)):
            candidate = candidates.nth(idx)
            try:
                if not candidate.is_visible(timeout=300) or not candidate.is_enabled(timeout=300):
                    continue
                href = str(candidate.get_attribute("href", timeout=300) or "").strip()
                text = str(candidate.inner_text(timeout=500) or "").strip()
                normalized = " ".join(text.lower().split())
                if "reset-password" not in href.lower() and not any(term in normalized for term in forgot_terms):
                    continue
                return {
                    "ok": True,
                    "reason": "playwright_native_forgot_password",
                    "button": AntBrowserElement(self.page, locator=candidate),
                    "href": href,
                    "text": text[:80],
                }
            except Exception:
                continue
        return {"ok": False, "reason": "missing_forgot_password_link"}

    def mfa_targets_native(self) -> dict:
        """Return live Playwright-backed MFA controls without serializing DOM handles."""
        input_loc = self.page.locator(
            'input[name="code"], input[autocomplete="one-time-code"], input[maxlength="6"]'
        ).filter(visible=True).first
        try:
            if input_loc.count() < 1 or not input_loc.is_visible(timeout=1000):
                return {"ok": False, "reason": "missing_code_input"}
        except Exception:
            return {"ok": False, "reason": "missing_code_input"}

        form = input_loc.locator("xpath=ancestor::form[1]")
        scope = form if form.count() else self.page.locator("body")
        buttons = scope.locator('button[type="submit"], button[data-dd-action-name="Continue"], button')
        input_box = input_loc.bounding_box()
        for index in range(min(buttons.count(), 20)):
            button = buttons.nth(index)
            try:
                if not button.is_visible(timeout=300) or not button.is_enabled(timeout=300):
                    continue
                button_box = button.bounding_box()
                if input_box and button_box and button_box["y"] < input_box["y"] + input_box["height"] - 10:
                    continue
                return {
                    "ok": True,
                    "reason": "playwright_native_mfa_targets",
                    "input": AntBrowserElement(self.page, locator=input_loc),
                    "button": AntBrowserElement(self.page, locator=button),
                }
            except Exception:
                continue
        return {"ok": False, "reason": "missing_submit"}

    def back(self) -> None:
        self.page.go_back(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)

    def refresh(self) -> None:
        self.page.reload(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)

    def quit(self) -> None:
        # Ant owns the process: stop/delete via its API before CDP shutdown,
        # which can hang when the remote browser is unresponsive.
        opened = getattr(self, "_ant_cleanup_opened", None)
        if opened is not None:
            try:
                cleanup_ant_profile(opened)
            except Exception as exc:
                logger.warning("[AntCleanup] cleanup deferred for retry: %s", type(exc).__name__)
        try:
            if self.context is not None:
                self.context.close()
        except Exception:
            pass
        try:
            self.browser.close()
        except Exception:
            pass
        playwright = getattr(self, "_ant_playwright", None)
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass
            self._ant_playwright = None

    def find_elements(self, by: Any, selector: str) -> list[AntBrowserElement]:
        loc = self._locator(by, selector)
        try:
            count = min(int(loc.count()), 200)
        except Exception:
            count = 0
        return [AntBrowserElement(self.page, loc.nth(i)) for i in range(count)]

    def find_element(self, by: Any, selector: str) -> AntBrowserElement:
        els = self.find_elements(by, selector)
        if not els:
            raise RuntimeError(f"找不到页面元素: {selector}")
        return els[0]

    def _locator(self, by: Any, selector: str):
        by_s = str(by or "").lower()
        if "xpath" in by_s or str(selector).startswith("//"):
            return self.page.locator(f"xpath={selector}")
        return self.page.locator(selector)

    def execute_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=False)

    def execute_async_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=True)

    def execute_cdp_cmd(self, cmd: str, params: dict | None = None) -> Any:
        params = params or {}
        try:
            if getattr(self, "_cached_cdp_session", None) is None:
                self._cached_cdp_session = self.context.new_cdp_session(self.page) if self.context is not None else self.page.context.new_cdp_session(self.page)
            return self._cached_cdp_session.send(cmd, params)
        except Exception as exc:
            self._cached_cdp_session = None
            logger.debug("[AntBrowser] CDP 命令失败 %s: %s", cmd, exc)
            return None

    def _serialize_args(self, args: tuple[Any, ...]) -> tuple[AntBrowserElement | None, list[Any]]:
        """拆分 Selenium 脚本参数。

        Playwright 的 JSHandle/ElementHandle 不能可靠地嵌在 dict/list payload 中跨
        page.evaluate 传递；Selenium 脚本最常见模式是 `arguments[0]` 为元素，
        因此这里把第一个 AntBrowserElement 作为真实 DOM `el` 传入，其它参数保持
        JSON 可序列化。
        """
        first_el = args[0] if args and isinstance(args[0], AntBrowserElement) else None
        rest = list(args[1:] if first_el else args)
        cleaned = []
        for item in rest:
            if isinstance(item, AntBrowserElement):
                # 极少数脚本会传多个元素；用真实 handle 直接会在嵌套 payload 中失效，
                # 这里退化为 None，比把错误对象传进 JS 更安全。
                cleaned.append(None)
            else:
                cleaned.append(item)
        return first_el, cleaned

    @staticmethod
    def _unwrap_js_result(page, handle: Any) -> Any:
        try:
            element = handle.as_element()
        except Exception:
            element = None
        if element is not None:
            return AntBrowserElement(page, handle=element)
        try:
            return handle.json_value()
        except Exception as exc:
            msg = str(exc)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                logger.info("[AntBrowser] JS 执行后页面发生跳转，忽略返回值读取失败：%s", msg[:160])
                return {"ok": True, "reason": "navigation_after_script"}
            raise
        finally:
            try:
                handle.dispose()
            except Exception:
                pass

    def _evaluate(self, script: str, args: tuple[Any, ...], async_mode: bool) -> Any:
        first_el, serial_args = self._serialize_args(args)
        if async_mode:
            timeout_ms = getattr(self, "_script_timeout_ms", 30000) or 30000
            wrapper = f"""async ({{script, args}}) => {{
              return await new Promise((resolve) => {{
                const fn = new Function(...args.map((_, i) => 'a' + i), '__ant_done', script);
                const timer = setTimeout(() => resolve({{__ant_timeout:true}}), {timeout_ms});
                const __ant_done = (v) => {{ clearTimeout(timer); resolve(v); }};
                try {{ fn(...args, __ant_done); }} catch (e) {{ clearTimeout(timer); resolve({{ok:false, error:String(e)}}); }}
              }});
            }}"""
            element_wrapper = f"""async (el, payload) => {{
              const args = [el, ...payload.args];
              return await new Promise((resolve) => {{
                const fn = new Function(...args.map((_, i) => 'a' + i), '__ant_done', payload.script);
                const timer = setTimeout(() => resolve({{__ant_timeout:true}}), {timeout_ms});
                const __ant_done = (v) => {{ clearTimeout(timer); resolve(v); }};
                try {{ fn(...args, __ant_done); }} catch (e) {{ clearTimeout(timer); resolve({{ok:false, error:String(e)}}); }}
              }});
            }}"""
            if first_el is not None:
                result = first_el._eval(element_wrapper, {"script": script, "args": serial_args})
            else:
                try:
                    result = self.page.evaluate(wrapper, {"script": script, "args": serial_args})
                except Exception as exc:
                    msg = str(exc)
                    if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                        logger.info("[AntBrowser] 异步执行遇页面跳转，返回 None：%s", msg[:160])
                        time.sleep(0.5)
                        return None
                    raise
            if isinstance(result, dict) and result.get("__ant_timeout"):
                raise TimeoutError("execute_async_script timeout")
            return result

        # Selenium 脚本经常以 `return ...` 为主体；用 Function 保持语义。
        wrapper = """({script, args}) => {
          const fn = new Function(...args.map((_, i) => 'a' + i), script);
          return fn(...args);
        }"""
        element_wrapper = """(el, payload) => {
          const args = [el, ...payload.args];
          const fn = new Function(...args.map((_, i) => 'a' + i), payload.script);
          return fn(...args);
        }"""
        if first_el is not None:
            handle = first_el._eval_handle(element_wrapper, {"script": script, "args": serial_args})
        else:
            try:
                handle = self.page.evaluate_handle(wrapper, {"script": script, "args": serial_args})
            except Exception as exc:
                msg = str(exc)
                if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                    logger.info("[AntBrowser] 页面跳转导致上下文销毁，返回 None：%s", msg[:160])
                    time.sleep(0.5)
                    return None
                raise
        if handle is None:
            return None
        return self._unwrap_js_result(self.page, handle)


def _normalize_proxy(proxy: str | None) -> str | None:
    proxy = str(proxy or "").strip()
    if not proxy:
        return None
    from core.chatgpt_plan import normalize_proxy_url
    proxy = normalize_proxy_url(proxy)
    return proxy.replace("socks5h://", "socks5://")


def _mask_proxy(proxy: str | None) -> str:
    value = str(proxy or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    auth = "***:***@" if parsed.username or parsed.password else ""
    return f"{parsed.scheme}://{auth}{host}{port}"


def _detect_ant_exit_geo(proxy_url: str | None = None) -> dict:
    """按当前/代理出口检测地理信息，供 AntBrowser 显式 locale/timezone 使用。"""
    try:
        import requests
        from config import browser as _browser_cfg
        endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])[:2]
        timeout = min(float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 4) or 4), 4.0)
    except Exception:
        return {}
    proxies = None
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    for url in endpoints:
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            from core.session import BrowserSession
            geo = BrowserSession._normalize_geo_response(data)
            if geo.get("country") or geo.get("timezone"):
                logger.info(
                    "[AntBrowser] 出口IP地理信息：ip=%s country=%s city=%s timezone=%s",
                    geo.get("ip") or "?", geo.get("country") or "?", geo.get("city") or "?", geo.get("timezone") or "?",
                )
                return geo
        except Exception as exc:
            logger.debug("[AntBrowser] 出口 IP 地理检测失败 endpoint=%s: %s: %s", url, type(exc).__name__, exc)

    # 兜底：若网络端点均超时/失败，但代理 URL 显式包含区域特征（如 -region-JP / -region-IN）
    if proxy_url:
        import re
        m = re.search(r"-region-([a-zA-Z]{2})\b", proxy_url, re.I)
        if m:
            hint_country = m.group(1).upper()
            tz_map = {
                "IN": "Asia/Kolkata", "JP": "Asia/Tokyo", "US": "America/New_York",
                "SG": "Asia/Singapore", "GB": "Europe/London", "DE": "Europe/Berlin",
            }
            fallback_geo = {
                "ip": None,
                "country": hint_country,
                "region": None,
                "city": None,
                "timezone": tz_map.get(hint_country, "UTC"),
            }
            logger.info("[AntBrowser] 出口 IP 地理从代理参数回退识别: country=%s", hint_country)
            return fallback_geo
    return {}


def _build_ant_locale_options(proxy_url: str | None = None) -> dict:
    """生成 AntBrowser/Playwright 双层语言时区配置。"""
    explicit_locale = str(getattr(_cfg, "ANT_LOCALE", "") or "").strip()
    explicit_timezone = str(getattr(_cfg, "ANT_TIMEZONE", "") or "").strip()
    out = {}
    if explicit_locale:
        out["locale"] = explicit_locale
        # Accept-Language 用 config.browser 自动推断更完整；显式时给一个保守值。
        out["accept_language"] = f"{explicit_locale},{explicit_locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7"
    if explicit_timezone:
        out["timezone"] = explicit_timezone
    if explicit_locale and explicit_timezone:
        return out
    if not bool(getattr(_cfg, "ANT_GEOIP", True)):
        return out
    try:
        from config.browser import build_browser_environment
        geo = _detect_ant_exit_geo(proxy_url)
        profile = build_browser_environment(geo)
        out.setdefault("locale", str(profile.get("navigator_language") or ""))
        out.setdefault("timezone", str(profile.get("timezone_iana") or ""))
        out.setdefault("accept_language", str(profile.get("accept_language") or ""))
        out["geo"] = geo
    except Exception as exc:
        logger.debug("[AntBrowser] 构建自动语言/时区失败：%s: %s", type(exc).__name__, exc)
    return {k: v for k, v in out.items() if v}


def _ant_json(method: str, url: str, **kwargs):
    method_name = str(method or "GET").upper()
    # Ant Browser 的实例创建/启动会等待内核与用户目录初始化，繁忙时可能超过 15 秒。
    # 分离连接与读取超时：服务失联仍快速报错，正常的实例生命周期操作有完整执行时间。
    timeout = (5, 60) if method_name in {"POST", "PUT", "PATCH", "DELETE"} else (5, 20)
    response = requests.request(method_name, url, timeout=timeout, **kwargs)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = str(response.text or "").strip().replace("\r", " ").replace("\n", " ")
        detail = body[:500] or response.reason or "unknown error"
        raise RuntimeError(
            f"Ant Browser API {method_name} {response.status_code}: {detail} ({url})"
        ) from exc
    return response.json() if response.content else {}


def _launch_ant_profile(base: str, profile_id: str, launch_code: str) -> dict:
    """启动实例，并以 profile status 作为最终状态来源。

    Ant 在内核启动较慢时可能让 /api/launch 返回 500，但实例随后仍会进入
    debugReady。每次启动响应异常后先查询状态，仅在确认尚未启动时再次请求。
    """
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            _ant_json("POST", f"{base}/api/launch", json={"code": launch_code})
        except Exception as exc:
            last_error = exc
            logger.warning(
                "[AntBrowser] 启动接口异常，检查实例实际状态：profile=%s attempt=%s/3 error=%s",
                profile_id, attempt, str(exc)[:500],
            )

        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                status = _ant_json("GET", f"{base}/api/profiles/{profile_id}/status")
                if status.get("debugReady") or status.get("cdpUrl") or status.get("directDebugUrl"):
                    return status
            except Exception as exc:
                last_error = exc
            time.sleep(1)
        time.sleep(1.5)

    raise RuntimeError(
        f"Ant Browser 实例启动失败：profile={profile_id}; {str(last_error or '未进入 debugReady')[:500]}"
    )


def _cleanup_stale_ant_profiles(base: str) -> None:
    """Only remove old, confirmed stopped temporary profiles; never stop another job."""
    try:
        payload = _ant_json("GET", f"{base}/api/profiles")
        profiles = payload.get("items", payload.get("profiles", []))
    except Exception as exc:
        logger.debug("[AntBrowser] Profile cleanup listing failed: %s", type(exc).__name__)
        return
    now = time.time()
    active_keys = ("running", "debugReady", "cdpUrl", "directDebugUrl")
    for profile in profiles or []:
        name = str(profile.get("profileName") or "")
        pid = str(profile.get("profileId") or "")
        if not pid or not name.startswith("TurbGPT-"):
            continue
        if any(profile.get(key) for key in active_keys):
            continue
        try:
            created_ts = int(name[len("TurbGPT-"):].split("_")[0])
        except (ValueError, TypeError):
            continue
        # Allow creation/startup time; age alone is never grounds to stop a job.
        if created_ts <= 0 or now - created_ts <= 3600:
            continue
        try:
            status = _ant_json("GET", f"{base}/api/profiles/{pid}/status")
            if any(status.get(key) for key in active_keys):
                continue
            _ant_json("DELETE", f"{base}/api/profiles/{pid}")
            logger.info("[AntBrowser] Removed stopped stale temporary profile: %s", pid)
        except Exception as exc:
            logger.debug("[AntBrowser] Cleanup skipped profile=%s error=%s", pid, type(exc).__name__)


_PLAYWRIGHT_START_LOCK = threading.Lock()


def _safe_start_playwright(retries: int = 3, delay: float = 1.0):
    """安全启动 Playwright Sync API，加锁互斥启动防多线程并发管道竞争，并支持重试与异常兜底。"""
    last_err = None
    with _PLAYWRIGHT_START_LOCK:
        for attempt in range(1, retries + 1):
            try:
                return sync_playwright().start()
            except Exception as exc:
                last_err = exc
                logger.warning("[AntBrowser] Playwright 启动失败 (第 %s/%s 次)：%s", attempt, retries, exc)
                try:
                    asyncio.set_event_loop(asyncio.new_event_loop())
                except Exception:
                    pass
                time.sleep(delay)
    if last_err:
        raise last_err
    raise RuntimeError("Playwright 启动失败")


def _build_standalone_playwright_driver(effective_proxy: str | None, locale_options: dict, *, headless: bool = False):
    """显式有头模式下的兼容入口；无头模式不得调用此函数。"""
    pw = None
    browser = None
    try:
        pw = _safe_start_playwright()
        launch_kwargs: dict[str, Any] = {
            "headless": headless,
            "args": [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--use-angle=d3d11",
                "--enable-gpu",
                "--enable-webgl",
            ],
        }
        if effective_proxy:
            parsed = urlparse(effective_proxy)
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""
            launch_kwargs["proxy"] = proxy_dict

        browser = pw.chromium.launch(**launch_kwargs)
        context_kwargs: dict[str, Any] = {
            "viewport": {"width": 1280, "height": 800},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "ignore_https_errors": bool(effective_proxy and effective_proxy.startswith("http://127.0.0.1:")),
        }
        if locale_options.get("locale"):
            context_kwargs["locale"] = locale_options["locale"]
        if locale_options.get("timezone"):
            context_kwargs["timezone_id"] = locale_options["timezone"]
        if locale_options.get("accept_language"):
            context_kwargs["extra_http_headers"] = {"Accept-Language": locale_options["accept_language"]}
    
        context = browser.new_context(**context_kwargs)
        context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {}
        };
        try {
            Object.defineProperty(window, 'outerWidth', { get: () => (window.innerWidth || 1280) + 16 });
            Object.defineProperty(window, 'outerHeight', { get: () => (window.innerHeight || 800) + 87 });
            Object.defineProperty(window, 'screenX', { get: () => 0 });
            Object.defineProperty(window, 'screenY', { get: () => 0 });
            if (window.screen) {
                Object.defineProperty(screen, 'availHeight', { get: () => (screen.height || 800) - 40 });
            }
            if (window.Notification) {
                Object.defineProperty(Notification, 'permission', { get: () => 'default' });
            }
        } catch (e) {}
        if (navigator.userAgentData) {
            Object.defineProperty(navigator, 'userAgentData', {
                get: () => ({
                    brands: [
                        { brand: 'Not(A:Brand', version: '99' },
                        { brand: 'Google Chrome', version: '133' },
                        { brand: 'Chromium', version: '133' }
                    ],
                    mobile: false,
                    platform: 'Windows',
                    getHighEntropyValues: async () => ({
                        architecture: 'x86',
                        bitness: '64',
                        brands: [
                            { brand: 'Not(A:Brand', version: '99' },
                            { brand: 'Google Chrome', version: '133' },
                            { brand: 'Chromium', version: '133' }
                        ],
                        mobile: false,
                        model: '',
                        platform: 'Windows',
                        platformVersion: '15.0.0',
                        uaFullVersion: '133.0.6943.127'
                    })
                })
            });
        }
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        """)
        page = context.new_page()
        driver = AntBrowserSeleniumDriver(browser=browser, context=context, page=page)
        driver._ant_playwright = pw
        driver._registration_log_prefix = "[无头浏览器换绑]"
        driver.set_page_load_timeout(90)
        logger.info(
            "[AntBrowser] 已直接拉起内置无头浏览器：headless=%s proxy=%s",
            headless, _mask_proxy(effective_proxy) if effective_proxy else "direct",
        )
        return driver, AntBrowserOpenResult(
            profile_id="standalone-playwright",
            raw={
                "driver": "playwright",
                "proxy": effective_proxy,
                "locale": locale_options.get("locale"),
                "timezone": locale_options.get("timezone"),
            },
        )
    except Exception:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass
        raise


def build_ant_driver(proxy: str | None = None, *, force_headless: bool | None = None, ant_headless: bool = False, playwright_instance=None):
    """连接 Ant Browser；无头运行必须使用临时 Ant 实例，且不得回退内置 Chromium。"""
    base = str(getattr(_cfg, "ANT_API_BASE", "http://127.0.0.1:19876") or "").rstrip("/")
    effective_proxy = _normalize_proxy(proxy)
    if proxy is None:
        from config import proxy as _proxy_cfg
        effective_proxy = _normalize_proxy(_proxy_cfg.pick_proxy())
    locale_options = _build_ant_locale_options(effective_proxy)
    static_proxy = None
    browser_proxy = effective_proxy

    if force_headless is True:
        ant_headless = True  # All headless runs use an isolated Ant profile.

    try:
        _cleanup_stale_ant_profiles(base)
        profiles_resp = _ant_json("GET", f"{base}/api/profiles")
    except Exception as exc:
        if force_headless is not False:
            raise RuntimeError("Ant local API unavailable for headless profile") from exc
        headed = True
        logger.warning(
            "[AntBrowser] 本地 Ant API 无法连接（%s），降级为 Playwright 内置%s浏览器: %s",
            base, "有头" if headed else "无头", exc,
        )
        driver, opened = _build_standalone_playwright_driver(browser_proxy, locale_options, headless=not headed)
        opened.raw.update({"proxy": effective_proxy, "static_asset_proxy": static_proxy})
        return driver, opened

    profiles = profiles_resp.get("items", profiles_resp.get("profiles", []))
    profile_id = str(getattr(_cfg, "ANT_PROFILE_ID", "") or "").strip()
    launch_code = str(getattr(_cfg, "ANT_LAUNCH_CODE", "") or "").strip()
    selected = next((p for p in profiles if profile_id and str(p.get("profileId")) == profile_id), None)
    if selected is None and launch_code:
        selected = next((p for p in profiles if str(p.get("launchCode")) == launch_code), None)
    ephemeral = False
    if ant_headless:
        selected = None  # Never change or reuse the user's existing profile.
    if selected is None and (ant_headless or bool(getattr(_cfg, "ANT_AUTO_CREATE", True))):
        fingerprint_args = [
            "--fingerprint-brand=Chrome",
            "--fingerprint-platform=windows",
        ]
        if locale_options.get("locale"):
            fingerprint_args.append(f"--lang={locale_options['locale']}")
        if locale_options.get("accept_language"):
            fingerprint_args.append(f"--accept-lang={locale_options['accept_language']}")
        if locale_options.get("timezone"):
            fingerprint_args.append(f"--timezone={locale_options['timezone']}")
        fingerprint_args.extend([
            "--disable-non-proxied-udp",
        ])
        profile_payload = {
            "profileName": f"TurbGPT-{int(time.time())}",
            "fingerprintArgs": fingerprint_args,
        }
        if ant_headless:
            profile_payload["launchArgs"] = ["--headless=new", "--disable-gpu", "--disable-sync", "--no-first-run"]
        if effective_proxy:
            profile_payload["proxyConfig"] = browser_proxy
        created_resp = _ant_json(
            "POST",
            f"{base}/api/profiles",
            json={"profile": profile_payload},
        )
        selected = created_resp.get("profile") or created_resp.get("item")
        if not selected:
            raise RuntimeError("Ant Browser 创建实例返回数据为空")
        ephemeral = True
        created_profile_id = str(selected.get("profileId") or "")
        if created_profile_id:
            from core import ant_cleanup_journal as cleanup_journal
            cleanup_journal.record_owned(base, created_profile_id)
        logger.info("[AntLifecycle] created profile=%s", created_profile_id)

    if selected is None:
        raise RuntimeError("Ant Browser 没有可连接的运行实例，且自动创建未成功")
    if ant_headless and not ephemeral:
        raise RuntimeError("Ant headless requires a newly created isolated profile")
    pid = str(selected.get("profileId") or "")
    try:
        if ephemeral:
            created_launch_code = str(selected.get("launchCode") or "").strip()
            if not created_launch_code:
                raise RuntimeError("Ant Browser 创建实例未返回 launchCode")
            status = _launch_ant_profile(base, pid, created_launch_code)
        else:
            launch_code = str(selected.get("launchCode") or "").strip()
            if launch_code:
                status = _launch_ant_profile(base, pid, launch_code)
            else:
                status = _ant_json("GET", f"{base}/api/profiles/{pid}/status")
        deadline = time.time() + 30
        while not (status.get("debugReady") or status.get("cdpUrl") or status.get("directDebugUrl")) and time.time() < deadline:
            time.sleep(1)
            status = _ant_json("GET", f"{base}/api/profiles/{pid}/status")
        cdp = status.get("directDebugUrl") or status.get("cdpUrl")
        if not cdp:
            port = status.get("cdpPort") or status.get("debugPort")
            if port:
                cdp = f"http://127.0.0.1:{int(port)}"
        if not cdp:
            raise RuntimeError(f"Ant Browser 实例尚未准备好 CDP：{pid}")
        pw = None
        browser = None
        try:
            pw = playwright_instance if playwright_instance is not None else _safe_start_playwright()
            connect_deadline = time.time() + 15
            connect_err = None
            while time.time() < connect_deadline:
                try:
                    browser = pw.chromium.connect_over_cdp(cdp, timeout=10000)
                    if browser:
                        break
                except Exception as exc:
                    connect_err = exc
                    time.sleep(1)
            if not browser:
                raise RuntimeError(f"连接 Ant Browser CDP 失败 ({cdp}): {connect_err}") from connect_err
            contexts = list(browser.contexts)
            context = contexts[0] if contexts else browser.new_context()
            pages = list(context.pages)
            page = pages[0] if pages else context.new_page()
            driver = AntBrowserSeleniumDriver(browser=browser, context=context, page=page)
            driver._ant_playwright = None if playwright_instance is not None else pw
            driver._registration_log_prefix = "[Ant Browser注册]"
            driver.set_page_load_timeout(90)
            logger.info(
                "[AntBrowser] 实例已接管：profile=%s proxy=%s locale=%s timezone=%s ephemeral=%s",
                pid, _mask_proxy(effective_proxy) if effective_proxy else "direct",
                locale_options.get("locale") or "default", locale_options.get("timezone") or "default", ephemeral,
            )
            opened = AntBrowserOpenResult(
                profile_id=pid,
                raw={
                    "cdp": cdp,
                    "profile_id": pid,
                    "api_base": base,
                    "ephemeral": ephemeral,
                    "proxy": effective_proxy,
                    "static_asset_proxy": static_proxy,
                    "locale": locale_options.get("locale"),
                    "timezone": locale_options.get("timezone"),
                },
            )
            driver._ant_cleanup_opened = opened
            return driver, opened
        except Exception:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if pw is not None and playwright_instance is None:
                try:
                    pw.stop()
                except Exception:
                    pass
            raise
    except Exception:
        if static_proxy is not None:
            static_proxy.stop()
        if ephemeral and pid:
            try:
                cleanup_ant_profile(AntBrowserOpenResult(profile_id=pid,raw={
                    "ephemeral":True,"profile_id":pid,"api_base":base,
                }))
            except Exception as cleanup_exc:
                logger.warning("[AntBrowser] 创建失败后的实例清理已记录补偿 profile=%s: %s", pid, type(cleanup_exc).__name__)
        raise



def _cleanup_ant_profile_once(opened):
    raw = getattr(opened, "raw", {}) or {}
    static_proxy = raw.get("static_asset_proxy")
    try:
        if not raw.get("ephemeral") or not bool(getattr(_cfg, "ANT_DELETE_AFTER_RUN", True)):
            return
        base = str(raw.get("api_base") or getattr(_cfg, "ANT_API_BASE", "http://127.0.0.1:19876")).rstrip("/")
        pid = str(raw.get("profile_id") or "")
        if not pid:
            return
        def cleanup_request(method, url, *, allow_invalid_stop=False):
            try:
                return _ant_json(method, url), False
            except Exception as exc:
                # A concurrent cleanup may already have removed this exact
                # temporary profile. Treat explicit profile-not-found as done,
                # not arbitrary 404s, access errors or connection failures.
                error = str(exc).lower()
                if "404" in error and "profile not found" in error:
                    logger.info("[AntBrowser] 临时实例已不存在，清理完成：%s", pid)
                    return {}, True
                # Some Ant builds return HTTP 500 {error: invalid argument} when
                # stop is requested for an already-stopped profile.  The status
                # check below is authoritative, so this response is idempotent.
                if allow_invalid_stop and "500" in error and "invalid argument" in error:
                    logger.info("[AntLifecycle] stop_already_inactive profile=%s", pid)
                    return {}, False
                raise

        logger.info("[AntLifecycle] stop_request profile=%s", pid)
        _, absent = cleanup_request("POST", f"{base}/api/profiles/{pid}/stop", allow_invalid_stop=True)
        if absent:
            return
        deadline = time.time() + 20
        while time.time() < deadline:
            status, absent = cleanup_request("GET", f"{base}/api/profiles/{pid}/status")
            if absent:
                return
            if not any(status.get(key) for key in ("running", "debugReady", "cdpUrl", "directDebugUrl")):
                logger.info("[AntLifecycle] stopped profile=%s", pid)
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"Ant Browser 实例停止超时：{pid}")
        last_error = None
        for attempt in range(1, 6):
            try:
                logger.info("[AntLifecycle] delete_request profile=%s attempt=%s", pid, attempt)
                _, absent = cleanup_request("DELETE", f"{base}/api/profiles/{pid}")
                if not absent:
                    for verify_attempt in range(3):
                        _, absent = cleanup_request("GET", f"{base}/api/profiles/{pid}/status")
                        if absent:
                            break
                        time.sleep(0.5)
                    if not absent:
                        raise RuntimeError("Ant Browser delete not confirmed: " + pid)
                logger.info("[AntLifecycle] absent_confirmed profile=%s", pid)
                logger.info("[AntBrowser] 已停止并删除临时实例：%s", pid)
                return
            except Exception as exc:
                last_error = exc
                if "409" not in str(exc) or attempt >= 5:
                    raise
                time.sleep(attempt)
        if last_error:
            raise last_error
    finally:
        if static_proxy is not None:
            static_proxy.stop()


def cleanup_ant_profile(opened):
    """Record intent before API calls; preserve failures for bounded recovery."""
    from core import ant_cleanup_journal as journal
    raw = getattr(opened, "raw", {}) or {}
    if not raw.get("ephemeral") or not bool(getattr(_cfg, "ANT_DELETE_AFTER_RUN", True)):
        return _cleanup_ant_profile_once(opened)
    base = str(raw.get("api_base") or getattr(_cfg,"ANT_API_BASE","http://127.0.0.1:19876")).rstrip("/")
    pid = str(raw.get("profile_id") or "")
    if not pid:
        return _cleanup_ant_profile_once(opened)
    if not journal.claim(base,pid):
        logger.info("[AntLifecycle] cleanup_already_claimed profile=%s", pid)
        return
    logger.info("[AntLifecycle] cleanup_claimed profile=%s", pid)
    try:
        _cleanup_ant_profile_once(opened)
    except Exception as exc:
        journal.finish(base,pid,exc)
        logger.warning("[AntLifecycle] cleanup_pending profile=%s error=%s", pid, type(exc).__name__)
        raise
    else:
        journal.finish(base,pid)
        logger.info("[AntLifecycle] cleanup_done profile=%s", pid)
