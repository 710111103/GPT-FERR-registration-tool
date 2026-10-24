# -*- coding: utf-8 -*-
"""
真实浏览器环境预热模块（纯静默无头，零弹窗）
使用 Playwright Chromium 在后台加载 ChatGPT 首页，建立真实的 Cloudflare 上下文（__cf_bm, _cfuvid 等），
并无缝注入到 Python BrowserSession 中，让后续纯协议流程免遭 403 拦截。
"""
import json
import logging
import time
from urllib.parse import urlparse, unquote
from contextlib import contextmanager

from playwright.sync_api import sync_playwright

from core.session import BrowserSession

logger = logging.getLogger(__name__)


def capture_runtime_fingerprint(page, session: BrowserSession) -> dict:
    """采集运行时指纹摘要并和账号 profile 对账；不改写浏览器能力。"""
    try:
        snapshot = page.evaluate("""() => {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
          const audio = window.AudioContext || window.webkitAudioContext;
          const rtc = window.RTCPeerConnection;
          return {
            user_agent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            languages: Array.from(navigator.languages || []),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen: [screen.width, screen.height, window.devicePixelRatio],
            hardware_concurrency: navigator.hardwareConcurrency,
            device_memory: navigator.deviceMemory || null,
            webdriver: navigator.webdriver,
            canvas: (() => { try { return canvas.toDataURL().slice(0, 32); } catch (e) { return 'error'; } })(),
            webgl_vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null,
            webgl_renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null,
            audio_context: !!audio,
            plugins: navigator.plugins ? navigator.plugins.length : 0,
            fonts_api: !!document.fonts,
            media_devices: !!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices),
            webrtc: !!rtc
          };
        }""")
        if isinstance(snapshot, dict):
            session._runtime_fingerprint = snapshot
            profile = getattr(session, "browser_profile", {}) or {}
            mismatches = []
            if snapshot.get("language") != profile.get("navigator_language"):
                mismatches.append("language")
            if snapshot.get("timezone") != profile.get("timezone_iana"):
                mismatches.append("timezone")
            expected_screen = [profile.get("screen_width"), profile.get("screen_height"), profile.get("device_pixel_ratio")]
            if snapshot.get("screen") != expected_screen:
                mismatches.append("screen")
            if mismatches:
                logger.warning("[指纹对账] 运行时与账号画像不一致: %s", ",".join(mismatches))
            else:
                logger.info("[指纹对账] 运行时画像与账号 profile 一致")
            try:
                from core.task_observability import observe_runtime_environment
                observe_runtime_environment(session.fingerprint_summary(), snapshot)
            except Exception:
                logger.debug("[指纹对账] 写入结构化运行时环境失败", exc_info=True)
            return snapshot
    except Exception as exc:
        logger.debug("[指纹对账] 运行时快照失败: %s", exc)
    return {}


def _attach_playwright_protocol_trace(page, session: BrowserSession) -> None:
    """把无头浏览器里的关键 Auth XHR 追加到同一份协议 trace。"""
    trace_path = getattr(session, "_trace_path", None)
    if trace_path is None:
        return

    def on_response(response) -> None:
        url = str(getattr(response, "url", "") or "")
        if "auth.openai.com/api/" not in url:
            return
        try:
            req = response.request
            body = req.post_data
            record = {
                "ts": time.time(),
                "source": "playwright",
                "method": str(req.method or "GET"),
                "url": url,
                "request_headers": session._trace_redact(dict(req.headers or {})),
                "request_body": session._trace_redact(body),
                "status": int(response.status),
                "response_headers": session._trace_redact(dict(response.headers or {})),
            }
            try:
                record["response_body"] = session._trace_redact(response.json())
            except Exception:
                record["response_body"] = session._trace_redact(response.text())
            with session._trace_lock:
                with trace_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            if "email-otp/send" in url:
                setattr(session, "_playwright_otp_send_seen", True)
                logger.info("[抓包] Playwright 捕获 email-otp/send: method=%s status=%s", req.method, response.status)
        except Exception as exc:
            logger.debug("[抓包] Playwright response trace failed: %s", exc)

    page.on("response", on_response)


def sync_session_cookies_to_playwright(session: BrowserSession, ctx) -> int:
    """
    将 BrowserSession (curl_cffi) 的全部有效 Cookie 准确注入 Playwright 上下文。
    严格遵守 RFC 6265bis 与 Chromium 内核规范：
    - 对 __Host- 前缀的 cookie：绝对不能带 domain 属性，必须提供 url，且 secure 必须为 True。
    - 对 __Secure- 前缀的 cookie：必须设置 secure 为 True。
    - 普通 cookie 保持其对应的 domain、path 与 secure 状态。
    """
    cookies_to_add = []
    jar = getattr(getattr(session, "session", session), "cookies", None)
    cookie_jar = getattr(jar, "jar", None) or jar

    try:
        for c in cookie_jar:
            name = getattr(c, "name", "")
            value = getattr(c, "value", "")
            if not name:
                continue
            domain = str(getattr(c, "domain", "") or "").strip()
            path = str(getattr(c, "path", "/") or "/").strip() or "/"
            secure = bool(getattr(c, "secure", False))

            entry = {"name": name, "value": str(value)}
            if name.startswith("__Host-"):
                host = domain.lstrip(".") or "chatgpt.com"
                entry["url"] = f"https://{host}"
                entry["secure"] = True
            elif name.startswith("__Secure-"):
                host = domain.lstrip(".") or "chatgpt.com"
                entry["url"] = f"https://{host}"
                entry["secure"] = True
            else:
                if domain:
                    entry["domain"] = domain
                    entry["path"] = path
                else:
                    entry["url"] = "https://chatgpt.com"
                if secure:
                    entry["secure"] = True
            cookies_to_add.append(entry)
    except Exception as exc:
        logger.debug("[Cookie注入] 遍历 cookie_jar 提示: %s", exc)

    if not cookies_to_add:
        try:
            cookie_dict = session.session.cookies.get_dict()
            for name, value in cookie_dict.items():
                entry = {"name": name, "value": str(value)}
                if name.startswith("__Host-") or name.startswith("__Secure-"):
                    entry["url"] = "https://chatgpt.com"
                    entry["secure"] = True
                else:
                    entry["domain"] = ".chatgpt.com" if ("chatgpt" in name or "cf" in name or "next-auth" in name or "oai" in name) else ".openai.com"
                    entry["path"] = "/"
                cookies_to_add.append(entry)
        except Exception:
            pass

    injected = 0
    for cookie in cookies_to_add:
        try:
            ctx.add_cookies([cookie])
            injected += 1
        except Exception as e:
            logger.debug("[Cookie注入] 单条注入异常 %s: %s", cookie.get("name"), e)
    return injected


def sync_playwright_cookies_to_session(ctx, session: BrowserSession) -> int:
    """将 Playwright 上下文里的 Cookie 同步回 BrowserSession。"""
    cookies = ctx.cookies()
    synced = 0
    for c in cookies:
        c_name = c["name"]
        c_val = c["value"]
        c_domain = c.get("domain") or ".chatgpt.com"
        c_path = c.get("path") or "/"
        try:
            session.session.cookies.set(c_name, c_val, domain=c_domain, path=c_path)
            synced += 1
            if c_name == "oai-did":
                session.device_id = c_val
        except Exception as e:
            logger.debug("[Cookie同步] 同步失败 %s: %s", c_name, e)
    return synced


@contextmanager
def _browser_cleanup_scope():
    """Close an owned browser even when navigation or cookie syncing raises."""
    owned = []
    try:
        yield owned
    finally:
        if owned:
            try:
                owned[0].close()
            except Exception as exc:
                logger.warning("[AntCleanup] browser close failed: %s", type(exc).__name__)


class _AntManagedBrowser:
    """Expose Playwright's Browser API and clean up the isolated Ant profile."""
    def __init__(self, driver, opened):
        self.driver = driver
        self.opened = opened
        self.browser = driver.browser
        self._closed = False

    def new_context(self, **kwargs):
        return self.browser.new_context(**kwargs)

    def close(self):
        if self._closed:
            return
        from core.antbrowser_driver import cleanup_ant_profile
        try:
            self.driver.quit()
        finally:
            cleanup_ant_profile(self.opened)
        self._closed = True


def _create_stealth_context(p, session: BrowserSession, ua_override: str | None = None, proxy_dict: dict | None = None, headless: bool = True, cleanup_scope=None):
    """
    统一创建具备完整反反爬与真实指纹伪装的后台无头 Chromium 上下文。
    默认纯后台静默无头运行（零弹窗、零打扰）。
    """
    profile = getattr(session, "browser_profile", None) or {}
    ua = str(ua_override or profile.get("user_agent") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

    import os
    if headless is not None:
        is_headless = headless
    else:
        headless_setting = os.environ.get("BROWSER_HEADLESS", "True").strip().lower()
        is_headless = headless_setting in ("1", "true", "yes")
    logger.info("[浏览器模式] 启动模式: %s", "后台静默无头" if is_headless else "真实可见有头(Headed)")

    launch_args = {
        "headless": is_headless,
        "args": [
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
            "--use-angle=d3d11",
            "--enable-gpu",
            "--enable-webgl",
        ],
    }
    if proxy_dict:
        launch_args["proxy"] = proxy_dict

    if is_headless:
        from core.antbrowser_driver import build_ant_driver
        driver, opened = build_ant_driver(proxy=getattr(session, "proxy", None), force_headless=True, playwright_instance=p)
        browser = _AntManagedBrowser(driver, opened)
    else:
        browser = p.chromium.launch(**launch_args)
    if cleanup_scope is not None:
        cleanup_scope.append(browser)
    width = int(profile.get("screen_width") or 1280)
    height = int(profile.get("screen_height") or 800)
    locale = str(profile.get("navigator_language") or "en-US")
    timezone_id = str(profile.get("timezone_iana") or "UTC")
    dpr = float(profile.get("device_pixel_ratio") or 1)
    try:
        ctx = browser.new_context(
        viewport={"width": width, "height": height},
        screen={"width": width, "height": height},
        device_scale_factor=dpr,
        locale=locale,
        timezone_id=timezone_id,
        user_agent=ua,
        extra_http_headers={
            "accept-language": str(profile.get("accept_language") or locale),
            "sec-ch-ua": str(profile.get("sec_ch_ua") or '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"'),
            "sec-ch-ua-mobile": str(profile.get("sec_ch_ua_mobile") or "?0"),
            "sec-ch-ua-platform": str(profile.get("sec_ch_ua_platform") or '"macOS"'),
        },
    )
    except Exception:
        browser.close()
        raise

    try:
        from core.browser_data_saver import BrowserDataSaver
        saver = BrowserDataSaver(label="HeadlessSaver")
        if saver.enabled:
            saver.install_playwright(ctx)
            logger.info("[省流量] 已在无头浏览器中挂载极致省流拦截器（拦截图片/媒体/外部埋点）")
    except Exception as e:
        logger.debug("[省流量] 挂载拦截器提示: %s", e)

    ctx.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        window.chrome = { runtime: {} };
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
    """)
    # 覆盖自动化运行时默认值，使 JS 暴露面与同一份账号画像一致。
    platform = str(profile.get("navigator_platform") or "MacIntel")
    vendor = str(profile.get("navigator_vendor") or "Google Inc.")
    languages = profile.get("navigator_languages") or [locale]
    cores = int(profile.get("hardware_concurrency") or 8)
    memory = int(profile.get("device_memory") or 8)
    ua_data_platform = str(profile.get("user_agent_data_platform") or "macOS")
    ua_data_version = str(profile.get("chrome_major") or "146")
    ctx.add_init_script(f"""
        (() => {{
          const define = (obj, key, value) => {{ try {{ Object.defineProperty(obj, key, {{get: () => value, configurable: true}}); }} catch (e) {{}} }};
          define(navigator, 'platform', {json.dumps(platform)});
          define(navigator, 'vendor', {json.dumps(vendor)});
          define(navigator, 'language', {json.dumps(locale)});
          define(navigator, 'languages', {json.dumps(list(languages))});
          define(navigator, 'hardwareConcurrency', {cores});
          define(navigator, 'deviceMemory', {memory});
          define(window, 'devicePixelRatio', {dpr});
          if (navigator.userAgentData) {{
            define(navigator, 'userAgentData', {{
              brands: [
                {{brand: 'Not/A)Brand', version: '8'}},
                {{brand: 'Chromium', version: {json.dumps(ua_data_version)}}},
                {{brand: 'Google Chrome', version: {json.dumps(ua_data_version)}}}
              ], mobile: false, platform: {json.dumps(ua_data_platform)},
              getHighEntropyValues: async () => ({{platform: {json.dumps(ua_data_platform)}, platformVersion: {json.dumps(str(profile.get('sec_ch_ua_platform_version') or '15.0.0'))}, architecture: 'arm', model: '', uaFullVersion: {json.dumps(str(profile.get('chrome_full_version') or ua_data_version + '.0.0.0'))}}})
            }});
          }}
        }})();
    """)
    return browser, ctx


def prewarm_with_headless_browser(session: BrowserSession, timeout_ms: int = 20000) -> bool:
    """使用真实无头 Chromium 预热并同步 Cloudflare Cookie 到 session。"""
    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    logger.info("[环境预热] 启动后台真实浏览器内核（纯静默无头）建立 Cloudflare 上下文...")

    try:
        with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
            browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)
            page = ctx.new_page()

            # 访问 ChatGPT 登录页建立完整 NextAuth 与 Cloudflare 信任会话
            try:
                page.goto("https://chatgpt.com/auth/login", wait_until="domcontentloaded", timeout=timeout_ms)
                page.wait_for_timeout(2500)
            except Exception as nav_exc:
                logger.warning("[环境预热] 页面跳转超时，尝试提取已下发的 Cookie：%s", str(nav_exc)[:120])

            cookies = ctx.cookies()
            injected_count = sync_playwright_cookies_to_session(ctx, session)

            # 从 Cookie 中直接提取与 Cookie 完全一致的 CSRF Token
            extracted_csrf = None
            for c in cookies:
                if "csrf" in c["name"].lower():
                    raw = unquote(c["value"])
                    token = raw.split("|")[0].split("%7C")[0]
                    if token and len(token) >= 32:
                        extracted_csrf = token
                        break

            if extracted_csrf:
                setattr(session, "cached_csrf_token", extracted_csrf)
                logger.info("[环境预热] 从 Cookie 中成功提取 CSRF Token: %s...", extracted_csrf[:20])
            else:
                try:
                    csrf_token = page.evaluate('async () => { const r = await fetch("/api/auth/csrf"); const d = await r.json(); return d.csrfToken || ""; }')
                    if csrf_token:
                        setattr(session, "cached_csrf_token", csrf_token)
                        logger.info("[环境预热] 页面 fetch 提取 CSRF Token: %s...", csrf_token[:20])
                except Exception as csrf_exc:
                    logger.debug("[环境预热] fetch 提取 CSRF Token 提示: %s", csrf_exc)

            browser.close()
            logger.info("[环境预热] 真实浏览器环境预热完成，已同步 %d 个 Cookie 到协议会话", injected_count)

            # 清理可能的熔断状态
            reset = getattr(session, "reset_circuit_breaker", None)
            if callable(reset):
                reset()
            else:
                session.blocked_until = 0.0
                session.blocked_reason = ""
            return True
    except Exception as exc:
        logger.warning("[环境预热] 真实浏览器环境预热失败（降级继续纯协议）：%s: %s", type(exc).__name__, exc)
        return False



def _complete_password_setup_on_page(
    page,
    session: BrowserSession,
    *,
    email: str,
    otp_provider,
    password: str,
    otp_after_ts: float,
    template_path=None,
) -> dict:
    """Keep OTP validation and password submission inside the current browser transaction."""
    from pathlib import Path
    from core.password_setup_protocol import build_password_request_template
    from core.password_setup_service import _looks_like_password_submit

    captured = []
    response_statuses = []
    response_errors = []

    def on_request(req):
        try:
            url = str(getattr(req, "url", "") or "")
            method = str(getattr(req, "method", "POST") or "POST").upper()
            body = str(getattr(req, "post_data", "") or "")
            if "auth.openai.com" not in url or method not in {"POST", "PUT", "PATCH"}:
                return
            if not _looks_like_password_submit(url, body):
                return
            item = build_password_request_template(req)
            item["body"] = str(item.get("body") or "").replace(password, "$PASSWORD")
            captured.append(item)
        except Exception:
            pass

    def on_response(resp):
        try:
            req = resp.request
            url = str(getattr(req, "url", "") or "")
            body = str(getattr(req, "post_data", "") or "")
            if _looks_like_password_submit(url, body):
                response_statuses.append(int(resp.status))
                try:
                    text = str(resp.text() or "").replace(password, "<redacted>")
                    if text:
                        response_errors.append(text[:800])
                except Exception:
                    pass
        except Exception:
            pass

    page.on("request", on_request)
    page.on("response", on_response)

    otp_selectors = (
        "input[autocomplete='one-time-code']:visible",
        "input[name='code']:visible",
        "input[inputmode='numeric']:visible",
    )
    password_selector = "input[type='password']:visible:not([autocomplete*='current-password']):not([name='current-password'])"
    current_password_selector = "input[autocomplete*='current-password']:visible, input[name='current-password']:visible"

    def first_visible(selectors):
        for selector in selectors:
            try:
                loc = page.locator(selector).first
                if loc.count() and loc.is_visible():
                    return loc
            except Exception:
                continue
        return None

    # Existing accounts may first request their current password.  Imported
    # passwordless records must take the provider's recovery branch; never fill
    # a generated candidate into the current-password field.
    try:
        current_password_visible = page.locator(current_password_selector).count() > 0
    except Exception:
        current_password_visible = False
    if current_password_visible:
        forgot = first_visible((
            "a:has-text('Forgot password')", "button:has-text('Forgot password')",
            "a:has-text('パスワードをお忘れですか')", "button:has-text('パスワードをお忘れですか')",
            "a:has-text('忘记密码')", "button:has-text('忘记密码')",
            "a:has-text('忘記密碼')", "button:has-text('忘記密碼')",
        ))
        if not forgot:
            raise RuntimeError("browser_current_password_required")
        otp_after_ts = time.time() - 2.0
        forgot.click(timeout=4000)
        page.wait_for_timeout(800)

    # The identity shell may need a primary Continue click before the OTP input exists.
    deadline = time.monotonic() + 25.0
    otp_input = None
    while time.monotonic() < deadline:
        otp_input = first_visible(otp_selectors)
        try:
            if otp_input or page.locator(password_selector).count():
                break
        except Exception:
            pass
        page.wait_for_timeout(400)

    if otp_input:
        rejected = set()
        otp_validated = False
        for _attempt in range(2):
            try:
                code = otp_provider(email, after_ts=otp_after_ts, exclude_codes=rejected)
            except TypeError:
                code = otp_provider(email, after_ts=otp_after_ts)
            code = str(code or "").strip()
            if not code:
                raise RuntimeError("browser_otp_missing")
            otp_input.fill(code)
            submit = first_visible((
                "button[type='submit']:visible", "button:has-text('Continue'):visible",
                "button:has-text('続行'):visible", "button:has-text('继续'):visible",
                "button:has-text('繼續'):visible",
            ))
            if submit:
                submit.click()
            else:
                otp_input.press("Enter")
            transition = time.monotonic() + 20.0
            while time.monotonic() < transition:
                try:
                    if page.locator(password_selector).count():
                        otp_validated = True
                        break
                except Exception:
                    pass
                if not first_visible(otp_selectors):
                    # Some pages briefly remove OTP before rendering the password form.
                    page.wait_for_timeout(500)
                page.wait_for_timeout(300)
            if otp_validated:
                break
            rejected.add(code)
            otp_input = first_visible(otp_selectors)
            if not otp_input:
                break
        if not otp_validated:
            raise RuntimeError("browser_otp_validation_failed")

    password_deadline = time.monotonic() + 20.0
    while time.monotonic() < password_deadline:
        try:
            if page.locator(password_selector).count():
                break
        except Exception:
            pass
        page.wait_for_timeout(400)
    inputs = page.locator(password_selector)
    count = inputs.count()
    if count == 0:
        raise RuntimeError(f"browser_password_form_missing:{page.url}")
    for index in range(count):
        inputs.nth(index).fill(password)
        page.wait_for_timeout(150)

    origin_url = str(page.url or "")
    submit = first_visible((
        "button[type='submit']:visible", "button:has-text('Continue'):visible",
        "button:has-text('続行'):visible", "button:has-text('继续'):visible",
        "button:has-text('繼續'):visible", "button:has-text('Reset password'):visible",
        "button:has-text('Save password'):visible",
    ))
    if submit:
        submit.click()
    else:
        inputs.last.press("Enter")

    submitted = False
    end_time = time.monotonic() + 25.0
    while time.monotonic() < end_time:
        current_url = str(page.url or "")
        visible_passwords = 0
        try:
            visible_passwords = page.locator(password_selector).count()
        except Exception:
            pass
        if current_url != origin_url or visible_passwords == 0:
            submitted = True
            break
        page.wait_for_timeout(400)

    if template_path and captured:
        target = Path(template_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(captured[-1], ensure_ascii=False, indent=2), encoding="utf-8")

    status_ok = not response_statuses or any(200 <= value < 400 for value in response_statuses)
    return {
        "ok": bool(submitted and status_ok),
        "otp_validated": bool(otp_input),
        "submitted": submitted,
        "response_statuses": response_statuses[-4:],
        "response_errors": response_errors[-2:],
        "template_captured": bool(captured),
        "final_url": str(page.url or ""),
    }


def follow_authorize_with_headless_browser(
    session: BrowserSession,
    authorize_url: str,
    timeout_ms: int = 25000,
    *,
    email: str = "",
    otp_provider=None,
    new_password: str = "",
    template_path=None,
) -> str:
    """
    使用真实无头 Chromium 导航 authorize URL，完全规避 Cloudflare WAF 针对 auth.openai.com 的 403 拦截。
    零弹窗静默运行，跟随所有 302 重定向到达 email-verification，并将建立的全部 auth cookies 注入 session。
    """
    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    logger.info("[步骤4] 启动后台真实浏览器（纯静默无头）跟随 OAuth authorize...")
    otp_after_ts = time.time() - 5.0
    setattr(session, "_single_browser_password_result", None)

    with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
        browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)

        # 将 session 现有 Cookie 预置到浏览器中（规范解析 __Host- / __Secure- 与各域名）
        injected = sync_session_cookies_to_playwright(session, ctx)
        logger.info("[步骤4] 已预置 %d 个 Cookie 到后台真实浏览器", injected)

        page = ctx.new_page()
        _attach_playwright_protocol_trace(page, session)
        try:
            # authorize 请求是关键重定向链，不要用 networkidle；使用 commit 或 domcontentloaded
            page.goto(authorize_url, wait_until="commit", timeout=timeout_ms)
            import time as _time
            deadline = _time.monotonic() + 15.0
            while _time.monotonic() < deadline:
                cur = str(page.url or "")
                if "email-verification" in cur or "mfa-challenge" in cur or "chatgpt.com" in cur:
                    break
                page.wait_for_timeout(500)
            page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning("[步骤4] 浏览器跳转完成等待中: %s", str(e)[:120])

        final_url = str(page.url or "")

        # The add-password transaction may first land on an identity-confirmation
        # shell while keeping the authorize URL.  Its primary Continue button is
        # the real transition that sends the email OTP.  Handle this inside the
        # challenge bridge so the protocol session receives the resulting auth
        # cookies/state instead of repeating a document GET against the shell.
        try:
            page_title = str(page.title() or "")
        except Exception:
            page_title = ""
        identity_titles = (
            "first, verify", "verify your identity", "confirm your identity",
            "まず本人確認", "本人確認", "验证身份", "驗證身分", "确认身份", "確認身分",
        )
        if any(marker in page_title.lower() for marker in identity_titles):
            has_current_password = False
            try:
                has_current_password = page.locator("input[autocomplete*='current-password'], input[name='current-password']").count() > 0
            except Exception:
                pass
            clicked = False
            # Accounts imported without a locally known password must enter the
            # provider's normal password-recovery branch, not submit an empty
            # current-password form.
            if has_current_password and bool(getattr(session, "_recover_missing_password", False)):
                forgot_selectors = (
                    "a:has-text('Forgot password')", "button:has-text('Forgot password')",
                    "a:has-text('パスワードをお忘れですか')", "button:has-text('パスワードをお忘れですか')",
                    "a:has-text('忘记密码')", "button:has-text('忘记密码')",
                    "a:has-text('忘記密碼')", "button:has-text('忘記密碼')",
                )
                for selector in forgot_selectors:
                    try:
                        loc = page.locator(selector).first
                        if loc.is_visible():
                            loc.click(timeout=1500)
                            clicked = True
                            logger.info("[步骤4] 当前密码未知，已进入标准找回密码分支")
                            break
                    except Exception:
                        continue
            elif not has_current_password:
                continue_selectors = (
                    "button[type='submit']",
                    "button:has-text('Continue')", "button:has-text('続行')",
                    "button:has-text('继续')", "button:has-text('繼續')",
                )
                for selector in continue_selectors:
                    try:
                        loc = page.locator(selector).first
                        if loc.is_visible() and loc.is_enabled():
                            loc.click(timeout=800)
                            clicked = True
                            logger.info("[步骤4] 身份确认页已提交，等待 OTP 页面")
                            break
                    except Exception:
                        continue
            if clicked:
                import time as _time
                transition_deadline = _time.monotonic() + 15.0
                original_url = final_url
                while _time.monotonic() < transition_deadline:
                    cur = str(page.url or "")
                    if cur != original_url or "email-verification" in cur or "mfa-challenge" in cur or "create-account/password" in cur:
                        page.wait_for_timeout(800)
                        break
                    page.wait_for_timeout(250)
                final_url = str(page.url or final_url)
        if "/reset-password" in final_url:
            reset_selectors = (
                "button[type='submit']", "button:has-text('Continue')",
                "button:has-text('続行')", "button:has-text('继续')", "button:has-text('繼續')",
            )
            reset_clicked = False
            for selector in reset_selectors:
                try:
                    loc = page.locator(selector).first
                    if loc.is_visible() and loc.is_enabled():
                        loc.click(timeout=1500)
                        reset_clicked = True
                        logger.info("[步骤4] 已提交密码找回请求，等待邮件验证码页面")
                        break
                except Exception:
                    continue
            if reset_clicked:
                import time as _time
                reset_deadline = _time.monotonic() + 15.0
                while _time.monotonic() < reset_deadline:
                    cur = str(page.url or "")
                    if "email-verification" in cur or "reset-password/code" in cur or "verify" in cur:
                        page.wait_for_timeout(800)
                        break
                    page.wait_for_timeout(250)
                final_url = str(page.url or final_url)
        # When password signup is enabled, the email-verification page exposes
        # a real state transition button.  Trigger it in the browser context
        # instead of issuing a bare GET to /create-account/password.
        if "email-verification" in final_url:
            password_selectors = (
                "button:has-text('使用密码继续')",
                "button:has-text('Continue with password')",
                "button:has-text('パスワードで続ける')",
                "a:has-text('使用密码继续')",
                "[role='button']:has-text('Continue with password')",
            )
            clicked = False
            import time as _time
            control_deadline = _time.monotonic() + 10.0
            while _time.monotonic() < control_deadline and not clicked:
                for selector in password_selectors:
                    try:
                        loc = page.locator(selector).first
                        if loc.is_visible():
                            loc.click(timeout=4000)
                            clicked = True
                            break
                    except Exception:
                        continue
                if not clicked:
                    page.wait_for_timeout(400)
            if clicked:
                nav_deadline = _time.monotonic() + 8.0
                while _time.monotonic() < nav_deadline:
                    if "/create-account/password" in str(page.url or ""):
                        break
                    page.wait_for_timeout(250)
            else:
                try:
                    labels = page.locator("button, a, [role='button']").all_inner_texts()
                    logger.warning("[步骤4] 验证码页未找到密码入口，页面控件=%s", labels[:30])
                except Exception:
                    logger.warning("[步骤4] 验证码页未找到密码入口，控件文本采集失败")
            final_url = str(page.url or "")
            if "/create-account/password" in final_url:
                logger.info("[步骤4] 已在真实浏览器点击“使用密码继续”，完成密码注册状态切换")
        if otp_provider is not None and new_password and email:
            single_result = _complete_password_setup_on_page(
                page, session, email=email, otp_provider=otp_provider, password=new_password,
                otp_after_ts=otp_after_ts, template_path=template_path,
            )
            setattr(session, "_single_browser_password_result", single_result)
            final_url = str(single_result.get("final_url") or page.url or final_url)
            logger.info("[步骤4] 同一浏览器事务完成 OTP 与密码提交: %s", {
                "ok": single_result.get("ok"),
                "submitted": single_result.get("submitted"),
                "response_statuses": single_result.get("response_statuses"),
                "template_captured": single_result.get("template_captured"),
            })
        logger.info("[步骤4] 真实浏览器导航完成，落点 URL: %s", final_url)
        try:
            setattr(session, "_last_bridge_title", str(page.title() or "")[:160])
            setattr(session, "_last_bridge_final_url", final_url)
            setattr(session, "_last_bridge_controls", page.locator("button, a, [role='button']").all_inner_texts()[:20])
            setattr(session, "_last_bridge_inputs", page.locator("input").evaluate_all("els => els.map(e => ({type:e.type,name:e.name,autocomplete:e.autocomplete,placeholder:e.placeholder})).slice(0,10)"))
        except Exception as exc:
            logger.debug("[步骤4] 页面诊断采集失败: %s", exc)

        # 提取全部新下发的 Cookie 回同步 session
        synced = sync_playwright_cookies_to_session(ctx, session)
        browser.close()
        logger.info("[步骤4] 已同步 %d 个 Cookie 回协议会话", synced)

        reset = getattr(session, "reset_circuit_breaker", None)
        if callable(reset):
            reset()
        else:
            session.blocked_until = 0.0
            session.blocked_reason = ""

        return final_url


def navigate_auth_page_with_headless_browser(
    session: BrowserSession,
    url: str,
    *,
    timeout_ms: int = 25000,
) -> str:
    """在同一代理和画像下承接 Auth 文档导航，并把新 Cookie 同步回协议会话。"""
    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
        browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)
        sync_session_cookies_to_playwright(session, ctx)
        page = ctx.new_page()
        _attach_playwright_protocol_trace(page, session)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(1200)
            capture_runtime_fingerprint(page, session)
        except Exception as exc:
            logger.warning("[Auth导航] 浏览器页面等待: %s", str(exc)[:160])
        final_url = str(page.url or url)
        synced = sync_playwright_cookies_to_session(ctx, session)
        browser.close()
        logger.info("[Auth导航] 真实浏览器落点=%s，同步 Cookie=%s", final_url, synced)
        reset = getattr(session, "reset_circuit_breaker", None)
        if callable(reset):
            reset()
        else:
            session.blocked_until = 0.0
            session.blocked_reason = ""
        return final_url


def follow_oauth_callback_with_headless_browser(session: BrowserSession, continue_url: str, timeout_ms: int = 25000) -> dict:
    """
    使用真实无头 Chromium 执行最后的 OAuth 回调与 accessToken 拉取。
    彻底规避 hop=2 回调 chatgpt.com/ 时被 Cloudflare 403 拦截的问题。
    """
    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    logger.info("[OAuth回调] 启动后台真实浏览器（纯静默无头）执行 OAuth 回调与拉取 Session...")

    with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
        browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)

        # 注入 session 现有所有 Cookie
        injected = sync_session_cookies_to_playwright(session, ctx)
        logger.info("[OAuth回调] 已预置 %d 个 Cookie 到后台真实浏览器", injected)

        page = ctx.new_page()
        _attach_playwright_protocol_trace(page, session)
        try:
            page.goto(continue_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(2500)
        except Exception as e:
            logger.warning("[OAuth回调] 浏览器页面等待: %s", str(e)[:120])

        current_url = str(page.url or "")
        logger.info("[OAuth回调] 真实浏览器落点: %s", current_url)

        # 在浏览器中直接拉取 /api/auth/session
        session_data = None
        for poll in range(1, 8):
            try:
                session_data = page.evaluate('async () => { const r = await fetch("/api/auth/session"); return await r.json(); }')
                if isinstance(session_data, dict) and session_data.get("accessToken"):
                    logger.info("[Session] 真实浏览器内成功拉取 accessToken: %s...", session_data["accessToken"][:20])
                    break
            except Exception as e:
                logger.debug("[Session] 轮询第 %d 次: %s", poll, e)
            page.wait_for_timeout(1500)

        # 同步所有 Cookie 回 session
        synced = sync_playwright_cookies_to_session(ctx, session)
        logger.info("[OAuth回调] 浏览器已同步 %d 个 Cookie 回协议会话", synced)

        browser.close()

        reset = getattr(session, "reset_circuit_breaker", None)
        if callable(reset):
            reset()
        else:
            session.blocked_until = 0.0
            session.blocked_reason = ""

        if isinstance(session_data, dict) and session_data.get("accessToken"):
            return session_data

        raise RuntimeError(f"真实浏览器回调后未能拉取到 accessToken，当前落点: {current_url}")


def _require_email_login_form(page, response) -> object:
    """Check the loaded page before using the email form."""
    status = int(getattr(response, "status", 0) or 0)
    try:
        title = str(page.title() or "")[:80]
    except Exception:
        title = ""
    if status in (403, 429):
        raise RuntimeError(f"login page blocked (HTTP Error {status}; title={title!r}); email form unavailable")
    email_input = page.locator('input[type="email"], input[name="email"]').first
    try:
        email_input.wait_for(state="visible", timeout=5000)
    except Exception as exc:
        raise RuntimeError(f"login page missing email input (HTTP {status or 'unknown'}; title={title!r}); password not evaluated") from exc
    return email_input


def _signin_diagnostics(page, email_input, expected_email: str, network_events: list[dict]) -> str:
    """Only non-secret navigation evidence; never log input text, URLs or tokens."""
    try:
        email_matches = email_input.input_value(timeout=1000).strip().casefold() == expected_email.strip().casefold()
    except Exception:
        email_matches = False
    try:
        title = str(page.title() or "").strip()[:60]
    except Exception:
        title = "unavailable"
    try:
        buttons = page.locator('button[type="submit"], input[type="submit"]')
        submit_enabled = bool(buttons.first.is_enabled(timeout=1000))
    except Exception:
        submit_enabled = False
    events = ",".join(
        f"{event.get('stage')}:{event.get('status')}:{event.get('challenge', False)}"
        for event in network_events[-8:]
    ) or "none"
    return f"email_matches={email_matches} submit_enabled={submit_enabled} title={title!r} network={events}"


def signin_with_headless_browser(session: BrowserSession, email: str, timeout_ms: int = 25000) -> str:
    """
    使用真实无头 Chromium 在 ChatGPT 页面内执行 OAuth Signin 原生表单提交，获取 authorize_url。
    完全规避 Cloudflare WAF 对 curl_cffi POST /api/auth/signin/openai 的 403 拦截，
    直接到达 auth.openai.com/email-verification 并同步所有认证 Cookie。
    """
    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    logger.info("[步骤3] 启动后台真实浏览器（纯静默无头）执行 OAuth Signin 原生提交...")

    with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
        browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)
        sync_session_cookies_to_playwright(session, ctx)
        page = ctx.new_page()
        _attach_playwright_protocol_trace(page, session)

        captured_authorize_url: list[str] = []
        signin_events: list[dict] = []

        def observe_signin_response(resp):
            # Restrict to the login handshake; do not persist full URLs, headers or bodies.
            parsed_url = urlparse(str(resp.url or ""))
            path = parsed_url.path.lower()
            if parsed_url.hostname not in {"chatgpt.com", "auth.openai.com"}:
                return
            if not any(part in path for part in ("/api/auth/", "/api/accounts/authorize", "/auth/login")):
                return
            try:
                challenge = str(resp.headers.get("cf-mitigated", "")).lower() == "challenge"
            except Exception:
                challenge = False
            stage = "authorize" if "/authorize" in path else ("signin" if "signin" in path else "login")
            signin_events.append({"stage": stage, "status": int(resp.status), "challenge": challenge})

        page.on("response", observe_signin_response)

        def handle_request(req):
            if "auth.openai.com/api/accounts/authorize" in req.url:
                captured_authorize_url.append(req.url)

        page.on("request", handle_request)

        try:
            response = page.goto("https://chatgpt.com/auth/login", wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(2500)
        except Exception as exc:
            logger.warning("[signin] login page navigation failed: %s", str(exc).splitlines()[0][:120])
            raise RuntimeError("login page navigation failed; email form unavailable") from exc

        # 原生填写邮箱并点击提交 Continue，完全自然触发 NextAuth 流程。
        # 部分代理/指纹环境首个 click 只触发 React 状态更新，会短暂停留 /auth/login；
        # 旧逻辑固定等待 10 秒后判失败，导致验证码已发但刷新 AT 失败。
        logger.info("[步骤3] 无头浏览器填写邮箱并提交: %s", email)
        email_input = _require_email_login_form(page, response)
        email_input.fill(email, timeout=6000)
        page.wait_for_timeout(400)
        submit = page.locator('button[type="submit"], input[type="submit"]').first
        submit.click(timeout=6000)

        # 等待授权导航；仍停留登录页时补交一次表单。
        navigation_deadline = time.monotonic() + min(timeout_ms / 1000.0, 15.0)
        retried_submit = False
        while time.monotonic() < navigation_deadline:
            page.wait_for_timeout(500)
            capture_runtime_fingerprint(page, session)
            current = str(page.url or "")
            if captured_authorize_url or "auth.openai.com" in current:
                break
            if any(event["challenge"] for event in signin_events):
                logger.info("[步骤3] Signin 返回验证页，本轮不重复提交表单")
                break
            if not retried_submit and "/auth/login" in current and time.monotonic() + 8.0 < navigation_deadline:
                try:
                    if email_input.is_visible(timeout=500):
                        retried_submit = True
                        logger.info("[步骤3] 登录页仍未导航，补交一次 Signin 表单")
                        submit.click(timeout=5000)
                except Exception as retry_exc:
                    logger.debug("[步骤3] 补交 Signin 表单失败: %s", retry_exc)

        final_page_url = str(page.url or "")
        diagnostic = _signin_diagnostics(page, email_input, email, signin_events)
        logger.info("[步骤3] Signin 导航诊断：proxy_configured=%s %s", bool(proxy_dict), diagnostic)
        capture_runtime_fingerprint(page, session)
        logger.info("[步骤3] 无头浏览器页面导航完成，落点 URL: %s", final_page_url)
        if "email-verification" in final_page_url or "about-you" in final_page_url or "create-account" in final_page_url:
            setattr(session, "_cached_authorize_landing_url", final_page_url)

        synced = sync_playwright_cookies_to_session(ctx, session)
        browser.close()
        logger.info("[步骤3] 无头浏览器已同步 %d 个 Cookie 回协议会话", synced)

        # 重置任何潜在熔断
        reset = getattr(session, "reset_circuit_breaker", None)
        if callable(reset):
            reset()
        else:
            session.blocked_until = 0.0
            session.blocked_reason = ""

        if captured_authorize_url:
            auth_url = captured_authorize_url[0]
            logger.info("[步骤3] 无头浏览器成功捕获 authorize URL: %s...", auth_url[:120])
            return auth_url

        if "email-verification" in final_page_url or "auth.openai.com" in final_page_url:
            logger.info("[步骤3] 无头浏览器已直达 auth.openai.com 认证页面: %s", final_page_url)
            return final_page_url

        raise RuntimeError(f"无头浏览器未能完成 Signin 导航（{diagnostic}）")









def capture_and_submit_new_password(
    session: BrowserSession,
    continue_url: str,
    password: str,
    template_path,
    timeout_ms: int = 35000,
) -> bool:
    from pathlib import Path
    """复用当前会话在后台 Chromium 中打开密码页，填入密码并提交，同时拦截真实请求生成协议模板。"""
    from core.password_setup_protocol import build_password_request_template
    from core.password_setup_service import _looks_like_password_submit

    proxy_dict = None
    if session.proxy:
        parsed = urlparse(session.proxy)
        if parsed.hostname:
            proxy_dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
            if parsed.username or parsed.password:
                proxy_dict["username"] = parsed.username or ""
                proxy_dict["password"] = parsed.password or ""

    captured = []
    submitted_ok = False

    try:
        with sync_playwright() as p, _browser_cleanup_scope() as cleanup_scope:
            browser, ctx = _create_stealth_context(p, session, proxy_dict=proxy_dict, cleanup_scope=cleanup_scope)
            sync_session_cookies_to_playwright(session, ctx)
            page = ctx.new_page()
            _attach_playwright_protocol_trace(page, session)

            def on_request(req):
                try:
                    url = str(getattr(req, "url", "") or "")
                    method = str(getattr(req, "method", "POST") or "POST").upper()
                    body = str(getattr(req, "post_data", "") or "")

                    if "auth.openai.com" not in url:
                        return
                    if method not in {"POST", "PUT", "PATCH"}:
                        return
                    if "/rum" in url.lower() or "telemetry" in url.lower() or "datadog" in url.lower():
                        return
                    if not _looks_like_password_submit(url, body):
                        return

                    item = build_password_request_template(req)
                    item["body"] = str(item["body"]).replace(password, "$PASSWORD")
                    captured.append(item)
                except Exception:
                    pass

            page.on("request", on_request)

            try:
                page.goto(continue_url, wait_until="domcontentloaded", timeout=timeout_ms)
                page.wait_for_timeout(1500)
            except Exception as e:
                logger.warning("[捕获密码表单] 导航超时: %s", str(e)[:120])

            inputs = page.locator('input[type="password"]:visible')
            count = inputs.count()
            if count == 0:
                logger.warning("[捕获密码表单] 未找到可见的密码输入框，当前落点: %s", page.url)
                browser.close()
                return False

            for i in range(count):
                inputs.nth(i).fill(password)
                page.wait_for_timeout(200)

            submit_selectors = (
                "button[type='submit']:visible",
                "button:has-text('Continue'):visible",
                "button:has-text('続行'):visible",
                "button:has-text('继续'):visible",
                "button:has-text('Reset password'):visible",
            )
            submit_btn = None
            for sel in submit_selectors:
                loc = page.locator(sel).last
                if loc.count() and loc.is_visible():
                    submit_btn = loc
                    break

            if submit_btn:
                submit_btn.click()
            else:
                inputs.last.press("Enter")

            end_time = time.time() + 20
            while time.time() < end_time:
                cur_url = str(page.url or "")
                if "reset-password/new-password" not in cur_url or page.locator('input[type="password"]:visible').count() == 0:
                    submitted_ok = True
                    break
                page.wait_for_timeout(500)

            if captured:
                try:
                    template_path.parent.mkdir(parents=True, exist_ok=True)
                    template_path.write_text(json.dumps(captured[-1], ensure_ascii=False, indent=2), encoding="utf-8")
                    logger.info("[捕获密码表单] 成功保存协议密码请求模板: %s", str(template_path))
                except Exception as ex:
                    logger.error("[捕获密码表单] 保存模板失败: %s", ex)

            sync_playwright_cookies_to_session(ctx, session)
            browser.close()

            reset = getattr(session, "reset_circuit_breaker", None)
            if callable(reset):
                reset()
            else:
                session.blocked_until = 0.0
                session.blocked_reason = ""

            return submitted_ok or bool(captured)
    except Exception as exc:
        logger.error("[捕获密码表单] 异常: %s", exc)
        return False