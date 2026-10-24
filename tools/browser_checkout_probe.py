# -*- coding: utf-8 -*-
"""真实浏览器 checkout 探针。

判定 `POST /backend-api/payments/checkout` 的 400 是「协议客户端被识别」还是
「账号/出口被风控」：在真实 Chromium 里用真实前端走登录 + 点升级，抓前端自己
发出去的 checkout 请求状态码。

用法：
    python tools/browser_checkout_probe.py --account-id 29 --proxy URL --stage login
    python tools/browser_checkout_probe.py --account-id 29 --proxy URL --stage upgrade --state-in state.json
    python tools/browser_checkout_probe.py --account-id 29 --proxy URL --stage upgrade --dump out.html
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402
from core.antbrowser_driver import build_ant_driver, cleanup_ant_profile  # noqa: E402

from core import db  # noqa: E402

_CHECKOUT_MARK = "/backend-api/payments/checkout"
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
_EMAIL_SELECTORS = (
    "#mobile-auth-email", "input[type=email]", "input[name=email]",
    "#email-input", "input[name=username]", "input[name=login_hint]",
)
_OTP_SELECTORS = (
    "input[autocomplete=one-time-code]", "input[name=code]",
    "input[inputmode=numeric]",
)
_SUBMIT_LABELS = ("Continue", "继续", "Next", "Log in", "Verify", "Submit")


def _account_password(row: dict) -> str:
    extra = row.get("extra_json")
    if isinstance(extra, str) and extra.strip():
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    if not isinstance(extra, dict):
        extra = {}
    return str(extra.get("registration_password") or row.get("registration_password") or "").strip()


def _email_source(row: dict) -> str:
    extra = row.get("extra_json")
    if isinstance(extra, str) and extra.strip():
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    if not isinstance(extra, dict):
        extra = {}
    return str((extra.get("email_service") or {}).get("source") or row.get("email_source") or "").strip()


def _body_text(page) -> str:
    try:
        return page.inner_text("body")
    except Exception:
        return ""


def _settle(page, seconds: float = 25.0, *, quiet: bool = False) -> str:
    """等页面真正渲染出内容（readyState complete 且有正文），返回正文。"""
    end = time.time() + seconds
    last = ""
    while time.time() < end:
        try:
            if page.evaluate("document.readyState") == "complete":
                last = _body_text(page).strip()
                if last:
                    return last
        except Exception:
            pass
        time.sleep(1)
    if not quiet:
        print(f"  [settle] 超时，正文长度 {len(last)}")
    return last


def _fill_first(page, selectors, value: str) -> str:
    for sel in selectors:
        try:
            loc = page.locator(sel)
            if loc.count():
                loc.first.fill(value, timeout=8000)
                return sel
        except Exception:
            continue
    return ""


def _click_first(page, names) -> str:
    for name in names:
        try:
            btn = page.get_by_role("button", name=re.compile(f"^{re.escape(name)}$", re.I)).first
            if btn.count():
                btn.click(timeout=6000)
                return name
        except Exception:
            continue
    return ""


def _wait_until(page, pred, timeout: float = 60.0) -> bool:
    """轮询等待条件成立（代理慢时页面会长时间空白）。"""
    end = time.time() + timeout
    while time.time() < end:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def _wait_input(page, selectors, timeout: float = 25.0) -> str:
    """等某个输入框真的出现（SPA 里旧页面还在，不能只等 readyState）。"""
    end = time.time() + timeout
    while time.time() < end:
        for sel in selectors:
            try:
                if page.locator(sel).count():
                    return sel
            except Exception:
                pass
        time.sleep(0.8)
    return ""


def _click_any(page, texts) -> str:
    """按文案点击，依次尝试 button / link / 任意含文本的可点节点。"""
    for text in texts:
        pat = re.compile(re.escape(text), re.I)
        for role in ("button", "link"):
            try:
                el = page.get_by_role(role, name=pat).first
                if el.count():
                    el.click(timeout=6000)
                    return f"{text}({role})"
            except Exception:
                continue
        try:
            el = page.locator(f"text={text}").first
            if el.count():
                el.click(timeout=6000)
                return f"{text}(text)"
        except Exception:
            continue
    return ""


def _dump(page, label: str) -> None:
    try:
        info = page.eval_on_selector_all(
            "input,button,a",
            "els => els.map(e => e.tagName==='INPUT' "
            "? {t:'input',name:e.name,type:e.type,id:e.id,ph:e.placeholder} "
            ": {t:e.tagName.toLowerCase(),text:(e.innerText||'').trim().slice(0,44)})",
        )
    except Exception as exc:
        print(f"  [{label}] 元素枚举失败: {type(exc).__name__}: {exc}")
        return
    ins = [x for x in info if x["t"] == "input" and x.get("type") not in ("file", "hidden")]
    bts = [x for x in info if x["t"] != "input" and x.get("text")]
    print(f"  [{label}] url={page.url[:110]}")
    print(f"  [{label}] inputs={ins}")
    print(f"  [{label}] 可点={[b['text'] for b in bts][:18]}")
    txt = _body_text(page)[:220].replace("\n", " | ")
    print(f"  [{label}] text={txt}")


def _login(page, *, email: str, password: str, source: str, wait_otp: int) -> None:
    print("直连 auth.openai.com/log-in …")
    page.goto("https://auth.openai.com/log-in", wait_until="domcontentloaded", timeout=90000)
    _settle(page, 40)
    _dump(page, "auth 入口")

    # "Your session has ended" 之类的中转页需要再点一次 Log in
    if not _wait_input(page, _EMAIL_SELECTORS, 3):
        hit = _click_any(page, ("Log in", "登录"))
        print(f"  入口页点击 Log in: {hit or '未找到'}")
        if hit:
            _settle(page, 30)
            _dump(page, "auth 登录页")

    sel = _wait_input(page, _EMAIL_SELECTORS, 30)
    print(f"  邮箱输入框: {sel or '未找到'}")
    if sel:
        page.fill(sel, email, timeout=8000)
        print(f"  已填邮箱 via {sel}")
        time.sleep(0.8)
        page.keyboard.press("Enter")
        clicked = _click_any(page, ("Continue", "继续", "Next"))
        print(f"  提交邮箱: {clicked or '回车'}")

    # 等下一步渲染出内容
    _wait_until(page, lambda: len(_body_text(page).strip()) > 0 and "log-in" not in page.url, 60)
    _settle(page, 30)
    print("  邮箱提交后 URL:", page.url[:120])
    _dump(page, "邮箱提交后")

    # 邮件验证码页：有密码就先切到密码路径（该页常报 "We couldn't send your code"）
    if password and re.search(r"(verification code|check your inbox)", _body_text(page), re.I):
        hit = _click_any(page, ("Continue with password", "Use password", "密码"))
        print(f"  切到密码路径: {hit or '未找到入口'}")
        if hit:
            _wait_input(page, ("input[type=password]",), 25)
            _settle(page, 15)
            _dump(page, "密码页")

    # 密码
    pwd_done = False
    pwd_sel = _wait_input(page, ("input[type=password]",), 20) if password else ""
    if pwd_sel:
        page.fill(pwd_sel, password, timeout=8000)
        print(f"  已填密码 via {pwd_sel}")
        time.sleep(0.6)
        clicked = _click_any(page, ("Continue", "Log in", "继续", "Verify"))
        print(f"  密码后点击: {clicked or '直接回车'}")
        if not clicked:
            page.keyboard.press("Enter")
        pwd_done = True
        _settle(page, 30)
        _dump(page, "密码提交后")

    # OTP
    txt = _body_text(page)
    need_otp = bool(re.search(r"(verification code|enter the code|check your email|check your inbox|验证码)", txt, re.I)) \
        or page.locator(",".join(_OTP_SELECTORS)).count() > 0
    if pwd_done:
        print("  已走密码路径，跳过 OTP")
        need_otp = False
    if need_otp:
        print("  需要邮箱 OTP，开始取件…")
        try:
            from core.email_provider import wait_for_otp
            started = time.time()
            code = wait_for_otp(email, started, max_wait=wait_otp, email_source=source or None)
            print(f"  取到 OTP: {code}")
            sel3 = _fill_first(page, _OTP_SELECTORS, str(code))
            print(f"  已填 OTP via {sel3 or '未找到'}")
            time.sleep(0.6)
            if not _click_first(page, _SUBMIT_LABELS):
                page.keyboard.press("Enter")
            _settle(page, 30)
            _dump(page, "OTP 提交后")
        except Exception as exc:
            print("  OTP 流程失败:", type(exc).__name__, str(exc)[:200])
    else:
        print("  未检测到 OTP 页面")

    _settle(page, 10)
    print("\n登录后 URL:", page.url[:140])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-id", type=int, required=True)
    ap.add_argument("--proxy", required=True)
    ap.add_argument("--country", default="IN")
    ap.add_argument("--stage", choices=["login", "auth", "upgrade"], default="login")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--pause", action="store_true", help="结束前等待回车（headed 调试用）")
    ap.add_argument("--dump", default="", help="把页面 HTML 写到该路径")
    ap.add_argument("--store", default="", help="登录后 storage_state 落盘路径（复用会话）")
    ap.add_argument("--state-in", default="", help="复用已有 storage_state")
    ap.add_argument("--wait-otp", type=int, default=180)
    args = ap.parse_args()

    row = db.get_account(args.account_id)
    if not row:
        print(f"账号 {args.account_id} 不存在")
        return 2
    email = str(row.get("email") or "").strip()
    password = _account_password(row)
    source = _email_source(row)
    print(f"账号 #{args.account_id} {email} password={'有' if password else '无'} email_source={source}")

    proxy_cfg = None
    if args.proxy:
        from urllib.parse import urlparse
        u = urlparse(args.proxy)
        proxy_cfg = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
        if u.username:
            proxy_cfg["username"] = u.username
            proxy_cfg["password"] = u.password or ""

    events: list[dict] = []
    checkout_hits: list[dict] = []

    driver = None
    opened = None
    if args.headed:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=False, args=["--no-sandbox"])
    else:
        pw = None
        driver, opened = build_ant_driver(proxy=args.proxy, force_headless=True)
        browser = driver.browser
    try:
        ctx = browser.new_context(
            user_agent=_UA, locale="en-US", viewport={"width": 1440, "height": 900},
            timezone_id="Asia/Kolkata" if args.country == "IN" else "UTC",
            proxy=proxy_cfg,
            storage_state=args.state_in or None,
        )
        ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
        page = ctx.new_page()

        def on_response(resp):
            url = resp.url
            if "/backend-api/" not in url:
                return
            rec = {"status": resp.status, "method": resp.request.method, "url": url[:180]}
            events.append(rec)
            if _CHECKOUT_MARK in url:
                try:
                    body = resp.text()[:500]
                except Exception:
                    body = "<unreadable>"
                rec["body"] = body
                try:
                    rec["post_data"] = (resp.request.post_data or "")[:800]
                except Exception:
                    pass
                checkout_hits.append(rec)
                print(f"\n>>> [CHECKOUT] {resp.request.method} -> {resp.status}")
                print(f">>> body: {body[:320]}")

        page.on("response", on_response)

        if args.stage == "auth":
            print("直连 auth.openai.com/log-in …")
            for url in ("https://auth.openai.com/log-in", "https://auth.openai.com/"):
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=90000)
                    break
                except Exception as exc:
                    print("  跳转失败:", type(exc).__name__, str(exc)[:140])
            _settle(page, 60)
            _dump(page, "auth 直连")
            title = ""
            try:
                title = page.title()
            except Exception:
                pass
            print("  title:", title[:120])

        elif args.stage == "login":
            _login(page, email=email, password=password, source=source, wait_otp=args.wait_otp)
            if args.store:
                ctx.storage_state(path=args.store)
                print("已保存 storage_state:", args.store)

        else:  # upgrade
            print("进入 chatgpt.com 并打开套餐页 …")
            page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=60000)
            _settle(page, 25)
            _dump(page, "首页")
            for url in ("https://chatgpt.com/#pricing",):
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=60000)
                except Exception as exc:
                    print("  套餐页跳转失败:", type(exc).__name__, str(exc)[:120])
            _settle(page, 20)
            _dump(page, "套餐页")

            clicked_any = False
            for name in ("See plans and pricing", "Upgrade to Plus", "Upgrade", "Get Plus", "Plus"):
                try:
                    el = page.get_by_role("button", name=re.compile(f"^{re.escape(name)}$", re.I)).first
                    if el.count():
                        print(f"  点击 {name}")
                        el.click(timeout=8000)
                        clicked_any = True
                        _settle(page, 12)
                        break
                except Exception:
                    continue
            if not clicked_any:
                try:
                    el = page.get_by_role("link", name=re.compile("plans and pricing", re.I)).first
                    if el.count():
                        print("  点击链接 See plans and pricing")
                        el.click(timeout=8000)
                        _settle(page, 12)
                except Exception as exc:
                    print("  套餐入口点击失败:", type(exc).__name__, str(exc)[:120])
            _dump(page, "套餐弹层")

            # 弹层里再找一次 Plus 升级按钮
            for name in ("Upgrade to Plus", "Get Plus", "Upgrade", "Plus", "Subscribe"):
                try:
                    el = page.get_by_role("button", name=re.compile(f"^{re.escape(name)}", re.I)).first
                    if el.count():
                        print(f"  弹层内点击 {name}")
                        el.click(timeout=8000)
                        _settle(page, 15)
                        break
                except Exception:
                    continue
            _dump(page, "升级点击后")

        if args.dump:
            Path(args.dump).write_text(page.content(), encoding="utf-8")
            print("已落盘 HTML:", args.dump)

        summary = {
            "account_id": args.account_id, "email": email, "stage": args.stage,
            "final_url": page.url,
            "checkout_hits": checkout_hits,
            "backend_calls": events[-80:],
        }
        out = _PROJECT_ROOT / "注册日志" / "payment_capture" / f"browser-probe-{args.stage}.json"
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\nbackend-api 调用 {len(events)} 条, checkout 命中 {len(checkout_hits)} 条 -> {out}")
        if args.pause:
            input("按回车关闭…")
    finally:
        if driver:
            try:
                driver.quit()
            finally:
                cleanup_ant_profile(opened)
        else:
            browser.close()
            pw.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
