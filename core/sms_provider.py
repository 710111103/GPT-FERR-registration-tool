# -*- coding: utf-8 -*-
"""
接码平台客户端。

用于 Codex OAuth "全新 session" 流程过 OpenAI 的 /phone-verification 手机号验证：
    1. acquire_number()       getNumber 取一个手机号（返回 激活ID + 号码）
    2. wait_for_sms_code()    轮询 getStatus 直到拿到短信验证码
    3. complete() / cancel()  setStatus 标记完成(6) / 取消(8)

当前支持：
    - 5sim：JSON REST 接口，文档 https://5sim.net/docs
    - GrizzlySMS：GET 文本接口，文档 https://api.grizzlysms.com
    - L：本地 JSON 管理接口，文档 L_API.md
    - H：本地 JSON 管理接口，文档 H_API.md

价格相关：每取一个号、收到短信都会计费，所以：
    - 取号后若收不到短信，必须 cancel(8) 释放，避免白扣钱；
    - 成功拿到码后 complete(6) 正式完成激活。
"""
import json
import logging
import re
import threading
import time
from urllib.parse import urljoin

from curl_cffi.requests import Session as CurlSession

# 注意：用 `from config import codex` 而不是 `from config.codex import X`，
# 这样 WebUI 调 config.reload_all() 后，本模块通过 codex.X 读到的是最新值。
from config import codex as _cfg
from config import IMPERSONATE

logger = logging.getLogger(__name__)

# GrizzlySMS 规则：号码取出后 2 分钟内不允许取消（防薅号）。
# 这里留 5 秒缓冲，时间到了再发 setStatus=8。
_MIN_CANCEL_DELAY = 125

# 记录每个 activation_id 的取号时间，供 cancel() 判断是否要等。
# 用模块级 dict 而不是改 acquire_number 返回值，保持向后兼容。
_ACQUIRED_AT: dict[str, float] = {}


class _PhoneSession:
    """追踪单个已购号码的多次复用生命周期。"""
    def __init__(self, activation_id: str, phone: str, provider: str, max_uses: int):
        self.activation_id = activation_id
        self.phone = phone
        self.provider = provider
        self.max_uses = max_uses
        self.used_count = 1
        self.created_at = time.time()
        self.codes: list[str] = []
        self.in_use = True


_PHONE_POOL_LOCK = threading.Lock()
_ACTIVE_SESSIONS: dict[str, _PhoneSession] = {}
_REUSABLE_QUEUE: list[_PhoneSession] = []


class SmsProviderError(RuntimeError):
    """接码平台通用错误。"""


class SmsNoNumbersError(SmsProviderError):
    """暂无可用号码（NO_NUMBERS），可换国家或稍后重试。"""


class SmsNoBalanceError(SmsProviderError):
    """余额不足（NO_BALANCE），必须充值，重试无意义——上层应立即停止。"""


class SmsCodeTimeout(SmsProviderError):
    """单个号等短信超时（OpenAI 没发或没到达）。"""


def _http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.timeout = _cfg.SMS_REQUEST_TIMEOUT
    return s


def _provider() -> str:
    return str(getattr(_cfg, "SMS_PROVIDER", "grizzly") or "grizzly").strip().lower()


def _request_grizzly(http: CurlSession, params: dict) -> str:
    """
    发一个 GrizzlySMS API 请求，返回去空白的响应文本。
    统一识别公共错误码并抛对应异常。
    """
    base_params = {"api_key": _cfg.SMS_API_KEY}
    base_params.update(params)
    resp = http.get(_cfg.SMS_API_BASE, params=base_params)
    if resp.status_code != 200:
        raise SmsProviderError(
            f"GrizzlySMS HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    text = (resp.text or "").strip()

    # 公共错误码（任何 action 都可能返回）
    if text == "BAD_KEY":
        raise SmsProviderError("接码平台 API key 无效（BAD_KEY）")
    if text == "NO_BALANCE":
        raise SmsNoBalanceError("接码平台余额不足（NO_BALANCE），请充值")
    if text == "NO_NUMBERS":
        raise SmsNoNumbersError("接码平台暂无可用号码（NO_NUMBERS）")
    if text == "SERVICE_UNAVAILABLE_REGION":
        raise SmsProviderError("接码平台地区受限（SERVICE_UNAVAILABLE_REGION），请换 IP")
    if text in ("BAD_ACTION", "BAD_SERVICE", "BAD_STATUS"):
        raise SmsProviderError(f"接码平台请求参数错误：{text}")
    if text == "NO_ACTIVATION":
        raise SmsProviderError("激活 ID 不存在（NO_ACTIVATION）")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"该服务被平台禁售：{text}")

    return text


def _l_url(path: str) -> str:
    base = str(getattr(_cfg, "L_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("L_API_BASE 不能为空")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _l_headers() -> dict:
    token = str(getattr(_cfg, "L_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("L_ADMIN_AUTH_CODE 不能为空")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_l_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_l_url(path), headers=_l_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"L HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"L 余额不足：{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"L 暂无可用号码：{combined}")
        raise SmsProviderError(f"L 请求失败：{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"L 响应不是 JSON 对象：{text[:200]}")
    return data


def _h_url(path: str) -> str:
    base = str(getattr(_cfg, "H_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("H_API_BASE 不能为空")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _h_headers() -> dict:
    token = str(getattr(_cfg, "H_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("H_ADMIN_AUTH_CODE 不能为空")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_h_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_h_url(path), headers=_h_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"H HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"H 余额不足：{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"H 暂无可用号码：{combined}")
        raise SmsProviderError(f"H 请求失败：{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"H 响应不是 JSON 对象：{text[:200]}")
    return data


def _release_h_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """调用 H_API /api/admin/h/release 释放单个号码。"""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("H release 缺少 id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"H release 失败 id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:H] 已释放号码 id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_h_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """批量释放 H 号码。"""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("H release 缺少 ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:H] 批量释放号码完成 released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _release_l_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """调用 L_API /api/admin/l/release 释放单个号码。"""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("L release 缺少 id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            # 接口允许部分失败。单个释放时 failed 非空基本代表这个 id 释放失败。
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"L release 失败 id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:L] 已释放号码 id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_l_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """批量释放 L 号码，供工具/后续批处理复用。"""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("L release 缺少 ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:L] 批量释放号码完成 released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _normalize_phone_digits(value: str) -> str:
    """把平台返回/配置的号码片段规范化为纯数字，避免 +-849... 这类非法 E.164。"""
    return "".join(ch for ch in str(value or "").strip() if ch.isdigit())


def _normalize_l_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "L_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _normalize_h_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "H_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _h_phone_acquire_mode() -> str:
    """
    H 取号模式：
      - reusable/reuse/prefer_reuse：优先复用，调用 /api/admin/h/take-reusable-phone
      - new/fresh/always_new：每次取新号，调用 /api/admin/h/take-phone
    """
    raw = str(getattr(_cfg, "H_PHONE_ACQUIRE_MODE", "reusable") or "reusable").strip().lower()
    if raw in ("new", "fresh", "always_new", "take_phone", "take-phone", "每次取新号", "新号"):
        return "new"
    return "reusable"


# ============================================================
# 5sim API 适配器（https://5sim.net/docs）
# ============================================================

def _5sim_token() -> str:
    token = str(getattr(_cfg, "FIVESIM_API_KEY", "") or getattr(_cfg, "SMS_API_KEY", "") or "").strip()
    if not token:
        raise SmsProviderError("5sim API Token 不能为空：请在配置中填写 FIVESIM_API_KEY 或 SMS_API_KEY")
    return token


def _5sim_headers() -> dict:
    return {
        "Authorization": f"Bearer {_5sim_token()}",
        "Accept": "application/json",
    }


def _5sim_url(path: str) -> str:
    base = str(getattr(_cfg, "FIVESIM_API_BASE", "https://5sim.net/v1") or "https://5sim.net/v1").strip()
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _acquire_5sim_number(
    http: CurlSession,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str]:
    product = str(service or getattr(_cfg, "FIVESIM_PRODUCT", "openai") or "openai").strip().lower()
    c = str(country or getattr(_cfg, "FIVESIM_COUNTRY", "any") or getattr(_cfg, "SMS_COUNTRY", "any") or "any").strip().lower()
    op = str(getattr(_cfg, "FIVESIM_OPERATOR", "any") or "any").strip().lower()
    url = _5sim_url(f"/user/buy/activation/{c}/{op}/{product}")
    logger.info(f"[SMS:5sim] 正在从 5sim 请求号码：country={c}, operator={op}, product={product}")
    resp = http.get(url, headers=_5sim_headers())
    text = (resp.text or "").strip()
    text_l = text.lower()

    if resp.status_code == 401 or "unauthorized" in text_l or "bad token" in text_l:
        raise SmsProviderError(f"5sim API Token 无效（401）: {text[:200]}")
    if "no free phones" in text_l or "no_free_phones" in text_l or "not available" in text_l:
        raise SmsNoNumbersError(f"5sim 暂无可用号码（country={c}, product={product}）: {text[:200]}")
    if "no balance" in text_l or "not enough user balance" in text_l or "not enough balance" in text_l:
        raise SmsNoBalanceError(f"5sim 余额不足，请充值: {text[:200]}")
    if resp.status_code != 200:
        raise SmsProviderError(f"5sim buy HTTP {resp.status_code}: {text[:200]}")

    try:
        data = resp.json()
    except Exception as exc:
        raise SmsProviderError(f"5sim buy 响应不是 JSON: {text[:200]}") from exc

    if not isinstance(data, dict):
        raise SmsProviderError(f"5sim buy 响应异常: {text[:200]}")

    activation_id = str(data.get("id") or "").strip()
    raw_phone = str(data.get("phone") or "").strip()
    phone = _normalize_phone_digits(raw_phone)
    if not activation_id or not phone:
        raise SmsProviderError(f"5sim 响应缺少 id 或 phone: {text[:200]}")

    _ACQUIRED_AT[activation_id] = time.time()
    logger.info(
        f"[SMS:5sim] 取号成功：id={activation_id}, phone=+{phone}, "
        f"country={data.get('country')}, operator={data.get('operator')}, price={data.get('price')}"
    )
    return activation_id, phone


def _fetch_5sim_code(http: CurlSession, activation_id: str, exclude_codes: list[str] | None = None) -> tuple[str, str, str]:
    url = _5sim_url(f"/user/check/{activation_id}")
    resp = http.get(url, headers=_5sim_headers())
    text = (resp.text or "").strip()
    if resp.status_code != 200:
        raise SmsProviderError(f"5sim check HTTP {resp.status_code}: {text[:200]}")
    try:
        data = resp.json()
    except Exception as exc:
        raise SmsProviderError(f"5sim check 响应不是 JSON: {text[:200]}") from exc

    if not isinstance(data, dict):
        raise SmsProviderError(f"5sim check 响应异常: {text[:200]}")

    status = str(data.get("status") or "").strip().upper()
    sms_list = data.get("sms") or []
    code = ""
    raw_sms = ""
    exclude = set(exclude_codes or [])
    if isinstance(sms_list, list) and sms_list:
        for item in reversed(sms_list):
            if isinstance(item, dict):
                cand_sms = str(item.get("text") or "")
                cand_code = str(item.get("code") or "").strip()
                if not cand_code and cand_sms:
                    m = re.search(r'\b(\d{6})\b', cand_sms)
                    if m:
                        cand_code = m.group(1)
                if cand_code and cand_code not in exclude:
                    code = cand_code
                    raw_sms = cand_sms
                    break
    return code, status, raw_sms


def _finish_5sim_order(activation_id: str, http: CurlSession | None = None) -> None:
    own_http = http is None
    http = http or _http()
    try:
        url = _5sim_url(f"/user/finish/{activation_id}")
        resp = http.get(url, headers=_5sim_headers())
        logger.info(f"[SMS:5sim] 已完成订单 id={activation_id}, HTTP {resp.status_code}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS:5sim] 标记完成失败（不影响主流程）：id={activation_id}, {exc}")
    finally:
        if own_http:
            http.close()


def _cancel_5sim_order(activation_id: str, http: CurlSession | None = None) -> None:
    own_http = http is None
    http = http or _http()
    try:
        url = _5sim_url(f"/user/cancel/{activation_id}")
        resp = http.get(url, headers=_5sim_headers())
        logger.info(f"[SMS:5sim] 已取消订单 id={activation_id}, HTTP {resp.status_code}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS:5sim] 取消订单失败（不影响主流程）：id={activation_id}, {exc}")
    finally:
        if own_http:
            http.close()


# ============================================================
# 取号
# ============================================================

def acquire_number(
    http: CurlSession | None = None,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str]:
    """
    取一个手机号（getNumber）。支持单号复用多账号。

    Returns:
        (activation_id, phone_number) —— phone_number 不带 + 前缀（如 15500000000）

    Raises:
        SmsNoNumbersError / SmsNoBalanceError / SmsProviderError
    """
    own_http = http is None
    http = http or _http()
    try:
        provider = _provider()
        max_reuse = max(1, int(getattr(_cfg, "SMS_REUSE_MAX_ACCOUNTS", 2) or 2))
        expire_sec = max(60, int(getattr(_cfg, "SMS_REUSE_EXPIRE_SECONDS", 600) or 600))
        now = time.time()

        # 检查是否可以复用已有号码
        if max_reuse > 1 and provider in ("5sim", "fivesim", "grizzly"):
            with _PHONE_POOL_LOCK:
                valid_queue = []
                for s in _REUSABLE_QUEUE:
                    if (now - s.created_at) < expire_sec and s.used_count < s.max_uses and s.provider == provider:
                        valid_queue.append(s)
                    else:
                        _ACTIVE_SESSIONS.pop(s.activation_id, None)
                _REUSABLE_QUEUE[:] = valid_queue
                if _REUSABLE_QUEUE:
                    sess = _REUSABLE_QUEUE.pop(0)
                    sess.in_use = True
                    sess.used_count += 1
                    logger.info(
                        f"[SMS] 命中可复用号码池：+{sess.phone} "
                        f"(第 {sess.used_count}/{sess.max_uses} 次使用，activation_id={sess.activation_id})"
                    )
                    return sess.activation_id, sess.phone

        if provider in ("5sim", "fivesim"):
            activation_id, phone = _acquire_5sim_number(http, service=service, country=country)
        elif provider == "l":
            payload = {
                "service": service or _cfg.SMS_SERVICE,
                "country": country or _cfg.SMS_COUNTRY,
            }
            if _cfg.SMS_MAX_PRICE:
                payload["maxPrice"] = _cfg.SMS_MAX_PRICE

            data = _post_l_json(http, "/api/admin/l/take-phone", payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "L_PHONE_PREFIX", "") or "")
            phone = _normalize_l_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:L] 号码规范化：raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"L take-phone 响应缺少 item.id/item.phone：{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(f"[SMS:L] 取号成功：id={activation_id}, phone=+{phone}")
        elif provider == "h":
            # H_API 使用 projectId + country；统一复用 SMS_SERVICE / SMS_COUNTRY，
            # 避免接码平台之间出现重复的“服务/国家”配置。
            project_id = str(service or _cfg.SMS_SERVICE).strip()
            h_country = str(country or _cfg.SMS_COUNTRY).strip()
            if not project_id:
                raise SmsProviderError("H projectId 不能为空：请填写 SMS_SERVICE")
            if not h_country:
                raise SmsProviderError("H country 不能为空：请填写 SMS_COUNTRY")
            payload = {
                "projectId": project_id,
                "country": h_country,
            }
            mode = _h_phone_acquire_mode()
            api_path = "/api/admin/h/take-phone" if mode == "new" else "/api/admin/h/take-reusable-phone"
            data = _post_h_json(http, api_path, payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "H_PHONE_PREFIX", "") or "")
            phone = _normalize_h_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:H] 号码规范化：raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"H {api_path.rsplit('/', 1)[-1]} 响应缺少 item.id/item.phone：{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                f"[SMS:H] 取号成功：mode={mode}, api={api_path}, id={activation_id}, phone=+{phone}, "
                f"reused={bool(data.get('reused'))}, duplicate={bool(data.get('duplicate'))}"
            )
        else:
            params = {
                "action": "getNumber",
                "service": service or _cfg.SMS_SERVICE,
                "country": country or _cfg.SMS_COUNTRY,
            }
            if _cfg.SMS_MAX_PRICE:
                params["maxPrice"] = _cfg.SMS_MAX_PRICE

            text = _request_grizzly(http, params)
            # 成功格式：ACCESS_NUMBER:激活ID:号码
            if not text.startswith("ACCESS_NUMBER:"):
                raise SmsProviderError(f"getNumber 非预期响应：{text[:200]}")
            parts = text.split(":")
            if len(parts) < 3:
                raise SmsProviderError(f"getNumber 响应格式异常：{text[:200]}")
            activation_id = parts[1].strip()
            phone = parts[2].strip()
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(f"[SMS] 取号成功：activation_id={activation_id}, phone=+{phone}")

        if max_reuse > 1 and provider in ("5sim", "fivesim", "grizzly"):
            with _PHONE_POOL_LOCK:
                _ACTIVE_SESSIONS[activation_id] = _PhoneSession(
                    activation_id=activation_id,
                    phone=phone,
                    provider=provider,
                    max_uses=max_reuse,
                )

        return activation_id, phone
    finally:
        if own_http:
            http.close()


# ============================================================
# 取短信验证码
# ============================================================

def wait_for_sms_code(
    activation_id: str,
    http: CurlSession | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
) -> str:
    """
    轮询 getStatus 直到拿到短信验证码。

    Returns:
        验证码字符串

    Raises:
        SmsCodeTimeout —— 超时没收到（上层可换号重试）
        SmsProviderError —— 激活被取消等
    """
    own_http = http is None
    http = http or _http()
    deadline = time.time() + (max_wait or _cfg.SMS_CODE_WAIT)
    interval = poll_interval or _cfg.SMS_POLL_INTERVAL
    try:
        provider = _provider()
        total_wait = max_wait or _cfg.SMS_CODE_WAIT
        logger.info(f"[SMS] 等待短信验证码 activation_id={activation_id}，最长 {total_wait}s...")
        round_no = 0
        while time.time() < deadline:
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except ImportError:
                pass
            round_no += 1
            elapsed = max(0, int(total_wait - max(0, deadline - time.time())))
            remaining_before = max(0, int(deadline - time.time()))
            logger.info(
                f"[SMS] 第 {round_no} 轮获取验证码 activation_id={activation_id}，"
                f"已等 {elapsed}s，剩余约 {remaining_before}s"
            )
            if provider == "l":
                data = _post_l_json(http, "/api/admin/l/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:L] 第 {round_no} 轮收到验证码：{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:L] 第 {round_no} 轮未收到验证码，状态={status or raw or 'WAIT'}，"
                    f"{interval}s 后重试（剩余 {remaining}s）"
                )
                time.sleep(interval)
                continue

            if provider == "h":
                data = _post_h_json(http, "/api/admin/h/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:H] 第 {round_no} 轮收到验证码：{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:H] 第 {round_no} 轮未收到验证码，状态={status or raw or 'WAIT'}，"
                    f"{interval}s 后重试（剩余 {remaining}s）"
                )
                time.sleep(interval)
                continue

            exclude_codes = []
            with _PHONE_POOL_LOCK:
                sess = _ACTIVE_SESSIONS.get(activation_id)
                if sess:
                    exclude_codes = list(sess.codes)

            if provider in ("5sim", "fivesim"):
                code, status, raw_sms = _fetch_5sim_code(http, activation_id, exclude_codes=exclude_codes)
                if code:
                    logger.info(f"[SMS:5sim] 第 {round_no} 轮收到验证码：{code}")
                    with _PHONE_POOL_LOCK:
                        sess = _ACTIVE_SESSIONS.get(activation_id)
                        if sess and code not in sess.codes:
                            sess.codes.append(code)
                    return code
                if status in ("CANCELED", "CANCEL"):
                    raise SmsProviderError(f"5sim 订单已被取消：id={activation_id}")
                if status in ("TIMEOUT", "EXPIRED"):
                    raise SmsCodeTimeout(f"5sim 订单已超时：id={activation_id}")
                if status in ("BANNED",):
                    raise SmsProviderError(f"5sim 号码已被平台拉黑：id={activation_id}")
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:5sim] 第 {round_no} 轮未收到验证码，状态={status or 'PENDING'}，"
                    f"{interval}s 后重试（剩余 {remaining}s）"
                )
                time.sleep(interval)
                continue

            text = _request_grizzly(http, {"action": "getStatus", "id": activation_id})

            if text.startswith("STATUS_OK:"):
                code = text.split(":", 1)[1].strip()
                if code and code not in exclude_codes:
                    logger.info(f"[SMS] 第 {round_no} 轮收到验证码：{code}")
                    with _PHONE_POOL_LOCK:
                        sess = _ACTIVE_SESSIONS.get(activation_id)
                        if sess and code not in sess.codes:
                            sess.codes.append(code)
                    return code
            if text == "STATUS_CANCEL":
                raise SmsProviderError("激活已被取消（STATUS_CANCEL）")
            # STATUS_WAIT_CODE / STATUS_WAIT_RETRY:* / STATUS_WAIT_RESEND → 继续等
            remaining = max(0, int(deadline - time.time()))
            logger.info(f"[SMS] 第 {round_no} 轮未收到验证码，状态={text}，{interval}s 后重试（剩余 {remaining}s）")
            time.sleep(interval)

        raise SmsCodeTimeout(f"等待短信超时（>{total_wait}s），activation_id={activation_id}")
    finally:
        if own_http:
            http.close()


# ============================================================
# 改状态
# ============================================================

def set_status(activation_id: str, status: int, http: CurlSession | None = None) -> str:
    """
    设置激活状态（setStatus）。
        1 = 号码已就绪（短信已发出）
        3 = 等下一条短信（重发）
        6 = 完成激活
        8 = 取消激活
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() == "l":
            logger.debug(f"[SMS:L] 忽略状态设置 id={activation_id}, status={status}")
            return "OK"
        if _provider() in ("5sim", "fivesim"):
            logger.debug(f"[SMS:5sim] 忽略通用状态设置 id={activation_id}, status={status}")
            return "OK"
        return _request_grizzly(http, {"action": "setStatus", "status": str(status), "id": activation_id})
    finally:
        if own_http:
            http.close()


def complete(activation_id: str, http: CurlSession | None = None) -> None:
    """标记激活完成。若开启复用且未达上限，保留在复用池供下一个账号使用。"""
    provider = _provider()
    with _PHONE_POOL_LOCK:
        sess = _ACTIVE_SESSIONS.get(activation_id)

    if sess and sess.used_count < sess.max_uses:
        with _PHONE_POOL_LOCK:
            sess.in_use = False
            if sess not in _REUSABLE_QUEUE:
                _REUSABLE_QUEUE.append(sess)
        if sess.provider == "grizzly":
            try:
                set_status(activation_id, 3, http=http)
            except Exception:
                pass
        logger.info(
            f"[SMS] 号码 +{sess.phone} 验证通过，已保留在复用池待下一账号使用 "
            f"({sess.used_count}/{sess.max_uses})"
        )
        return

    # 达到上限或未复用，正式完成订单
    with _PHONE_POOL_LOCK:
        _ACTIVE_SESSIONS.pop(activation_id, None)
        if sess and sess in _REUSABLE_QUEUE:
            _REUSABLE_QUEUE.remove(sess)

    if provider == "l":
        logger.info(f"[SMS:L] 已完成 id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if provider == "h":
        # H 成功 fetch-code 后后台会自动按多次收码策略重取；这里不 release。
        logger.info(f"[SMS:H] 已完成 id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if provider in ("5sim", "fivesim"):
        _finish_5sim_order(activation_id, http=http)
        return
    try:
        set_status(activation_id, 6, http=http)
        logger.info(f"[SMS] 已标记完成 activation_id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS] 标记完成失败（不影响结果）：{exc}")


def _do_cancel_sync(activation_id: str, http_factory) -> None:
    """实际的同步取消逻辑：等够 2 分钟限制 → 发请求 → 失败重试一次。"""
    acquired_at = _ACQUIRED_AT.get(activation_id)
    if acquired_at is not None:
        elapsed = time.time() - acquired_at
        if elapsed < _MIN_CANCEL_DELAY:
            wait = _MIN_CANCEL_DELAY - elapsed
            logger.info(
                f"[SMS] 取消等待 GrizzlySMS 2 分钟限制：activation_id={activation_id}，"
                f"还需等 {wait:.0f}s..."
            )
            time.sleep(wait)

    # 后台线程不能复用外部 http session（curl_cffi 非线程安全），自己建一个
    http = http_factory()
    try:
        for attempt in range(1, 3):
            try:
                set_status(activation_id, 8, http=http)
                logger.info(f"[SMS] 已取消 activation_id={activation_id}")
                _ACQUIRED_AT.pop(activation_id, None)
                return
            except Exception as exc:
                if attempt == 1:
                    logger.warning(f"[SMS] 取消失败（{exc}），5s 后重试...")
                    time.sleep(5)
                else:
                    logger.warning(
                        f"[SMS] 取消最终失败（不影响结果，需到平台手动取消）：activation_id={activation_id}, {exc}"
                    )
    finally:
        try:
            http.close()
        except Exception:
            pass


def cancel(activation_id: str, http: CurlSession | None = None, background: bool = True) -> None:
    """
    取消激活（status=8），释放号码避免白扣费。
    若为复用号码且此前已成功过，直接结算关闭订单。
    """
    provider = _provider()
    with _PHONE_POOL_LOCK:
        sess = _ACTIVE_SESSIONS.get(activation_id)
        if sess and sess in _REUSABLE_QUEUE:
            _REUSABLE_QUEUE.remove(sess)

    # 如果该号码之前已经成功验证过至少 1 个账号，无法退款，直接关闭订单
    if sess and sess.used_count > 1 and len(sess.codes) >= 1:
        logger.info(
            f"[SMS] 号码 +{sess.phone} 曾成功验证过其他账号，本次取消直接结算关闭，不再申请退款"
        )
        with _PHONE_POOL_LOCK:
            _ACTIVE_SESSIONS.pop(activation_id, None)
        if provider in ("5sim", "fivesim"):
            _finish_5sim_order(activation_id, http=http)
            return
        if provider == "grizzly":
            try:
                set_status(activation_id, 6, http=http)
            except Exception:
                pass
            return

    with _PHONE_POOL_LOCK:
        _ACTIVE_SESSIONS.pop(activation_id, None)
    if _provider() == "l":
        try:
            _release_l_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:L] 释放号码失败（不影响主流程）：id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        try:
            _release_h_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:H] 释放号码失败（不影响主流程）：id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() in ("5sim", "fivesim"):
        # 5sim 无需强制等待 2 分钟，未收到验证码时可立即取消并退款
        _cancel_5sim_order(activation_id, http=http)
        return

    if not background:
        _do_cancel_sync(activation_id, _http)
        return

    t = threading.Thread(
        target=_do_cancel_sync,
        args=(activation_id, _http),
        name=f"sms-cancel-{activation_id}",
        daemon=True,
    )
    t.start()
    logger.debug(f"[SMS] 取消任务已派后台：activation_id={activation_id}")
