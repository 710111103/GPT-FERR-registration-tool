# -*- coding: utf-8 -*-
"""
代理池配置

每次注册随机抽取一个代理，保证不同 sid 之间彼此独立，避免风控关联。

协议说明：
    - http:// / https://   HTTP(S) 代理
    - socks5://            SOCKS5（DNS 本地解析，可能泄漏）
    - socks5h://           SOCKS5（DNS 在代理端解析，推荐，避免 DNS-IP 错配）
"""
from config.env_loader import apply_env_overrides
import random
from urllib.parse import quote, urlparse


# 本地代理入口；实际出口地区以代理/分流规则为准。
# 推荐使用 socks5h://（DNS 在代理端解析），避免本地 DNS 与出口 IP 地区错配。
PROXY_POOL = [
    "socks5://127.0.0.1:7897",
]

# 代理池使用的本地上游代理；留空时直接连接目标代理。
PROXY_POOL_UPSTREAM_PROXY = ""

# 套餐/Plus 试用资格查询与 Codex Agent Token 生成共用这组独立网络策略，
# 避免批量请求被注册代理池中的临时本地代理拖垮，也避免无条件直连造成出口策略失控。
#   auto   = 优先使用 PLAN_CHECK_PROXY 或代理池；本地代理端口未监听时回退直连
#   proxy  = 强制使用 PLAN_CHECK_PROXY 或代理池，失败直接报错
#   direct = 始终直连
PLAN_CHECK_PROXY_MODE = "proxy"

# 套餐查询 / Codex Agent Token 生成专用代理。留空时 auto/proxy 模式从 PROXY_POOL 选择。
# 代理可能包含账号密码，因此 WebUI 会把它保存到 .env。
PLAN_CHECK_PROXY = ""

# 多地区套餐检测代理，每行格式：国家代码|代理URL。
# 示例：US|http://user:pass@host:port
PLAN_CHECK_COUNTRY_PROXIES = []

# 查套餐 / 生成 Codex Agent Token 使用独立的短超时和有限重试，避免后台任务长时间卡住。
PLAN_CHECK_TIMEOUT = 35.0
PLAN_CHECK_MAX_ATTEMPTS = 3
PLAN_CHECK_RETRY_DELAY = 2.0

# 新注册账号的权益可能存在短暂同步延迟。首次查询失败，或返回 free 且暂未发现
# Plus 试用资格时，等待该秒数后再复查一次；设为 0 可关闭复查。
PLAN_CHECK_REGISTRATION_RECHECK_DELAY = 2.0

# 自动、手动和批量套餐查询共用同一个后台队列；Codex Agent Token 使用独立队列，
# 但复用这里的网络模式、请求启动间隔与随机抖动，避免批量后台请求过于集中。
PLAN_CHECK_WORKERS = 8
LIVE_CHECK_WORKERS = 6
PLAN_CHECK_QUEUE_LIMIT = 500
PLAN_CHECK_MIN_INTERVAL = 0.2
PLAN_CHECK_JITTER = 0.1

# 账号状态轻量巡检：复用套餐接口验证 access token，不触发邮箱 OTP。
# 0 表示关闭；每轮限制数量，避免进程启动后一次性打满代理和接口。
ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES = 360
ACCOUNT_STATUS_CHECK_BATCH_SIZE = 10

# 完整账号测活：按 live_checked_at 判断是否到期，执行登录/Token 刷新并更新账号存活状态。
# 这比套餐资格查询更重，默认每轮仅处理 3 个；0 表示关闭。
ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES = 360
ACCOUNT_LIVE_CHECK_BATCH_SIZE = 3
AUTO_REFRESH_EXPIRED_AT = True  # AT 的 JWT exp 到期后自动排队，失败至少间隔一小时。

# 查活遇到可重试的网络/代理错误时，自动创建新的认证会话并轮换代理。
# 1 表示只执行首轮；建议 2，避免验证码/风控类失败被无意义重试。
ACCOUNT_LIVE_CHECK_NETWORK_RETRIES = 2

# 查活成功并获得新 AT 后，是否顺带刷新套餐/试用资格。
# 默认关闭，避免一次手动查活额外触发套餐接口并消耗代理流量。
AUTO_PLAN_CHECK_AFTER_LIVE_REFRESH = False

# 支付方式/账单/订阅查询复用上面同一套网络模式与代理选择，但使用独立线程池与错峰参数。
PAYMENT_CHECK_WORKERS = 3
PAYMENT_CHECK_QUEUE_LIMIT = 500
PAYMENT_CHECK_MIN_INTERVAL = 1.0
PAYMENT_CHECK_JITTER = 0.8


def _valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    """Normalize common proxy shorthand while preserving explicit URLs."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "1024proxy" in text and "-sid-" not in text:
        import secrets
        sid = secrets.token_hex(4)
        if "://" in text:
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(text)
            if parts.username and parts.password:
                new_user = f"{parts.username}-sid-{sid}-t-5"
                netloc = f"{new_user}:{parts.password}@{parts.hostname}:{parts.port}"
                return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    if "://" in text:
        return text
    parts = text.split(":", 3)
    if len(parts) == 4 and parts[0] and _valid_port(parts[1]) and parts[2] and parts[3]:
        host, port, username, password = parts
        if "1024proxy" in host and "-sid-" not in username:
            import secrets
            username = f"{username}-sid-{secrets.token_hex(4)}-t-5"
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if len(parts) == 4 and parts[0] and parts[1] and parts[2] and _valid_port(parts[3]):
        username, password, host, port = parts
        if "1024proxy" in host and "-sid-" not in username:
            import secrets
            username = f"{username}-sid-{secrets.token_hex(4)}-t-5"
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    parsed = urlparse(f"//{text}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if parsed.hostname and port:
        return f"{default_scheme}://{text}"
    return text


normalize_proxy = normalize_proxy_url


def normalize_proxy_list(values, default_scheme: str = "http") -> list[str]:
    """Normalize a multiline proxy list and omit empty entries."""
    if values is None:
        return []
    if isinstance(values, str):
        values = values.splitlines()
    return [
        normalized
        for value in values
        if (normalized := normalize_proxy_url(value, default_scheme=default_scheme))
    ]


def pick_proxy() -> str:
    """从代理池中随机抽取一个代理 URL；池为空时返回空串（即不使用代理）。"""
    p = random.choice(PROXY_POOL) if PROXY_POOL else ""
    return normalize_proxy(p)


# 兼容入口：默认每次进程启动随机选一个，作为本次注册全程的固定代理
PROXY = pick_proxy()

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'PROXY_POOL': 'list_str_multiline',
    'PROXY_POOL_UPSTREAM_PROXY': 'str',
    'PLAN_CHECK_PROXY_MODE': 'str',
    'PLAN_CHECK_PROXY': 'str',
    'PLAN_CHECK_COUNTRY_PROXIES': 'list_str_multiline',
    'PLAN_CHECK_TIMEOUT': 'float',
    'PLAN_CHECK_MAX_ATTEMPTS': 'int',
    'PLAN_CHECK_RETRY_DELAY': 'float',
    'PLAN_CHECK_REGISTRATION_RECHECK_DELAY': 'float',
    'PLAN_CHECK_WORKERS': 'int',
    'PLAN_CHECK_QUEUE_LIMIT': 'int',
    'PLAN_CHECK_MIN_INTERVAL': 'float',
    'PLAN_CHECK_JITTER': 'float',
    'ACCOUNT_STATUS_CHECK_INTERVAL_MINUTES': 'int',
    'ACCOUNT_STATUS_CHECK_BATCH_SIZE': 'int',
    'ACCOUNT_LIVE_CHECK_INTERVAL_MINUTES': 'int',
    'ACCOUNT_LIVE_CHECK_BATCH_SIZE': 'int',
    'AUTO_REFRESH_EXPIRED_AT': 'bool',
    'ACCOUNT_LIVE_CHECK_NETWORK_RETRIES': 'int',
    'AUTO_PLAN_CHECK_AFTER_LIVE_REFRESH': 'bool',
    'PAYMENT_CHECK_WORKERS': 'int',
    'PAYMENT_CHECK_QUEUE_LIMIT': 'int',
    'PAYMENT_CHECK_MIN_INTERVAL': 'float',
    'PAYMENT_CHECK_JITTER': 'float',
})
PROXY = pick_proxy()

