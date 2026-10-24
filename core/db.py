# -*- coding: utf-8 -*-
"""
SQLite 持久化层（JSON/TXT 仅用于首次迁移）。

运行时数据全部存储在根目录 `turb.sqlite3`；旧 JSON/TXT/Codex 文件仅用于一次性迁移。
"""
import hashlib
from core.token_expiry import access_token_expires_at
import json
import logging

logger = logging.getLogger(__name__)
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT
_LEGACY_DATA_DIR = _PROJECT_ROOT / "data"
_LOG_DIR = _PROJECT_ROOT / "注册日志"
_PLAN_CHECK_STALE_SECONDS = 120
_PLAN_CHECK_QUEUE_STALE_SECONDS = 1800

_OUTLOOK_JSON = _PROJECT_ROOT / "用于注册的邮箱.json"
_OUTLOOK_TXT = _PROJECT_ROOT / "用于注册的邮箱.txt"
_GENERIC_API_EMAIL_JSON = _PROJECT_ROOT / "用于注册的API邮箱.json"
_GENERIC_API_EMAIL_TXT = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_ACCOUNTS_JSON = _PROJECT_ROOT / "注册成功的邮箱.json"
_ACCOUNTS_TXT = _PROJECT_ROOT / "注册成功的邮箱.txt"
_TOKENS_TXT = _PROJECT_ROOT / "注册成功的token.txt"
_JOBS_JSON = _PROJECT_ROOT / "注册任务.json"
# 兼容旧测试/外部调用方；静态查看器已停用，不会再写入此路径。
_VIEWER_HTML = _PROJECT_ROOT / "accounts_viewer.html"
_CODEX_DIR = _PROJECT_ROOT / "codex_accounts"
_CODEX_AGENT_DIR = _PROJECT_ROOT / "codex_agent_accounts"
# 仅供一次性迁移旧导出状态，运行期间不再读取该文件。
_LEGACY_CODEX_EXPORT_STATE = _PROJECT_ROOT / "codex_导出状态.json"
# SQLite 是运行时唯一业务数据主存储；旧 JSON/TXT 仅用于一次性迁移。
_SQLITE_PATH = _PROJECT_ROOT / "turb.sqlite3"
_SQLITE_LOCK = threading.RLock()
_SQLITE_READY = False
_TABLES = {
    "accounts": "accounts",
    "outlook": "email_pool",
    "generic_api": "email_pool",
    "imap": "email_pool",
    "jobs": "registration_jobs",
    "domain": "email_pool",
    "codex": "codex_accounts",
}
_EMAIL_SOURCES = {"outlook": "outlook", "generic_api": "generic_api", "imap": "imap", "domain": "cloudflare_domain", "remail": "remail"}
_LEGACY_TABLES = {"outlook": "outlook_pool", "generic_api": "generic_api_pool", "domain": "domain_email_pool"}

_LEGACY_SQLITE = _LEGACY_DATA_DIR / "registrations.db"
_LEGACY_OUTLOOK_JSON = _LEGACY_DATA_DIR / "outlook_accounts.json"
_LEGACY_ACCOUNTS_JSON = _LEGACY_DATA_DIR / "registered_accounts.json"
_LEGACY_JOBS_JSON = _LEGACY_DATA_DIR / "registration_jobs.json"
_LOCK = threading.RLock()
_DEFAULT_SQLITE_PATH = _SQLITE_PATH
_DEFAULT_ACCOUNTS_JSON = _ACCOUNTS_JSON
_DEFAULT_OUTLOOK_JSON = _OUTLOOK_JSON
_DEFAULT_JOBS_JSON = _JOBS_JSON
_SQLITE_READY_PATH: Path | None = None


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _ensure_storage() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _sqlite_conn() -> sqlite3.Connection:
    """创建短生命周期连接；WAL 允许 WebUI 读与注册线程写并行。"""
    _ensure_storage()
    conn = sqlite3.connect(str(_active_sqlite_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _active_sqlite_path() -> Path:
    """测试替换旧 JSON 路径时使用同目录数据库，避免污染正式库。"""
    if (
        _ACCOUNTS_JSON != _DEFAULT_ACCOUNTS_JSON
        or _OUTLOOK_JSON != _DEFAULT_OUTLOOK_JSON
        or _JOBS_JSON != _DEFAULT_JOBS_JSON
    ):
        return _ACCOUNTS_JSON.parent / "turb.sqlite3"
    return _DEFAULT_SQLITE_PATH


def _read_legacy_sqlite_collection(collection: str) -> list[dict] | None:
    """读取旧 data/registrations.db 的数据，仅在一次性迁移阶段调用。"""
    if not _LEGACY_SQLITE.exists():
        return None
    try:
        with closing(sqlite3.connect(str(_LEGACY_SQLITE))) as legacy_conn:
            legacy_conn.row_factory = sqlite3.Row
            table = "registered_accounts" if collection == "accounts" else "outlook_pool" if collection == "outlook" else ""
            if not table or not _table_exists(legacy_conn, table):
                return None
            return [dict(row) for row in legacy_conn.execute(f"SELECT * FROM {table}").fetchall()]
    except Exception:
        return None


def _ensure_sqlite() -> None:
    """首次运行将现有 JSON 一次性导入 SQLite，之后 SQLite 为唯一读写源。"""
    global _SQLITE_READY, _SQLITE_READY_PATH
    active_path = _active_sqlite_path()
    if _SQLITE_READY and _SQLITE_READY_PATH == active_path:
        return
    with _SQLITE_LOCK:
        active_path = _active_sqlite_path()
        if _SQLITE_READY and _SQLITE_READY_PATH == active_path:
            return
        conn = _sqlite_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                PRIMARY KEY (id)
            );
            CREATE TABLE IF NOT EXISTS email_pool (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registration_jobs AS SELECT * FROM accounts WHERE 0;
            CREATE TABLE IF NOT EXISTS codex_accounts (
                id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL UNIQUE, email TEXT NOT NULL DEFAULT '',
                archived INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS codex_agent_accounts (
                account_id INTEGER PRIMARY KEY,
                email TEXT NOT NULL DEFAULT '', filename TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL
            );
                CREATE TABLE IF NOT EXISTS account_inspections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_account_inspection
                    ON account_inspections ((1)) WHERE status IN ('queued', 'running');
                CREATE TABLE IF NOT EXISTS account_inspection_snapshots (
                    inspection_id INTEGER PRIMARY KEY,
                    account_ids TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS account_inspection_failures (
                    inspection_id INTEGER NOT NULL,
                    account_id INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT NOT NULL,
                    failed_at TEXT NOT NULL,
                    PRIMARY KEY (inspection_id, account_id)
                );
            CREATE TABLE IF NOT EXISTS storage_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        for table in {"accounts", "email_pool", "registration_jobs"}:
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status, id DESC)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_archived ON {table}(archived, id DESC)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_email ON {table}(email COLLATE NOCASE)")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_created ON {table}(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email_pool_source_status ON email_pool(source, status, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_codex_accounts_archived ON codex_accounts(archived, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_codex_accounts_email ON codex_accounts(email COLLATE NOCASE)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_codex_accounts_created ON codex_accounts(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_codex_agent_accounts_email ON codex_agent_accounts(email COLLATE NOCASE)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_codex_agent_accounts_updated ON codex_agent_accounts(updated_at DESC)")
        migration_done = conn.execute(
            "SELECT 1 FROM storage_meta WHERE key='legacy_import_completed' LIMIT 1"
        ).fetchone()
        # 迁移标记写入 SQLite，而不是依赖“表是否为空”。这样用户删除全部数据后，
        # 重启也不会再次从旧 JSON 恢复已删除的数据。
        if not migration_done:
            sources = {
                "accounts": (_ACCOUNTS_JSON, _LEGACY_ACCOUNTS_JSON),
                "outlook": (_OUTLOOK_JSON, _LEGACY_OUTLOOK_JSON),
                "generic_api": (_GENERIC_API_EMAIL_JSON,),
                "jobs": (_JOBS_JSON, _LEGACY_JOBS_JSON),
                "domain": (_DOMAIN_EMAIL_JSON,),
            }
            for collection, paths in sources.items():
                table = _TABLES[collection]
                exists = conn.execute(
                    f"SELECT 1 FROM {table}" + (" WHERE source=?" if table == "email_pool" else " LIMIT 1"),
                    ((_EMAIL_SOURCES[collection],) if table == "email_pool" else ()),
                ).fetchone()
                if exists:
                    continue
                rows = None
            # 兼容上一版“records 单表 + collection”实现。
                if _table_exists(conn, "records"):
                    legacy = conn.execute("SELECT payload FROM records WHERE collection=? ORDER BY id", (collection,)).fetchall()
                    if legacy:
                        rows = [json.loads(item["payload"]) for item in legacy]
            # 兼容上一版按邮箱来源拆分的三张表。
                if collection in _EMAIL_SOURCES and rows is None:
                    old_table = _LEGACY_TABLES[collection]
                    if _table_exists(conn, old_table):
                        legacy = conn.execute(f"SELECT payload FROM {old_table} ORDER BY id").fetchall()
                        if legacy:
                            rows = [json.loads(item["payload"]) for item in legacy]
                for path in paths:
                    if rows is None and path.exists():
                        candidate = _read_json(path, None)
                        if isinstance(candidate, list):
                            rows = candidate
                            break
                if rows is None:
                    rows = _read_legacy_sqlite_collection(collection)
                if not rows:
                    continue
                next_email_id = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM email_pool").fetchone()[0]) + 1 if table == "email_pool" else 0
                for pos, row in enumerate(rows, 1):
                    row = dict(row)
                    rid = next_email_id if table == "email_pool" else int(row.get("id") or pos)
                    if table == "email_pool":
                        next_email_id += 1
                    row["id"] = rid
                    conn.execute(
                        f"INSERT OR REPLACE INTO {table}(id,email,source,status,archived,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?,?)" if table == "email_pool" else
                        f"INSERT OR REPLACE INTO {table}(id,email,status,archived,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?)",
                        ((rid, str(row.get("email") or ""), _EMAIL_SOURCES[collection], str(row.get("status") or ""),
                          int(bool(row.get("archived"))), str(row.get("created_at") or row.get("imported_at") or ""),
                          str(row.get("updated_at") or ""), json.dumps(row, ensure_ascii=False)) if table == "email_pool" else
                         (rid, str(row.get("email") or ""), str(row.get("status") or ""),
                          int(bool(row.get("archived"))), str(row.get("created_at") or row.get("imported_at") or ""),
                          str(row.get("updated_at") or ""), json.dumps(row, ensure_ascii=False))),
                    )
        # 兼容早期 SQLite 版本的保存逻辑：当时写入 email_pool 时漏掉了
        # source 列，导致通用 API 邮箱在“全部邮箱池”中没有类型，按来源筛选
        # 也查不到。根据素材字段只修复可明确识别的历史行，避免误分类域名邮箱。
        conn.execute(
            "UPDATE email_pool SET source=? "
            "WHERE (source IS NULL OR trim(source)='') AND ("
            "json_extract(payload, '$.code_url') IS NOT NULL OR "
            "json_extract(payload, '$.url') IS NOT NULL OR "
            "json_extract(payload, '$.source') IN ('generic_api', 'generic-api') OR "
            "json_extract(payload, '$.email_source') IN ('generic_api', 'generic-api')"
            ")",
            (_EMAIL_SOURCES["generic_api"],),
        )
        conn.execute(
            "UPDATE email_pool SET source=? "
            "WHERE (source IS NULL OR trim(source)='') AND ("
            "json_extract(payload, '$.client_id') IS NOT NULL OR "
            "json_extract(payload, '$.clientId') IS NOT NULL OR "
            "json_extract(payload, '$.refresh_token') IS NOT NULL OR "
            "json_extract(payload, '$.refreshToken') IS NOT NULL OR "
            "json_extract(payload, '$.source') IN ('outlook', 'outlook_pool') OR "
            "json_extract(payload, '$.email_source') = 'outlook'"
            ")",
            (_EMAIL_SOURCES["outlook"],),
        )
        # 域名邮箱的历史 payload 没有 client_id/code_url 等特征，剩余的空来源
        # 记录只能归入域名邮箱池。否则它们会在“全部邮箱池”中显示为未知来源，
        # 前端又会按 Outlook 处理，导致列表里能看到但删除/改状态找不到。
        conn.execute(
            "UPDATE email_pool SET source=? "
            "WHERE (source IS NULL OR trim(source)='') AND COALESCE(("
            "json_extract(payload, '$.code_url') IS NOT NULL OR "
            "json_extract(payload, '$.url') IS NOT NULL OR "
            "json_extract(payload, '$.source') IN ('generic_api', 'generic-api', 'outlook', 'outlook_pool') OR "
            "json_extract(payload, '$.email_source') IN ('generic_api', 'generic-api', 'outlook') OR "
            "json_extract(payload, '$.client_id') IS NOT NULL OR "
            "json_extract(payload, '$.clientId') IS NOT NULL OR "
            "json_extract(payload, '$.refresh_token') IS NOT NULL OR "
            "json_extract(payload, '$.refreshToken') IS NOT NULL"
            "), 0)=0",
            (_EMAIL_SOURCES["domain"],),
        )
        # CPA Codex 凭证首次导入数据库；后续列表查询不再扫描 codex_accounts/ 文件。
        if not migration_done and not conn.execute("SELECT 1 FROM codex_accounts LIMIT 1").fetchone() and _CODEX_DIR.exists():
            state = _read_json(_LEGACY_CODEX_EXPORT_STATE, {})
            state = state if isinstance(state, dict) else {}
            for pos, path in enumerate(sorted(_CODEX_DIR.glob("codex-*.json")), 1):
                try:
                    content = json.loads(path.read_text(encoding="utf-8"))
                    stat = path.stat()
                except Exception:
                    continue
                filename = path.name
                meta = dict(content)
                meta["_filename"] = filename
                meta["_size"] = stat.st_size
                meta["_mtime"] = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
                es = state.get(filename) or {}
                meta["_exported_at"] = es.get("exported_at")
                meta["_exported_count"] = es.get("exported_count", 0)
                meta["_archived"] = bool(es.get("archived"))
                conn.execute(
                    "INSERT OR IGNORE INTO codex_accounts(id,filename,email,archived,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?)",
                    (pos, filename, str(content.get("email") or ""), int(meta["_archived"]), meta["_mtime"], meta["_mtime"], json.dumps(meta, ensure_ascii=False)),
                )
        # Agent 凭证也只在首次迁移时读取；运行期间完整内容保存在 SQLite。
        if not migration_done and not conn.execute("SELECT 1 FROM codex_agent_accounts LIMIT 1").fetchone() and _CODEX_AGENT_DIR.exists():
            for path in sorted(_CODEX_AGENT_DIR.glob("codex-agent-*.json")):
                try:
                    content = json.loads(path.read_text(encoding="utf-8"))
                    stat = path.stat()
                except Exception:
                    continue
                identity = content.get("agent_identity") if isinstance(content.get("agent_identity"), dict) else {}
                email = str(content.get("email") or identity.get("email") or "").strip()
                account = conn.execute("SELECT id, payload FROM accounts WHERE lower(email)=lower(?) LIMIT 1", (email,)).fetchone() if email else None
                if not account:
                    continue
                account_id = int(account["id"])
                stamp = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
                conn.execute(
                    "INSERT OR IGNORE INTO codex_agent_accounts(account_id,email,filename,created_at,updated_at,payload) VALUES(?,?,?,?,?,?)",
                    (account_id, email or str(json.loads(account["payload"]).get("email") or ""), path.name, stamp, stamp, json.dumps(content, ensure_ascii=False)),
                )
                account_payload = json.loads(account["payload"])
                account_payload.setdefault("codex_agent_token", json.dumps(content, ensure_ascii=False))
                account_payload.pop("codex_agent_auth_path", None)
                conn.execute("UPDATE accounts SET payload=?, updated_at=? WHERE id=?", (json.dumps(account_payload, ensure_ascii=False), stamp, account_id))
        # 旧版把 1–99% 折扣误记为“免费试用”；只迁移有明确折扣证据的账号。
        conn.execute(
            "UPDATE accounts SET updated_at=?, payload=json_remove(json_set(payload, "
            "'$.discount_offer_eligible', json('true'), "
            "'$.discount_offer_campaign_id', json_extract(payload, '$.plus_trial_campaign_id'), "
            "'$.discount_offer_title', json_extract(payload, '$.plus_trial_title'), "
            "'$.discount_offer_percentage', json_extract(payload, '$.plus_trial_discount_percentage'), "
            "'$.plus_trial_eligible', json('false')), "
            "'$.plus_trial_campaign_id', '$.plus_trial_title', "
            "'$.plus_trial_discount_percentage', '$.plus_trial_duration_num_periods', "
            "'$.plus_trial_duration_period') "
            "WHERE json_extract(payload, '$.plus_trial_eligible') IN (1, 'true') AND ("
            "(CAST(json_extract(payload, '$.plus_trial_discount_percentage') AS REAL) > 0 "
            "AND CAST(json_extract(payload, '$.plus_trial_discount_percentage') AS REAL) < 100) "
            "OR lower(COALESCE(json_extract(payload, '$.plus_trial_campaign_id'), '')) LIKE '%pct-off%' "
            "OR lower(COALESCE(json_extract(payload, '$.plus_trial_campaign_id'), '')) LIKE '%discount%')",
            (_now(),),
        )
        conn.commit()
        # 迁移完成后删除旧的通用表，避免运行时继续依赖它。
        for old_table in (*_LEGACY_TABLES.values(), "records"):
            if _table_exists(conn, old_table) and old_table not in _TABLES.values():
                conn.execute(f"DROP TABLE {old_table}")
        if not migration_done:
            conn.execute("INSERT OR REPLACE INTO storage_meta(key, value) VALUES('legacy_import_completed', ?)", (_now(),))
        conn.commit()
        conn.close()
        _SQLITE_READY = True
        _SQLITE_READY_PATH = active_path


def _load_collection(collection: str) -> list[dict]:
    _ensure_sqlite()
    table = _TABLES[collection]
    with closing(_sqlite_conn()) as conn:
        with conn:
            sql = f"SELECT payload FROM {table}"
            params: tuple[str, ...] = ()
            if table == "email_pool":
                sql += " WHERE source=?"; params = (_EMAIL_SOURCES[collection],)
            sql += " ORDER BY id"
            return [json.loads(row["payload"]) for row in conn.execute(sql, params)]


def _save_collection(collection: str, rows: list[dict]) -> None:
    _ensure_sqlite()
    table = _TABLES[collection]
    source = _EMAIL_SOURCES[collection] if table == "email_pool" else None
    with closing(_sqlite_conn()) as conn:
        with conn:
            if table == "email_pool":
                conn.execute("DELETE FROM email_pool WHERE source=?", (source,))
            else:
                conn.execute(f"DELETE FROM {table}")
            for pos, raw in enumerate(rows, 1):
                row = dict(raw)
                rid = int(row.get("id") or pos)
                row["id"] = rid
                if table == "email_pool" and conn.execute("SELECT 1 FROM email_pool WHERE id=?", (rid,)).fetchone():
                    rid = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM email_pool").fetchone()[0])
                    row["id"] = rid
                if table == "email_pool":
                    conn.execute(
                        "INSERT INTO email_pool(id,email,source,status,archived,created_at,updated_at,payload) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (rid, str(row.get("email") or ""), source, str(row.get("status") or ""),
                         int(bool(row.get("archived"))), str(row.get("created_at") or row.get("imported_at") or ""),
                         str(row.get("updated_at") or ""), json.dumps(row, ensure_ascii=False)),
                    )
                else:
                    conn.execute(
                        f"INSERT INTO {table}(id,email,status,archived,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?)",
                        (rid, str(row.get("email") or ""), str(row.get("status") or ""),
                         int(bool(row.get("archived"))), str(row.get("created_at") or row.get("imported_at") or ""),
                         str(row.get("updated_at") or ""), json.dumps(row, ensure_ascii=False)),
                    )


def _query_collection(collection: str, *, status: str | None = None, archived: str | bool | None = None,
                       q: str | None = None, date_from: str | None = None, date_to: str | None = None,
                       limit: int | None = None, offset: int = 0) -> list[dict]:
    """利用索引分页读取，避免 WebUI 为一个页面加载整个 JSON 文件。"""
    _ensure_sqlite()
    table = _TABLES[collection]
    where = ["1=1"]
    params: list[Any] = []
    if table == "email_pool":
        where.append("source=?"); params.append(_EMAIL_SOURCES[collection])
    if status:
        where.append("status=?"); params.append(status)
    if archived not in (None, "all", "include"):
        where.append("archived=?"); params.append(int(archived in (True, "1", "true", "yes", "only")))
    if q and str(q).strip():
        where.append("lower(payload) LIKE ?"); params.append("%" + str(q).strip().lower() + "%")
    if date_from:
        where.append("created_at >= ?"); params.append(str(date_from) + ("T00:00:00" if len(str(date_from)) == 10 else ""))
    if date_to:
        value = str(date_to)
        where.append("created_at <= ?"); params.append(value + ("T23:59:59.999999" if len(value) == 10 else ""))
    sql = f"SELECT payload FROM {table} WHERE " + " AND ".join(where) + " ORDER BY id DESC"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"; params.extend([max(0, int(limit)), max(0, int(offset))])
    with closing(_sqlite_conn()) as conn:
        return [json.loads(row["payload"]) for row in conn.execute(sql, params)]


def _query_collection_page(collection: str, *, status: str | None = None,
                           archived: str | bool | None = None, q: str | None = None,
                           date_from: str | None = None, date_to: str | None = None,
                           extra_where: list[str] | None = None,
                           extra_params: list[Any] | None = None,
                           limit: int = 50, offset: int = 0) -> tuple[list[dict], int, str]:
    """执行真正的 SQL COUNT/LIMIT/OFFSET 分页，并返回最新更新时间。"""
    _ensure_sqlite()
    table = _TABLES[collection]
    where = ["1=1"]
    params: list[Any] = []
    if table == "email_pool":
        where.append("source=?"); params.append(_EMAIL_SOURCES[collection])
    if status:
        where.append("status=?"); params.append(status)
    if archived not in (None, "all", "include"):
        where.append("archived=?"); params.append(int(archived in (True, "1", "true", "yes", "only")))
    if q and str(q).strip():
        where.append("lower(payload) LIKE ?"); params.append("%" + str(q).strip().lower() + "%")
    if date_from:
        value = str(date_from)
        where.append("created_at >= ?"); params.append(value + ("T00:00:00" if len(value) == 10 else ""))
    if date_to:
        value = str(date_to)
        where.append("created_at <= ?"); params.append(value + ("T23:59:59.999999" if len(value) == 10 else ""))
    if extra_where:
        where.extend(extra_where)
        params.extend(extra_params or [])
    clause = " AND ".join(where)
    with closing(_sqlite_conn()) as conn:
        total = int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", params).fetchone()[0])
        latest = str(conn.execute(f"SELECT COALESCE(MAX(updated_at), '') FROM {table} WHERE {clause}", params).fetchone()[0] or "")
        rows = [json.loads(row["payload"]) for row in conn.execute(
            f"SELECT payload FROM {table} WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, max(1, int(limit)), max(0, int(offset))],
        )]
    return rows, total, latest


def _overview_filter_sql(overview_filter: str | None = None) -> tuple[list[str], list[Any]]:
    """把总览卡片下钻条件下推到 SQLite，保证跨分页筛选。

    registering/interrupted 只是注册流程留下的原始标记；如果密码、AT、
    2FA 都已完成，则按“实际已完成”处理，不再归入注册异常。
    """
    key = str(overview_filter or "").strip().lower()
    if not key or key in {"all", "total"}:
        return [], []
    token = "trim(COALESCE(CAST(json_extract(payload, '$.access_token') AS TEXT), ''))"
    expired = "lower(COALESCE(CAST(json_extract(payload, '$.token_expired') AS TEXT), ''))"
    http = "CAST(COALESCE(json_extract(payload, '$.plan_check_http_status'), 0) AS INTEGER)"
    plan = "lower(COALESCE(NULLIF(CAST(json_extract(payload, '$.current_plan_type') AS TEXT), ''), CAST(json_extract(payload, '$.plan_type') AS TEXT), ''))"
    eligible = "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
    check = "lower(COALESCE(CAST(json_extract(payload, '$.plan_check_status') AS TEXT), ''))"
    live = "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
    registration = "lower(trim(COALESCE(status, '')))"
    password_login_verified = "lower(COALESCE(CAST(json_extract(payload, '$.password_setup_login_verified') AS TEXT), ''))"
    password_extra_verified = (
        "lower(COALESCE(CAST(json_extract(json_extract(payload, '$.extra_json'), "
        "'$.registration_password_verified') AS TEXT), ''))"
    )
    password_ok = (
        f"({password_login_verified} IN ('1','true','yes','on') OR "
        f"{password_extra_verified} IN ('1','true','yes','on'))"
    )
    totp_secret = "trim(COALESCE(CAST(json_extract(payload, '$.totp_secret') AS TEXT), ''))"
    totp_ok = "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_ok') AS TEXT), ''))"
    totp_status = "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_status') AS TEXT), ''))"
    at_valid = (
        f"length({token})>0 AND {expired} NOT IN ('1','true','yes','on') "
        f"AND {http}<>401 AND {live} NOT IN ('failed','deactivated','dead')"
    )
    registration_complete = (
        f"({password_ok} AND {at_valid} "
        f"AND length({totp_secret})>0 AND "
        f"({totp_ok} IN ('1','true','yes','on') OR {totp_status}='success'))"
    )
    registration_incomplete = f"{registration} IN ('registering','interrupted') AND NOT {registration_complete}"
    if key == "registering": return [f"{registration}='registering' AND NOT {registration_complete}"], []
    if key == "interrupted": return [f"{registration}='interrupted' AND NOT {registration_complete}"], []
    if key == "registration_incomplete": return [registration_incomplete], []
    if key == "registration_recovered": return [f"{registration} IN ('registering','interrupted') AND {registration_complete}"], []
    if key == "password_saved": return [password_ok], []
    if key == "at_expired": return [f"({expired} IN ('1','true','yes','on') OR {http}=401)"], []
    if key == "at_missing": return [f"length({token})=0"], []
    if key == "at_valid": return [f"length({token})>0 AND {expired} NOT IN ('1','true','yes','on') AND {http}<>401"], []
    if key == "eligible": return [f"{eligible} IN ('1','true','yes','on') AND {expired} NOT IN ('1','true','yes','on') AND {check}<>'failed' AND {live} NOT IN ('failed','deactivated','dead') AND {http}<>401 AND length({token})>0 AND {plan}='free'"], []
    if key == "ineligible": return [f"{eligible} IN ('0','false','no','off')"], []
    if key == "eligibility_unknown": return [f"{eligible}=''"], []
    if key == "plus": return [f"{plan} LIKE '%plus%' AND {plan} NOT LIKE '%free%'"], []
    if key == "free": return [f"{plan}='free'"], []
    if key in {"queued", "running", "success", "failed"}: return [f"{check}=?"], [key]
    if key == "unchecked": return [f"{check}=''"], []
    if key == "live_failed": return [f"{live} IN ('failed','deactivated','dead')"], []
    if key == "live": return [f"{live}='live'"], []
    return [], []


def _account_filter_sql(
    plan_filter: str | None = None,
    codex_filter: str | None = None,
    totp_filter: str | None = None,
) -> tuple[list[str], list[Any]]:
    """把账号列表的套餐、Codex、2FA 过滤条件下推到 SQLite。

    套餐、Codex、2FA 状态仍保存在账号 payload 中，因此这里使用 SQLite JSON1
    直接过滤，而不是先把整张 accounts 表反序列化到 Python 再切页。
    """
    where: list[str] = []
    params: list[Any] = []
    plan = str(plan_filter or "").strip().lower()
    codex = str(codex_filter or "").strip().lower()
    totp = str(totp_filter or "").strip().lower()

    plan_expr = (
        "lower(COALESCE(NULLIF(CAST(json_extract(payload, '$.current_plan_type') AS TEXT), ''), "
        "CAST(json_extract(payload, '$.plan_type') AS TEXT), ''))"
    )
    if plan and plan not in {"all", "any"}:
        if plan == "plus":
            # 与 _account_matches_plan_filter 保持一致：free(可试用)不算已开通 Plus。
            where.extend([f"{plan_expr} LIKE ?", f"{plan_expr} NOT LIKE ?"])
            params.extend(["%plus%", "%free%"])
        elif plan in {"plus_trial", "plus_trial_eligible", "trial", "trial_eligible"}:
            # 只有当前套餐为 free 且套餐查询明确返回可试用资格，且未失效/未失败时才命中。
            trial_expr = "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
            check_status_expr = "lower(COALESCE(CAST(json_extract(payload, '$.plan_check_status') AS TEXT), ''))"
            expired_expr = "lower(COALESCE(CAST(json_extract(payload, '$.token_expired') AS TEXT), ''))"
            live_expr = "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
            http_expr = "CAST(COALESCE(json_extract(payload, '$.plan_check_http_status'), 0) AS INTEGER)"
            where.append(f"{plan_expr} = ?")
            where.append(f"{trial_expr} IN (?, ?, ?, ?)")
            where.append(f"{check_status_expr} <> ?")
            where.append(f"{expired_expr} NOT IN ('1', 'true', 'yes', 'on')")
            where.append(f"{live_expr} NOT IN ('failed', 'deactivated', 'dead')")
            where.append(f"{http_expr} <> 401")
            params.extend(["free", "1", "true", "yes", "on", "failed"])
        elif plan in {"discount", "discount_offer", "discount_eligible"}:
            discount_expr = "lower(COALESCE(CAST(json_extract(payload, '$.discount_offer_eligible') AS TEXT), ''))"
            where.append(f"{plan_expr} = ?")
            where.append(f"{discount_expr} IN (?, ?, ?, ?)")
            params.extend(["free", "1", "true", "yes", "on"])
        elif plan in {"free_no_trial", "free_without_trial", "free_not_trial"}:
            # 只匹配已明确查询到“不具备 Plus 试用资格”的 free 账号；字段缺失表示资格未知，不命中。
            trial_expr = "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
            where.append(f"{plan_expr} = ?")
            where.append(f"{trial_expr} IN (?, ?, ?, ?)")
            params.extend(["free", "0", "false", "no", "off"])
        elif plan == "free":
            where.append(f"{plan_expr} = ?")
            params.append("free")
        else:
            where.append(f"{plan_expr} = ?")
            params.append(plan)

    status_expr = "lower(COALESCE(CAST(json_extract(payload, '$.codex_status') AS TEXT), ''))"
    live_status_expr = "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
    if codex and codex not in {"all", "*"}:
        if codex == "deactivated":
            where.append(f"{live_status_expr} = ?")
        else:
            where.append(f"{status_expr} = ?")
        params.append(codex)

    totp_secret_expr = "lower(COALESCE(CAST(json_extract(payload, '$.totp_secret') AS TEXT), ''))"
    totp_setup_expr = "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_status') AS TEXT), ''))"
    if totp and totp not in {"all", "*"}:
        if totp in {"enabled", "on", "active"}:
            where.append(f"length(trim({totp_secret_expr})) > 0")
        elif totp in {"disabled", "off", "not_enabled", "unset"}:
            where.append(f"length(trim({totp_secret_expr})) = 0")
        elif totp in {"pending", "setup", "setting", "queued", "running"}:
            where.append(f"{totp_setup_expr} IN (?, ?)")
            params.extend(["queued", "running"])
        elif totp == "failed":
            where.append(f"{totp_setup_expr} = ?")
            params.append("failed")
        elif totp == "stopped":
            where.append(f"{totp_setup_expr} = ?")
            params.append("stopped")
        else:
            where.append(f"{totp_setup_expr} = ?")
            params.append(totp)
    return where, params


def _pool_summary_sql(collection: str) -> dict:
    _ensure_sqlite()
    table = _TABLES[collection]
    with closing(_sqlite_conn()) as conn:
        where = " WHERE source=?" if table == "email_pool" else ""
        params = (_EMAIL_SOURCES[collection],) if table == "email_pool" else ()
        counts = {str(r["status"] or "available"): int(r["n"]) for r in conn.execute(
            f"SELECT status, COUNT(*) AS n FROM {table}{where} GROUP BY status", params
        )}
    out = {"available": counts.get("available", 0), "used": counts.get("used", 0), "failed": counts.get("failed", 0)}
    out.update({k: v for k, v in counts.items() if k not in out})
    out["total"] = sum(v for k, v in out.items() if k != "total")
    return out


def _read_json(path: Path, default: Any) -> Any:
    _ensure_storage()
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _next_id(items: list[dict]) -> int:
    ids = [int(item.get("id") or 0) for item in items]
    return (max(ids) if ids else 0) + 1


def _outlook_line(row: dict) -> str:
    return "----".join([
        row.get("email") or "",
        row.get("password") or "",
        row.get("client_id") or "",
        row.get("refresh_token") or "",
    ])


def _generic_api_email_line(row: dict) -> str:
    return "----".join([
        row.get("email") or "",
        row.get("code_url") or "",
    ])


def _imap_email_line(row: dict) -> str:
    return "----".join([
        row.get("email") or "",
        row.get("imap_password") or row.get("password") or "",
    ])


def _password_extra(row: dict) -> dict:
    extra_raw = row.get("extra_json")
    if isinstance(extra_raw, str) and extra_raw.strip():
        try:
            extra = json.loads(extra_raw)
        except Exception:
            extra = {}
    elif isinstance(extra_raw, dict):
        extra = extra_raw
    else:
        extra = {}
    return extra if isinstance(extra, dict) else {}


def account_password_login_verified(row: dict | None) -> bool:
    """只有本地的候选密码通过登录验证或具有有效密码记录后，才可视为可用登录密码。"""
    value = row or {}
    extra = _password_extra(value)
    return (
        value.get("password_setup_login_verified") is True
        or value.get("password_change_login_verified") is True
        or extra.get("registration_password_verified") is True
    )


def _extract_registration_password(row: dict, *, verified_only: bool = False) -> str:
    extra_raw = row.get("extra_json")
    if isinstance(extra_raw, str) and extra_raw.strip():
        try:
            extra = json.loads(extra_raw)
        except Exception:
            extra = {}
    elif isinstance(extra_raw, dict):
        extra = extra_raw
    else:
        extra = {}

    pwd = str(extra.get("registration_password") or row.get("registration_password") or "").strip()
    if not pwd:
        return ""

    if not verified_only or extra.get("registration_password_manual_approved") is True:
        return pwd

    if extra.get("registration_password_verified") is False or row.get("password_setup_login_verified") is False or row.get("password_setup_status") == "verification_failed":
        verified = False
    else:
        # “远端已提交/任务成功”不等于密码可登录；只认独立登录验收标志。
        verified = account_password_login_verified(row)
    if not verified:
        token = str(row.get("access_token") or "").strip()
        if token and token.count(".") == 2:
            try:
                import base64
                payload_part = token.split(".")[1]
                padded = payload_part + "=" * (-len(payload_part) % 4)
                claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
                amr = claims.get("amr") or []
                if isinstance(amr, list) and any(m in {"pwd", "urn:openai:amr:password"} for m in amr):
                    verified = True
            except Exception:
                pass
    if not verified:
        return ""
    return pwd


def approve_candidate_passwords_manually(account_ids: list[int]) -> list[int]:
    """Store operator-approved candidates as official local credentials without claiming login verification."""
    target = {int(value) for value in account_ids}
    approved: list[int] = []
    _ensure_sqlite()
    with closing(_sqlite_conn()) as conn:
        with conn:
            for aid in sorted(target):
                record = conn.execute("SELECT payload FROM accounts WHERE id=?", (aid,)).fetchone()
                if record is None:
                    continue
                row = json.loads(record["payload"])
                extra = _password_extra(row)
                candidate = str(row.get("password_setup_candidate") or row.get("registration_password") or extra.get("registration_password") or "").strip()
                if not candidate or extra.get("registration_password_manual_approved") is True or account_password_login_verified(row):
                    continue
                now = _now()
                previous_status = str(row.get("password_setup_status") or "")
                row["registration_password"] = candidate
                extra["registration_password"] = candidate
                extra["registration_password_manual_approved"] = True
                extra["registration_password_manual_approved_at"] = now
                # Keep the last failed verification as audit data. Manual storage is not remote login proof.
                extra["registration_password_before_manual_status"] = previous_status
                row["password_setup_status"] = "manual_approved"
                row["password_setup_message"] = "人工指定为正式记录；未证明可登录或可刷新 AT"
                row["extra_json"] = json.dumps(extra, ensure_ascii=False)
                row["copy_line"] = _account_line(row)
                row["updated_at"] = now
                conn.execute("UPDATE accounts SET payload=?, updated_at=? WHERE id=?", (
                    json.dumps(row, ensure_ascii=False), now, aid,
                ))
                approved.append(aid)
    return approved


def get_registration_password(account: dict | None, *, verified_only: bool = True) -> str:
    """获取已通过独立登录验收的 ChatGPT 密码；显式传 False 才读取候选/旧字段。"""
    return _extract_registration_password(account or {}, verified_only=verified_only)


def has_registration_password(account: dict | None, *, verified_only: bool = True) -> bool:
    return bool(get_registration_password(account, verified_only=verified_only))


def save_registration_password_checkpoint(
    email: str,
    password: str,
    *,
    verified: bool = True,
    stage: str = "password_submitted",
    proxy_used: str | None = None,
    email_source: str | None = None,
    extra_context: dict | None = None,
    create_missing: bool = True,
) -> int:
    """两阶段即时原子预存（Stage-1 Immediate Persistence）：远端验证密码生效立即入库。"""
    email_clean = str(email or "").strip().lower()
    pwd = str(password or "").strip()
    if not email_clean or not pwd:
        return 0

    with _LOCK:
        accounts = _load_accounts()
        row = _find_by_email(accounts, email_clean)
        now = _now()
        if row is None:
            if not create_missing:
                return 0
            row_id = _next_id(accounts)
            extra = {
                "registration_password": pwd,
                "registration_password_verified": bool(verified),
                "registration_password_checkpoint_stage": stage,
                "registration_password_checkpoint_at": now,
            }
            if extra_context:
                extra.update(extra_context)
            row = {
                "id": row_id,
                "email": email_clean,
                "status": "registering",
                "password": pwd,
                "registration_password": pwd,
                "password_setup_remote_password_present": True,
                "password_setup_ok": bool(verified),
                "password_setup_login_verified": bool(verified),
                "password_setup_status": "checkpoint_saved",
                "password_setup_message": f"密码已于远端验证成功并预落盘（阶段：{stage}）",
                "proxy_used": proxy_used,
                "email_source": email_source,
                "extra_json": json.dumps(extra, ensure_ascii=False),
                "created_at": now,
                "updated_at": now,
            }
            row["copy_line"] = _account_line(row)
            accounts.append(row)
        else:
            row_id = int(row.get("id") or 0)
            try:
                extra = json.loads(row.get("extra_json") or "{}")
            except Exception:
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            extra["registration_password"] = pwd
            extra["registration_password_verified"] = bool(verified)
            extra["registration_password_checkpoint_stage"] = stage
            extra["registration_password_checkpoint_at"] = now
            if extra_context:
                extra.update(extra_context)
            row["password"] = pwd
            row["registration_password"] = pwd
            row["password_setup_remote_password_present"] = True
            row["password_setup_ok"] = bool(verified)
            row["password_setup_login_verified"] = bool(verified)
            row["password_setup_status"] = "checkpoint_saved"
            row["password_setup_message"] = f"密码已于远端验证成功并原子更新（阶段：{stage}）"
            row["extra_json"] = json.dumps(extra, ensure_ascii=False)
            row["updated_at"] = now
            row["copy_line"] = _account_line(row)

        _save_accounts(accounts)

    try:
        ck_dir = _PROJECT_ROOT / "注册日志" / "password-checkpoints"
        ck_dir.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(c if c.isalnum() or c in ".-_@" else "_" for c in email_clean)
        ck_file = ck_dir / f"{safe_name}.json"
        ck_file.write_text(
            json.dumps({
                "email": email_clean,
                "password": pwd,
                "verified": bool(verified),
                "stage": stage,
                "timestamp": now,
                "proxy_used": proxy_used,
                "email_source": email_source,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[Checkpoint] 写入本地密码镜像失败（SQLite已持久化）：%s", exc)

    logger.info("[Checkpoint] 真实密码已原子落盘保全：email=%s stage=%s row_id=%s", email_clean, stage, row_id)
    return row_id


def mark_account_registration_interrupted(
    email: str,
    *,
    stage: str,
    error: str,
    password: str | None = None,
) -> bool:
    """当注册在密码设置成功后的后续步骤中断时调用，确保密码不丢失。"""
    email_clean = str(email or "").strip().lower()
    if not email_clean:
        return False
    with _LOCK:
        accounts = _load_accounts()
        row = _find_by_email(accounts, email_clean)
        if row is None:
            return False
        now = _now()
        row["status"] = "interrupted"
        row["password_setup_status"] = "interrupted_after_password"
        row["password_setup_message"] = f"密码已在远端生效，后续步骤中断（{stage}）：{error}"
        if password:
            row["registration_password"] = password
            row["password_setup_remote_password_present"] = True
            row["password_setup_ok"] = True
        row["updated_at"] = now
        row["copy_line"] = _account_line(row)
        _save_accounts(accounts)
        logger.info("[注册中断保全] 账号中断状态已写入，密码已安全保留：email=%s stage=%s", email_clean, stage)
        return True


def _looks_like_email_material_segment(segment: str) -> bool:
    seg = str(segment or "").strip()
    if not seg:
        return False
    if seg.startswith("M.") or seg.startswith("m."):
        return True
    if len(seg) >= 32 and "-" in seg and seg.count("-") >= 4:
        return True
    if any(ch in seg for ch in ("@", ":", "/", "\\")):
        return True
    return False


def _ensure_password_in_material_line(base: str, password: str) -> str:
    base = str(base or "").strip()
    password = str(password or "").strip()
    if not password:
        return base
    parts = [p for p in base.split("----") if p != ""] if base else []
    if not parts:
        return password
    if len(parts) == 1:
        if parts[0] == password:
            return base
        return "----".join([parts[0], password])
    if parts[1] == password:
        return base
    if _looks_like_email_material_segment(parts[1]):
        parts.insert(1, password)
        return "----".join(parts)
    return base


def _account_line(row: dict) -> str:
    base = row.get("original_email_line") or row.get("email") or ""
    email_password = str(row.get("password") or "").strip()
    base = _ensure_password_in_material_line(base, email_password)
    token = row.get("access_token") or ""
    gpt_password = _extract_registration_password(row) or "未设置"
    totp = row.get("totp_secret") or ""
    parts = [base, token, gpt_password]
    if totp:
        parts.append(totp)
    return "----".join(parts)


_TWOFA_EXPORT_URL = "https://2fa.run/"


def _account_full_export_line(row: dict) -> str:
    """生成“完整导出”单行：
        邮箱---邮箱接码API---密码---https://2fa.run/----2FA:密钥----Token
    """
    email = str(row.get("email") or "").strip()
    email_api = _resolve_email_api_link(email, str(row.get("email_source") or "").strip())
    password = _extract_registration_password(row)
    totp = str(row.get("totp_secret") or "").strip()
    token = str(row.get("access_token") or "").strip()
    line = "---".join([email, email_api, password, _TWOFA_EXPORT_URL])
    line = line + "----" + ("2FA:" + totp)
    if token:
        line = line + "----" + token
    return line


def _resolve_email_api_link(email: str, email_source: str) -> str:
    """把“邮箱接码API”字段解析为完整接码链接格式。"""
    if email_source == "generic_api" and email:
        try:
            pool_row = get_generic_api_email_by_email(email)
        except Exception:
            pool_row = None
        if pool_row:
            link = str(pool_row.get("code_url") or "").strip()
            if link:
                return link
    elif email_source == "remail":
        return "https://remail.aishop6.com"
    return email_source


def _registered_email_line(row: dict) -> str:
    """生成注册成功邮箱 TXT 的行内容；token 由注册成功的token.txt 单独保存。"""
    return row.get("original_email_line") or row.get("email") or ""


def _load_outlook() -> list[dict]:
    return _load_collection("outlook")


def _save_outlook(rows: list[dict]) -> None:
    _save_collection("outlook", rows)


def _load_generic_api_emails() -> list[dict]:
    return _load_collection("generic_api")


def _save_generic_api_emails(rows: list[dict]) -> None:
    for row in rows:
        row["copy_line"] = _generic_api_email_line(row)
    _save_collection("generic_api", rows)


def _load_imap_emails() -> list[dict]:
    return _load_collection("imap")


def _save_imap_emails(rows: list[dict]) -> None:
    for row in rows:
        row["copy_line"] = _imap_email_line(row)
    _save_collection("imap", rows)


def _load_accounts() -> list[dict]:
    return _load_collection("accounts")


def _save_accounts(rows: list[dict]) -> None:
    for row in rows:
        row["token_expires_at"] = access_token_expires_at(row.get("access_token"))
        row["copy_line"] = _account_line(row)
    _save_collection("accounts", rows)


def _load_jobs() -> list[dict]:
    return _load_collection("jobs")


def _save_jobs(rows: list[dict]) -> None:
    _save_collection("jobs", rows)


def _find_by_email(rows: list[dict], email: str) -> dict | None:
    target = (email or "").lower()
    return next((r for r in rows if (r.get("email") or "").lower() == target), None)


def _account_registration_is_effectively_complete(row: dict) -> bool:
    """判断注册标记是否已被实际完成状态覆盖。

    不修改数据库原始 status，只统一工作台展示、统计和筛选语义。
    """
    status = str(row.get("status") or "").strip().lower()
    if status not in {"registering", "interrupted"}:
        return False

    def _truthy(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    password_ok = account_password_login_verified(row)
    token = str(row.get("access_token") or "").strip()
    token_expired = _truthy(row.get("token_expired"))
    http_status = str(row.get("plan_check_http_status") or "").strip()
    live_status = str(row.get("live_check_status") or "").strip().lower()
    at_ok = bool(token) and not token_expired and http_status != "401" and live_status not in {"failed", "deactivated", "dead"}
    totp_secret = str(row.get("totp_secret") or "").strip()
    totp_status = str(row.get("totp_setup_status") or "").strip().lower()
    totp_ok = bool(totp_secret) and (_truthy(row.get("totp_setup_ok")) or totp_status == "success")
    return password_ok and at_ok and totp_ok


def mark_expired_access_tokens(now=None) -> int:
    """Persist known JWT expiry without asserting that the account itself is dead."""
    from datetime import timezone
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    with _LOCK:
        rows = _load_accounts()
        changed = 0
        for row in rows:
            if row.get("archived") or not row.get("access_token") or row.get("token_expired") is True:
                continue
            deadline = access_token_expires_at(row.get("access_token"))
            if deadline and datetime.fromisoformat(deadline.replace("Z", "+00:00")) <= current:
                row["token_expired"] = True
                row["token_expires_at"] = deadline
                changed += 1
        if changed:
            _save_accounts(rows)
        return changed


def _decorate_account(row: dict) -> dict:
    out = dict(row)
    # Existing records are also readable without a network refresh.
    out["token_expires_at"] = access_token_expires_at(out.get("access_token"))
    # Display expiry immediately even before the next one-minute scheduler tick.
    if out["token_expires_at"] and datetime.fromisoformat(out["token_expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
        out["token_expired"] = True
    out["note"] = out.get("note") or ""
    out["note_updated_at"] = out.get("note_updated_at") or ""
    plan_status = out.get("plan_check_status")
    if plan_status in {"queued", "running"}:
        try:
            stamp_key = "plan_check_queued_at" if plan_status == "queued" else "plan_check_started_at"
            stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if plan_status == "queued" else _PLAN_CHECK_STALE_SECONDS
            started_at = datetime.fromisoformat(str(out.get(stamp_key) or ""))
            if (datetime.now() - started_at).total_seconds() >= stale_after:
                out["plan_check_status"] = "failed"
                out["plan_check_error"] = "上次套餐查询状态已超时，可重新查询"
                out["plan_check_stale"] = True
        except (TypeError, ValueError):
            out["plan_check_status"] = "failed"
            out["plan_check_error"] = "上次套餐查询状态异常，可重新查询"
            out["plan_check_stale"] = True
    payment_status = out.get("payment_check_status")
    if payment_status in {"queued", "running"}:
        try:
            stamp_key = "payment_check_queued_at" if payment_status == "queued" else "payment_check_started_at"
            stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if payment_status == "queued" else _PLAN_CHECK_STALE_SECONDS
            started_at = datetime.fromisoformat(str(out.get(stamp_key) or ""))
            if (datetime.now() - started_at).total_seconds() >= stale_after:
                out["payment_check_status"] = "failed"
                out["payment_check_error"] = "上次支付方式查询状态已超时，可重新查询"
                out["payment_check_stale"] = True
        except (TypeError, ValueError):
            out["payment_check_status"] = "failed"
            out["payment_check_error"] = "上次支付方式查询状态异常，可重新查询"
            out["payment_check_stale"] = True
    out["registration_effectively_complete"] = _account_registration_is_effectively_complete(out)
    out["registration_display_status"] = (
        "complete" if out["registration_effectively_complete"] else str(out.get("status") or "")
    )
    out["copy_line"] = _account_line(out)
    if not out.get("password"):
        extracted_pwd = _extract_registration_password(out) or out.get("registration_password")
        if extracted_pwd:
            out["password"] = extracted_pwd
    return out


def _account_matches_plan_filter(row: dict, plan_filter: str | None = None) -> bool:
    """账号套餐过滤：支持已开通 Plus、可试用 Plus、不可试用 Plus 的 free 账号。"""
    f = str(plan_filter or "").strip().lower()
    if not f or f in {"all", "any"}:
        return True
    plan = str(row.get("current_plan_type") or row.get("plan_type") or "").strip().lower()
    if f == "plus":
        # “free(可Plus试用)”/plus_trial_eligible 只是可试用，不算已开通 Plus。
        # 只有套餐字段本身是 Plus/ChatGPT Plus/plus_* 且不含 free 时才命中。
        return "plus" in plan and "free" not in plan
    if f in {"plus_trial", "plus_trial_eligible", "trial", "trial_eligible"}:
        trial = row.get("plus_trial_eligible")
        if isinstance(trial, str):
            trial = trial.strip().lower() in {"1", "true", "yes", "on"}
        if not (plan == "free" and bool(trial)):
            return False
        # 失效或查询失败的账号直接不显示在可试用列表
        if bool(row.get("token_expired")) or str(row.get("plan_check_status") or "").lower() == "failed":
            return False
        if str(row.get("live_check_status") or "").lower() in {"failed", "deactivated", "dead"}:
            return False
        if int(row.get("plan_check_http_status") or 0) == 401:
            return False
        return True
    if f in {"discount", "discount_offer", "discount_eligible"}:
        return plan == "free" and bool(row.get("discount_offer_eligible"))
    if f in {"free_no_trial", "free_without_trial", "free_not_trial"}:
        if "plus_trial_eligible" not in row:
            return False
        trial = row.get("plus_trial_eligible")
        if isinstance(trial, str):
            trial = trial.strip().lower() in {"1", "true", "yes", "on"}
        return plan == "free" and not bool(trial)
    if f == "free":
        return plan == "free"
    return plan == f


def _decorate_outlook(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _outlook_line(out)
    account = None
    if account_by_email is not None:
        account = account_by_email.get((out.get("email") or "").lower())
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["access_token_preview"] = (
            (account.get("access_token") or "")[:40] + "..."
            if account.get("access_token")
            else ""
        )
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _decorate_generic_api_email(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _generic_api_email_line(out)
    out["password"] = out.get("password") or ""
    out["client_id"] = out.get("client_id") or ""
    out["refresh_token"] = out.get("refresh_token") or ""
    account = None
    if account_by_email is not None:
        account = account_by_email.get((out.get("email") or "").lower())
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["access_token_preview"] = (
            (account.get("access_token") or "")[:40] + "..."
            if account.get("access_token")
            else ""
        )
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _decorate_imap_email(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _imap_email_line(out)
    account = account_by_email.get((out.get("email") or "").lower()) if account_by_email else None
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["access_token_preview"] = ((account.get("access_token") or "")[:40] + "...") if account.get("access_token") else ""
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def list_email_pool_page(
    source: str = "all",
    status: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """从统一邮箱库直接执行 COUNT + LIMIT/OFFSET。

    ``email_pool`` 是三个邮箱来源共用的表。source 为具体来源时按 id 倒序，
    source=all 时按入库时间合并倒序；两种情况都只从 SQLite 取当前页，
    不再先加载全部邮箱再由 WebUI 切片。
    """
    _ensure_sqlite()
    source = str(source or "outlook").strip().lower()
    if source not in {"all", "outlook", "generic_api", "imap", "cloudflare_domain", "remail"}:
        source = "outlook"
    collection = "domain" if source == "cloudflare_domain" else source
    db_source = None if source == "all" else _EMAIL_SOURCES[collection]
    limit = max(1, int(limit))
    offset = max(0, int(offset or 0))
    where = ["1=1"]
    params: list[Any] = []
    if db_source is not None:
        where.append("ep.source=?")
        params.append(db_source)
    if status:
        where.append("ep.status=?")
        params.append(status)
    if q and str(q).strip():
        like = "%" + str(q).strip().lower() + "%"
        # payload 覆盖邮箱池自身字段；source 和关联账号 payload 保持旧 WebUI
        # 的搜索能力（例如搜索 generic_api 或已注册账号 token）。
        where.append(
            "(lower(ep.payload) LIKE ? OR lower(ep.source) LIKE ? OR EXISTS ("
            "SELECT 1 FROM accounts AS a "
            "WHERE a.email = ep.email COLLATE NOCASE AND lower(a.payload) LIKE ?))"
        )
        params.extend([like, like, like])
    clause = " AND ".join(where)
    order_by = "ep.created_at DESC, ep.id DESC" if source == "all" else "ep.id DESC"
    with _LOCK, closing(_sqlite_conn()) as conn:
        total = int(conn.execute(f"SELECT COUNT(*) FROM email_pool AS ep WHERE {clause}", params).fetchone()[0])
        latest = str(conn.execute(
            f"SELECT COALESCE(MAX(ep.updated_at), '') FROM email_pool AS ep WHERE {clause}",
            params,
        ).fetchone()[0] or "")
        rows = conn.execute(
            f"SELECT ep.payload, ep.source, "
            f"(SELECT a.payload FROM accounts AS a "
            f" WHERE a.email = ep.email COLLATE NOCASE ORDER BY a.id DESC LIMIT 1) AS account_payload "
            f"FROM email_pool AS ep WHERE {clause} "
            f"ORDER BY {order_by} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    # ``domain`` 是内部 collection 名，API 对外统一使用 cloudflare_domain；
    # 直接反转 _EMAIL_SOURCES 会把域名邮箱错误地返回成 source=domain。
    source_names = {
        _EMAIL_SOURCES["outlook"]: "outlook",
        _EMAIL_SOURCES["generic_api"]: "generic_api",
        _EMAIL_SOURCES["imap"]: "imap",
        _EMAIL_SOURCES["domain"]: "cloudflare_domain",
        _EMAIL_SOURCES["remail"]: "remail",
    }
    items: list[dict] = []
    for row in rows:
        item = json.loads(row["payload"])
        account_payload = row["account_payload"]
        account = None
        if account_payload:
            try:
                account = json.loads(account_payload)
            except (TypeError, ValueError):
                account = None
        item_source = source_names.get(str(row["source"]), str(row["source"]))
        if item_source == "outlook":
            item = _decorate_outlook(item, {str(item.get("email") or "").lower(): account} if account else {})
        elif item_source == "generic_api":
            item = _decorate_generic_api_email(item, {str(item.get("email") or "").lower(): account} if account else {})
        elif item_source == "imap":
            item = _decorate_imap_email(item, {str(item.get("email") or "").lower(): account} if account else {})
        else:
            item = dict(item)
        item["source"] = item_source
        if not item.get("copy_line"):
            item["copy_line"] = item.get("email") or ""
        items.append(item)
    return {"items": items, "total": total, "offset": offset, "limit": limit, "latest": latest}


def _get_conn() -> sqlite3.Connection:
    """兼容旧入口：返回 SQLite 连接。"""
    return _sqlite_conn()


def _row_to_dict(row: dict | None) -> dict | None:
    return dict(row) if row is not None else None


# ============================================================
# registered_accounts
# ============================================================

def insert_account(
    *,
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    user_id: str | None = None,
    user_name: str | None = None,
    plan_type: str | None = None,
    expires_at: str | None = None,
    device_id: str | None = None,
    proxy_used: str | None = None,
    email_source: str | None = None,
    extra: dict | None = None,
    codex_status: str | None = None,   # success / failed / skipped / missing
    codex_error: str | None = None,    # 失败原因（仅 codex_status=failed 时有意义）
) -> int:
    """插入或更新注册成功账号，返回本地文件中的 id。"""
    with _LOCK:
        accounts = _load_accounts()
        outlook_rows = _load_outlook()
        existing = _find_by_email(accounts, email)
        outlook_row = _find_by_email(outlook_rows, email)
        # 【真实密码防回退与零丢失保护】
        extra = dict(extra or {}) if extra else {}
        existing_pwd = _extract_registration_password(existing) if existing else ""
        existing_verified = bool(
            existing and (
                (isinstance(existing.get("extra_json"), dict) and existing["extra_json"].get("registration_password_verified"))
                or (isinstance(existing.get("extra_json"), str) and '"registration_password_verified": true' in existing["extra_json"])
                or existing.get("password_setup_ok") is True
                or existing.get("password_setup_login_verified") is True
            )
        )
        incoming_pwd = str(extra.get("registration_password") or "").strip()
        incoming_verified = extra.get("registration_password_verified") is True

        if incoming_pwd:
            final_pwd = incoming_pwd
            final_verified = incoming_verified
        elif existing_pwd:
            final_pwd = existing_pwd
            final_verified = existing_verified
        else:
            final_pwd = ""
            final_verified = False

        if final_pwd:
            extra["registration_password"] = final_pwd
            if final_verified:
                extra["registration_password_verified"] = True

        extra_json = json.dumps(extra, ensure_ascii=False) if extra else None

        if existing is None:
            row_id = _next_id(accounts)
            row = {
                "id": row_id,
                "email": email,
                "created_at": _now(),
            }
            accounts.append(row)
        else:
            row = existing
            row_id = int(row["id"])

        row.update({
            "access_token": access_token,
            "totp_secret": totp_secret if totp_secret is not None else row.get("totp_secret"),
            "user_id": user_id if user_id is not None else row.get("user_id"),
            "user_name": user_name if user_name is not None else row.get("user_name"),
            "plan_type": plan_type if plan_type is not None else row.get("plan_type"),
            "expires_at": expires_at if expires_at is not None else row.get("expires_at"),
            "proxy_used": proxy_used if proxy_used is not None else row.get("proxy_used"),
            "email_source": email_source if email_source is not None else row.get("email_source"),
            "extra_json": extra_json if extra_json is not None else row.get("extra_json"),
            "codex_status": codex_status if codex_status is not None else row.get("codex_status"),
            "codex_error": codex_error if codex_error is not None else row.get("codex_error"),
            "updated_at": _now(),
        })

        if outlook_row:
            row["password"] = outlook_row.get("password")
            row["client_id"] = outlook_row.get("client_id")
            row["refresh_token"] = outlook_row.get("refresh_token")
            row["original_email_line"] = _outlook_line(outlook_row)
            outlook_row["status"] = "used"
            outlook_row["used_at"] = outlook_row.get("used_at") or _now()
            outlook_row["registered_account_id"] = row_id
            outlook_row["access_token"] = access_token
            outlook_row["completed_at"] = _now()
            if totp_secret:
                outlook_row["totp_secret"] = totp_secret

        if final_pwd:
            # 协议注册也必须把真实密码写入顶层 password。此前只有 outlook_row
            # 分支赋值，导致协议子库已有密码但主库显示为空，后续被误判为需补密码。
            # Outlook 顶层 password 仍用于邮箱收码凭证；协议/域名邮箱没有该冲突。
            if not outlook_row:
                row["password"] = final_pwd
            row["registration_password"] = final_pwd
            if final_verified:
                extra["registration_password_verified"] = True
                row["password_setup_remote_password_present"] = True
                row["password_setup_ok"] = True
                row["password_setup_login_verified"] = True
                row["password_setup_status"] = "success"
                row["password_setup_error"] = None
        row["copy_line"] = _account_line(row)
        _save_accounts(accounts)
        _save_outlook(outlook_rows)
        return row_id


def update_account_codex_status(email: str, codex_status: str, codex_error: str | None = None) -> bool:
    """
    单独更新某账号的 codex_status / codex_error（手动补跑 Codex 时用）。
    返回是否找到该账号。
    """
    with _LOCK:
        accounts = _load_accounts()
        row = _find_by_email(accounts, email)
        if row is None:
            return False
        row["codex_status"] = codex_status
        row["codex_error"] = codex_error
        if str(codex_status or "").strip().lower() == "deactivated":
            # Codex 授权阶段判定为 deactivated，按账号废号处理，便于账号列表统一筛选。
            row["live_check_status"] = "deactivated"
            row["live_check_ok"] = False
            row["live_check_error"] = codex_error or "Codex 授权判定账号已废号"
            row["live_checked_at"] = _now()
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def claim_account_codex_agent(acc_id: int, trigger: str = "manual") -> bool:
    """原子占用账号 Codex Agent Token 生成任务；已有未超时任务时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current_status = row.get("codex_agent_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "codex_agent_queued_at" if current_status == "queued" else "codex_agent_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass
        now = _now()
        row["codex_agent_status"] = "queued"
        row["codex_agent_ok"] = False
        row["codex_agent_trigger"] = str(trigger or "manual")
        row["codex_agent_queued_at"] = now
        row["codex_agent_started_at"] = None
        row["codex_agent_completed_at"] = None
        row["codex_agent_error"] = None
        row["codex_agent_message"] = "已入队"
        row["updated_at"] = now
        _save_accounts(accounts)
        return True


def mark_account_codex_agent_running(acc_id: int) -> bool:
    """把 Codex Agent Token 生成任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("codex_agent_status") not in {"queued", "running"}:
            return False
        row["codex_agent_status"] = "running"
        row["codex_agent_started_at"] = _now()
        row["codex_agent_error"] = None
        row["codex_agent_message"] = "正在生成 Codex Agent Token"
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def update_account_codex_agent(acc_id: int, result: dict | None = None) -> bool:
    """更新账号 Codex Agent Token 生成结果/进度。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["codex_agent_status"] = status
        row["codex_agent_ok"] = ok
        row["codex_agent_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped"}:
            row["codex_agent_completed_at"] = _now()
        row["codex_agent_error"] = None if ok or status == "running" else result.get("error")
        if result.get("message") is not None:
            row["codex_agent_message"] = result.get("message")
        if result.get("agent_runtime_id") is not None:
            row["codex_agent_runtime_id"] = result.get("agent_runtime_id")
        if result.get("auth_path") is not None:
            row["codex_agent_auth_path"] = result.get("auth_path")
        if isinstance(result.get("auth_json"), dict):
            auth_json = result.get("auth_json")
            row["codex_agent_token"] = json.dumps(auth_json, ensure_ascii=False)
            agent_filename = f"codex-agent-{str(row.get('email') or acc_id)}.json"
            stamp = _now()
            _ensure_sqlite()
            with closing(_sqlite_conn()) as conn:
                conn.execute(
                    "INSERT INTO codex_agent_accounts(account_id,email,filename,created_at,updated_at,payload) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(account_id) DO UPDATE SET email=excluded.email, filename=excluded.filename, updated_at=excluded.updated_at, payload=excluded.payload",
                    (int(acc_id), str(row.get("email") or ""), agent_filename, stamp, stamp, json.dumps(auth_json, ensure_ascii=False)),
                )
                conn.commit()
            row.pop("codex_agent_auth_path", None)
        for _k in (
            "codex_agent_network_route",
            "codex_agent_proxy_mode",
            "codex_agent_proxy_used",
            "codex_agent_proxy_fallback_reason",
            "codex_agent_attempt_count",
            "codex_agent_max_attempts",
            "codex_agent_request_timeout",
            "codex_agent_sub2api_path",
            "codex_agent_sub2api_url",
            "codex_agent_sub2api_mode",
            "codex_agent_sub2api_total",
        ):
            src_key = _k.replace("codex_agent_", "", 1)
            if result.get(src_key) is not None:
                row[_k] = result.get(src_key)
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def get_codex_agent_credential(acc_id: int) -> tuple[str, str] | None:
    """从 SQLite 获取 Agent 凭证，返回 JSON 文本和下载文件名。"""
    _ensure_sqlite()
    with closing(_sqlite_conn()) as conn:
        row = conn.execute("SELECT filename, payload FROM codex_agent_accounts WHERE account_id=?", (int(acc_id),)).fetchone()
    if not row:
        return None
    return json.dumps(json.loads(row["payload"]), ensure_ascii=False, indent=2) + "\n", row["filename"]


def recover_interrupted_codex_agents() -> int:
    """服务启动时恢复上次进程中断的 Codex Agent 任务状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if row.get("codex_agent_status") not in {"queued", "running"}:
                continue
            row["codex_agent_status"] = "failed"
            row["codex_agent_ok"] = False
            row["codex_agent_error"] = "WebUI 重启导致 Codex Agent Token 任务中断，请重新生成"
            row["codex_agent_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def claim_account_plan_check(
    acc_id: int | None = None,
    email: str | None = None,
    trigger: str = "manual",
) -> bool:
    """原子占用账号的套餐查询；已有未超时查询时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        current_status = row.get("plan_check_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "plan_check_queued_at" if current_status == "queued" else "plan_check_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass

        now = _now()
        row["plan_check_status"] = "queued"
        row["plan_check_trigger"] = str(trigger or "manual")
        row["plan_check_queued_at"] = now
        row["plan_check_started_at"] = None
        row["plan_check_completed_at"] = None
        row["plan_check_error"] = None
        row["updated_at"] = now
        _save_accounts(accounts)
        return True


def claim_account_plan_checks_batch(
    acc_ids: list[int],
    trigger: str = "manual",
) -> set[int]:
    """批量原子占用账号的套餐查询；仅执行一次全表读写，避免上百次磁盘 I/O 阻塞前端。"""
    if not acc_ids:
        return set()
    id_set = {int(x) for x in acc_ids}
    claimed: set[int] = set()
    with _LOCK:
        accounts = _load_accounts()
        now = _now()
        modified = False
        for row in accounts:
            rid = int(row.get("id") or 0)
            if rid not in id_set:
                continue
            current_status = row.get("plan_check_status")
            if current_status in {"queued", "running"}:
                try:
                    stamp_key = "plan_check_queued_at" if current_status == "queued" else "plan_check_started_at"
                    stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                    started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                    if (datetime.now() - started_at).total_seconds() < stale_after:
                        continue
                except (TypeError, ValueError):
                    pass
            row["plan_check_status"] = "queued"
            row["plan_check_trigger"] = str(trigger or "manual")
            row["plan_check_queued_at"] = now
            row["plan_check_started_at"] = None
            row["plan_check_completed_at"] = None
            row["plan_check_error"] = None
            row["updated_at"] = now
            claimed.add(rid)
            modified = True
        if modified:
            _save_accounts(accounts)
    return claimed


def mark_account_plan_check_running(acc_id: int) -> bool:
    """把已排队的套餐查询标记为执行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("plan_check_status") not in {"queued", "running"}:
            return False
        row["plan_check_status"] = "running"
        row["plan_check_started_at"] = _now()
        row["plan_check_error"] = None
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def recover_interrupted_plan_checks() -> int:
    """服务启动时把上次进程遗留的内存队列状态恢复为可重试失败。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if row.get("plan_check_status") not in {"queued", "running"}:
                continue
            row["plan_check_status"] = "failed"
            row["plan_check_ok"] = False
            row["plan_check_error"] = "WebUI 重启导致套餐查询中断，请重新查询"
            row["plan_check_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def update_account_plan_check(acc_id: int | None = None, email: str | None = None, result: dict | None = None) -> bool:
    """更新账号套餐/Plus 试用资格查询结果。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        ok = bool(result.get("ok"))
        row["plan_check_status"] = "success" if ok else "failed"
        row["plan_check_ok"] = ok
        row["plan_checked_at"] = result.get("checked_at") or _now()
        row["plan_check_completed_at"] = _now()
        row["plan_check_http_status"] = result.get("http_status")
        row["plan_check_error"] = None if ok else result.get("error")
        row["plan_check_failure_summary"] = result.get("region_failure_summary") if not ok else None

        if result.get("account_id"):
            row["account_id"] = result.get("account_id")
        http_status = int(result.get("http_status") or 0)
        if result.get("token_expired") is True or result.get("needs_live_check") is True or http_status == 401:
            row["token_expired"] = True
        elif ok and "token_expired" in result and result.get("token_expired") is False:
            # Only a successful authenticated plan response may clear a previous expiry marker.
            row["token_expired"] = False
        # 查询失败只更新本次错误和网络信息，不覆盖上一次成功拿到的套餐、
        # 试用资格、优惠及有效期，避免临时网络故障把真实权益清空。
        if ok:
            if isinstance(result.get("region_results"), dict):
                row["plan_region_results"] = result.get("region_results")
                row["plan_region_checked_at"] = result.get("checked_at") or _now()
                row["plus_trial_eligible"] = bool(result.get("plus_trial_eligible"))
                row["plan_last_success_at"] = result.get("checked_at") or _now()
                row["plan_last_success_result_json"] = json.dumps(result, ensure_ascii=False)
            else:
                row.pop("plan_region_results", None)
            if result.get("current_plan_type"):
                row["current_plan_type"] = result.get("current_plan_type")
                row["plan_type"] = result.get("current_plan_type")
            if result.get("subscription_plan") is not None:
                row["subscription_plan"] = result.get("subscription_plan")
            if result.get("has_active_subscription") is not None:
                row["has_active_subscription"] = bool(result.get("has_active_subscription"))
            if result.get("expires_at") is not None:
                row["plan_expires_at"] = result.get("expires_at")
            if result.get("renews_at") is not None:
                row["plan_renews_at"] = result.get("renews_at")
            if result.get("cancels_at") is not None:
                row["plan_cancels_at"] = result.get("cancels_at")
            if result.get("billing_period") is not None:
                row["billing_period"] = result.get("billing_period")
            if result.get("billing_currency") is not None:
                row["billing_currency"] = result.get("billing_currency")
            if result.get("is_delinquent") is not None:
                row["is_delinquent"] = bool(result.get("is_delinquent"))
            for _k in (
                "discount_type",
                "discount_amount",
                "discount_duration_num_periods",
                "discount_expires_at",
                "discount_cancellation_policy",
                "discount_promo_campaign_id",
                "last_purchase_origin_platform",
                "last_will_renew",
            ):
                if result.get(_k) is not None:
                    row[_k] = result.get(_k)

            row["plus_trial_eligible"] = bool(result.get("plus_trial_eligible"))
            row["discount_offer_eligible"] = bool(result.get("discount_offer_eligible"))
            row["discount_offer_campaign_id"] = result.get("discount_offer_campaign_id")
            row["discount_offer_title"] = result.get("discount_offer_title")
            row["discount_offer_percentage"] = result.get("discount_offer_percentage")
            row["has_50_discount"] = bool(result.get("has_50_discount"))
            row["plus_trial_campaign_id"] = result.get("plus_trial_campaign_id")
            row["plus_trial_title"] = result.get("plus_trial_title")
            row["plus_trial_discount_percentage"] = result.get("plus_trial_discount_percentage")
            row["plus_trial_duration_num_periods"] = result.get("plus_trial_duration_num_periods")
            row["plus_trial_duration_period"] = result.get("plus_trial_duration_period")
            row["eligible_promo_campaigns"] = result.get("eligible_promo_campaigns") or {}
            row["eligible_offer_ids"] = result.get("eligible_offer_ids") or []
            row["plan_last_success_at"] = result.get("checked_at") or _now()
            row["plan_last_success_result_json"] = json.dumps(result, ensure_ascii=False)
        row["plan_check_proxy_mode"] = result.get("proxy_mode")
        row["plan_check_network_route"] = result.get("network_route")
        row["plan_check_proxy_used"] = result.get("proxy_used")
        row["plan_check_proxy_fallback_reason"] = result.get("proxy_fallback_reason")
        if result.get("token_expires_at") is not None:
            row["token_expires_at"] = result.get("token_expires_at")
        row["plan_check_result_json"] = json.dumps(result, ensure_ascii=False)
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def claim_account_payment_check(
    acc_id: int | None = None,
    email: str | None = None,
    trigger: str = "manual",
) -> bool:
    """原子占用账号的支付方式查询；已有未超时查询时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        current_status = row.get("payment_check_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "payment_check_queued_at" if current_status == "queued" else "payment_check_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass

        now = _now()
        row["payment_check_status"] = "queued"
        row["payment_check_trigger"] = str(trigger or "manual")
        row["payment_check_queued_at"] = now
        row["payment_check_started_at"] = None
        row["payment_check_completed_at"] = None
        row["payment_check_error"] = None
        row["updated_at"] = now
        _save_accounts(accounts)
        return True


def mark_account_payment_check_running(acc_id: int) -> bool:
    """把已排队的支付方式查询标记为执行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("payment_check_status") not in {"queued", "running"}:
            return False
        row["payment_check_status"] = "running"
        row["payment_check_started_at"] = _now()
        row["payment_check_error"] = None
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def recover_interrupted_payment_checks() -> int:
    """服务启动时把上次进程遗留的内存队列状态恢复为可重试失败。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if row.get("payment_check_status") not in {"queued", "running"}:
                continue
            row["payment_check_status"] = "failed"
            row["payment_check_ok"] = False
            row["payment_check_error"] = "WebUI 重启导致支付方式查询中断，请重新查询"
            row["payment_check_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def update_account_payment_check(
    acc_id: int | None = None, email: str | None = None, result: dict | None = None,
) -> bool:
    """更新账号支付方式/账单/订阅查询结果。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        ok = bool(result.get("ok"))
        row["payment_check_status"] = "success" if ok else "failed"
        row["payment_check_ok"] = ok
        row["payment_checked_at"] = result.get("checked_at") or _now()
        row["payment_check_completed_at"] = _now()
        row["payment_check_error"] = None if ok else result.get("error")
        row["payment_check_proxy_mode"] = result.get("proxy_mode")
        row["payment_check_network_route"] = result.get("network_route")
        row["payment_check_proxy_used"] = result.get("proxy_used")
        if result.get("token_expired") is True:
            row["token_expired"] = True

        # 失败只写本次错误与网络信息，保留上一次成功结果，避免临时网络故障清空支付方式。
        if ok:
            methods = result.get("payment_methods") or []
            # 落库前去掉每条支付方式的 raw 原文，避免账号表被原始响应撑大
            row["payment_methods"] = [
                {k: v for k, v in method.items() if k != "raw"}
                for method in methods if isinstance(method, dict)
            ]
            row["payment_methods_text"] = str(result.get("payment_methods_text") or "")
            row["payment_has_method"] = bool(result.get("has_payment_method"))
            row["payment_default_method_id"] = result.get("default_payment_method_id")
            row["payment_one_click_trial_eligible"] = bool(result.get("one_click_trial_eligible"))
            row["payment_portal_url"] = result.get("portal_url") or ""
            row["payment_invoice_count"] = int(result.get("invoice_count") or 0)
            row["payment_endpoint_status"] = result.get("endpoint_status") or {}
            row["payment_endpoint_unavailable"] = result.get("endpoint_unavailable") or []
            row["has_customer_object"] = bool(result.get("has_customer_object"))
            row["processor_entity"] = result.get("processor_entity")
            row["has_transaction_history"] = bool(result.get("has_transaction_history"))
            row["payment_subscription"] = result.get("subscription")
            row["payment_last_success_at"] = result.get("checked_at") or _now()
            row["payment_profile_json"] = json.dumps(result, ensure_ascii=False, default=str)
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def claim_account_extract(acc_id: int, trigger: str = "manual", link_type: str = "pix") -> bool:
    """原子占用账号提链任务；已有未超时任务时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current_status = row.get("extract_link_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "extract_link_queued_at" if current_status == "queued" else "extract_link_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass
        now = _now()
        row["extract_link_status"] = "queued"
        row["extract_link_ok"] = False
        row["extract_link_trigger"] = str(trigger or "manual")
        row["extract_link_type"] = str(link_type or "pix").lower()
        row["extract_link_queued_at"] = now
        row["extract_link_started_at"] = None
        row["extract_link_completed_at"] = None
        row["extract_link_error"] = None
        row["extract_link_message"] = "已入队"
        row["updated_at"] = now
        _save_accounts(accounts)
        return True


def mark_account_extract_running(acc_id: int) -> bool:
    """把提链任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("extract_link_status") not in {"queued", "running"}:
            return False
        row["extract_link_status"] = "running"
        row["extract_link_started_at"] = _now()
        row["extract_link_error"] = None
        row["extract_link_message"] = "任务运行中"
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def update_account_extract(acc_id: int, result: dict | None = None) -> bool:
    """更新账号提链任务结果/进度。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["extract_link_status"] = status
        row["extract_link_ok"] = ok
        row["extract_link_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped"}:
            row["extract_link_completed_at"] = _now()
        row["extract_link_error"] = None if ok or status == "running" else result.get("error")
        if result.get("message") is not None:
            row["extract_link_message"] = result.get("message")
        if result.get("job_id") is not None:
            row["extract_link_job_id"] = result.get("job_id")
        if result.get("link_type") is not None:
            row["extract_link_type"] = result.get("link_type")
        if result.get("cdk_remaining") is not None:
            row["extract_link_cdk_remaining"] = result.get("cdk_remaining")
        payload = result.get("result") if isinstance(result.get("result"), dict) else {}
        if payload:
            row["extract_link_long_url"] = payload.get("long_url")
            row["extract_link_copy_paste"] = payload.get("copy_paste")
            row["extract_link_image_url_png"] = payload.get("image_url_png")
            row["extract_link_image_url_svg"] = payload.get("image_url_svg")
            row["extract_link_payment_method"] = payload.get("payment_method")
            row["extract_link_payment_link_type"] = payload.get("payment_link_type")
            row["extract_link_expires_at"] = payload.get("expires_at")
            if payload.get("cdk_remaining") is not None:
                row["extract_link_cdk_remaining"] = payload.get("cdk_remaining")
            row["extract_link_result_json"] = json.dumps(payload, ensure_ascii=False)
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def recover_interrupted_extract_links() -> int:
    """服务启动时恢复上次进程中断的提链状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if row.get("extract_link_status") not in {"queued", "running"}:
                continue
            row["extract_link_status"] = "failed"
            row["extract_link_ok"] = False
            row["extract_link_error"] = "WebUI 重启导致提链任务中断，请重新提链"
            row["extract_link_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def _account_matches_query(row: dict, q: str | None) -> bool:
    q = str(q or "").strip().lower()
    if not q:
        return True
    try:
        return q in "\n".join(str(v) for v in row.values()).lower()
    except Exception:
        return False


def _parse_iso_dt(value: str | None, end_of_day: bool = False) -> datetime | None:
    """宽松解析 ISO 日期/时间字符串；支持 YYYY-MM-DD 或完整 ISO；解析失败返回 None。

    end_of_day=True 时，纯日期（YYYY-MM-DD）按当天 23:59:59.999999 解析，
    用于 date_to 过滤（保证包含截止当天）；完整时间串原样返回。
    """
    if not value:
        return None
    text = str(value).strip()
    try:
        if len(text) == 10 and text[4] == "-":
            if end_of_day:
                return datetime.fromisoformat(text + "T23:59:59.999999")
            return datetime.fromisoformat(text + "T00:00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _matches_codex_status_filter(row: dict, codex_filter: str | None) -> bool:
    codex_filter = str(codex_filter or "").strip().lower()
    if not codex_filter:
        return True
    status = str(row.get("codex_status") or "").strip().lower()
    live_status = str(row.get("live_check_status") or "").strip().lower()
    if codex_filter in {"all", "*"}:
        return True
    if codex_filter == "deactivated":
        return live_status == "deactivated"
    return status == codex_filter


def _matches_totp_status_filter(row: dict, totp_filter: str | None) -> bool:
    """按 2FA/TOTP 是否已配置及设置任务状态筛选账号。"""
    totp_filter = str(totp_filter or "").strip().lower()
    if not totp_filter or totp_filter in {"all", "*"}:
        return True

    enabled = bool(str(row.get("totp_secret") or "").strip())
    setup_status = str(row.get("totp_setup_status") or "").strip().lower()
    if totp_filter in {"enabled", "on", "active"}:
        return enabled
    if totp_filter in {"disabled", "off", "not_enabled", "unset"}:
        return not enabled
    if totp_filter in {"pending", "setup", "setting", "queued", "running"}:
        return setup_status in {"queued", "running"}
    if totp_filter in {"failed", "stopped"}:
        return setup_status == totp_filter
    return setup_status == totp_filter


def _filtered_decorated_accounts(
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    codex_filter: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    totp_filter: str | None = None,
) -> list[dict]:
    rows = _load_accounts()
    if archived in (True, "1", "true", "yes", "only"):
        rows = [r for r in rows if bool(r.get("archived"))]
    elif archived in ("all", "include"):
        pass
    else:
        rows = [r for r in rows if not bool(r.get("archived"))]
    decorated = [_decorate_account(r) for r in rows]
    decorated = [r for r in decorated if _account_matches_plan_filter(r, plan_filter)]
    decorated = [r for r in decorated if _matches_codex_status_filter(r, codex_filter)]
    decorated = [r for r in decorated if _matches_totp_status_filter(r, totp_filter)]
    decorated = [r for r in decorated if _account_matches_query(r, q)]
    # 按创建时间筛选（date_from/date_to 为 ISO 字符串或 YYYY-MM-DD）
    if date_from or date_to:
        d_from = _parse_iso_dt(date_from)
        d_to = _parse_iso_dt(date_to, end_of_day=True)
        if d_from or d_to:
            filtered = []
            for r in decorated:
                ct = _parse_iso_dt(str(r.get("created_at") or ""))
                if ct is None:
                    continue
                if d_from and ct < d_from:
                    continue
                if d_to and ct > d_to:
                    continue
                filtered.append(r)
            decorated = filtered
    return sorted(decorated, key=lambda x: int(x.get("id") or 0), reverse=True)



def get_account_overview_summary(archived: str | bool | None = False) -> dict:
    """返回账号工作台总览；仅做本地 SQLite 聚合，不触发网络请求。"""
    _ensure_sqlite()
    table = _TABLES["accounts"]
    where = ["1=1"]
    params: list[Any] = []
    if archived not in (None, "all", "include"):
        where.append("archived=?")
        params.append(int(archived in (True, "1", "true", "yes", "only")))
    clause = " AND ".join(where)
    token_expr = "trim(COALESCE(CAST(json_extract(payload, '$.access_token') AS TEXT), ''))"
    expired_expr = "lower(COALESCE(CAST(json_extract(payload, '$.token_expired') AS TEXT), ''))"
    http_expr = "CAST(COALESCE(json_extract(payload, '$.plan_check_http_status'), 0) AS INTEGER)"
    plan_expr = (
        "lower(COALESCE(NULLIF(CAST(json_extract(payload, '$.current_plan_type') AS TEXT), ''), "
        "CAST(json_extract(payload, '$.plan_type') AS TEXT), ''))"
    )
    eligible_expr = "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
    check_expr = "lower(COALESCE(CAST(json_extract(payload, '$.plan_check_status') AS TEXT), ''))"
    live_expr = "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
    registration_expr = "lower(trim(COALESCE(status, '')))"
    password_login_verified_expr = "lower(COALESCE(CAST(json_extract(payload, '$.password_setup_login_verified') AS TEXT), ''))"
    password_extra_verified_expr = (
        "lower(COALESCE(CAST(json_extract(json_extract(payload, '$.extra_json'), "
        "'$.registration_password_verified') AS TEXT), ''))"
    )
    password_ok_expr = (
        f"({password_login_verified_expr} IN ('1','true','yes','on') OR "
        f"{password_extra_verified_expr} IN ('1','true','yes','on'))"
    )
    totp_secret_expr = "trim(COALESCE(CAST(json_extract(payload, '$.totp_secret') AS TEXT), ''))"
    totp_ok_expr = "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_ok') AS TEXT), ''))"
    totp_status_expr = "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_status') AS TEXT), ''))"
    at_valid_expr = (
        f"length({token_expr}) > 0 AND {expired_expr} NOT IN ('1','true','yes','on') "
        f"AND {http_expr}<>401 AND {live_expr} NOT IN ('failed','deactivated','dead')"
    )
    registration_complete_expr = (
        f"({password_ok_expr} AND {at_valid_expr} "
        f"AND length({totp_secret_expr})>0 AND "
        f"({totp_ok_expr} IN ('1','true','yes','on') OR {totp_status_expr}='success'))"
    )
    registration_incomplete_expr = f"{registration_expr} IN ('registering','interrupted') AND NOT {registration_complete_expr}"
    duration_expr = (
        "(julianday(json_extract(payload, '$.plan_check_completed_at')) - "
        "julianday(json_extract(payload, '$.plan_check_started_at'))) * 86400.0"
    )
    sql = f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN {registration_expr}='registering' AND NOT {registration_complete_expr} THEN 1 ELSE 0 END) AS registering,
            SUM(CASE WHEN {registration_expr}='interrupted' AND NOT {registration_complete_expr} THEN 1 ELSE 0 END) AS interrupted,
            SUM(CASE WHEN {registration_incomplete_expr} THEN 1 ELSE 0 END) AS registration_incomplete,
            SUM(CASE WHEN {registration_expr} IN ('registering','interrupted') AND {registration_complete_expr} THEN 1 ELSE 0 END) AS registration_recovered,
            SUM(CASE WHEN {password_ok_expr} THEN 1 ELSE 0 END) AS password_saved,
            SUM(CASE WHEN length({token_expr}) > 0 THEN 1 ELSE 0 END) AS at_present,
            SUM(CASE WHEN length({token_expr}) = 0 THEN 1 ELSE 0 END) AS at_missing,
            SUM(CASE WHEN {expired_expr} IN ('1','true','yes','on') OR {http_expr}=401 THEN 1 ELSE 0 END) AS at_expired,
            SUM(CASE WHEN length({token_expr}) > 0 AND {expired_expr} NOT IN ('1','true','yes','on') AND {http_expr}<>401 THEN 1 ELSE 0 END) AS at_valid,
            SUM(CASE WHEN {eligible_expr} IN ('1','true','yes','on') AND {expired_expr} NOT IN ('1','true','yes','on') AND {check_expr}<>'failed' AND {live_expr} NOT IN ('failed','deactivated','dead') AND {http_expr}<>401 AND {plan_expr}='free' THEN 1 ELSE 0 END) AS eligible,
            SUM(CASE WHEN {eligible_expr} IN ('0','false','no','off') THEN 1 ELSE 0 END) AS ineligible,
            SUM(CASE WHEN {eligible_expr}='' THEN 1 ELSE 0 END) AS eligibility_unknown,
            SUM(CASE WHEN {plan_expr} LIKE '%plus%' AND {plan_expr} NOT LIKE '%free%' THEN 1 ELSE 0 END) AS plus,
            SUM(CASE WHEN {plan_expr}='free' THEN 1 ELSE 0 END) AS free,
            SUM(CASE WHEN {plan_expr}<>'' AND {plan_expr}<>'free' AND NOT ({plan_expr} LIKE '%plus%' AND {plan_expr} NOT LIKE '%free%') THEN 1 ELSE 0 END) AS other_plan,
            SUM(CASE WHEN {plan_expr}='' THEN 1 ELSE 0 END) AS plan_unknown,
            SUM(CASE WHEN {check_expr}='queued' THEN 1 ELSE 0 END) AS queued,
            SUM(CASE WHEN {check_expr}='running' THEN 1 ELSE 0 END) AS running,
            SUM(CASE WHEN {check_expr}='success' THEN 1 ELSE 0 END) AS success,
            SUM(CASE WHEN {check_expr}='failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN {check_expr}='' THEN 1 ELSE 0 END) AS unchecked,
            SUM(CASE WHEN {live_expr}='live' THEN 1 ELSE 0 END) AS live,
            SUM(CASE WHEN {live_expr} IN ('failed','deactivated','dead') THEN 1 ELSE 0 END) AS live_failed,
            SUM(CASE WHEN {live_expr} IN ('queued','running') THEN 1 ELSE 0 END) AS live_pending,
            AVG(CASE WHEN {duration_expr} >= 0 AND {duration_expr} <= 3600 THEN {duration_expr} END) AS average_duration_seconds,
            MAX(COALESCE(NULLIF(json_extract(payload, '$.plan_checked_at'), ''), NULLIF(json_extract(payload, '$.plan_check_completed_at'), ''))) AS last_checked_at
        FROM {table}
        WHERE {clause}
    """
    with closing(_sqlite_conn()) as conn:
        row = dict(conn.execute(sql, params).fetchone())
    integer_fields = (
        "total", "registering", "interrupted", "registration_incomplete", "registration_recovered", "password_saved",
        "at_present", "at_missing", "at_expired", "at_valid",
        "eligible", "ineligible", "eligibility_unknown", "plus", "free",
        "other_plan", "plan_unknown", "queued", "running", "success",
        "failed", "unchecked", "live", "live_failed", "live_pending",
    )
    for key in integer_fields:
        row[key] = int(row.get(key) or 0)
    row["average_duration_seconds"] = round(float(row.get("average_duration_seconds") or 0.0), 1)
    row["last_checked_at"] = str(row.get("last_checked_at") or "")
    return row

def list_account_plan_check_statuses(
    limit: int = 5000,
    offset: int = 0,
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    codex_filter: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    totp_filter: str | None = None,
    overview_filter: str | None = None,
) -> dict:
    """返回不含 Token/邮箱密码的套餐查询轻量状态快照。"""
    fields = (
        "id", "email", "archived",
        "plan_type", "current_plan_type", "plus_trial_eligible", "eligible_promo_campaigns",
        "discount_offer_eligible", "discount_offer_campaign_id",
        "discount_offer_title", "discount_offer_percentage", "has_50_discount",
        "plan_check_status", "plan_check_ok", "plan_check_error", "plan_check_http_status", "plan_check_failure_summary",
        "plan_check_trigger", "plan_check_queued_at", "plan_check_started_at",
        "plan_check_completed_at", "plan_checked_at", "plan_last_success_at",
        "plan_region_results", "plan_region_checked_at",
        "plan_check_network_route", "plan_check_proxy_used", "plan_check_proxy_fallback_reason",
        "payment_check_status", "payment_check_ok", "payment_check_error",
        "payment_check_trigger", "payment_check_queued_at", "payment_check_started_at",
        "payment_check_completed_at", "payment_checked_at", "payment_last_success_at",
        "payment_methods", "payment_methods_text", "payment_has_method",
        "payment_one_click_trial_eligible", "payment_invoice_count",
        "payment_endpoint_unavailable", "has_customer_object", "processor_entity",
        "has_transaction_history", "payment_check_network_route", "payment_check_proxy_used",
        "live_check_status", "live_check_error", "live_checked_at",
        "live_check_queued_at", "live_check_started_at", "token_expired", "token_expires_at",
        "live_check_proxy_used", "live_check_fingerprint_text",
        "expires_at", "plan_expires_at", "plan_renews_at", "renews_at",
        "billing_period", "billing_currency", "discount_amount", "discount_type",
        "discount_expires_at", "discount_promo_campaign_id",
        "extract_link_status", "extract_link_ok", "extract_link_type",
        "extract_link_message", "extract_link_error",
        "extract_link_long_url", "extract_link_copy_paste",
        "extract_link_image_url_png", "extract_link_image_url_svg",
        "extract_link_expires_at",
        "codex_status", "codex_error",
        "codex_agent_status", "codex_agent_message",
        "codex_agent_runtime_id", "codex_agent_sub2api_url",
        "codex_agent_sub2api_mode", "codex_agent_sub2api_total",
        "totp_setup_status", "totp_setup_ok", "totp_setup_error",
        "totp_setup_message", "totp_setup_trigger", "totp_setup_queued_at",
        "totp_setup_started_at", "totp_setup_completed_at", "totp_setup_checked_at",
        "original_email", "email_source", "email_change_status", "email_change_ok",
        "email_change_error", "email_change_new_email", "email_change_started_at", "email_change_completed_at",
    )
    with _LOCK:
        limit = max(1, int(limit))
        offset = max(0, int(offset or 0))
        extra_where, extra_params = _account_filter_sql(
            plan_filter=plan_filter,
            codex_filter=codex_filter,
            totp_filter=totp_filter,
        )
        overview_where, overview_params = _overview_filter_sql(overview_filter)
        extra_where.extend(overview_where)
        extra_params.extend(overview_params)
        candidates, total, latest = _query_collection_page(
            "accounts",
            archived=archived,
            q=q,
            date_from=date_from,
            date_to=date_to,
            extra_where=extra_where,
            extra_params=extra_params,
            limit=limit,
            offset=offset,
        )
        rows = [_decorate_account(row) for row in candidates]
        items = []
        for row in rows:
            item = {"id": row.get("id"), "email": row.get("email")}
            for key in fields:
                value = row.get(key)
                if key in ("id", "email"):
                    continue
                if value is not None and value != "":
                    item[key] = value
            item["totp_enabled"] = bool(str(row.get("totp_secret") or "").strip())
            plan = str(row.get("current_plan_type") or row.get("plan_type") or "").lower()
            if not any(x in plan for x in ("plus", "pro", "team", "go")):
                for expire_key in ("expires_at", "plan_expires_at", "plan_renews_at", "renews_at"):
                    item.pop(expire_key, None)
            item["codex_agent_has_token"] = bool(str(row.get("codex_agent_token") or "").strip())
            item["has_access_token"] = bool(str(row.get("access_token") or "").strip())
            items.append(item)
        # updated_at 目前只有秒级精度；一次快速查询可能在同一秒内完成
        # queued -> running -> success/failed，导致 revision 不变，前端跳过合并状态，
        # 页面就会一直停在“查询中”。把轻量状态本身纳入签名，保证状态变化可被轮询发现。
        revision_payload = json.dumps(
            [
                {
                    "id": row.get("id"),
                    "updated_at": row.get("updated_at"),
                    "live_check_status": row.get("live_check_status"),
                    "live_check_error": row.get("live_check_error"),
                    "live_checked_at": row.get("live_checked_at"),
                    "token_expired": row.get("token_expired"),
                    "has_access_token": bool(str(row.get("access_token") or "").strip()),
                    "plan_check_status": row.get("plan_check_status"),
                    "plan_check_ok": row.get("plan_check_ok"),
                    "plan_check_error": row.get("plan_check_error"),
                    "current_plan_type": row.get("current_plan_type"),
                    "plan_type": row.get("plan_type"),
                    "plus_trial_eligible": row.get("plus_trial_eligible"),
                    "eligible_promo_campaigns": row.get("eligible_promo_campaigns"),
                    "discount_offer_eligible": row.get("discount_offer_eligible"),
                    "discount_offer_campaign_id": row.get("discount_offer_campaign_id"),
                    "discount_offer_percentage": row.get("discount_offer_percentage"),
                    "plan_region_results": row.get("plan_region_results"),
                    "extract_link_status": row.get("extract_link_status"),
                    "codex_status": row.get("codex_status"),
                    "codex_agent_status": row.get("codex_agent_status"),
                    "totp_setup_status": row.get("totp_setup_status"),
                    "totp_setup_ok": row.get("totp_setup_ok"),
                    "totp_setup_error": row.get("totp_setup_error"),
                    "totp_setup_message": row.get("totp_setup_message"),
                    "totp_setup_checked_at": row.get("totp_setup_checked_at"),
                    "totp_setup_started_at": row.get("totp_setup_started_at"),
                    "totp_setup_completed_at": row.get("totp_setup_completed_at"),
                    "totp_enabled": bool(str(row.get("totp_secret") or "").strip()),
                    "email": row.get("email"),
                    "original_email": row.get("original_email"),
                    "email_source": row.get("email_source"),
                    "email_change_status": row.get("email_change_status"),
                    "email_change_error": row.get("email_change_error"),
                }
                for row in rows
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        revision_sig = hashlib.sha1(revision_payload.encode("utf-8")).hexdigest()[:12]
        return {"items": items, "total": total, "offset": offset, "limit": limit, "revision": f"{total}:{latest}:{revision_sig}"}


def list_accounts(
    limit: int = 500,
    offset: int = 0,
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    codex_filter: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    totp_filter: str | None = None,
    overview_filter: str | None = None,
) -> list[dict]:
    # 非分页兼容接口也走同一条 SQL 分页路径，避免 limit=500 时先读取整张表。
    result = list_accounts_page(
        limit=limit,
        offset=offset,
        archived=archived,
        plan_filter=plan_filter,
        codex_filter=codex_filter,
        q=q,
        date_from=date_from,
        date_to=date_to,
        totp_filter=totp_filter,
        overview_filter=overview_filter,
    )
    return result["items"]


def list_accounts_page(
    limit: int = 50,
    offset: int = 0,
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    codex_filter: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    totp_filter: str | None = None,
    overview_filter: str | None = None,
) -> dict:
    with _LOCK:
        limit = max(1, int(limit))
        offset = max(0, int(offset or 0))
        extra_where, extra_params = _account_filter_sql(
            plan_filter=plan_filter,
            codex_filter=codex_filter,
            totp_filter=totp_filter,
        )
        overview_where, overview_params = _overview_filter_sql(overview_filter)
        extra_where.extend(overview_where)
        extra_params.extend(overview_params)
        candidates, total, latest = _query_collection_page(
            "accounts",
            archived=archived,
            q=q,
            date_from=date_from,
            date_to=date_to,
            extra_where=extra_where,
            extra_params=extra_params,
            limit=limit,
            offset=offset,
        )
        items = [_decorate_account(row) for row in candidates]
        return {"items": items, "total": total, "offset": offset, "limit": limit, "revision": f"{total}:{latest}"}


def get_account(acc_id: int) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        return _decorate_account(row) if row else None


def get_accounts_by_ids(account_ids: list[int]) -> dict[int, dict]:
    """一次批量读取账号；避免逐个 get_account 重复扫描整张账号表。"""
    ids = list(dict.fromkeys(int(value) for value in account_ids))
    if not ids:
        return {}
    _ensure_sqlite()
    result: dict[int, dict] = {}
    with _LOCK:
        with closing(_sqlite_conn()) as conn:
            for offset in range(0, len(ids), 400):
                chunk = ids[offset:offset + 400]
                marks = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT id, payload FROM accounts WHERE id IN ({marks})", chunk
                )
                for row in rows:
                    result[int(row["id"])] = _decorate_account(json.loads(row["payload"]))
    return result


def get_account_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_by_email(_load_accounts(), email)
        return _decorate_account(row) if row else None


def update_account_note(acc_id: int, note: str) -> bool:
    """更新单个已注册账号备注。note 为空字符串时表示清空备注。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        row["note"] = str(note or "")
        row["note_updated_at"] = now
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def update_account_password_setup(acc_id: int, result: dict | None = None) -> bool:
    """记录补设密码任务；只有独立登录验收成功才公开候选密码。"""
    result = result or {}
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        previously_verified = account_password_login_verified(row)
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        login_verified_supplied = "login_verified" in result
        login_verified = result.get("login_verified") is True
        if login_verified_supplied:
            row["password_setup_login_verified"] = login_verified
        row["password_setup_status"] = status
        row["password_setup_ok"] = bool(result.get("ok")) and status == "success" and login_verified
        row["password_setup_message"] = str(result.get("message") or "")
        row["password_setup_error"] = None if row["password_setup_ok"] else result.get("error")
        if "remote_password_present" in result:
            row["password_setup_remote_password_present"] = bool(result.get("remote_password_present"))
        if result.get("clear_candidate") is True:
            row["password_setup_candidate"] = None
        candidate_password = str(result.get("candidate_password") or "").strip()
        if candidate_password:
            row["password_setup_candidate"] = candidate_password
        if status == "queued":
            row["password_setup_queued_at"] = now
        elif status == "running":
            row["password_setup_started_at"] = now
        elif status in {"success", "failed", "verification_failed", "expired", "cancelled"}:
            row["password_setup_completed_at"] = now
        try:
            extra = json.loads(row.get("extra_json") or "{}")
        except Exception:
            extra = {}
        if not isinstance(extra, dict):
            extra = {}
        if login_verified_supplied and not login_verified:
            extra["registration_password_verified"] = False
            if not previously_verified:
                # 旧版本可能提前把候选密码写进正式字段；验收失败时必须撤销公开凭证。
                extra.pop("registration_password", None)
                row.pop("registration_password", None)
        password = str(result.get("password") or "").strip()
        if row["password_setup_ok"] and password:
            extra["registration_password"] = password
            extra["registration_password_verified"] = True
            row["registration_password"] = password
            row["password_setup_candidate"] = None
            row["password_setup_remote_password_present"] = True
        row["extra_json"] = json.dumps(extra, ensure_ascii=False)
        row["copy_line"] = _account_line(row)
        row["updated_at"] = now
        _save_accounts(rows)
        return True



def claim_account_password_change(acc_id: int, candidate_password: str, trigger: str = "manual") -> bool:
    """原子占用远端改密任务；候选值在验收前绝不替换正式密码。"""
    candidate = str(candidate_password or "").strip()
    if not candidate:
        return False
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or str(row.get("password_change_status") or "") in {"queued", "running", "verifying"}:
            return False
        now = _now()
        row.update({
            "password_change_status": "queued",
            "password_change_ok": False,
            "password_change_candidate": candidate,
            "password_change_trigger": str(trigger or "manual"),
            "password_change_queued_at": now,
            "password_change_started_at": None,
            "password_change_completed_at": None,
            "password_change_login_verified": False,
            "password_change_error": None,
            "password_change_message": "已进入远端改密队列",
            "updated_at": now,
        })
        _save_accounts(rows)
        return True


def update_account_password_change(acc_id: int, result: dict | None = None) -> bool:
    """更新远端改密状态；仅新密码独立登录验收成功后原子替换正式密码。"""
    result = result or {}
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        verified = result.get("login_verified") is True
        row["password_change_status"] = status
        row["password_change_ok"] = bool(result.get("ok")) and status == "success" and verified
        row["password_change_login_verified"] = verified
        row["password_change_message"] = str(result.get("message") or "")
        row["password_change_error"] = None if row["password_change_ok"] else str(result.get("error") or "")[:1000] or None
        if status == "running":
            row["password_change_started_at"] = now
        if status in {"success", "failed", "verification_failed", "cancelled"}:
            row["password_change_completed_at"] = now
        password = str(result.get("password") or "").strip()
        if row["password_change_ok"] and password:
            try:
                extra = json.loads(row.get("extra_json") or "{}")
            except Exception:
                extra = {}
            if not isinstance(extra, dict):
                extra = {}
            extra["registration_password"] = password
            extra["registration_password_verified"] = True
            extra["password_changed_at"] = now
            row["extra_json"] = json.dumps(extra, ensure_ascii=False)
            row["registration_password"] = password
            row["password_setup_ok"] = True
            row["password_setup_login_verified"] = True
            row["password_setup_remote_password_present"] = True
            row["password_setup_status"] = "success"
            row["password_setup_error"] = None
            row["password_setup_message"] = "远端密码已修改并通过全新浏览器登录验收"
            row["password_change_candidate"] = None
        row["copy_line"] = _account_line(row)
        row["updated_at"] = now
        _save_accounts(rows)
        return True

def update_account_password(acc_id: int, password: str = "") -> bool:
    """手动更新或清空账号的注册/登录密码凭证。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        pwd = str(password or "").strip()
        row["password"] = pwd or None
        row["registration_password"] = pwd or None
        row["password_setup_ok"] = bool(pwd)
        row["password_setup_login_verified"] = bool(pwd)
        row["password_setup_remote_password_present"] = bool(pwd)
        if pwd:
            row["password_setup_status"] = "success"
            row["password_setup_error"] = None
            row["password_setup_message"] = "手动更新密码"
        else:
            row["password_setup_status"] = "idle"
            row["password_setup_error"] = None
            row["password_setup_message"] = "密码已清空"
        try:
            extra = json.loads(row.get("extra_json") or "{}")
        except Exception:
            extra = {}
        if not isinstance(extra, dict):
            extra = {}
        if pwd:
            extra["registration_password"] = pwd
            extra["registration_password_verified"] = True
        else:
            extra.pop("registration_password", None)
            extra.pop("registration_password_verified", None)
        row["extra_json"] = json.dumps(extra, ensure_ascii=False)
        row["copy_line"] = _account_line(row)
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def claim_account_email_change(acc_id: int, source: str, trigger: str = "manual") -> bool:
    """原子占用账号邮箱换绑任务。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("email_change_status") in {"queued", "running"}:
            return False
        now = _now()
        row.update({
            "email_change_status": "queued", "email_change_ok": False,
            "email_change_source": str(source or ""), "email_change_trigger": str(trigger or "manual"),
            "email_change_queued_at": now, "email_change_started_at": None,
            "email_change_completed_at": None, "email_change_error": None, "updated_at": now,
        })
        _save_accounts(rows)
        return True


def mark_account_email_change_running(acc_id: int, new_email: str) -> bool:
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("email_change_status") not in {"queued", "running"}:
            return False
        row.update({"email_change_status": "running", "email_change_new_email": new_email,
                    "email_change_started_at": _now(), "email_change_error": None, "updated_at": _now()})
        _save_accounts(rows)
        return True


def finish_account_email_change(
    acc_id: int, *, ok: bool, new_email: str | None = None, source: str | None = None,
    material_line: str | None = None, error: str | None = None,
) -> bool:
    """写回换绑结果；成功时保留初始邮箱并将账号主邮箱切换为新邮箱。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        if ok and new_email:
            old_email = str(row.get("email") or "").strip()
            row["original_email"] = str(row.get("original_email") or old_email)
            history = row.get("email_history") if isinstance(row.get("email_history"), list) else []
            if old_email and old_email.lower() not in {str(x).lower() for x in history}:
                history.append(old_email)
            row["email_history"] = history
            row["email"] = str(new_email).strip()
            row["email_source"] = str(source or row.get("email_source") or "")
            row["original_email_line"] = str(material_line or new_email)
            # 清理旧邮箱来源遗留的 Outlook 凭证；若新来源仍为 Outlook 则写入新素材。
            row["password"] = ""
            row["client_id"] = ""
            row["refresh_token"] = ""
            if str(source or "") == "outlook":
                mailbox = _find_by_email(_load_outlook(), str(new_email))
                if mailbox:
                    row["password"] = mailbox.get("password") or ""
                    row["client_id"] = mailbox.get("client_id") or ""
                    row["refresh_token"] = mailbox.get("refresh_token") or ""
            # 抓包表明 verify 成功后当前 OAuth token 会立即失效。
            row["access_token"] = ""
            row["token_expired"] = True
            row["live_check_status"] = ""
            row["email_change_new_email"] = str(new_email).strip()
        row["email_change_status"] = "success" if ok else "failed"
        row["email_change_ok"] = bool(ok)
        row["email_change_error"] = None if ok else str(error or "换绑失败")[:1000]
        row["email_change_completed_at"] = now
        row["updated_at"] = now
        row["copy_line"] = _account_line(row)
        _save_accounts(rows)
        return True


def recover_interrupted_email_changes() -> int:
    """启动时将上次进程中断的邮箱换绑任务标记为失败。"""
    with _LOCK:
        rows = _load_accounts()
        count = 0
        for row in rows:
            if row.get("email_change_status") not in {"queued", "running"}:
                continue
            row.update({
                "email_change_status": "failed", "email_change_ok": False,
                "email_change_error": "WebUI 重启导致邮箱换绑中断，请重新操作",
                "email_change_completed_at": _now(), "updated_at": _now(),
            })
            count += 1
        if count:
            _save_accounts(rows)
        return count


def update_account_liveness(acc_id: int, result: dict | None = None) -> bool:
    """写回账号查活结果；成功时同步刷新最新 access_token 和账号基础信息。"""
    result = result or {}
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False

        now = _now()
        ok = bool(result.get("ok"))
        status = str(result.get("status") or ("live" if ok else "failed"))
        row["live_check_status"] = status
        row["live_check_ok"] = ok
        row["live_checked_at"] = result.get("checked_at") or now
        row["live_check_error"] = None if ok else result.get("error")
        row["updated_at"] = now

        if ok:
            token = str(result.get("access_token") or "").strip()
            if token:
                row["access_token"] = token
                # 新 AT 已经由 OAuth session 返回，旧 AT 产生的套餐失败结论随之失效。
                # 清空后交给新 AT 的套餐复查重新生成状态，避免页面同时显示
                # “查活正常”和“AT 已过期”。
                row["token_expired"] = False
                row["token_expires_at"] = access_token_expires_at(token)
                # Liveness success must not erase a completed eligibility check
                # or an in-flight plan job, even when a fresh AT is returned.
                plan_error = str(row.get("plan_check_error") or "").lower()
                stale_auth_failure = (
                    row.get("plan_check_status") == "failed"
                    and (row.get("plan_check_http_status") == 401
                         or "token_expired" in plan_error
                         or "unauthorized" in plan_error)
                )
                if stale_auth_failure:
                    row["plan_check_status"] = ""
                    row["plan_check_ok"] = None
                    row["plan_check_error"] = None
                    row["plan_checked_at"] = None
            session = result.get("session") or {}
            user = session.get("user") or {}
            account = session.get("account") or {}
            if user.get("id"):
                row["user_id"] = user.get("id")
            if user.get("name") is not None:
                row["user_name"] = user.get("name")
            if account.get("planType"):
                row["plan_type"] = account.get("planType")
            if session.get("expires"):
                row["expires_at"] = session.get("expires")
            row["live_check_proxy_used"] = result.get("proxy_used") or row.get("live_check_proxy_used")
            row["live_check_fingerprint_text"] = result.get("fingerprint_text") or row.get("live_check_fingerprint_text")
            if result.get("fingerprint"):
                row["live_check_fingerprint"] = result.get("fingerprint")
            session_token = str(result.get("session_token") or "").strip()
            if session_token:
                try:
                    extra = json.loads(row.get("extra_json") or "{}")
                except Exception:
                    extra = {}
                if not isinstance(extra, dict):
                    extra = {}
                extra["session_token"] = session_token
                extra["user"] = session.get("user") or extra.get("user")
                extra["account"] = session.get("account") or extra.get("account")
                row["extra_json"] = json.dumps(extra, ensure_ascii=False)
            row["live_check_error"] = None
        else:
            if result.get("token_expired") is True:
                row["token_expired"] = True
                row["plan_check_status"] = "failed"
                row["plan_check_error"] = result.get("error") or "AT已过期/失效"

        row["copy_line"] = _account_line(row)
        _save_accounts(rows)
        return True


def claim_account_totp_setup(acc_id: int, trigger: str = "manual") -> bool:
    """原子占用账号 2FA 设置任务；已有未超时任务时返回 False。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current_status = row.get("totp_setup_status")
        if row.get("totp_setup_candidate_secret") or current_status in {"prepared", "activation_unknown"}:
            return False  # 已有待核验候选密钥，禁止重复 enroll
        if current_status in {"queued", "running"}:
            # 手动触发允许立即重试；自动触发在 90 秒超时后亦允许抢占重试，杜绝 30 分钟死锁
            if trigger != "manual":
                try:
                    stamp_key = "totp_setup_queued_at" if current_status == "queued" else "totp_setup_started_at"
                    stale_after = 90
                    started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                    if (datetime.now() - started_at).total_seconds() < stale_after:
                        return False
                except (TypeError, ValueError):
                    pass
        now = _now()
        row["totp_setup_status"] = "queued"
        row["totp_setup_ok"] = False
        row["totp_setup_trigger"] = str(trigger or "manual")
        row["totp_setup_queued_at"] = now
        row["totp_setup_started_at"] = None
        row["totp_setup_completed_at"] = None
        row["totp_setup_error"] = None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def mark_account_totp_setup_running(acc_id: int) -> bool:
    """把 2FA 设置任务标记为运行中。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("totp_setup_status") not in {"queued", "running"}:
            return False
        now = _now()
        row["totp_setup_status"] = "running"
        row["totp_setup_started_at"] = now
        row["totp_setup_error"] = None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def update_account_totp_secret(acc_id: int, result: dict | None = None) -> bool:
    """更新账号 2FA/TOTP 设置结果。"""
    result = result or {}
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["totp_setup_status"] = status
        row["totp_setup_ok"] = ok
        row["totp_setup_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped", "activation_unknown", "remote_enabled"}:
            row["totp_setup_completed_at"] = _now()
        row["totp_setup_error"] = None if ok or status == "running" else result.get("error")
        secret = str(result.get("totp_secret") or "").strip()
        if status == "prepared" and secret:
            row["totp_setup_candidate_secret"] = secret
        if ok and secret:
            row["totp_secret"] = secret
            row["totp_setup_candidate_secret"] = None
        if result.get("message") is not None:
            row["totp_setup_message"] = result.get("message")
        row["copy_line"] = _account_line(row)
        row["updated_at"] = _now()
        _save_accounts(rows)
        return True


def recover_interrupted_totp_setups() -> int:
    """服务启动时恢复上次进程中断的 2FA 设置状态。"""
    with _LOCK:
        rows = _load_accounts()
        recovered = 0
        now = _now()
        for row in rows:
            if row.get("totp_setup_status") not in {"queued", "running", "prepared"}:
                continue
            has_candidate = bool(row.get("totp_setup_candidate_secret"))
            row["totp_setup_status"] = "activation_unknown" if has_candidate else "failed"
            row["totp_setup_ok"] = False
            row["totp_setup_error"] = ("进程中断，候选密钥已保留，需核验远端状态" if has_candidate
                                       else "WebUI 重启导致 2FA 设置中断，请重新开启")
            row["totp_setup_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(rows)
        return recovered


def claim_account_totp_rotation(acc_id: int, trigger: str = "manual") -> bool:
    """原子占用 TOTP 密钥轮换任务。轮换与首次开启互斥。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        if row.get("totp_setup_status") in {"queued", "running"}:
            return False
        if row.get("totp_rotation_status") in {"queued", "running", "prepared", "verifying"}:
            return False
        now = _now()
        row["totp_rotation_status"] = "queued"
        row["totp_rotation_ok"] = False
        row["totp_rotation_trigger"] = str(trigger or "manual")
        row["totp_rotation_queued_at"] = now
        row["totp_rotation_started_at"] = None
        row["totp_rotation_completed_at"] = None
        row["totp_rotation_error"] = None
        row["totp_rotation_message"] = "等待更换 2FA 密钥"
        row["totp_rotation_candidate_secret"] = None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def mark_account_totp_rotation_running(acc_id: int) -> bool:
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("totp_rotation_status") not in {"queued", "running"}:
            return False
        now = _now()
        row["totp_rotation_status"] = "running"
        row["totp_rotation_started_at"] = now
        row["totp_rotation_error"] = None
        row["totp_rotation_message"] = "正在登录并申请新密钥"
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def update_account_totp_rotation(acc_id: int, result: dict | None = None) -> bool:
    """写回轮换阶段；仅完整双向验证成功后替换当前密钥。"""
    result = result or {}
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["totp_rotation_status"] = status
        row["totp_rotation_ok"] = ok
        row["totp_rotation_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped"}:
            row["totp_rotation_completed_at"] = _now()
        row["totp_rotation_error"] = None if ok or status in {"running", "prepared", "verifying"} else result.get("error")
        if result.get("message") is not None:
            row["totp_rotation_message"] = result.get("message")
        candidate = str(result.get("candidate_secret") or "").strip()
        if candidate:
            row["totp_rotation_candidate_secret"] = candidate
        if result.get("clear_candidate") is True:
            row["totp_rotation_candidate_secret"] = None
        if ok:
            new_secret = str(result.get("totp_secret") or candidate or "").strip()
            if not new_secret:
                return False
            row["totp_secret"] = new_secret
            row["totp_rotation_candidate_secret"] = None
            row["totp_setup_status"] = "success"
            row["totp_setup_ok"] = True
        row["copy_line"] = _account_line(row)
        row["updated_at"] = _now()
        _save_accounts(rows)
        return True


def recover_interrupted_totp_rotations() -> int:
    """保留候选密钥并把进程中断的轮换标记为失败，避免盲目重放。"""
    with _LOCK:
        rows = _load_accounts()
        recovered = 0
        now = _now()
        for row in rows:
            if row.get("totp_rotation_status") not in {"queued", "running", "prepared", "verifying"}:
                continue
            row["totp_rotation_status"] = "failed"
            row["totp_rotation_ok"] = False
            row["totp_rotation_error"] = "WebUI 重启导致 2FA 更换中断；原密钥未被本地覆盖"
            row["totp_rotation_message"] = "若远端已激活候选密钥，请从日志确认后重新验证"
            row["totp_rotation_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(rows)
        return recovered


def claim_account_live_check(acc_id: int, trigger: str = "manual") -> bool:
    """原子占用账号查活任务；已有 queued/running 时返回 False。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        if row.get("live_check_status") in {"queued", "running"}:
            try:
                stamp_key = "live_check_queued_at" if row.get("live_check_status") == "queued" else "live_check_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if row.get("live_check_status") == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass
        now = _now()
        row["live_check_status"] = "queued"
        row["live_check_ok"] = False
        row["live_check_trigger"] = str(trigger or "manual")
        row["live_check_queued_at"] = now
        row["live_check_started_at"] = None
        row["live_checked_at"] = None
        row["live_check_error"] = None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def claim_account_live_checks_batch(
    acc_ids: list[int],
    trigger: str = "manual",
) -> set[int]:
    """批量原子占用账号查活任务；仅单次磁盘/数据库写入，实现数百账号瞬间入队。"""
    if not acc_ids:
        return set()
    id_set = {int(x) for x in acc_ids}
    claimed: set[int] = set()
    with _LOCK:
        rows = _load_accounts()
        now = _now()
        modified = False
        for row in rows:
            rid = int(row.get("id") or 0)
            if rid not in id_set:
                continue
            current_status = row.get("live_check_status")
            if current_status in {"queued", "running"}:
                try:
                    stamp_key = "live_check_queued_at" if current_status == "queued" else "live_check_started_at"
                    stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                    started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                    if (datetime.now() - started_at).total_seconds() < stale_after:
                        continue
                except (TypeError, ValueError):
                    pass
            row["live_check_status"] = "queued"
            row["live_check_ok"] = False
            row["live_check_trigger"] = str(trigger or "manual")
            row["live_check_queued_at"] = now
            row["live_check_started_at"] = None
            row["live_checked_at"] = None
            row["live_check_error"] = None
            row["updated_at"] = now
            claimed.add(rid)
            modified = True
        if modified:
            _save_accounts(rows)
    return claimed


def recover_interrupted_live_checks() -> int:
    """服务启动时恢复上次进程中断的查活状态，避免 queued/running 卡死。"""
    with _LOCK:
        rows = _load_accounts()
        recovered = 0
        now = _now()
        for row in rows:
            if row.get("live_check_status") not in {"queued", "running"}:
                continue
            row["live_check_status"] = "failed"
            row["live_check_ok"] = False
            row["live_check_error"] = "WebUI 重启或任务异常中断；账号与凭证状态未判定，请重新查活"
            # Recovery is not a completed account check. Preserve its timestamp.
            row["live_check_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(rows)
        return recovered


def mark_account_live_check_running(acc_id: int) -> bool:
    """把账号查活任务标记为运行中。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("live_check_status") not in {"queued", "running"}:
            return False
        now = _now()
        row["live_check_status"] = "running"
        row["live_check_started_at"] = now
        row["live_check_error"] = None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def update_accounts_note(account_ids: list[int] | None, note: str) -> tuple[list[dict], list[dict]]:
    """
    批量更新已注册账号备注。
    返回 (updated, skipped)，updated/skipped 元素含 id/email。
    """
    ids = {int(x) for x in (account_ids or []) if str(x).strip().lstrip("-").isdigit()}
    updated: list[dict] = []
    skipped: list[dict] = []
    with _LOCK:
        rows = _load_accounts()
        seen_ids: set[int] = set()
        now = _now()
        text = str(note or "")
        for row in rows:
            row_id = int(row.get("id") or 0)
            if row_id not in ids:
                continue
            row["note"] = text
            row["note_updated_at"] = now
            row["updated_at"] = now
            updated.append({"id": row_id, "email": row.get("email"), "note": text, "note_updated_at": now})
            seen_ids.add(row_id)
        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        if updated:
            _save_accounts(rows)
    return updated, skipped


def archive_account(acc_id: int, archived: bool = True) -> bool:
    """归档/取消归档单个已注册账号。归档不会删除 token，只影响默认账号列表查询。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        row["archived"] = bool(archived)
        row["archived_at"] = now if archived else None
        row["updated_at"] = now
        _save_accounts(rows)
        return True


def archive_accounts(account_ids: list[int] | None, archived: bool = True) -> tuple[list[dict], list[dict]]:
    """批量归档/取消归档账号。返回 (updated, skipped)。"""
    ids = {int(x) for x in (account_ids or []) if str(x).strip().lstrip("-").isdigit()}
    updated: list[dict] = []
    skipped: list[dict] = []
    with _LOCK:
        rows = _load_accounts()
        seen_ids: set[int] = set()
        now = _now()
        for row in rows:
            row_id = int(row.get("id") or 0)
            if row_id not in ids:
                continue
            row["archived"] = bool(archived)
            row["archived_at"] = now if archived else None
            row["updated_at"] = now
            updated.append({"id": row_id, "email": row.get("email"), "archived": bool(archived), "archived_at": row.get("archived_at")})
            seen_ids.add(row_id)
        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        if updated:
            _save_accounts(rows)
    return updated, skipped


def count_accounts() -> int:
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])


def delete_account(acc_id: int | None = None, email: str | None = None) -> bool:
    """从 SQLite 删除一个已注册账号记录，并清理关联的 Agent 凭证。"""
    with _LOCK:
        rows = _load_accounts()
        target_email = (email or "").lower()
        new_rows = []
        deleted_ids = []
        deleted = False
        for row in rows:
            match_id = acc_id is not None and int(row.get("id") or 0) == int(acc_id)
            match_email = bool(target_email) and (row.get("email") or "").lower() == target_email
            if match_id or match_email:
                deleted = True
                deleted_ids.append(int(row.get("id") or 0))
                continue
            new_rows.append(row)
        if not deleted:
            return False
        _save_accounts(new_rows)
        if deleted_ids:
            _ensure_sqlite()
            with closing(_sqlite_conn()) as conn:
                conn.executemany("DELETE FROM codex_agent_accounts WHERE account_id=?", [(x,) for x in deleted_ids])
                conn.commit()
        return True


def delete_accounts(account_ids: list[int] | None = None, emails: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    """
    批量删除已注册账号。
    返回 (deleted, skipped)，deleted 元素含 id/email。
    """
    ids = {int(x) for x in (account_ids or []) if str(x).strip().isdigit()}
    email_set = {(e or "").lower() for e in (emails or []) if e}
    deleted: list[dict] = []
    skipped: list[dict] = []
    with _LOCK:
        rows = _load_accounts()
        new_rows = []
        seen_ids: set[int] = set()
        seen_emails: set[str] = set()
        for row in rows:
            row_id = int(row.get("id") or 0)
            row_email = (row.get("email") or "").lower()
            if row_id in ids or row_email in email_set:
                deleted.append({"id": row_id, "email": row.get("email")})
                seen_ids.add(row_id)
                seen_emails.add(row_email)
                continue
            new_rows.append(row)
        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        for item in email_set - seen_emails:
            skipped.append({"email": item, "reason": "账号不存在"})
        if deleted:
            _save_accounts(new_rows)
            _ensure_sqlite()
            with closing(_sqlite_conn()) as conn:
                conn.executemany("DELETE FROM codex_agent_accounts WHERE account_id=?", [(x["id"],) for x in deleted])
                conn.commit()
    return deleted, skipped


# ============================================================
# outlook_pool
# ============================================================

def import_outlook_accounts(records: list[dict]) -> tuple[int, int]:
    """
    批量导入 Outlook 账号。
    records 元素：{email, password, client_id, refresh_token}
    返回 (新增数, 跳过数)。
    """
    with _LOCK:
        rows = _load_outlook()
        inserted = skipped = 0
        for raw in records:
            email = (raw.get("email") or "").strip()
            if not email:
                skipped += 1
                continue
            if _find_by_email(rows, email):
                skipped += 1
                continue
            row = {
                "id": _next_id(rows),
                "email": email,
                "password": (raw.get("password") or "").strip(),
                "client_id": (raw.get("client_id") or raw.get("clientId") or "").strip(),
                "refresh_token": (raw.get("refresh_token") or raw.get("refreshToken") or "").strip(),
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _outlook_line(row)
            rows.append(row)
            inserted += 1
        _save_outlook(rows)
        return inserted, skipped


def import_registered_email_accounts(records: list[dict], source: str | None) -> tuple[int, int]:
    """
    把邮箱素材直接导入为“已注册成功账号”，用于跳过注册、直接在账号页补跑 Codex 授权。

    source:
      - outlook: records 元素 {email,password,client_id,refresh_token[,access_token,totp_secret]}
      - generic_api: records 元素 {email,code_url[,access_token,totp_secret]}
      - imap: records 元素 {email,imap_password,imap_server,imap_port,imap_ssl}

    返回 (新增账号数, 跳过数)。已存在账号会跳过；邮箱池中已存在的素材会复用并标记 used。
    """
    source = (source or "").strip().lower()
    if source not in ("outlook", "generic_api", "imap", "password_2fa"):
        raise ValueError("source 必须显式传入 outlook / generic_api / imap / password_2fa")

    with _LOCK:
        accounts = _load_accounts()
        outlook_rows = _load_outlook()
        generic_rows = _load_generic_api_emails()
        imap_rows = _load_imap_emails()
        inserted = skipped = 0

        for raw in records:
            email = (raw.get("email") or "").strip()
            if not email:
                skipped += 1
                continue
            if _find_by_email(accounts, email):
                skipped += 1
                continue

            now = _now()
            original_line = email
            pool_row = None

            if source == "password_2fa":
                reg_pwd = str(raw.get("password") or raw.get("registration_password") or "").strip()
                totp = str(raw.get("totp_secret") or "").strip()
                note = str(raw.get("note") or "").strip()
                new_acc = {
                    "id": _next_id(accounts),
                    "email": email,
                    "registration_password": reg_pwd,
                    "totp_secret": totp or None,
                    "totp_setup_status": "success" if totp else None,
                    "totp_setup_ok": bool(totp),
                    "note": note,
                    "created_at": now,
                    "updated_at": now,
                    "imported_at": now,
                    "email_source": "password_2fa",
                    "extra_json": json.dumps({"registration_password": reg_pwd}, ensure_ascii=False) if reg_pwd else "{}",
                }
                new_acc["copy_line"] = _account_line(new_acc)
                accounts.append(new_acc)
                inserted += 1
                continue

            if source == "imap":
                password = str(raw.get("imap_password") or raw.get("password") or "").strip()
                server = str(raw.get("imap_server") or raw.get("server") or "").strip()
                try:
                    port = int(raw.get("imap_port") or raw.get("port") or 993)
                except (TypeError, ValueError):
                    port = 0
                if not password or not server or not (1 <= port <= 65535):
                    skipped += 1
                    continue
                ssl_raw = raw.get("imap_ssl", raw.get("use_ssl", True))
                use_ssl = ssl_raw if isinstance(ssl_raw, bool) else str(ssl_raw).strip().lower() not in {"0", "false", "no", "off"}
                pool_row = _find_by_email(imap_rows, email)
                values = {
                    "imap_password": password, "imap_server": server, "imap_port": port,
                    "imap_username": str(raw.get("imap_username") or raw.get("username") or "").strip(),
                    "imap_ssl": bool(use_ssl),
                }
                if pool_row is None:
                    pool_row = {"id": _next_id(imap_rows), "email": email, **values,
                                "status": "used", "used_at": now,
                                "note": "导入为已注册账号，用于 Codex 授权", "imported_at": now}
                    imap_rows.append(pool_row)
                else:
                    pool_row.update(values)
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _imap_email_line(pool_row)
                original_line = _imap_email_line(pool_row)
            elif source == "generic_api":
                code_url = (raw.get("code_url") or raw.get("url") or "").strip()
                if not code_url:
                    skipped += 1
                    continue
                pool_row = _find_by_email(generic_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(generic_rows),
                        "email": email,
                        "code_url": code_url,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    generic_rows.append(pool_row)
                else:
                    pool_row["code_url"] = code_url or pool_row.get("code_url")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _generic_api_email_line(pool_row)
                original_line = _generic_api_email_line(pool_row)
            else:
                password = (raw.get("password") or "").strip()
                client_id = (raw.get("client_id") or raw.get("clientId") or "").strip()
                refresh_token = (raw.get("refresh_token") or raw.get("refreshToken") or "").strip()
                if not (password and client_id and refresh_token):
                    skipped += 1
                    continue
                pool_row = _find_by_email(outlook_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(outlook_rows),
                        "email": email,
                        "password": password,
                        "client_id": client_id,
                        "refresh_token": refresh_token,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    outlook_rows.append(pool_row)
                else:
                    pool_row["password"] = password or pool_row.get("password")
                    pool_row["client_id"] = client_id or pool_row.get("client_id")
                    pool_row["refresh_token"] = refresh_token or pool_row.get("refresh_token")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _outlook_line(pool_row)
                original_line = _outlook_line(pool_row)

            row_id = _next_id(accounts)
            access_token = (raw.get("access_token") or raw.get("token") or "").strip()
            totp_secret = (raw.get("totp_secret") or raw.get("totp") or "").strip() or None
            account = {
                "id": row_id,
                "email": email,
                "created_at": now,
                "access_token": access_token,
                "totp_secret": totp_secret,
                "user_id": raw.get("user_id"),
                "user_name": raw.get("user_name") or "Imported Account",
                "plan_type": raw.get("plan_type"),
                "expires_at": raw.get("expires_at"),
                "device_id": raw.get("device_id"),
                "proxy_used": raw.get("proxy_used"),
                "email_source": source,
                "extra_json": json.dumps({"imported_registered": True}, ensure_ascii=False),
                "codex_status": raw.get("codex_status") or "",
                "codex_error": raw.get("codex_error"),
                "updated_at": now,
                "original_email_line": original_line,
            }
            if source == "outlook":
                account["password"] = pool_row.get("password")
                account["client_id"] = pool_row.get("client_id")
                account["refresh_token"] = pool_row.get("refresh_token")
            account["copy_line"] = _account_line(account)
            accounts.append(account)

            pool_row["registered_account_id"] = row_id
            pool_row["access_token"] = access_token
            if totp_secret:
                pool_row["totp_secret"] = totp_secret
            inserted += 1

        _save_outlook(outlook_rows)
        _save_generic_api_emails(generic_rows)
        _save_imap_emails(imap_rows)
        _save_accounts(accounts)
        return inserted, skipped


def claim_next_outlook() -> dict | None:
    """原子领取一个可用 Outlook 账号并标记为 used，自动跳过已在 accounts 成功注册的邮箱。"""
    with _LOCK:
        registered_emails = {
            str(a.get("email") or "").strip().lower()
            for a in _load_accounts()
            if a.get("email")
        }
        rows = sorted(_load_outlook(), key=lambda x: int(x.get("id") or 0))
        changed = False
        target_row = None
        for r in rows:
            if not r.get("status") == "available":
                continue
            r_email = str(r.get("email") or "").strip().lower()
            if r_email in registered_emails:
                r["status"] = "disabled"
                r["note"] = "已在本地数据库注册过，自动跳过"
                r["used_at"] = _now()
                changed = True
                continue
            target_row = r
            break
        if target_row is None:
            if changed:
                _save_outlook(rows)
            return None
        target_row["status"] = "used"
        target_row["used_at"] = _now()
        target_row["note"] = None
        _save_outlook(rows)
        return _decorate_outlook(target_row)


def release_outlook(email: str, status: str = "available", note: str | None = None) -> None:
    """把账号状态改回 available，或标记为 used/failed/disabled。"""
    with _LOCK:
        rows = _load_outlook()
        row = _find_by_email(rows, email)
        if row is None:
            return
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_outlook(rows)


def release_unconsumed_outlook(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号且仍为 used 的 Outlook 邮箱。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        rows = _load_outlook()
        row = _find_by_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_outlook(rows)
        return True


def delete_email_pool(email: str, source: str = "all") -> bool:
    """按邮箱及来源从统一邮箱池删除记录。

    ``source=all`` 必须真正查询三个来源，而不能退化成 Outlook；旧版 WebUI
    在“全部邮箱池”中删除通用 API/域名邮箱时就是因此一直返回未找到。直接
    删除 SQLite 行也避免了逐条批量删除时反复加载并重写整个邮箱池。
    """
    target = str(email or "").strip()
    source = str(source or "all").strip().lower()
    if not target:
        return False
    if source not in {"all", "outlook", "generic_api", "imap", "cloudflare_domain", "remail"}:
        raise ValueError(f"非法邮箱来源: {source}")

    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            if source == "all":
                cur = conn.execute(
                    "DELETE FROM email_pool WHERE email = ? COLLATE NOCASE",
                    (target,),
                )
            else:
                db_source = (
                    _EMAIL_SOURCES["domain"]
                    if source == "cloudflare_domain"
                    else _EMAIL_SOURCES[source]
                )
                cur = conn.execute(
                    "DELETE FROM email_pool "
                    "WHERE email = ? COLLATE NOCASE AND source = ?",
                    (target, db_source),
                )
            conn.commit()
            return cur.rowcount > 0


def delete_outlook(email: str) -> bool:
    """从邮箱池彻底删除一个邮箱（按 email 匹配）。返回是否删到。"""
    return delete_email_pool(email, source="outlook")


def list_outlook_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    return list_email_pool_page(
        source="outlook", status=status, limit=limit, offset=0
    )["items"]


def outlook_pool_summary() -> dict:
    with _LOCK:
        out = _pool_summary_sql("outlook")
        out["total"] = sum(v for k, v in out.items() if k != "total")
        return out


def get_outlook_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_by_email(_load_outlook(), email)
        return _decorate_outlook(row) if row else None


# ============================================================
# generic_api email pool
# ============================================================

def import_generic_api_emails(records: list[dict]) -> tuple[int, int]:
    """
    批量导入通用 API 取码邮箱。
    records 元素：{email, code_url}
    返回 (新增数, 跳过数)。
    """
    with _LOCK:
        rows = _load_generic_api_emails()
        inserted = skipped = 0
        for raw in records:
            email = (raw.get("email") or "").strip()
            code_url = (raw.get("code_url") or raw.get("url") or "").strip()
            if not email or not code_url:
                skipped += 1
                continue
            if _find_by_email(rows, email):
                skipped += 1
                continue
            row = {
                "id": _next_id(rows),
                "email": email,
                "code_url": code_url,
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _generic_api_email_line(row)
            rows.append(row)
            inserted += 1
        _save_generic_api_emails(rows)
        return inserted, skipped


def _is_mailalias_generic_row(row: dict | None) -> bool:
    """MailAlias 复用 generic_api 表存储，但作为独立邮箱来源领取。"""
    url = str((row or {}).get("code_url") or "").strip().lower()
    return "mailalias.lund.asia/api/v1/pickup/" in url


def claim_next_generic_api_email() -> dict | None:
    """原子领取普通通用 API 邮箱；排除独立的 MailAlias 池，且自动跳过已在 accounts 成功注册的邮箱。"""
    with _LOCK:
        registered_emails = {
            str(a.get("email") or "").strip().lower()
            for a in _load_accounts()
            if a.get("email")
        }
        rows = sorted(_load_generic_api_emails(), key=lambda x: int(x.get("id") or 0))
        changed = False
        target_row = None
        for r in rows:
            if not r.get("status") == "available" or _is_mailalias_generic_row(r):
                continue
            r_email = str(r.get("email") or "").strip().lower()
            if r_email in registered_emails:
                r["status"] = "disabled"
                r["note"] = "已在本地数据库注册过，自动跳过"
                r["used_at"] = _now()
                changed = True
                continue
            target_row = r
            break
        if target_row is None:
            if changed:
                _save_generic_api_emails(rows)
            return None
        target_row["status"] = "used"
        target_row["used_at"] = _now()
        target_row["note"] = None
        _save_generic_api_emails(rows)
        return _decorate_generic_api_email(target_row)


def claim_next_mailalias_email() -> dict | None:
    """原子领取一个 MailAlias 邮箱并标记为 used，自动跳过已在 accounts 成功注册的邮箱。"""
    with _LOCK:
        registered_emails = {
            str(a.get("email") or "").strip().lower()
            for a in _load_accounts()
            if a.get("email")
        }
        rows = sorted(_load_generic_api_emails(), key=lambda x: int(x.get("id") or 0))
        changed = False
        target_row = None
        for r in rows:
            if not r.get("status") == "available" or not _is_mailalias_generic_row(r):
                continue
            r_email = str(r.get("email") or "").strip().lower()
            if r_email in registered_emails:
                r["status"] = "disabled"
                r["note"] = "已在本地数据库注册过，自动跳过"
                r["used_at"] = _now()
                changed = True
                continue
            target_row = r
            break
        if target_row is None:
            if changed:
                _save_generic_api_emails(rows)
            return None
        target_row["status"] = "used"
        target_row["used_at"] = _now()
        target_row["note"] = None
        _save_generic_api_emails(rows)
        out = _decorate_generic_api_email(target_row)
        out["source"] = "mailalias"
        return out


def release_generic_api_email(email: str, status: str = "available", note: str | None = None) -> None:
    """把通用 API 邮箱状态改回 available，或标记为 failed/used。"""
    with _LOCK:
        rows = _load_generic_api_emails()
        row = _find_by_email(rows, email)
        if row is None:
            return
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_generic_api_emails(rows)


def release_unconsumed_generic_api_email(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号且仍为 used 的通用 API 邮箱。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        rows = _load_generic_api_emails()
        row = _find_by_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_generic_api_emails(rows)
        return True


# ============================================================
# Remail order pool
# ============================================================

def save_remail_email(record: dict) -> None:
    """Persist a claimed Remail order so it can be reused after a failed registration."""
    email = str(record.get("email") or "").strip()
    if not email:
        raise ValueError("Remail 邮箱地址为空")
    now = _now()
    payload = dict(record)
    payload.update({
        "email": email,
        "source": "remail",
        "status": str(record.get("status") or "used"),
        "updated_at": now,
    })
    payload.setdefault("created_at", now)
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute(
                "SELECT id, created_at FROM email_pool WHERE source='remail' AND email=? COLLATE NOCASE LIMIT 1",
                (email,),
            ).fetchone()
            if row:
                payload["id"] = int(row["id"])
                payload["created_at"] = str(row["created_at"] or payload["created_at"])
                conn.execute(
                    "UPDATE email_pool SET status=?, archived=0, updated_at=?, payload=? WHERE id=?",
                    (payload["status"], now, json.dumps(payload, ensure_ascii=False), payload["id"]),
                )
            else:
                row_id = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM email_pool").fetchone()[0])
                payload["id"] = row_id
                conn.execute(
                    "INSERT INTO email_pool(id,email,source,status,archived,created_at,updated_at,payload) VALUES(?,?,?,?,0,?,?,?)",
                    (row_id, email, "remail", payload["status"], payload["created_at"], now, json.dumps(payload, ensure_ascii=False)),
                )
            conn.commit()


def claim_next_remail_email(project_id: int, email_suffix: str, service_mode: str) -> dict | None:
    """Atomically claim the oldest compatible reusable Remail order."""
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT ep.* FROM email_pool AS ep "
                "WHERE ep.source='remail' AND ep.status='available' AND ep.archived=0 "
                "AND CAST(json_extract(ep.payload, '$.project_id') AS INTEGER)=? "
                "AND lower(json_extract(ep.payload, '$.email_suffix'))=lower(?) "
                "AND lower(json_extract(ep.payload, '$.service_mode'))=lower(?) "
                "AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.email=ep.email COLLATE NOCASE) "
                "ORDER BY ep.id ASC LIMIT 1",
                (int(project_id), str(email_suffix), str(service_mode)),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            payload = json.loads(row["payload"] or "{}")
            payload["status"] = "used"
            payload["used_at"] = _now()
            payload["note"] = None
            payload["updated_at"] = _now()
            conn.execute(
                "UPDATE email_pool SET status='used', updated_at=?, payload=? WHERE id=? AND status='available'",
                (payload["updated_at"], json.dumps(payload, ensure_ascii=False), int(row["id"])),
            )
            conn.commit()
            return payload


def release_remail_email(email: str, status: str = "available", note: str | None = None) -> bool:
    """Update a Remail order state; only unregistered orders may become available."""
    target = str(email or "").strip()
    if not target:
        return False
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            if status == "available" and conn.execute(
                "SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE LIMIT 1", (target,)
            ).fetchone():
                return False
            row = conn.execute(
                "SELECT id,payload FROM email_pool WHERE source='remail' AND email=? COLLATE NOCASE LIMIT 1",
                (target,),
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload"] or "{}")
            # disabled is terminal for Remail orders. A later outer-task timeout
            # must not resurrect an address blacklisted after OTP timeout.
            if status == "available" and str(payload.get("status") or "").lower() == "disabled":
                return False
            payload["status"] = status
            payload["used_at"] = None if status == "available" else (payload.get("used_at") or _now())
            payload["note"] = note
            payload["updated_at"] = _now()
            conn.execute(
                "UPDATE email_pool SET status=?, updated_at=?, payload=? WHERE id=?",
                (status, payload["updated_at"], json.dumps(payload, ensure_ascii=False), int(row["id"])),
            )
            conn.commit()
            return True


def get_remail_email_by_email(email: str) -> dict | None:
    _ensure_sqlite()
    with _LOCK, closing(_sqlite_conn()) as conn:
        row = conn.execute(
            "SELECT payload FROM email_pool WHERE source='remail' AND email=? COLLATE NOCASE LIMIT 1",
            (str(email or "").strip(),),
        ).fetchone()
        return json.loads(row["payload"] or "{}") if row else None


def get_email_pool_item_by_email(email: str, source: str | None = None) -> dict | None:
    """按邮箱查找 email_pool 中的单条记录，不限来源或按指定来源查找。"""
    target = str(email or "").strip()
    if not target:
        return None
    _ensure_sqlite()
    where = ["email=? COLLATE NOCASE"]
    params: list[Any] = [target]
    if source:
        src = _EMAIL_SOURCES.get(source, source)
        where.append("source=?")
        params.append(src)
    with _LOCK, closing(_sqlite_conn()) as conn:
        row = conn.execute(
            f"SELECT payload, source FROM email_pool WHERE {' AND '.join(where)} LIMIT 1",
            params,
        ).fetchone()
        if not row:
            return None
        payload = json.loads(row["payload"] or "{}")
        payload["_pool_source"] = row["source"]
        return payload


def delete_generic_api_email(email: str) -> bool:
    """从通用 API 邮箱池彻底删除一个邮箱。"""
    return delete_email_pool(email, source="generic_api")


def list_generic_api_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    return list_email_pool_page(
        source="generic_api", status=status, limit=limit, offset=0
    )["items"]


def generic_api_email_pool_summary() -> dict:
    """普通通用 API 池统计（排除 MailAlias）。"""
    with _LOCK:
        rows = [r for r in _load_generic_api_emails() if not _is_mailalias_generic_row(r)]
    summary = {"available": 0, "used": 0, "failed": 0, "disabled": 0, "total": len(rows)}
    for row in rows:
        status = str(row.get("status") or "available")
        summary[status] = int(summary.get(status, 0)) + 1
    return summary


def mailalias_email_pool_summary() -> dict:
    """独立 MailAlias 池统计。"""
    with _LOCK:
        rows = [r for r in _load_generic_api_emails() if _is_mailalias_generic_row(r)]
    summary = {"available": 0, "used": 0, "failed": 0, "disabled": 0, "total": len(rows)}
    for row in rows:
        status = str(row.get("status") or "available")
        summary[status] = int(summary.get(status, 0)) + 1
    return summary


def get_generic_api_email_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_by_email(_load_generic_api_emails(), email)
        return _decorate_generic_api_email(row) if row else None


# ============================================================
# Generic IMAP email pool
# ============================================================

def import_imap_emails(records: list[dict]) -> tuple[int, int]:
    """导入 IMAP 邮箱。用户名留空时客户端使用邮箱地址登录。"""
    with _LOCK:
        rows = _load_imap_emails()
        inserted = skipped = 0
        for raw in records:
            email = str(raw.get("email") or "").strip()
            password = str(raw.get("imap_password") or raw.get("password") or "").strip()
            server = str(raw.get("imap_server") or raw.get("server") or "").strip()
            try:
                port = int(raw.get("imap_port") or raw.get("port") or 993)
            except (TypeError, ValueError):
                port = 0
            if not email or not password or not server or not (1 <= port <= 65535) or _find_by_email(rows, email):
                skipped += 1
                continue
            ssl_raw = raw.get("imap_ssl", raw.get("use_ssl", True))
            use_ssl = ssl_raw if isinstance(ssl_raw, bool) else str(ssl_raw).strip().lower() not in {"0", "false", "no", "off"}
            row = {
                "id": _next_id(rows), "email": email,
                "imap_password": password, "imap_server": server, "imap_port": port,
                "imap_username": str(raw.get("imap_username") or raw.get("username") or "").strip(),
                "imap_ssl": bool(use_ssl), "status": "available", "used_at": None,
                "note": None, "imported_at": _now(),
            }
            row["copy_line"] = _imap_email_line(row)
            rows.append(row)
            inserted += 1
        _save_imap_emails(rows)
        return inserted, skipped


def claim_next_imap_email() -> dict | None:
    with _LOCK:
        rows = sorted(_load_imap_emails(), key=lambda x: int(x.get("id") or 0))
        row = next((r for r in rows if r.get("status") == "available"), None)
        if row is None:
            return None
        row["status"], row["used_at"], row["note"] = "used", _now(), None
        _save_imap_emails(rows)
        return _decorate_imap_email(row)


def release_imap_email(email: str, status: str = "available", note: str | None = None) -> None:
    with _LOCK:
        rows = _load_imap_emails()
        row = _find_by_email(rows, email)
        if row is None:
            return
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_imap_emails(rows)


def release_unconsumed_imap_email(email: str, note: str | None = None) -> bool:
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        rows = _load_imap_emails()
        row = _find_by_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"], row["used_at"] = "available", None
        if note is not None:
            row["note"] = note
        _save_imap_emails(rows)
        return True


def delete_imap_email(email: str) -> bool:
    return delete_email_pool(email, source="imap")


def list_imap_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    return list_email_pool_page(source="imap", status=status, limit=limit, offset=0)["items"]


def imap_email_pool_summary() -> dict:
    with _LOCK:
        return _pool_summary_sql("imap")


def get_imap_email_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_by_email(_load_imap_emails(), email)
        return _decorate_imap_email(row) if row else None


# ============================================================
# Codex 授权账号（SQLite codex_accounts 表）
# ============================================================

def _codex_filter_sql(
    archived: str | bool | None = "0",
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
) -> tuple[list[str], list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    if archived in (True, "1", "true", "yes", "only"):
        where.append("archived=1")
    elif archived not in ("all", "include"):
        where.append("archived=0")
    if date_from:
        value = str(date_from)
        where.append("created_at >= ?")
        params.append(value + ("T00:00:00" if len(value) == 10 else ""))
    if date_to:
        value = str(date_to)
        where.append("created_at <= ?")
        params.append(value + ("T23:59:59.999999" if len(value) == 10 else ""))
    if q and str(q).strip():
        where.append("lower(payload) LIKE ?")
        params.append("%" + str(q).strip().lower() + "%")
    return where, params


def _codex_content_to_record(content: dict) -> dict:
    """把 SQLite 中的 Codex payload 转成列表展示对象。"""
    fname = content.get("_filename", "")
    without_prefix = fname[5:-5] if fname.startswith("codex-") and fname.endswith(".json") else fname
    email = content.get("email") or without_prefix
    plan = ""
    if "-" in without_prefix and without_prefix.rsplit("-", 1)[-1].lower() in ("free", "plus", "team", "pro", "enterprise"):
        plan = without_prefix.rsplit("-", 1)[-1].lower()
        if not content.get("email"):
            email = without_prefix.rsplit("-", 1)[0]
    return {
        "filename": fname, "path": f"sqlite://codex_accounts/{fname}", "email": email, "plan": plan,
        "account_id": content.get("account_id", ""), "type": content.get("type", "codex"),
        "last_refresh": content.get("last_refresh", ""), "expired": content.get("expired", ""),
        "access_token_preview": (content.get("access_token", "") or "")[:32],
        "access_token": content.get("access_token", ""),
        "refresh_token": content.get("refresh_token", ""),
        "has_refresh_token": bool(content.get("refresh_token")),
        "refresh_token_preview": (content.get("refresh_token", "") or "")[:24],
        "id_token": content.get("id_token", ""),
        "size": content.get("_size", 0), "mtime": content.get("_mtime", ""),
        "exported_at": content.get("_exported_at"), "exported_count": content.get("_exported_count", 0),
        "archived": bool(content.get("_archived")), "archived_at": content.get("_archived_at"),
    }


def list_codex_accounts_page(
    archived: str | bool | None = "0",
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """直接在 codex_accounts 表执行分页查询，不读取 codex_accounts/ 文件。"""
    _ensure_sqlite()
    limit = max(1, int(limit))
    offset = max(0, int(offset or 0))
    where, params = _codex_filter_sql(archived, date_from, date_to, q)
    clause = " AND ".join(where) if where else "1=1"
    with closing(_sqlite_conn()) as conn:
        total = int(conn.execute(f"SELECT COUNT(*) FROM codex_accounts WHERE {clause}", params).fetchone()[0])
        latest = str(conn.execute(
            f"SELECT COALESCE(MAX(updated_at), '') FROM codex_accounts WHERE {clause}", params
        ).fetchone()[0] or "")
        rows = conn.execute(
            f"SELECT payload FROM codex_accounts WHERE {clause} "
            "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    items = [_codex_content_to_record(json.loads(row["payload"])) for row in rows]
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "revision": f"{total}:{latest}",
    }


def list_codex_accounts(
    archived: str | bool | None = "0",
    date_from: str | None = None,
    date_to: str | None = None,
    q: str | None = None,
) -> list[dict]:
    """从 SQLite 读取 Codex 凭证元数据，不扫描 codex_accounts/ 文件。"""
    _ensure_sqlite()
    where, params = _codex_filter_sql(archived, date_from, date_to, q)
    clause = " AND ".join(where) if where else "1=1"
    with closing(_sqlite_conn()) as conn:
        rows = [json.loads(row["payload"]) for row in conn.execute(
            f"SELECT payload FROM codex_accounts WHERE {clause} ORDER BY created_at DESC, id DESC", params
        )]
    return [_codex_content_to_record(content) for content in rows]


def upsert_codex_credential(content: dict, filename: str) -> str:
    """把 Codex 凭证写入 SQLite，返回逻辑文件名（不创建本地文件）。"""
    if not isinstance(content, dict) or not filename:
        raise ValueError("Codex 凭证或文件名无效")
    _ensure_sqlite()
    now = _now()
    with _LOCK, closing(_sqlite_conn()) as conn:
        old = conn.execute("SELECT payload, created_at FROM codex_accounts WHERE filename=?", (filename,)).fetchone()
        meta = dict(content)
        if old:
            previous = json.loads(old["payload"])
            for key in ("_exported_at", "_exported_count", "_archived", "_archived_at"):
                if key not in meta:
                    meta[key] = previous.get(key)
            created_at = old["created_at"] or now
            account_id = conn.execute("SELECT id FROM codex_accounts WHERE filename=?", (filename,)).fetchone()[0]
        else:
            account_id = int(conn.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM codex_accounts").fetchone()[0])
            created_at = now
        meta.update({"_filename": filename, "_size": len(json.dumps(content, ensure_ascii=False).encode("utf-8")), "_mtime": now})
        conn.execute(
            "INSERT INTO codex_accounts(id,filename,email,archived,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(filename) DO UPDATE SET email=excluded.email, archived=excluded.archived, updated_at=excluded.updated_at, payload=excluded.payload",
            (account_id, filename, str(content.get("email") or ""), int(bool(meta.get("_archived"))), created_at, now, json.dumps(meta, ensure_ascii=False)),
        )
        conn.commit()
    return filename

def archive_codex(filename: str, archived: bool = True) -> dict | None:
    """归档/取消归档一条 Codex 授权凭证。"""
    with _LOCK:
        if not filename.startswith("codex-") or not filename.endswith(".json"):
            raise ValueError(f"非法文件名: {filename}")
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ValueError(f"非法文件名: {filename}")
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute("SELECT payload FROM codex_accounts WHERE filename=?", (filename,)).fetchone()
            if not row:
                return None
            content = json.loads(row["payload"])
            rec = {"exported_at": content.get("_exported_at"), "exported_count": content.get("_exported_count", 0)}
        rec["archived"] = bool(archived)
        rec["archived_at"] = _now() if archived else None
        content.update({"_archived": rec["archived"], "_archived_at": rec["archived_at"]})
        with closing(_sqlite_conn()) as conn:
            conn.execute("UPDATE codex_accounts SET archived=?, updated_at=?, payload=? WHERE filename=?", (int(archived), _now(), json.dumps(content, ensure_ascii=False), filename))
            conn.commit()
        return rec


def read_codex_credential(filename: str) -> tuple[str, str]:
    """
    读取一个 codex-*.json 文件原始内容。
    Returns: (content_string, filename)
    抛 ValueError：文件名不合法（防目录穿越）/ 不存在。
    """
    with _LOCK:
        # 防注入：只允许 codex-*.json 模式，不允许路径分隔符
        if not filename.startswith("codex-") or not filename.endswith(".json"):
            raise ValueError(f"非法文件名: {filename}")
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ValueError(f"非法文件名: {filename}")
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute("SELECT payload FROM codex_accounts WHERE filename=?", (filename,)).fetchone()
        if not row:
            raise ValueError(f"文件不存在: {filename}")
        content = json.loads(row["payload"])
        content = {k: v for k, v in content.items() if not k.startswith("_")}
        return json.dumps(content, ensure_ascii=False, indent=2), filename


def mark_codex_exported(filename: str) -> dict:
    """
    标记某个 codex 凭证已导出（导出计数 +1，记录最近导出时间）。
    Returns: 该 filename 当前的导出状态记录。
    """
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute("SELECT payload FROM codex_accounts WHERE filename=?", (filename,)).fetchone()
            if not row:
                return {"exported_count": 0}
            content = json.loads(row["payload"])
        rec = {"exported_count": int(content.get("_exported_count", 0) or 0)}
        rec["exported_count"] = int(rec.get("exported_count", 0)) + 1
        rec["exported_at"] = _now()
        content.update({"_exported_count": rec["exported_count"], "_exported_at": rec["exported_at"]})
        with closing(_sqlite_conn()) as conn:
            conn.execute("UPDATE codex_accounts SET updated_at=?, payload=? WHERE filename=?", (_now(), json.dumps(content, ensure_ascii=False), filename))
            conn.commit()
        return rec


def reset_codex_exported(filename: str) -> None:
    """清掉某个 codex 凭证的导出状态（用户想重置时用）。"""
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute("SELECT payload FROM codex_accounts WHERE filename=?", (filename,)).fetchone()
            if not row:
                return
            content = json.loads(row["payload"])
            content.update({"_exported_count": 0, "_exported_at": None})
            conn.execute("UPDATE codex_accounts SET updated_at=?, payload=? WHERE filename=?", (_now(), json.dumps(content, ensure_ascii=False), filename))
            conn.commit()


def delete_codex_credential(filename: str) -> bool:
    """从 SQLite 删除一个 Codex 凭证。"""
    with _LOCK:
        if not filename.startswith("codex-") or not filename.endswith(".json"):
            raise ValueError(f"非法文件名: {filename}")
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ValueError(f"非法文件名: {filename}")
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            cur = conn.execute("DELETE FROM codex_accounts WHERE filename=?", (filename,))
            conn.commit()
            return cur.rowcount > 0


def codex_accounts_summary() -> dict:
    """codex 账号汇总：总数 / 已导出 / 未导出。"""
    with _LOCK:
        _ensure_sqlite()
        with closing(_sqlite_conn()) as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN COALESCE(CAST(json_extract(payload, '$._exported_count') AS INTEGER), 0) > 0 "
                "THEN 1 ELSE 0 END) AS exported "
                "FROM codex_accounts WHERE archived=0"
            ).fetchone()
        total = int(row["total"] or 0)
        exported = int(row["exported"] or 0)
        return {
            "total": total,
            "exported": exported,
            "pending": total - exported,
        }


# ============================================================
# registration_jobs
# ============================================================

def _new_job_row(
    rows: list[dict],
    *,
    email_source: str,
    job_type: str = "registration",
    parent_job_id: int | None = None,
    root_job_id: int | None = None,
    retry_attempt: int = 0,
    retry_action: str | None = None,
    email: str | None = None,
    account_id: int | None = None,
) -> dict:
    job_uuid = str(uuid.uuid4())
    log_file = str(_LOG_DIR / f"{job_uuid}.log")
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    return {
        "id": _next_id(rows),
        "job_uuid": job_uuid,
        "job_type": job_type,
        "parent_job_id": parent_job_id,
        "root_job_id": root_job_id,
        "retry_attempt": int(retry_attempt or 0),
        "retry_action": retry_action,
        "email_source": email_source,
        "email": email,
        "status": "pending",
        "error_message": None,
        "log_file": log_file,
        "started_at": None,
        "completed_at": None,
        "account_id": account_id,
        "network_traffic": None,
        "created_at": _now(),
    }


def create_job(email_source: str) -> dict:
    """创建一个首次执行的 pending 注册任务。"""
    with _LOCK:
        rows = _load_jobs()
        row = _new_job_row(rows, email_source=email_source)
        rows.append(row)
        _save_jobs(rows)
        return dict(row)


def create_retry_job(
    source_job_id: int,
    *,
    job_type: str,
    email_source: str,
    email: str | None = None,
    account_id: int | None = None,
) -> tuple[dict, bool]:
    """原子创建重试子任务；同一任务链已有活跃任务时直接复用。"""
    with _LOCK:
        rows = _load_jobs()
        source = next((r for r in rows if int(r.get("id") or 0) == int(source_job_id)), None)
        if source is None:
            raise LookupError("任务不存在")
        if source.get("status") not in ("failed", "stopped", "cancelled"):
            raise ValueError(f"当前状态不支持重试：{source.get('status')}")

        root_id = int(source.get("root_job_id") or source.get("id"))
        active_states = {"pending", "running", "stopping"}
        active = next((
            r for r in rows
            if int(r.get("id") or 0) != int(source_job_id)
            and int(r.get("root_job_id") or 0) == root_id
            and r.get("status") in active_states
        ), None)
        if active is not None:
            if active.get("job_type", "registration") != job_type:
                raise ValueError(f"已有其他类型重试任务 #{active.get('id')} 在排队或运行中")
            return dict(active), False

        attempts = [
            int(r.get("retry_attempt") or 0)
            for r in rows
            if int(r.get("id") or 0) == root_id or int(r.get("root_job_id") or 0) == root_id
        ]
        row = _new_job_row(
            rows,
            email_source=email_source,
            job_type=job_type,
            parent_job_id=int(source_job_id),
            root_job_id=root_id,
            retry_attempt=(max(attempts) if attempts else 0) + 1,
            retry_action=("codex" if job_type == "codex_retry" else "registration"),
            email=email,
            account_id=account_id,
        )
        rows.append(row)
        _save_jobs(rows)
        return dict(row), True


def update_job(
    job_id: int,
    *,
    status: str | None = None,
    email: str | None = None,
    error: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    account_id: int | None = None,
    network_traffic: dict | None = None,
    registration_stage: dict | None = None,
    resume_account_id: int | None = None,
    resume_from: str | None = None,
) -> None:
    with _LOCK:
        rows = _load_jobs()
        row = next((r for r in rows if int(r.get("id") or 0) == int(job_id)), None)
        if row is None:
            return
        if status is not None:
            row["status"] = status
        if email is not None:
            row["email"] = email
        if error is not None:
            row["error_message"] = error
        if started_at is not None:
            row["started_at"] = started_at
        if completed_at is not None:
            row["completed_at"] = completed_at
        if account_id is not None:
            row["account_id"] = account_id
        if network_traffic is not None:
            row["network_traffic"] = dict(network_traffic)
        if registration_stage is not None:
            row["registration_stage"] = dict(registration_stage)
        if resume_account_id is not None:
            row["resume_account_id"] = int(resume_account_id)
        if resume_from is not None:
            row["resume_from"] = str(resume_from)
        _save_jobs(rows)


def cancel_pending_jobs(reason: str = "用户手动取消") -> int:
    """原子取消全部排队任务；一次 SQL 更新，避免逐条重写整张任务表。"""
    _ensure_sqlite()
    now_iso = _now()
    message = str(reason or "用户手动取消")[:500]
    with _LOCK, closing(_sqlite_conn()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE registration_jobs "
                "SET status='cancelled', updated_at=?, "
                "payload=json_set(payload, '$.status', 'cancelled', "
                "'$.completed_at', ?, '$.error_message', ?) "
                "WHERE status='pending'",
                (now_iso, now_iso, message),
            )
            return int(cursor.rowcount)


def cancel_pending_job(job_id: int, reason: str = "用户手动停止/取消排队") -> bool:
    """原子取消一个仍在排队的任务。"""
    _ensure_sqlite()
    now_iso = _now()
    message = str(reason or "用户手动停止/取消排队")[:500]
    with _LOCK, closing(_sqlite_conn()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE registration_jobs "
                "SET status='cancelled', updated_at=?, "
                "payload=json_set(payload, '$.status', 'cancelled', "
                "'$.completed_at', ?, '$.error_message', ?) "
                "WHERE id=? AND status='pending'",
                (now_iso, now_iso, message, int(job_id)),
            )
            return cursor.rowcount == 1


def claim_pending_job(job_id: int) -> bool:
    """仅将仍在排队的任务原子转为运行，防止取消与 worker 启动竞争。"""
    _ensure_sqlite()
    now_iso = _now()
    with _LOCK, closing(_sqlite_conn()) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE registration_jobs "
                "SET status='running', updated_at=?, "
                "payload=json_set(payload, '$.status', 'running', '$.started_at', ?) "
                "WHERE id=? AND status='pending'",
                (now_iso, now_iso, int(job_id)),
            )
            return cursor.rowcount == 1


def list_jobs(limit: int = 100) -> list[dict]:
    with _LOCK:
        return [dict(r) for r in _query_collection("jobs", limit=limit)]


def list_jobs_page(limit: int = 50, offset: int = 0) -> dict:
    """直接使用 registration_jobs 的 SQL LIMIT/OFFSET 返回任务页。"""
    with _LOCK:
        limit = max(1, int(limit))
        offset = max(0, int(offset or 0))
        rows, total, latest = _query_collection_page(
            "jobs", limit=limit, offset=offset
        )
        return {
            "items": rows,
            "total": total,
            "offset": offset,
            "limit": limit,
            "revision": f"{total}:{latest}",
        }


def job_status_counts() -> dict:
    """在 SQLite 中聚合任务状态，避免为统计目的加载全部任务 payload。"""
    _ensure_sqlite()
    with closing(_sqlite_conn()) as conn:
        counts = {
            str(row["status"] or "unknown"): int(row["n"])
            for row in conn.execute(
                "SELECT status, COUNT(*) AS n FROM registration_jobs GROUP BY status"
            )
        }
    counts["active"] = sum(int(counts.get(status, 0) or 0) for status in ("pending", "running", "stopping"))
    return counts


def get_job(job_id: int) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_jobs() if int(r.get("id") or 0) == int(job_id)), None)
        return dict(row) if row else None


def get_successful_retry_for_job(job_id: int) -> dict | None:
    """返回同一任务链中已成功的其他重试任务，用于保留原任务历史状态并阻止重复重试。"""
    with _LOCK:
        rows = _load_jobs()
        source = next((r for r in rows if int(r.get("id") or 0) == int(job_id)), None)
        if source is None:
            return None
        root_id = int(source.get("root_job_id") or source.get("id") or 0)
        matches = [
            r for r in rows
            if int(r.get("id") or 0) != int(job_id)
            and int(r.get("root_job_id") or 0) == root_id
            and r.get("status") == "success"
        ]
        if not matches:
            return None
        return dict(max(matches, key=lambda r: int(r.get("id") or 0)))


def delete_job(job_id: int, *, delete_log: bool = True, allow_running: bool = False) -> bool:
    """
    删除一个注册任务记录；默认同时删除该任务日志文件。返回是否删除到记录。
    默认不删除 running 任务，避免后台线程仍在执行但前端记录消失。
    """
    with _LOCK:
        rows = _load_jobs()
        idx = next((i for i, r in enumerate(rows) if int(r.get("id") or 0) == int(job_id)), None)
        if idx is None:
            return False
        if not allow_running and rows[idx].get("status") in ("running", "stopping"):
            return False
        row = rows.pop(idx)
        _save_jobs(rows)

    if delete_log:
        log_file = row.get("log_file")
        if log_file:
            try:
                Path(log_file).unlink(missing_ok=True)
            except Exception:
                pass
    return True


# ============================================================
# 迁移与路径
# ============================================================

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _migrate_legacy_sqlite() -> dict:
    summary = {"sqlite_accounts_imported": 0, "sqlite_outlook_imported": 0, "sqlite_outlook_skipped": 0}
    if not _LEGACY_SQLITE.exists():
        return summary
    try:
        conn = sqlite3.connect(str(_LEGACY_SQLITE))
        conn.row_factory = sqlite3.Row
        if _table_exists(conn, "outlook_pool"):
            records = []
            statuses = []
            for row in conn.execute("SELECT * FROM outlook_pool").fetchall():
                records.append({
                    "email": row["email"],
                    "password": row["password"],
                    "client_id": row["client_id"],
                    "refresh_token": row["refresh_token"],
                })
                statuses.append({
                    "email": row["email"],
                    "status": row["status"],
                    "note": row["note"],
                })
            ins, skip = import_outlook_accounts(records)
            for item in statuses:
                if item["status"] != "available":
                    release_outlook(item["email"], status=item["status"], note=item["note"])
            summary["sqlite_outlook_imported"] += ins
            summary["sqlite_outlook_skipped"] += skip
        if _table_exists(conn, "registered_accounts"):
            for row in conn.execute("SELECT * FROM registered_accounts").fetchall():
                insert_account(
                    email=row["email"],
                    access_token=row["access_token"],
                    totp_secret=row["totp_secret"],
                    user_id=row["user_id"],
                    user_name=row["user_name"],
                    plan_type=row["plan_type"],
                    expires_at=row["expires_at"],
                    proxy_used=row["proxy_used"],
                    email_source=row["email_source"],
                    extra=json.loads(row["extra_json"]) if row["extra_json"] else None,
                )
                summary["sqlite_accounts_imported"] += 1
        conn.close()
    except Exception as exc:
        summary["sqlite_error"] = f"{type(exc).__name__}: {exc}"
    return summary


def migrate_legacy_files() -> dict:
    """
    把历史 SQLite、accounts/*.json、旧邮箱 TXT/JSON 迁移到当前 SQLite 存储。
    多次调用是幂等的，不会生成或更新旧 JSON/TXT 文件。
    """
    summary = {
        "accounts_imported": 0,
        "outlook_imported": 0,
        "outlook_skipped": 0,
    }
    summary.update(_migrate_legacy_sqlite())

    accounts_dir = _PROJECT_ROOT / "accounts"
    if accounts_dir.exists():
        for jf in accounts_dir.glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                if not data.get("email") or not data.get("access_token"):
                    continue
                extra = data.get("extra") or {}
                user = extra.get("user") or {}
                account = extra.get("account") or {}
                insert_account(
                    email=data["email"],
                    access_token=data["access_token"],
                    totp_secret=data.get("totp_secret"),
                    user_id=user.get("id"),
                    user_name=user.get("name"),
                    plan_type=account.get("planType"),
                    expires_at=extra.get("expires"),
                    extra=extra,
                )
                summary["accounts_imported"] += 1
            except Exception:
                continue

    for txt in (_PROJECT_ROOT / "outlook_accounts.txt", _OUTLOOK_TXT):
        if txt.exists():
            records = []
            for line in txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("----")
                # 支持 4 段或 6 段格式
                if len(parts) == 4:
                    email, password, client_id, refresh_token = (p.strip() for p in parts)
                elif len(parts) == 6:
                    email, password, client_id, refresh_token, _, _ = (p.strip() for p in parts)
                else:
                    continue
                records.append({
                    "email": email,
                    "password": password,
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                })
            ins, skip = import_outlook_accounts(records)
            summary["outlook_imported"] += ins
            summary["outlook_skipped"] += skip

    used = _PROJECT_ROOT / "outlook_accounts_used.json"
    if used.exists():
        try:
            emails = json.loads(used.read_text(encoding="utf-8"))
            for email in emails:
                release_outlook(email, status="used")
        except Exception:
            pass

    return summary


def db_path() -> Path:
    """返回 SQLite 主数据库路径（保留函数名兼容旧调用方）。"""
    _ensure_sqlite()
    return _active_sqlite_path()


def storage_paths() -> dict:
    return {
        "sqlite": str(_SQLITE_PATH),
        "logs_dir": str(_LOG_DIR),
    }


# ============================================================
# Domain email pool（Cloudflare 域名邮箱跟踪）
# ============================================================

_DOMAIN_EMAIL_JSON = _PROJECT_ROOT / "用于注册的域名邮箱.json"


def _load_domain_pool() -> list[dict]:
    return _load_collection("domain")


def _save_domain_pool(rows: list[dict]) -> None:
    _save_collection("domain", rows)


def _find_domain_email(rows: list[dict], email: str) -> dict | None:
    target = (email or "").lower()
    return next((r for r in rows if (r.get("email") or "").lower() == target), None)


def claim_next_domain_email(email: str) -> dict:
    """记录一个新的域名邮箱地址到池中（标记为 available）。"""
    with _LOCK:
        rows = _load_domain_pool()
        if _find_domain_email(rows, email):
            # 已存在，直接返回
            row = _find_domain_email(rows, email)
            return row
        row = {
            "id": _next_id(rows),
            "email": email,
            "status": "available",
            "used_at": None,
            "note": None,
            "created_at": _now(),
        }
        rows.append(row)
        _save_domain_pool(rows)
        return dict(row)


def release_domain_email(email: str, status: str = "available", note: str | None = None) -> None:
    """更新域名邮箱状态。"""
    with _LOCK:
        rows = _load_domain_pool()
        row = _find_domain_email(rows, email)
        if row is None:
            return
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_domain_pool(rows)


def release_unconsumed_domain_email(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号且仍为 used 的域名邮箱。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        rows = _load_domain_pool()
        row = _find_domain_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_domain_pool(rows)
        return True


def get_domain_email_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_domain_email(_load_domain_pool(), email)
        return dict(row) if row else None


def list_domain_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    return list_email_pool_page(
        source="cloudflare_domain", status=status, limit=limit, offset=0
    )["items"]


def domain_email_pool_summary() -> dict:
    with _LOCK:
        return _pool_summary_sql("domain")


def delete_domain_email(email: str) -> bool:
    """从域名邮箱池删除一个邮箱。"""
    return delete_email_pool(email, source="cloudflare_domain")


# Upstream-compatible inspection record storage; does not launch account checks.
def _inspection_conn():
    _ensure_sqlite()
    return _sqlite_conn()


def _inspection_payload(run):
    return json.dumps({k: v for k, v in run.items() if k != "account_ids"}, ensure_ascii=False)


def create_account_inspection(account_ids: list[int] | None = None, workers: int = 3, archived: str = "0") -> tuple[dict, bool]:
    if account_ids is not None:
        account_ids = list(dict.fromkeys(int(account_id) for account_id in account_ids))
    with closing(_inspection_conn()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute("SELECT payload FROM account_inspections WHERE status IN ('queued','running')").fetchone()
        if active:
            existing = json.loads(active[0])
            snapshot = conn.execute("SELECT account_ids FROM account_inspection_snapshots WHERE inspection_id=?",
                                    (existing["id"],)).fetchone()
            existing["account_ids"] = json.loads(snapshot[0]) if snapshot else []
            return existing, False
        if account_ids is None:
            # 与任务占用处于同一事务中，避免 OFFSET 分页遇到新增/归档/删除时漏账号。
            sql = "SELECT id FROM accounts"
            params = ()
            if archived != "all":
                sql += " WHERE archived=?"
                params = (int(archived == "only"),)
            account_ids = [row[0] for row in conn.execute(sql + " ORDER BY id DESC", params)]
        run = dict(status="queued", workers=workers, archived=archived, created_at=_now(), finished_at=None,
                   total_count=len(account_ids), checked_count=0, skipped_count=0, deactivated_skipped_count=0, invalid_count=0,
                   live_success_count=0, live_failed_count=0,
                   plan_success_count=0, plan_failed_count=0, error="",
                   failure_details_available=True, account_ids=account_ids)
        cursor = conn.execute("INSERT INTO account_inspections(status,payload) VALUES (?,?)", (run["status"], _inspection_payload(run)))
        run["id"] = cursor.lastrowid
        conn.execute("UPDATE account_inspections SET payload=? WHERE id=?", (_inspection_payload(run), run["id"]))
        conn.execute("INSERT INTO account_inspection_snapshots(inspection_id,account_ids) VALUES (?,?)",
                     (run["id"], json.dumps(account_ids)))
        return run, True


def save_account_inspection(run: dict, *, failure: dict | None = None) -> bool:
    # 终态不可覆盖，防止旧线程把已中断任务重新写为 running 或冲突新任务唯一索引。
    with closing(_inspection_conn()) as conn, conn:
        cursor = conn.execute("""UPDATE account_inspections SET status=?,payload=?
                                 WHERE id=? AND status IN ('queued', 'running')""",
                              (run["status"], _inspection_payload(run), run["id"]))
        saved = cursor.rowcount == 1
        if saved and failure is not None:
            # 统计和明细同事务保存；终态/旧 worker 不能补写历史或留下孤立明细。
            conn.execute("""INSERT INTO account_inspection_failures
                (inspection_id,account_id,email,status,error,failed_at) VALUES (?,?,?,?,?,?)
                ON CONFLICT(inspection_id,account_id) DO NOTHING""",
                (run["id"], int(failure["account_id"]), str(failure.get("email") or "")[:320],
                 str(failure.get("status") or "failed")[:40],
                 str(failure.get("error") or "查活失败，未返回具体原因")[:2000],
                 str(failure.get("failed_at") or _now())))
        return saved


def list_account_inspection_failures(inspection_id: int, limit: int = 20, offset: int = 0) -> dict | None:
    with closing(_inspection_conn()) as conn:
        conn.execute("BEGIN")
        task = conn.execute("SELECT payload FROM account_inspections WHERE id=?", (inspection_id,)).fetchone()
        if task is None:
            return None
        run = json.loads(task[0])
        items = conn.execute("""SELECT account_id,email,status,error,failed_at
            FROM account_inspection_failures WHERE inspection_id=? ORDER BY account_id LIMIT ? OFFSET ?""",
            (inspection_id, limit, offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM account_inspection_failures WHERE inspection_id=?",
                             (inspection_id,)).fetchone()[0]
    return dict(task={k: v for k, v in run.items() if k != "account_ids"},
                items=[dict(row) for row in items], total=total,
                details_available=bool(run.get("failure_details_available")), limit=limit, offset=offset)


def list_account_inspections(limit: int = 50, offset: int = 0) -> dict:
    with closing(_inspection_conn()) as conn:
        conn.execute("BEGIN")  # items、active、total 使用同一读快照。
        rows = conn.execute("SELECT payload FROM account_inspections ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        active = conn.execute("SELECT payload FROM account_inspections WHERE status IN ('queued','running')").fetchone()
        total = conn.execute("SELECT COUNT(*) FROM account_inspections").fetchone()[0]
    def public(payload):
        return {k: v for k, v in json.loads(payload).items() if k != "account_ids"}
    return dict(items=[public(r[0]) for r in rows], total=total,
                active=public(active[0]) if active else None)


