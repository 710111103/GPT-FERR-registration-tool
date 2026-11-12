package store

import (
	"database/sql"
	"fmt"
)

// schemaVersion 记录当前迁移版本，写在 storage_meta 表里。
const schemaVersion = 4

// migrate 建表、建索引，并执行版本迁移。
func (s *Store) migrate() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return fmt.Errorf("设置 WAL 失败: %w", err)
	}
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("建表失败: %w", err)
	}
	return s.applyMigrations()
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    archived    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS email_pool (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    archived    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS registration_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL DEFAULT '',
    email_source TEXT NOT NULL DEFAULT '',
    batch_id    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    error       TEXT NOT NULL DEFAULT '',
    log_file    TEXT NOT NULL DEFAULT '',
    account_id  INTEGER,
    payload     TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS codex_accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL DEFAULT '',
    archived    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS codex_agent_accounts (
    account_id  INTEGER PRIMARY KEY,
    email       TEXT NOT NULL DEFAULT '',
    filename    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS storage_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_accounts_status      ON accounts(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_archived    ON accounts(archived, id DESC);
CREATE INDEX IF NOT EXISTS idx_accounts_email       ON accounts(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_accounts_created     ON accounts(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_email_pool_status    ON email_pool(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_email_pool_source    ON email_pool(source, status, id DESC);
CREATE INDEX IF NOT EXISTS idx_email_pool_email     ON email_pool(email COLLATE NOCASE);

CREATE INDEX IF NOT EXISTS idx_jobs_status          ON registration_jobs(status, id DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_created         ON registration_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_codex_archived       ON codex_accounts(archived, id DESC);
CREATE INDEX IF NOT EXISTS idx_codex_email          ON codex_accounts(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_codex_created        ON codex_accounts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_codex_agent_email    ON codex_agent_accounts(email COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS account_inspections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT NOT NULL DEFAULT 'queued',
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_account_inspection
    ON account_inspections ((1)) WHERE status IN ('queued','running');

CREATE TABLE IF NOT EXISTS account_inspection_snapshots (
    inspection_id INTEGER PRIMARY KEY,
    account_ids   TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS account_inspection_failures (
    inspection_id INTEGER NOT NULL,
    account_id    INTEGER NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    failed_at     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (inspection_id, account_id)
);
`

// applyMigrations 读取 storage_meta.schema_version 并逐版本升级。
func (s *Store) applyMigrations() error {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM storage_meta WHERE key='schema_version'`).Scan(&raw)
	if err == sql.ErrNoRows {
		if _, err = s.db.Exec(`INSERT INTO storage_meta(key, value) VALUES('schema_version', ?)`, fmt.Sprint(schemaVersion)); err != nil {
			return err
		}
		return s.ensureJobBatchSchema()
	}
	if err != nil {
		return fmt.Errorf("读取 schema_version 失败: %w", err)
	}
	var cur int
	if _, scanErr := fmt.Sscan(raw, &cur); scanErr != nil || cur < 1 {
		cur = 1
	}
	// v1 -> v2: status 列曾经只在 InsertAccount 里写，其它写路径只动 payload，
	// 造成「列=registered / payload=dead」。v2 起 InsertAccount 双写，
	// 这里把历史错位一次性回填。
	if cur < 2 {
		if err := s.backfillAccountStatus(); err != nil {
			return err
		}
		if _, err := s.db.Exec(`UPDATE storage_meta SET value=? WHERE key='schema_version'`, "2"); err != nil {
			return err
		}
	}
	// v2 -> v3: 新增巡检记录三张表（account_inspections /
	// account_inspection_snapshots / account_inspection_failures）。
	// 表结构本身由 schemaSQL 的 CREATE TABLE IF NOT EXISTS 建好，这里只推进版本号。
	if cur < 3 {
		if _, err := s.db.Exec(`UPDATE storage_meta SET value=? WHERE key='schema_version'`, "3"); err != nil {
			return err
		}
	}
	// v3 -> v4: 注册任务增加持久化批次 ID，用于按批次统计促销探测结果。
	if cur < 4 {
		if err := s.ensureJobBatchSchema(); err != nil {
			return err
		}
		if _, err := s.db.Exec(`UPDATE storage_meta SET value=? WHERE key='schema_version'`, "4"); err != nil {
			return err
		}
	}
	return nil
}

// ensureJobBatchSchema 兼容旧库：仅当列不存在时 ALTER，随后建立批次查询索引。
func (s *Store) ensureJobBatchSchema() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('registration_jobs') WHERE name='batch_id'`).Scan(&count); err != nil {
		return fmt.Errorf("检查 registration_jobs.batch_id 失败: %w", err)
	}
	if count == 0 {
		if _, err := s.db.Exec(`ALTER TABLE registration_jobs ADD COLUMN batch_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("增加 registration_jobs.batch_id 失败: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_jobs_batch_status ON registration_jobs(batch_id, status, id DESC)`); err != nil {
		return fmt.Errorf("创建任务批次索引失败: %w", err)
	}
	return nil
}

// backfillAccountStatus 把 accounts.status 列回填成 payload.status。
func (s *Store) backfillAccountStatus() error {
	_, err := s.db.Exec(`
UPDATE accounts
SET status = COALESCE(NULLIF(CAST(json_extract(payload, '$.status') AS TEXT), ''), status)
WHERE json_extract(payload, '$.status') IS NOT NULL
  AND COALESCE(CAST(json_extract(payload, '$.status') AS TEXT), '') <> COALESCE(status, '')`)
	if err != nil {
		return fmt.Errorf("回填 accounts.status 失败: %w", err)
	}
	return nil
}
