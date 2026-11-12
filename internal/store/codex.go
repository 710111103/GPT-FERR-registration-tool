package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CodexAccount struct {
	ID        int64          `json:"id"`
	Filename  string         `json:"filename"`
	Email     string         `json:"email"`
	Archived  bool           `json:"archived"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// InsertCodexAccount 插入或按 filename 更新 Codex 授权凭据。
//
// 对齐上游 core/db.py:upsert_codex_credential (L2948-2974)：更新已有记录时，
// 若新 payload 没带内部字段，则从旧 payload 继承 _exported_at / _exported_count /
// _archived / _archived_at。否则每次重刷凭证都会把导出计数和归档位清成 0，
// 前端「已导出/待导出」统计与归档列表会全部错乱。
func (s *Store) InsertCodexAccount(ctx context.Context, acc CodexAccount) (int64, error) {
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	var id int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()

		var (
			oldPayload string
			oldArch    int
			oldCreated string
		)
		row := tx.QueryRowContext(ctx,
			`SELECT payload, archived, created_at FROM codex_accounts WHERE filename=?`, acc.Filename)
		switch qerr := row.Scan(&oldPayload, &oldArch, &oldCreated); qerr {
		case nil:
			prev := parseJSON(oldPayload)
			for _, key := range []string{"_exported_at", "_exported_count", "_archived", "_archived_at"} {
				if _, exists := acc.Payload[key]; !exists {
					acc.Payload[key] = prev[key]
				}
			}
			if oldArch != 0 {
				acc.Archived = true
			}
			if oldCreated != "" {
				ts = oldCreated
			}
		case sql.ErrNoRows:
			// 新记录：保留调用方传入的 created_at/archived
		}

		if _, has := acc.Payload["_exported_count"]; !has {
			acc.Payload["_exported_count"] = 0
		}
		acc.Payload["_size"] = len(mustJSON(acc.Payload))
		acc.Payload["_mtime"] = now()

		res, err := tx.ExecContext(ctx,
			`INSERT INTO codex_accounts(filename, email, archived, created_at, updated_at, payload)
			 VALUES(?, ?, ?, ?, ?, ?)
			 ON CONFLICT(filename) DO UPDATE SET email=excluded.email, archived=excluded.archived,
			     updated_at=excluded.updated_at, payload=excluded.payload`,
			acc.Filename, acc.Email, boolInt(acc.Archived), ts, now(), mustJSON(acc.Payload))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// ListCodexAccounts 分页列出 Codex 授权账号。
func (s *Store) ListCodexAccounts(ctx context.Context, page, pageSize int, query string) ([]CodexAccount, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}
	var (
		items []CodexAccount
		total int64
	)
	err := s.Read(ctx, func(db *sql.DB) error {
		where := " WHERE archived=0"
		args := []any{}
		if query != "" {
			where += " AND email LIKE ? COLLATE NOCASE"
			args = append(args, "%"+query+"%")
		}
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM codex_accounts"+where, args...).Scan(&total); err != nil {
			return err
		}
		q := "SELECT id, filename, email, archived, created_at, updated_at, payload FROM codex_accounts" +
			where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		rows, err := db.QueryContext(ctx, q, append(args, pageSize, (page-1)*pageSize)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c       CodexAccount
				arch    int
				created string
				updated string
				payload string
			)
			if err := rows.Scan(&c.ID, &c.Filename, &c.Email, &arch, &created, &updated, &payload); err != nil {
				return err
			}
			c.Archived = arch != 0
			c.CreatedAt = parseTime(created)
			c.UpdatedAt = parseTime(updated)
			c.Payload = parseJSON(payload)
			items = append(items, c)
		}
		return rows.Err()
	})
	return items, total, err
}

// ---------------------------------------------------------------------------
// Codex 凭证读写（对齐上游 core/db.py 的 read/export/archive/delete/summary）
// ---------------------------------------------------------------------------

// validateCodexFilename 只允许 codex-*.json，拒绝路径穿越。
func validateCodexFilename(filename string) error {
	if !strings.HasPrefix(filename, "codex-") || !strings.HasSuffix(filename, ".json") {
		return fmt.Errorf("非法文件名: %s", filename)
	}
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		return fmt.Errorf("非法文件名: %s", filename)
	}
	return nil
}

// GetCodexAccount 按 filename 读取一条记录。
func (s *Store) GetCodexAccount(ctx context.Context, filename string) (*CodexAccount, error) {
	if err := validateCodexFilename(filename); err != nil {
		return nil, err
	}
	var out *CodexAccount
	err := s.Read(ctx, func(db *sql.DB) error {
		var (
			c       CodexAccount
			arch    int
			created string
			updated string
			payload string
		)
		err := db.QueryRowContext(ctx,
			"SELECT id, filename, email, archived, created_at, updated_at, payload FROM codex_accounts WHERE filename=?",
			filename).Scan(&c.ID, &c.Filename, &c.Email, &arch, &created, &updated, &payload)
		if err != nil {
			return err
		}
		c.Archived = arch != 0
		c.CreatedAt = parseTime(created)
		c.UpdatedAt = parseTime(updated)
		c.Payload = parseJSON(payload)
		out = &c
		return nil
	})
	return out, err
}

// ReadCodexCredential 返回去掉 _ 前缀内部字段后的 JSON 文本（缩进 2 空格）。
func (s *Store) ReadCodexCredential(ctx context.Context, filename string) (string, error) {
	acc, err := s.GetCodexAccount(ctx, filename)
	if err != nil {
		return "", err
	}
	if acc == nil {
		return "", fmt.Errorf("文件不存在: %s", filename)
	}
	clean := make(map[string]any, len(acc.Payload))
	for k, v := range acc.Payload {
		if strings.HasPrefix(k, "_") {
			continue
		}
		clean[k] = v
	}
	data, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// updateCodexPayload 读改写某条记录的 payload。
func (s *Store) updateCodexPayload(ctx context.Context, filename string, fn func(map[string]any)) (map[string]any, error) {
	acc, err := s.GetCodexAccount(ctx, filename)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, fmt.Errorf("文件不存在: %s", filename)
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	fn(acc.Payload)
	err = s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE codex_accounts SET updated_at=?, archived=?, payload=? WHERE filename=?",
			now(), boolInt(acc.Archived), mustJSON(acc.Payload), filename)
		return err
	})
	return acc.Payload, err
}

// MarkCodexExported 导出计数 +1 并记录时间。
func (s *Store) MarkCodexExported(ctx context.Context, filename string) (int, string, error) {
	var count int
	var at string
	_, err := s.updateCodexPayload(ctx, filename, func(p map[string]any) {
		prev := 0
		switch v := p["_exported_count"].(type) {
		case float64:
			prev = int(v)
		case int:
			prev = v
		case int64:
			prev = int(v)
		}
		count = prev + 1
		at = now()
		p["_exported_count"] = count
		p["_exported_at"] = at
		p["_size"] = len(mustJSON(p))
		p["_mtime"] = at
	})
	return count, at, err
}

// ResetCodexExported 清空导出标记。
func (s *Store) ResetCodexExported(ctx context.Context, filename string) error {
	_, err := s.updateCodexPayload(ctx, filename, func(p map[string]any) {
		p["_exported_count"] = 0
		p["_exported_at"] = nil
	})
	return err
}

// ArchiveCodex 归档/恢复。
func (s *Store) ArchiveCodex(ctx context.Context, filename string, archived bool) (bool, string, error) {
	var at string
	acc, err := s.GetCodexAccount(ctx, filename)
	if err != nil {
		return false, "", err
	}
	if acc == nil {
		return false, "", fmt.Errorf("文件不存在: %s", filename)
	}
	if archived {
		at = now()
	}
	acc.Archived = archived
	// 关键：必须同步写 archived 列，否则 ListCodexAccountsFiltered 的 SQL 过滤永远命中不到。
	err = s.Write(ctx, func(tx *sql.Tx) error {
		if _, uerr := tx.ExecContext(ctx, "UPDATE codex_accounts SET archived=?, updated_at=? WHERE filename=?",
			boolInt(archived), now(), filename); uerr != nil {
			return uerr
		}
		return nil
	})
	if err != nil {
		return archived, at, err
	}
	_, err = s.updateCodexPayload(ctx, filename, func(p map[string]any) {
		p["_archived"] = archived
		if archived {
			p["_archived_at"] = at
		} else {
			p["_archived_at"] = nil
		}
	})
	return archived, at, err
}

// DeleteCodex 删除一条凭证。
func (s *Store) DeleteCodex(ctx context.Context, filename string) (bool, error) {
	if err := validateCodexFilename(filename); err != nil {
		return false, err
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM codex_accounts WHERE filename=?", filename)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected > 0, err
}

// CodexSummary 汇总未归档凭证的总数与已导出数。
func (s *Store) CodexSummary(ctx context.Context) (total, exported, pending int, err error) {
	err = s.Read(ctx, func(db *sql.DB) error {
		rows, qerr := db.QueryContext(ctx, "SELECT payload FROM codex_accounts WHERE archived=0")
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var raw string
			if serr := rows.Scan(&raw); serr != nil {
				return serr
			}
			total++
			p := parseJSON(raw)
			cnt := 0
			switch v := p["_exported_count"].(type) {
			case float64:
				cnt = int(v)
			case int:
				cnt = v
			}
			if cnt > 0 {
				exported++
			}
		}
		return rows.Err()
	})
	pending = total - exported
	return
}

// CodexFilter 分页筛选参数。
type CodexFilter struct {
	Archived string // "" / "0" / "1" / "only" / "all"
	DateFrom string
	DateTo   string
	Query    string
	Page     int
	PageSize int
}

// ListCodexAccountsFiltered 支持 archived / 日期 / 关键字 的分页查询。
func (s *Store) ListCodexAccountsFiltered(ctx context.Context, f CodexFilter) ([]CodexAccount, int, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 500 {
		f.PageSize = 50
	}
	where := " WHERE 1=1"
	args := []any{}
	switch f.Archived {
	case "all", "include":
	case "1", "only", "true", "yes":
		where += " AND archived=1"
	default:
		where += " AND archived=0"
	}
	if f.DateFrom != "" {
		where += " AND created_at >= ?"
		val := f.DateFrom
		if len(val) == 10 {
			val += "T00:00:00"
		}
		args = append(args, val)
	}
	if f.DateTo != "" {
		where += " AND created_at <= ?"
		val := f.DateTo
		if len(val) == 10 {
			val += "T23:59:59"
		}
		args = append(args, val)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		where += " AND (lower(email) LIKE ? OR lower(filename) LIKE ? OR lower(payload) LIKE ?)"
		like := "%" + strings.ToLower(q) + "%"
		args = append(args, like, like, like)
	}

	var (
		items []CodexAccount
		total int
	)
	err := s.Read(ctx, func(db *sql.DB) error {
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM codex_accounts"+where, args...).Scan(&total); err != nil {
			return err
		}
		q := "SELECT id, filename, email, archived, created_at, updated_at, payload FROM codex_accounts" +
			where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
		rows, err := db.QueryContext(ctx, q, append(args, f.PageSize, (f.Page-1)*f.PageSize)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c       CodexAccount
				arch    int
				created string
				updated string
				payload string
			)
			if err := rows.Scan(&c.ID, &c.Filename, &c.Email, &arch, &created, &updated, &payload); err != nil {
				return err
			}
			c.Archived = arch != 0
			c.CreatedAt = parseTime(created)
			c.UpdatedAt = parseTime(updated)
			c.Payload = parseJSON(payload)
			items = append(items, c)
		}
		return rows.Err()
	})
	return items, total, err
}

// CodexAgentCredential 取某个账号已生成的 Codex Agent Token 文本与文件名。
func (s *Store) CodexAgentCredential(ctx context.Context, accountID int64) (string, string, error) {
	acc, err := s.GetAccount(ctx, accountID)
	if err != nil {
		return "", "", err
	}
	if acc == nil {
		return "", "", fmt.Errorf("账号不存在")
	}
	if acc.Payload != nil {
		if tok, ok := acc.Payload["codex_agent_token"].(string); ok && strings.TrimSpace(tok) != "" {
			safe := strings.ReplaceAll(strings.ReplaceAll(acc.Email, "/", "_"), "\\", "_")
			return tok, "codex-agent-" + safe + ".json", nil
		}
	}
	// 回退到 codex_agent_accounts 表
	var (
		content string
		fname   string
	)
	err = s.Read(ctx, func(db *sql.DB) error {
		return db.QueryRowContext(ctx,
			"SELECT filename, payload FROM codex_agent_accounts WHERE account_id=?",
			accountID).Scan(&fname, &content)
	})
	if err != nil {
		return "", "", fmt.Errorf("该账号还没有生成 Agent Token")
	}
	if !strings.HasPrefix(strings.TrimSpace(content), "{") {
		p := parseJSON(content)
		if raw, ok := p["content"].(string); ok && raw != "" {
			content = raw
		} else {
			b, _ := json.MarshalIndent(p, "", "  ")
			content = string(b)
		}
	}
	if strings.TrimSpace(fname) == "" {
		safe := strings.ReplaceAll(strings.ReplaceAll(acc.Email, "/", "_"), "\\", "_")
		fname = "codex-agent-" + safe + ".json"
	}
	return content, fname, nil
}
