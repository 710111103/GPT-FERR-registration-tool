package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// EmailItem 邮箱池中的一条记录。
type EmailItem struct {
	ID        int64          `json:"id"`
	Email     string         `json:"email"`
	Source    string         `json:"source"`
	Status    string         `json:"status"` // available / used / failed / disabled
	Archived  bool           `json:"archived"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// ImportEmails 批量导入邮箱，跳过已存在（同 email + source）的记录。
// 返回新增条数与跳过条数。
func (s *Store) ImportEmails(ctx context.Context, items []EmailItem) (added, skipped int, err error) {
	if len(items) == 0 {
		return 0, 0, nil
	}
	err = s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO email_pool(email, source, status, archived, created_at, updated_at, payload)
			 SELECT ?, ?, ?, 0, ?, ?, ?
			 WHERE NOT EXISTS (SELECT 1 FROM email_pool WHERE email=? COLLATE NOCASE AND source=?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, it := range items {
			status := it.Status
			if status == "" {
				status = "available"
			}
			res, err := stmt.ExecContext(ctx,
				it.Email, it.Source, status, ts, ts, mustJSON(it.Payload), it.Email, it.Source)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				added++
			} else {
				skipped++
			}
		}
		return nil
	})
	return added, skipped, err
}

// ClaimEmail 原子地领取一个可用邮箱，并标记为 used。
// 这是并发注册时的关键临界区：用 UPDATE ... RETURNING 保证同一邮箱不会被两个任务拿走。
func (s *Store) ClaimEmail(ctx context.Context, source string) (*EmailItem, error) {
	var out *EmailItem
	err := s.Write(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`UPDATE email_pool SET status='used', updated_at=?
			 WHERE id = (
			     SELECT id FROM email_pool
			     WHERE source=? AND status='available' AND archived=0
			       AND (
			           json_type(payload, '$.cooldown_until') IS NULL
			           OR COALESCE(CAST(json_extract(payload, '$.cooldown_until') AS TEXT), '') <= ?
			       )
			     ORDER BY id ASC LIMIT 1
			 )
			 RETURNING id, email, source, status, archived, created_at, updated_at, payload`,
			now(), source, now())
		it, err := scanEmail(row)
		if err == sql.ErrNoRows {
			return nil // 该来源已无可用邮箱
		}
		if err != nil {
			return err
		}
		out = it
		return nil
	})
	return out, err
}

// ReleaseEmail 把邮箱放回可用池（注册失败、未实际消费时使用）。
func (s *Store) ReleaseEmail(ctx context.Context, email string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE email_pool SET status='available', updated_at=?
			 WHERE email=? COLLATE NOCASE
			 AND NOT EXISTS (SELECT 1 FROM accounts WHERE email=email_pool.email COLLATE NOCASE)`,
			now(), email)
		return err
	})
}

// ReleaseEmailWithCooldown returns an uncommitted mailbox to the pool, but
// keeps it ineligible for ClaimEmail until the cooldown expires. This prevents
// an unrelated task in the same batch from immediately reusing an email after
// the user stops the task that had claimed it.
func (s *Store) ReleaseEmailWithCooldown(ctx context.Context, email string, cooldown time.Duration) error {
	ts := time.Now()
	until := ts.Add(cooldown).Format("2006-01-02T15:04:05")
	patch := mustJSON(map[string]any{
		"cooldown_until":    until,
		"last_cancelled_at": ts.Format("2006-01-02T15:04:05"),
	})
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE email_pool
			 SET status='available', updated_at=?, payload=json_patch(COALESCE(NULLIF(payload,''),'{}'), ?)
			 WHERE email=? COLLATE NOCASE
			 AND NOT EXISTS (SELECT 1 FROM accounts WHERE email=email_pool.email COLLATE NOCASE)`,
			ts.Format("2006-01-02T15:04:05"), patch, email)
		return err
	})
}

// RecordEmailFailure 记录一次失败：连续失败达到 maxFailures 次即标 failed 并返回 true，
// 否则放回 available 并返回 false，供调度层重试。reason=otp_rejected 时立即标 failed；
// 已存在于 accounts 的邮箱始终保留 used，绝不因一次失败重新进入领取池。
func (s *Store) RecordEmailFailure(ctx context.Context, email, source, reason string, maxFailures int) (bool, error) {
	reached := false
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx,
			`SELECT payload FROM email_pool WHERE email=? COLLATE NOCASE AND source=?`,
			email, source).Scan(&raw); err != nil {
			return err
		}
		payload := parseJSON(raw)
		failCount := 0
		switch v := payload["fail_count"].(type) {
		case float64:
			failCount = int(v)
		case int:
			failCount = v
		}
		failCount++
		payload["fail_count"] = failCount
		payload["last_failure_reason"] = reason
		payload["last_failure_at"] = now()

		status := "available"
		if reason == "otp_rejected" || (maxFailures > 0 && failCount >= maxFailures) {
			status = "failed"
			reached = true
		}
		var accountExists int
		accountErr := tx.QueryRowContext(ctx,
			`SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE LIMIT 1`, email).Scan(&accountExists)
		if accountErr != nil && accountErr != sql.ErrNoRows {
			return accountErr
		}
		if accountExists == 1 {
			status = "used"
			reached = true
		}
		_, err := tx.ExecContext(ctx,
			`UPDATE email_pool SET status=?, payload=?, updated_at=? WHERE email=? COLLATE NOCASE AND source=?`,
			status, mustJSON(payload), now(), email, source)
		return err
	})
	return reached, err
}

// RecoverUnconsumedEmails 把状态为 used 但实际上并未成功注册（不在 accounts 表中）的邮箱自动恢复为 available。
func (s *Store) RecoverUnconsumedEmails(ctx context.Context) (int64, error) {
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE email_pool SET status='available', updated_at=?
			 WHERE status='used'
			 AND NOT EXISTS (SELECT 1 FROM accounts WHERE email=email_pool.email COLLATE NOCASE)`,
			now())
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// UpdateEmailPoolStatus 按邮箱地址与来源修改状态。
func (s *Store) UpdateEmailPoolStatus(ctx context.Context, email, source, status, note string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		q := `UPDATE email_pool SET status=?, updated_at=?`
		args := []any{status, now(), email}
		if strings.TrimSpace(note) != "" {
			q += `, payload=json_set(COALESCE(NULLIF(payload, ''), '{}'), '$.note', ?)`
			args = append(args[:2], append([]any{note}, args[2:]...)...)
		}
		q += ` WHERE email=? COLLATE NOCASE`
		if source != "" && source != "all" {
			q += ` AND source=?`
			args = append(args, source)
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	})
}

// UpdateEmailPoolStatusBulk 批量修改邮箱状态。
func (s *Store) UpdateEmailPoolStatusBulk(ctx context.Context, emails []string, source, status string) (int64, error) {
	if len(emails) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		holders := make([]string, len(emails))
		args := []any{status, now()}
		for i, em := range emails {
			holders[i] = "?"
			args = append(args, em)
		}
		q := fmt.Sprintf(`UPDATE email_pool SET status=?, updated_at=? WHERE email IN (%s) COLLATE NOCASE`, strings.Join(holders, ","))
		if source != "" && source != "all" {
			q += ` AND source=?`
			args = append(args, source)
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// DeleteEmailPool 删除单条邮箱素材。
func (s *Store) DeleteEmailPool(ctx context.Context, email, source string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		q := `DELETE FROM email_pool WHERE email=? COLLATE NOCASE`
		args := []any{email}
		if source != "" && source != "all" {
			q += ` AND source=?`
			args = append(args, source)
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	})
}

// DeleteEmailPoolRecord deletes one source-scoped record and reports whether
// anything was removed. The dedicated domain-pool API needs this exact result.
func (s *Store) DeleteEmailPoolRecord(ctx context.Context, email, source string) (bool, error) {
	var deleted bool
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM email_pool WHERE email=? COLLATE NOCASE AND source=?`,
			email, source)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		deleted = n > 0
		return nil
	})
	return deleted, err
}

// DeleteEmailPoolBulk 批量删除邮箱素材。
func (s *Store) DeleteEmailPoolBulk(ctx context.Context, emails []string, source string) (int64, error) {
	if len(emails) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		holders := make([]string, len(emails))
		args := make([]any, 0, len(emails)+1)
		for i, em := range emails {
			holders[i] = "?"
			args = append(args, em)
		}
		q := fmt.Sprintf(`DELETE FROM email_pool WHERE email IN (%s) COLLATE NOCASE`, strings.Join(holders, ","))
		if source != "" && source != "all" {
			q += ` AND source=?`
			args = append(args, source)
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// MarkEmailStatus 显式设置邮箱状态（available/used/failed/disabled）。
func (s *Store) MarkEmailStatus(ctx context.Context, id int64, status string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE email_pool SET status=?, updated_at=? WHERE id=?`, status, now(), id)
		return err
	})
}

// EmailPoolSummary 各来源的可用统计。
type EmailPoolSummary struct {
	Total     int64 `json:"total"`
	Available int64 `json:"available"`
	Used      int64 `json:"used"`
	Failed    int64 `json:"failed"`
}

// SummarizeEmailPool 汇总邮箱池状态；source 为空表示全部来源。
func (s *Store) SummarizeEmailPool(ctx context.Context, source string) (EmailPoolSummary, error) {
	var sum EmailPoolSummary
	err := s.Read(ctx, func(db *sql.DB) error {
		q := `SELECT COUNT(*),
		             COALESCE(SUM(status='available'),0),
		             COALESCE(SUM(status='used'),0),
		             COALESCE(SUM(status='failed'),0)
		      FROM email_pool WHERE archived=0`
		args := []any{}
		if source != "" {
			q += " AND source=?"
			args = append(args, source)
		}
		return db.QueryRowContext(ctx, q, args...).Scan(&sum.Total, &sum.Available, &sum.Used, &sum.Failed)
	})
	return sum, err
}

// ListEmails 分页列出邮箱，可选按来源、状态与关键词过滤。
func (s *Store) ListEmails(ctx context.Context, source, status, query string, page, pageSize int) ([]EmailItem, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}
	var (
		items []EmailItem
		total int64
	)
	err := s.Read(ctx, func(db *sql.DB) error {
		where := " WHERE archived=0"
		args := []any{}
		if source != "" && source != "all" {
			where += " AND source=?"
			args = append(args, source)
		}
		if status != "" {
			where += " AND status=?"
			args = append(args, status)
		}
		if query != "" {
			where += " AND email LIKE ? COLLATE NOCASE"
			args = append(args, "%"+query+"%")
		}
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM email_pool"+where, args...).Scan(&total); err != nil {
			return err
		}
		q := "SELECT id, email, source, status, archived, created_at, updated_at, payload FROM email_pool" +
			where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		rows, err := db.QueryContext(ctx, q, append(args, pageSize, (page-1)*pageSize)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			it, err := scanEmail(rows)
			if err != nil {
				return err
			}
			items = append(items, *it)
		}
		return rows.Err()
	})
	return items, total, err
}

func scanEmail(sc interface{ Scan(...any) error }) (*EmailItem, error) {
	var (
		it       EmailItem
		archived int
		created  string
		updated  string
		payload  string
	)
	if err := sc.Scan(&it.ID, &it.Email, &it.Source, &it.Status, &archived, &created, &updated, &payload); err != nil {
		return nil, err
	}
	it.Archived = archived != 0
	it.CreatedAt = parseTime(created)
	it.UpdatedAt = parseTime(updated)
	it.Payload = parseJSON(payload)
	return &it, nil
}

// GetEmailItemByEmail 按邮箱查池中记录。
func (s *Store) GetEmailItemByEmail(ctx context.Context, email string) (*EmailItem, error) {
	var out *EmailItem
	err := s.Read(ctx, func(db *sql.DB) error {
		row := db.QueryRowContext(ctx,
			`SELECT id, email, source, status, archived, created_at, updated_at, payload
			 FROM email_pool WHERE email=? COLLATE NOCASE LIMIT 1`, email)
		it, err := scanEmail(row)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		out = it
		return nil
	})
	return out, err
}

var _ = domain.SourceOutlook
