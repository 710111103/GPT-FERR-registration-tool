package store

import (
	"context"
	"database/sql"
)

// LatestJobBatchID 返回最近一次提交的持久化注册批次。
func (s *Store) LatestJobBatchID(ctx context.Context) (string, error) {
	var batchID string
	err := s.Read(ctx, func(db *sql.DB) error {
		err := db.QueryRowContext(ctx,
			`SELECT batch_id FROM registration_jobs WHERE batch_id <> '' ORDER BY id DESC LIMIT 1`).Scan(&batchID)
		if err == sql.ErrNoRows {
			batchID = ""
			return nil
		}
		return err
	})
	return batchID, err
}

// ListSuccessfulJobAccountPayloads 返回指定批次中成功任务关联的去重账号 payload。
// 同一账号被多个成功任务关联时只返回一次，避免批量重试导致重复计数。
func (s *Store) ListSuccessfulJobAccountPayloads(ctx context.Context, batchID string) ([]map[string]any, error) {
	if batchID == "" {
		return []map[string]any{}, nil
	}
	var payloads []map[string]any
	err := s.Read(ctx, func(db *sql.DB) error {
		rows, err := db.QueryContext(ctx, `
SELECT a.payload
FROM accounts a
WHERE a.id IN (
    SELECT DISTINCT j.account_id
    FROM registration_jobs j
    WHERE j.batch_id = ? AND j.status = 'success' AND j.account_id IS NOT NULL
)
ORDER BY a.id`, batchID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			payloads = append(payloads, parseJSON(raw))
		}
		return rows.Err()
	})
	return payloads, err
}
