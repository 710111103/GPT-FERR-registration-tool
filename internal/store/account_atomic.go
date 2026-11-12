package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// UpdateAccountPayload atomically merges fields into accounts.payload. Callers
// must use this instead of InsertAccount with a stale account snapshot when
// they only own a small subset of the payload (for example extract-link state).
func (s *Store) UpdateAccountPayload(ctx context.Context, id int64, values map[string]any) error {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if !validPayloadKey(key) {
			return fmt.Errorf("非法账号 payload 字段: %q", key)
		}
		keys = append(keys, key)
	}

	err := s.Write(ctx, func(tx *sql.Tx) error {
		expr, args := payloadSetExpression("COALESCE(NULLIF(payload, ''), '{}')", keys, values)
		sets := []string{"payload=" + expr, "updated_at=?"}
		args = append(args, now())
		if status, ok := values["status"].(string); ok && strings.TrimSpace(status) != "" {
			sets = append(sets, "status=?")
			args = append(args, strings.TrimSpace(status))
		}
		args = append(args, id)
		res, err := tx.ExecContext(ctx,
			"UPDATE accounts SET "+strings.Join(sets, ", ")+" WHERE id=?", args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
	return err
}

// ClaimAccountExtract transitions an account into the queued state only when
// it is not already queued or running. The conditional UPDATE is the lock used
// to prevent duplicate extract jobs for the same account.
func (s *Store) ClaimAccountExtract(ctx context.Context, id int64, linkType, trigger string) (bool, error) {
	var claimed bool
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		values := map[string]any{
			"extract_link_status":            "queued",
			"extract_link_ok":                false,
			"extract_link_type":              linkType,
			"extract_link_queued_at":         ts,
			"extract_link_started_at":        "",
			"extract_link_completed_at":      "",
			"extract_link_checked_at":        "",
			"extract_link_error":             "",
			"extract_link_message":           "已加入提链队列",
			"extract_link_job_id":            "",
			"extract_link_cdk_remaining":     nil,
			"extract_link_long_url":          "",
			"extract_link_copy_paste":        "",
			"extract_link_image_url_png":     "",
			"extract_link_image_url_svg":     "",
			"extract_link_payment_method":    "",
			"extract_link_payment_link_type": "",
			"extract_link_expires_at":        "",
			"extract_link_result_json":       "",
			"extract_link_trigger":           trigger,
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		expr, args := payloadSetExpression("COALESCE(NULLIF(payload, ''), '{}')", keys, values)
		args = append(args, ts, id)
		res, err := tx.ExecContext(ctx, `UPDATE accounts SET payload=`+expr+`, updated_at=? WHERE id=?
			AND lower(COALESCE(CAST(json_extract(payload, '$.extract_link_status') AS TEXT), ''))
			    NOT IN ('queued', 'running')`, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		claimed = n == 1
		return nil
	})
	return claimed, err
}

// MarkAccountExtractRunning performs the queued -> running transition.
func (s *Store) MarkAccountExtractRunning(ctx context.Context, id int64) (bool, error) {
	var changed bool
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		values := map[string]any{
			"extract_link_status":     "running",
			"extract_link_ok":         false,
			"extract_link_started_at": ts,
			"extract_link_message":    "提链任务已启动",
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		expr, args := payloadSetExpression("COALESCE(NULLIF(payload, ''), '{}')", keys, values)
		args = append(args, ts, id)
		res, err := tx.ExecContext(ctx, `UPDATE accounts SET payload=`+expr+`, updated_at=? WHERE id=?
			AND lower(COALESCE(CAST(json_extract(payload, '$.extract_link_status') AS TEXT), ''))='queued'`, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		changed = n == 1
		return nil
	})
	return changed, err
}

// UpdateAccountExtract merges a partial extract result without touching any
// unrelated account fields.
func (s *Store) UpdateAccountExtract(ctx context.Context, id int64, values map[string]any) error {
	return s.UpdateAccountPayload(ctx, id, values)
}

// RecoverInterruptedExtractLinks closes queued/running extract states left by
// an unclean shutdown. It returns the number of recovered accounts.
func (s *Store) RecoverInterruptedExtractLinks(ctx context.Context) (int64, error) {
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		values := map[string]any{
			"extract_link_status":       "failed",
			"extract_link_ok":           false,
			"extract_link_completed_at": ts,
			"extract_link_checked_at":   ts,
			"extract_link_error":        "WebUI 重启导致提链任务中断，请重新提链",
			"extract_link_message":      "WebUI 重启导致提链任务中断，请重新提链",
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		expr, args := payloadSetExpression("COALESCE(NULLIF(payload, ''), '{}')", keys, values)
		args = append(args, ts)
		res, err := tx.ExecContext(ctx, `UPDATE accounts SET payload=`+expr+`, updated_at=?
			WHERE lower(COALESCE(CAST(json_extract(payload, '$.extract_link_status') AS TEXT), ''))
			      IN ('queued', 'running')`, args...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

func validPayloadKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func payloadSetExpression(base string, keys []string, values map[string]any) (string, []any) {
	parts := make([]string, 0, len(keys)*2+1)
	parts = append(parts, base)
	args := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		parts = append(parts, "?", "json(?)")
		args = append(args, "$."+key, mustJSON(values[key]))
	}
	return "json_set(" + strings.Join(parts, ", ") + ")", args
}
