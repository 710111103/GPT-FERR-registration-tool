package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// InspectionFailure 一条查活失败明细（对齐上游 account_inspection_failures）。
type InspectionFailure struct {
	AccountID int64  `json:"account_id"`
	Email     string `json:"email"`
	Status    string `json:"status"`
	Error     string `json:"error"`
	FailedAt  string `json:"failed_at"`
}

func inspectionPayload(run map[string]any) string {
	m := make(map[string]any, len(run))
	for k, v := range run {
		if k == "account_ids" {
			continue
		}
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func publicInspection(raw string) map[string]any {
	m := parseJSON(raw)
	delete(m, "account_ids")
	return m
}

// CreateAccountInspection 建一条巡检记录并快照参与账号。
// 已有 queued/running 任务时直接返回既有任务（created=false），与上游唯一索引语义一致。
func (s *Store) CreateAccountInspection(ctx context.Context, accountIDs []int64, workers int, archived string) (map[string]any, bool, error) {
	if workers <= 0 {
		workers = 3
	}
	if archived == "" {
		archived = "0"
	}
	ids := make([]int64, 0, len(accountIDs))
	seen := make(map[int64]struct{}, len(accountIDs))
	for _, id := range accountIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	var run map[string]any
	created := false
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var activePayload string
		err := tx.QueryRowContext(ctx,
			`SELECT payload FROM account_inspections WHERE status IN ('queued','running') LIMIT 1`).Scan(&activePayload)
		if err == nil {
			run = publicInspection(activePayload)
			if idf, ok := run["id"].(float64); ok {
				var snap string
				if e := tx.QueryRowContext(ctx,
					`SELECT account_ids FROM account_inspection_snapshots WHERE inspection_id=?`, int64(idf)).Scan(&snap); e == nil {
					var list []int64
					_ = json.Unmarshal([]byte(snap), &list)
					run["account_ids"] = list
				}
			}
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}

		if ids == nil || len(ids) == 0 {
			q := `SELECT id FROM accounts`
			args := []any{}
			if archived != "all" {
				q += ` WHERE archived=?`
				if archived == "only" {
					args = append(args, 1)
				} else {
					args = append(args, 0)
				}
			}
			rows, qerr := tx.QueryContext(ctx, q+` ORDER BY id DESC`, args...)
			if qerr != nil {
				return qerr
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id)
			}
			rows.Close()
		}

		nowStr := time.Now().Format("2006-01-02 15:04:05")
		run = map[string]any{
			"status":                    "queued",
			"workers":                   workers,
			"archived":                  archived,
			"created_at":                nowStr,
			"finished_at":               nil,
			"total_count":               len(ids),
			"checked_count":             0,
			"skipped_count":             0,
			"deactivated_skipped_count": 0,
			"invalid_count":             0,
			"live_success_count":        0,
			"live_failed_count":         0,
			"plan_success_count":        0,
			"plan_failed_count":         0,
			"error":                     "",
			"failure_details_available": true,
		}
		res, ierr := tx.ExecContext(ctx,
			`INSERT INTO account_inspections(status, payload) VALUES(?, ?)`, "queued", inspectionPayload(run))
		if ierr != nil {
			return ierr
		}
		id, _ := res.LastInsertId()
		run["id"] = id
		run["account_ids"] = ids
		if _, uerr := tx.ExecContext(ctx,
			`UPDATE account_inspections SET payload=? WHERE id=?`, inspectionPayload(run), id); uerr != nil {
			return uerr
		}
		snap, _ := json.Marshal(ids)
		if _, serr := tx.ExecContext(ctx,
			`INSERT INTO account_inspection_snapshots(inspection_id, account_ids) VALUES(?, ?)`, id, string(snap)); serr != nil {
			return serr
		}
		created = true
		return nil
	})
	return run, created, err
}

// SaveAccountInspection 保存运行态。终态不可覆盖，失败明细与统计同事务写入。
func (s *Store) SaveAccountInspection(ctx context.Context, run map[string]any, failure *InspectionFailure) (bool, error) {
	idf, ok := run["id"].(float64)
	if !ok {
		if idv, ok2 := run["id"].(int64); ok2 {
			idf = float64(idv)
		} else {
			return false, fmt.Errorf("巡检任务缺少 id")
		}
	}
	id := int64(idf)
	status, _ := run["status"].(string)
	if status == "" {
		status = "running"
	}
	saved := false
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE account_inspections SET status=?, payload=? WHERE id=? AND status IN ('queued','running')`,
			status, inspectionPayload(run), id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return nil
		}
		saved = true
		if failure != nil {
			failedAt := failure.FailedAt
			if failedAt == "" {
				failedAt = time.Now().Format("2006-01-02 15:04:05")
			}
			_, err = tx.ExecContext(ctx,
				`INSERT INTO account_inspection_failures(inspection_id, account_id, email, status, error, failed_at)
				 VALUES(?,?,?,?,?,?)
				 ON CONFLICT(inspection_id, account_id) DO NOTHING`,
				id, failure.AccountID, truncateStr(failure.Email, 320), truncateStr(failure.Status, 40),
				truncateStr(failure.Error, 2000), failedAt)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return saved, err
}

// ListAccountInspections 分页读取巡检记录，items/active/total 来自同一读快照。
func (s *Store) ListAccountInspections(ctx context.Context, limit, offset int) (map[string]any, error) {
	if limit <= 0 {
		limit = 20
	}
	out := map[string]any{}
	err := s.Read(ctx, func(db *sql.DB) error {
		rows, err := db.QueryContext(ctx,
			`SELECT payload FROM account_inspections ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for rows.Next() {
			var pl string
			if err := rows.Scan(&pl); err != nil {
				rows.Close()
				return err
			}
			items = append(items, publicInspection(pl))
		}
		rows.Close()

		var active string
		activeVal := any(nil)
		switch err := db.QueryRowContext(ctx,
			`SELECT payload FROM account_inspections WHERE status IN ('queued','running') LIMIT 1`).Scan(&active); err {
		case nil:
			activeVal = publicInspection(active)
		case sql.ErrNoRows:
		default:
			return err
		}

		var total int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_inspections`).Scan(&total); err != nil {
			return err
		}
		out["items"] = items
		out["total"] = total
		out["active"] = activeVal
		return nil
	})
	return out, err
}

// ListAccountInspectionFailures 读取某条巡检的失败明细；任务不存在时 found=false。
func (s *Store) ListAccountInspectionFailures(ctx context.Context, id int64, limit, offset int) (map[string]any, bool, error) {
	if limit <= 0 {
		limit = 20
	}
	out := map[string]any{}
	found := false
	err := s.Read(ctx, func(db *sql.DB) error {
		var pl string
		err := db.QueryRowContext(ctx, `SELECT payload FROM account_inspections WHERE id=?`, id).Scan(&pl)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		task := publicInspection(pl)

		rows, err := db.QueryContext(ctx,
			`SELECT account_id, email, status, error, failed_at FROM account_inspection_failures
			 WHERE inspection_id=? ORDER BY account_id LIMIT ? OFFSET ?`, id, limit, offset)
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for rows.Next() {
			var accountID int64
			var email, st, er, at string
			if err := rows.Scan(&accountID, &email, &st, &er, &at); err != nil {
				rows.Close()
				return err
			}
			items = append(items, map[string]any{
				"account_id": accountID, "email": email, "status": st, "error": er, "failed_at": at,
			})
		}
		rows.Close()

		var total int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM account_inspection_failures WHERE inspection_id=?`, id).Scan(&total); err != nil {
			return err
		}
		available := true
		if v, ok := task["failure_details_available"].(bool); ok {
			available = v
		}
		out["task"] = task
		out["items"] = items
		out["total"] = total
		out["details_available"] = available
		out["limit"] = limit
		out["offset"] = offset
		return nil
	})
	return out, found, err
}

func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
