package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// CreateJob 新建一条 pending 任务记录并返回 ID。
func (s *Store) CreateJob(ctx context.Context, email, emailSource, logFile string) (int64, error) {
	return s.CreateJobWithBatch(ctx, email, emailSource, logFile, "")
}

// CreateJobWithBatch 新建一条带持久化批次 ID 的 pending 任务记录并返回 ID。
func (s *Store) CreateJobWithBatch(ctx context.Context, email, emailSource, logFile, batchID string) (int64, error) {
	var id int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		res, err := tx.ExecContext(ctx,
			`INSERT INTO registration_jobs(email, email_source, batch_id, status, log_file, created_at, updated_at)
			 VALUES(?, ?, ?, 'pending', ?, ?, ?)`, email, emailSource, batchID, logFile, ts, ts)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// ClaimJob 原子地把 pending 任务置为 running。
// 返回 false 表示任务已被别的 worker 抢走或已被取消——对应 Python 版 claim_pending_job。
func (s *Store) ClaimJob(ctx context.Context, id int64) (bool, error) {
	var ok bool
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE registration_jobs SET status='running', updated_at=?
			 WHERE id=? AND status='pending'`, now(), id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n > 0
		return nil
	})
	return ok, err
}

// JobUpdate 是一次任务字段更新，零值字段不更新。
type JobUpdate struct {
	Email     *string
	Status    *domain.JobStatus
	Error     *string
	AccountID *int64
	Stage     *domain.Stage
	Traffic   *domain.Traffic
	Completed bool
	Driver    string
	Proxy     string
	// Payload 追加/覆盖 payload 里的键（走 json_patch 合并，不动其它键）。
	Payload map[string]any
}

// UpdateJob 局部更新任务字段。
func (s *Store) UpdateJob(ctx context.Context, id int64, u JobUpdate) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		sets := []string{"updated_at=?"}
		args := []any{now()}

		if u.Email != nil {
			sets = append(sets, "email=?")
			args = append(args, *u.Email)
		}
		if u.Status != nil {
			sets = append(sets, "status=?")
			args = append(args, string(*u.Status))
		}
		if u.Error != nil {
			sets = append(sets, "error=?")
			args = append(args, *u.Error)
		}
		if u.AccountID != nil {
			sets = append(sets, "account_id=?")
			args = append(args, *u.AccountID)
		}
		if u.Completed {
			sets = append(sets, "completed_at=?")
			args = append(args, now())
		}
		patch := map[string]any{}
		if u.Stage != nil {
			patch["stage"] = u.Stage
		}
		if u.Traffic != nil {
			patch["network_traffic"] = u.Traffic
		}
		if u.Driver != "" {
			patch["driver"] = u.Driver
		}
		if u.Proxy != "" {
			patch["proxy"] = u.Proxy
		}
		for k, v := range u.Payload {
			patch[k] = v
		}
		if len(patch) > 0 {
			sets = append(sets, "payload=json_patch(COALESCE(NULLIF(payload,''),'{}'), ?)")
			args = append(args, mustJSON(patch))
		}

		args = append(args, id)
		q := "UPDATE registration_jobs SET "
		for i, set := range sets {
			if i > 0 {
				q += ", "
			}
			q += set
		}
		q += " WHERE id=?"
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	})
}

// JobStopResult describes the state transition caused by a stop request.
// Status is the state after the request. Changed is false for idempotent or
// terminal requests.
type JobStopResult struct {
	Exists   bool
	Changed  bool
	Previous domain.JobStatus
	Status   domain.JobStatus
}

// RequestJobStop records a stop request before the in-memory cancellation is
// sent. Pending jobs become cancelled immediately; running jobs become
// stopping and are finalized by their worker. Terminal jobs are never
// overwritten.
func (s *Store) RequestJobStop(ctx context.Context, id int64) (JobStopResult, error) {
	var result JobStopResult
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var current string
		err := tx.QueryRowContext(ctx,
			`SELECT status FROM registration_jobs WHERE id=?`, id).Scan(&current)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}

		result.Exists = true
		result.Previous = domain.JobStatus(current)
		result.Status = result.Previous

		switch result.Previous {
		case domain.JobPending:
			ts := now()
			if _, err := tx.ExecContext(ctx,
				`UPDATE registration_jobs
				 SET status='cancelled', error='用户取消排队', updated_at=?, completed_at=?
				 WHERE id=? AND status='pending'`, ts, ts, id); err != nil {
				return err
			}
			result.Changed = true
			result.Status = domain.JobCancelled
		case domain.JobRunning:
			if _, err := tx.ExecContext(ctx,
				`UPDATE registration_jobs SET status='stopping', updated_at=?
				 WHERE id=? AND status='running'`, now(), id); err != nil {
				return err
			}
			result.Changed = true
			result.Status = domain.JobStopping
		case domain.JobStopping:
			// Idempotent retry: keep stopping and let Stop send the cancel
			// signal again if a handle still exists.
		}
		return nil
	})
	return result, err
}

// FinalizeStoppedJob closes an active job that has no live in-process handle.
// The conditional update prevents a stale stop click from overwriting success,
// failure or another terminal state.
func (s *Store) FinalizeStoppedJob(ctx context.Context, id int64) (JobStopResult, error) {
	var result JobStopResult
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var current string
		err := tx.QueryRowContext(ctx,
			`SELECT status FROM registration_jobs WHERE id=?`, id).Scan(&current)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		result.Exists = true
		result.Previous = domain.JobStatus(current)
		result.Status = result.Previous
		if result.Previous != domain.JobRunning && result.Previous != domain.JobStopping {
			return nil
		}

		ts := now()
		if _, err := tx.ExecContext(ctx,
			`UPDATE registration_jobs
			 SET status='stopped', error='用户手动停止', updated_at=?, completed_at=?
			 WHERE id=? AND status IN ('running','stopping')`, ts, ts, id); err != nil {
			return err
		}
		result.Changed = true
		result.Status = domain.JobStopped
		return nil
	})
	return result, err
}

// GetJob 按 ID 读取任务。
func (s *Store) GetJob(ctx context.Context, id int64) (*domain.Job, error) {
	var out *domain.Job
	err := s.Read(ctx, func(db *sql.DB) error {
		row := db.QueryRowContext(ctx,
			`SELECT id, email, email_source, batch_id, status, error, log_file, account_id, payload,
			        created_at, updated_at, completed_at
			 FROM registration_jobs WHERE id=?`, id)
		j, err := scanJob(row)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		out = j
		return nil
	})
	return out, err
}

// ListJobs 分页列出任务，status 为空表示全部。
func (s *Store) ListJobs(ctx context.Context, status string, page, pageSize int) ([]domain.Job, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}
	var (
		jobs  []domain.Job
		total int64
	)
	err := s.Read(ctx, func(db *sql.DB) error {
		where := ""
		args := []any{}
		if status != "" {
			where = " WHERE status=?"
			args = append(args, status)
		}
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM registration_jobs"+where, args...).Scan(&total); err != nil {
			return err
		}
		q := `SELECT id, email, email_source, batch_id, status, error, log_file, account_id, payload,
		             created_at, updated_at, completed_at
		      FROM registration_jobs` + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		rows, err := db.QueryContext(ctx, q, append(args, pageSize, (page-1)*pageSize)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return err
			}
			jobs = append(jobs, *j)
		}
		return rows.Err()
	})
	return jobs, total, err
}

// RecoverInterruptedJobs 把进程崩溃时残留的 running 任务复位为 failed。
// Python 版对应一串 recover_interrupted_* 函数；这里统一在启动时调用一次。
func (s *Store) RecoverInterruptedJobs(ctx context.Context) (int64, error) {
	var n int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE registration_jobs
			 SET status='failed', error='进程重启，任务中断', updated_at=?, completed_at=?
			 WHERE status IN ('running','stopping')`, now(), now())
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// GetJobStatusCounts 返回各状态任务数量分布，供前端顶部状态标签与统计使用。
func (s *Store) GetJobStatusCounts(ctx context.Context) (map[string]int64, error) {
	counts := map[string]int64{
		"total":     0,
		"active":    0,
		"running":   0,
		"pending":   0,
		"success":   0,
		"failed":    0,
		"stopped":   0,
		"cancelled": 0,
	}
	err := s.Read(ctx, func(db *sql.DB) error {
		rows, err := db.QueryContext(ctx, `SELECT status, COUNT(*) FROM registration_jobs GROUP BY status`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var total int64
		for rows.Next() {
			var st string
			var n int64
			if err := rows.Scan(&st, &n); err != nil {
				return err
			}
			counts[st] = n
			total += n
		}
		counts["total"] = total
		counts["active"] = counts["running"] + counts["pending"] + counts["stopping"]
		return rows.Err()
	})
	return counts, err
}

// DeleteJob 删除单条任务记录。
func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM registration_jobs WHERE id=?`, id)
		return err
	})
}

// DeleteJobs 批量删除任务记录。
func (s *Store) DeleteJobs(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		q, args := inClause("DELETE FROM registration_jobs WHERE id IN (%s)", ids)
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// CancelPendingJobs atomically cancels all pending jobs and returns their IDs
// so the scheduler can also cancel the goroutines waiting on the semaphore.
func (s *Store) CancelPendingJobs(ctx context.Context) ([]int64, error) {
	var ids []int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM registration_jobs WHERE status='pending' ORDER BY id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		ts := now()
		_, err = tx.ExecContext(ctx,
			`UPDATE registration_jobs
			 SET status='cancelled', error='用户取消排队', updated_at=?, completed_at=?
			 WHERE status='pending'`, ts, ts)
		return err
	})
	return ids, err
}

func scanJob(sc interface{ Scan(...any) error }) (*domain.Job, error) {
	var (
		j         domain.Job
		status    string
		accountID sql.NullInt64
		payload   string
		created   string
		updated   string
		completed string
	)
	if err := sc.Scan(&j.ID, &j.Email, &j.EmailSource, &j.BatchID, &status, &j.Error, &j.LogFile,
		&accountID, &payload, &created, &updated, &completed); err != nil {
		return nil, err
	}
	j.Status = domain.JobStatus(status)
	if accountID.Valid {
		id := accountID.Int64
		j.AccountID = &id
	}
	j.CreatedAt = parseTime(created)
	j.UpdatedAt = parseTime(updated)
	if completed != "" {
		t := parseTime(completed)
		j.CompletedAt = &t
	}
	p := parseJSON(payload)
	j.Payload = p
	if v, ok := p["stage"].(map[string]any); ok {
		j.Stage = stageFromMap(v)
	}
	if v, ok := p["network_traffic"]; ok && v != nil {
		j.NetworkTraffic = v
	}
	return &j, nil
}

func stageFromMap(m map[string]any) *domain.Stage {
	boolOf := func(k string) bool { b, _ := m[k].(bool); return b }
	strOf := func(k string) string { s, _ := m[k].(string); return s }
	return &domain.Stage{
		AccountCreated:     boolOf("account_created"),
		PasswordSet:        boolOf("password_set"),
		OTPSent:            boolOf("otp_sent"),
		OTPVerified:        boolOf("otp_verified"),
		CredentialAcquired: boolOf("credential_acquired"),
		ExistingAccount:    boolOf("existing_account"),
		Flow:               strOf("flow"),
		FailureStage:       strOf("failure_stage"),
		ErrorCode:          strOf("error_code"),
	}
}

var _ = time.Now
