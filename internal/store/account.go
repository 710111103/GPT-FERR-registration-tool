package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// AccountFilter 账号列表查询条件，与 Python 版 /api/accounts 参数对齐。
type AccountFilter struct {
	Archived       bool
	OverviewFilter string
	PlanFilter     string
	CodexStatus    string
	TOTPFilter     string
	Query          string
	DateFrom       string
	DateTo         string
	Page           int
	PageSize       int
}

// AccountPage 分页结果。
type AccountPage struct {
	Items    []domain.Account `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// InsertAccount 插入或按 email 更新账号，返回行 ID。
// 语义与 Python 版 insert_account 一致：同邮箱重复保存时覆盖 payload 并刷新 updated_at。
func (s *Store) InsertAccount(ctx context.Context, acc domain.Account) (int64, error) {
	if acc.Payload == nil {
		return 0, fmt.Errorf("账号 %s 的 payload 为空，拒绝入库", acc.Email)
	}
	did, _ := acc.Payload["device_id"].(string)
	if strings.TrimSpace(did) == "" {
		return 0, fmt.Errorf("断言失败: 账号 %s 缺少必须的 device_id 字段，拒绝入库", acc.Email)
	}
	var id int64
	// status 列是冗余快照，真正的状态在 payload.status 里（dead / registered / ...）。
	// 任何写路径只要改了 payload.status，这里就自动把列同步过去，
	// 避免出现「payload 说 dead、列还说 registered」的错位。
	if v, ok := acc.Payload["status"].(string); ok && strings.TrimSpace(v) != "" {
		acc.Status = strings.TrimSpace(v)
	}
	err := s.Write(ctx, func(tx *sql.Tx) error {
		ts := now()
		if acc.CreatedAt.IsZero() {
			acc.CreatedAt = time.Now()
		}
		var existing int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM accounts WHERE email = ? COLLATE NOCASE LIMIT 1`, acc.Email).Scan(&existing)
		switch {
		case err == sql.ErrNoRows:
			res, err := tx.ExecContext(ctx,
				`INSERT INTO accounts(email, status, archived, created_at, updated_at, payload)
				 VALUES(?, ?, ?, ?, ?, ?)`,
				acc.Email, acc.Status, boolInt(acc.Archived), ts, ts, mustJSON(acc.Payload))
			if err != nil {
				return err
			}
			id, err = res.LastInsertId()
			return err
		case err != nil:
			return err
		default:
			id = existing
			_, err := tx.ExecContext(ctx,
				`UPDATE accounts SET status=?, archived=?, updated_at=?, payload=? WHERE id=?`,
				acc.Status, boolInt(acc.Archived), ts, mustJSON(acc.Payload), existing)
			return err
		}
	})
	return id, err
}

// GetAccount 按 ID 读取单个账号。
func (s *Store) GetAccount(ctx context.Context, id int64) (*domain.Account, error) {
	var out *domain.Account
	err := s.Read(ctx, func(db *sql.DB) error {
		row := db.QueryRowContext(ctx,
			`SELECT id, email, status, archived, created_at, updated_at, payload FROM accounts WHERE id=?`, id)
		a, err := scanAccount(row)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		out = a
		return nil
	})
	return out, err
}

// GetAccountByEmail 按邮箱查账号，用于"已存在则跳过"的快速路径。
func (s *Store) GetAccountByEmail(ctx context.Context, email string) (*domain.Account, error) {
	var out *domain.Account
	err := s.Read(ctx, func(db *sql.DB) error {
		row := db.QueryRowContext(ctx,
			`SELECT id, email, status, archived, created_at, updated_at, payload
			 FROM accounts WHERE email=? COLLATE NOCASE LIMIT 1`, email)
		a, err := scanAccount(row)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		out = a
		return nil
	})
	return out, err
}

// ListAccounts 分页查询，直接下推 LIMIT/OFFSET 到 SQLite。
func (s *Store) ListAccounts(ctx context.Context, f AccountFilter) (AccountPage, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 500 {
		f.PageSize = 50
	}
	where, args := buildAccountWhere(f)

	var page AccountPage
	page.Page = f.Page
	page.PageSize = f.PageSize

	err := s.Read(ctx, func(db *sql.DB) error {
		if err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM accounts"+where, args...).Scan(&page.Total); err != nil {
			return err
		}
		q := "SELECT id, email, status, archived, created_at, updated_at, payload FROM accounts" +
			where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		qargs := append(append([]any{}, args...), f.PageSize, (f.Page-1)*f.PageSize)
		rows, err := db.QueryContext(ctx, q, qargs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAccount(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, *a)
		}
		return rows.Err()
	})
	return page, err
}

func buildAccountWhere(f AccountFilter) (string, []any) {
	var sb strings.Builder
	var args []any
	sb.WriteString(" WHERE 1=1")
	if f.Archived {
		sb.WriteString(" AND archived=1")
	} else {
		sb.WriteString(" AND archived=0")
	}
	if f.Query != "" {
		sb.WriteString(" AND (email LIKE ? COLLATE NOCASE OR payload LIKE ? COLLATE NOCASE)")
		args = append(args, "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.DateFrom != "" {
		sb.WriteString(" AND created_at >= ?")
		args = append(args, f.DateFrom)
	}
	if f.DateTo != "" {
		val := f.DateTo
		if len(val) == 10 {
			val += "T23:59:59"
		}
		sb.WriteString(" AND created_at <= ?")
		args = append(args, val)
	}

	token := "trim(COALESCE(CAST(json_extract(payload, '$.access_token') AS TEXT), ''))"
	expired := "lower(COALESCE(CAST(json_extract(payload, '$.token_expired') AS TEXT), ''))"
	plan := "lower(COALESCE(NULLIF(CAST(json_extract(payload, '$.current_plan_type') AS TEXT), ''), CAST(json_extract(payload, '$.plan_type') AS TEXT), ''))"
	eligible := "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
	trialKind := "lower(COALESCE(CAST(json_extract(payload, '$.trial_offer_kind') AS TEXT), ''))"
	trialCampaign := "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_campaign_id') AS TEXT), ''))"
	check := "lower(COALESCE(CAST(json_extract(payload, '$.plan_check_status') AS TEXT), ''))"
	live := "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
	reg := "lower(trim(COALESCE(status, '')))"
	pwLoginVerified := "lower(COALESCE(CAST(json_extract(payload, '$.password_setup_login_verified') AS TEXT), ''))"
	pwSaved := fmt.Sprintf("(%s IN ('1','true','yes','on') OR length(trim(COALESCE(CAST(json_extract(payload, '$.password') AS TEXT), '')))>0 OR length(trim(COALESCE(CAST(json_extract(payload, '$.registration_password') AS TEXT), '')))>0)", pwLoginVerified)
	totpSecret := "trim(COALESCE(CAST(json_extract(payload, '$.totp_secret') AS TEXT), ''))"
	totpOk := "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_ok') AS TEXT), ''))"
	totpStatus := "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_status') AS TEXT), ''))"

	atValid := fmt.Sprintf("length(%s)>0 AND %s NOT IN ('1','true','yes','on') AND %s NOT IN ('failed','deactivated','dead')", token, expired, live)
	regComplete := fmt.Sprintf("(%s AND %s AND length(%s)>0 AND (%s IN ('1','true','yes','on') OR %s='success'))", pwSaved, atValid, totpSecret, totpOk, totpStatus)
	plusEligible := fmt.Sprintf("(%s IN ('1','true','yes','on') AND %s NOT IN ('go','generic') AND %s NOT LIKE 'go-%%' AND %s NOT LIKE '%%one_click_trial%%')", eligible, trialKind, trialCampaign, trialCampaign)
	goTrial := fmt.Sprintf("(%s='go' OR %s LIKE 'go-%%' OR lower(COALESCE(CAST(json_extract(payload, '$.go_trial_eligible') AS TEXT), '')) IN ('1','true','yes','on'))", trialKind, trialCampaign)

	// 1. OverviewFilter (总览分类卡片)
	key := strings.ToLower(strings.TrimSpace(f.OverviewFilter))
	switch key {
	case "", "all", "total":
		// 全量无过滤
	case "registering":
		sb.WriteString(fmt.Sprintf(" AND %s='registering' AND NOT %s", reg, regComplete))
	case "interrupted":
		sb.WriteString(fmt.Sprintf(" AND %s='interrupted' AND NOT %s", reg, regComplete))
	case "registration_incomplete":
		sb.WriteString(fmt.Sprintf(" AND %s IN ('registering','interrupted') AND NOT %s", reg, regComplete))
	case "registration_recovered":
		sb.WriteString(fmt.Sprintf(" AND %s IN ('registering','interrupted') AND %s", reg, regComplete))
	case "password_saved":
		sb.WriteString(fmt.Sprintf(" AND %s", pwSaved))
	case "at_valid":
		sb.WriteString(fmt.Sprintf(" AND %s", atValid))
	case "at_expired":
		sb.WriteString(fmt.Sprintf(" AND (%s IN ('1','true','yes','on') OR %s IN ('failed','deactivated','dead'))", expired, live))
	case "at_missing":
		sb.WriteString(fmt.Sprintf(" AND length(%s)=0", token))
	case "eligible":
		sb.WriteString(fmt.Sprintf(" AND %s AND %s='free'", plusEligible, plan))
	case "ineligible":
		sb.WriteString(fmt.Sprintf(" AND NOT %s AND %s='free'", plusEligible, plan))
	case "eligibility_unknown":
		sb.WriteString(fmt.Sprintf(" AND (%s='' OR %s IS NULL) AND (%s='free' OR %s='')", eligible, eligible, plan, plan))
	case "plus":
		sb.WriteString(fmt.Sprintf(" AND %s LIKE '%%plus%%' AND %s NOT LIKE '%%free%%'", plan, plan))
	case "free":
		sb.WriteString(fmt.Sprintf(" AND (%s='free' OR %s='')", plan, plan))
	case "queued", "running", "success", "failed":
		sb.WriteString(fmt.Sprintf(" AND %s=?", check))
		args = append(args, key)
	case "unchecked":
		sb.WriteString(fmt.Sprintf(" AND (%s='' OR %s IS NULL)", check, check))
	case "live":
		sb.WriteString(fmt.Sprintf(" AND %s='live'", live))
	case "live_failed":
		sb.WriteString(fmt.Sprintf(" AND %s IN ('failed','deactivated','dead')", live))
	}

	// 2. PlanFilter (顶部套餐快捷筛选按钮)
	pFilter := strings.ToLower(strings.TrimSpace(f.PlanFilter))
	switch pFilter {
	case "", "all", "any":
	case "plus":
		sb.WriteString(fmt.Sprintf(" AND %s LIKE '%%plus%%' AND %s NOT LIKE '%%free%%'", plan, plan))
	case "plus_trial", "plus_trial_eligible", "trial":
		sb.WriteString(fmt.Sprintf(" AND %s='free' AND %s", plan, plusEligible))
	case "discount", "discount_offer":
		discountExpr := "lower(COALESCE(CAST(json_extract(payload, '$.discount_offer_eligible') AS TEXT), ''))"
		sb.WriteString(fmt.Sprintf(" AND %s='free' AND %s IN ('1','true','yes','on')", plan, discountExpr))
	case "free_no_trial":
		sb.WriteString(fmt.Sprintf(" AND %s='free' AND %s IN ('0','false','no','off') AND NOT %s", plan, eligible, goTrial))
	case "free":
		sb.WriteString(fmt.Sprintf(" AND (%s='free' OR %s='')", plan, plan))
	}

	// 3. CodexStatus (全部状态下拉筛选)
	codex := strings.ToLower(strings.TrimSpace(f.CodexStatus))
	if codex != "" && codex != "all" && codex != "*" {
		codexStatusExpr := "lower(COALESCE(CAST(json_extract(payload, '$.codex_status') AS TEXT), ''))"
		if codex == "deactivated" {
			sb.WriteString(fmt.Sprintf(" AND %s='deactivated'", live))
		} else {
			sb.WriteString(fmt.Sprintf(" AND %s=?", codexStatusExpr))
			args = append(args, codex)
		}
	}

	// 4. TOTPFilter (2FA 下拉筛选)
	totp := strings.ToLower(strings.TrimSpace(f.TOTPFilter))
	if totp != "" && totp != "all" && totp != "*" {
		switch totp {
		case "enabled", "on", "active":
			sb.WriteString(fmt.Sprintf(" AND length(%s)>0", totpSecret))
		case "disabled", "off", "not_enabled", "unset":
			sb.WriteString(fmt.Sprintf(" AND length(%s)=0", totpSecret))
		case "pending", "setup", "setting", "queued", "running":
			sb.WriteString(fmt.Sprintf(" AND %s IN ('queued','running')", totpStatus))
		default:
			sb.WriteString(fmt.Sprintf(" AND %s=?", totpStatus))
			args = append(args, totp)
		}
	}

	return sb.String(), args
}

// AccountSummary 全表总览统计。
type AccountSummary struct {
	Total                  int64 `json:"total"`
	Registering            int64 `json:"registering"`
	Interrupted            int64 `json:"interrupted"`
	RegistrationIncomplete int64 `json:"registration_incomplete"`
	RegistrationRecovered  int64 `json:"registration_recovered"`
	PasswordSaved          int64 `json:"password_saved"`
	AtPresent              int64 `json:"at_present"`
	AtMissing              int64 `json:"at_missing"`
	AtExpired              int64 `json:"at_expired"`
	AtValid                int64 `json:"at_valid"`
	Eligible               int64 `json:"eligible"`
	Ineligible             int64 `json:"ineligible"`
	EligibilityUnknown     int64 `json:"eligibility_unknown"`
	Plus                   int64 `json:"plus"`
	Free                   int64 `json:"free"`
	Queued                 int64 `json:"queued"`
	Running                int64 `json:"running"`
	Success                int64 `json:"success"`
	Failed                 int64 `json:"failed"`
	Unchecked              int64 `json:"unchecked"`
	Live                   int64 `json:"live"`
	LiveFailed             int64 `json:"live_failed"`
}

// GetAccountSummary 统计全表总览卡片数字。
func (s *Store) GetAccountSummary(ctx context.Context, archived bool) (AccountSummary, error) {
	var sum AccountSummary
	err := s.Read(ctx, func(db *sql.DB) error {
		arch := 0
		if archived {
			arch = 1
		}

		token := "trim(COALESCE(CAST(json_extract(payload, '$.access_token') AS TEXT), ''))"
		expired := "lower(COALESCE(CAST(json_extract(payload, '$.token_expired') AS TEXT), ''))"
		plan := "lower(COALESCE(NULLIF(CAST(json_extract(payload, '$.current_plan_type') AS TEXT), ''), CAST(json_extract(payload, '$.plan_type') AS TEXT), ''))"
		eligible := "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_eligible') AS TEXT), ''))"
		trialKind := "lower(COALESCE(CAST(json_extract(payload, '$.trial_offer_kind') AS TEXT), ''))"
		trialCampaign := "lower(COALESCE(CAST(json_extract(payload, '$.plus_trial_campaign_id') AS TEXT), ''))"
		check := "lower(COALESCE(CAST(json_extract(payload, '$.plan_check_status') AS TEXT), ''))"
		live := "lower(COALESCE(CAST(json_extract(payload, '$.live_check_status') AS TEXT), ''))"
		reg := "lower(trim(COALESCE(status, '')))"
		pwLoginVerified := "lower(COALESCE(CAST(json_extract(payload, '$.password_setup_login_verified') AS TEXT), ''))"
		pwSaved := fmt.Sprintf("(%s IN ('1','true','yes','on') OR length(trim(COALESCE(CAST(json_extract(payload, '$.password') AS TEXT), '')))>0 OR length(trim(COALESCE(CAST(json_extract(payload, '$.registration_password') AS TEXT), '')))>0)", pwLoginVerified)
		totpSecret := "trim(COALESCE(CAST(json_extract(payload, '$.totp_secret') AS TEXT), ''))"
		totpOk := "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_ok') AS TEXT), ''))"
		totpStatus := "lower(COALESCE(CAST(json_extract(payload, '$.totp_setup_status') AS TEXT), ''))"
		atValid := fmt.Sprintf("length(%s)>0 AND %s NOT IN ('1','true','yes','on') AND %s NOT IN ('failed','deactivated','dead')", token, expired, live)
		regComplete := fmt.Sprintf("(%s AND %s AND length(%s)>0 AND (%s IN ('1','true','yes','on') OR %s='success'))", pwSaved, atValid, totpSecret, totpOk, totpStatus)
		plusEligible := fmt.Sprintf("(%s IN ('1','true','yes','on') AND %s NOT IN ('go','generic') AND %s NOT LIKE 'go-%%' AND %s NOT LIKE '%%one_click_trial%%')", eligible, trialKind, trialCampaign, trialCampaign)

		query := fmt.Sprintf(`SELECT
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN %s='registering' AND NOT %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='interrupted' AND NOT %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s IN ('registering','interrupted') AND NOT %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s IN ('registering','interrupted') AND %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN length(%s) > 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN length(%s) = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s IN ('1','true','yes','on') OR %s IN ('failed','deactivated','dead') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s AND %s='free' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s IN ('0','false','no','off') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN (%s='' OR %s IS NULL) AND (%s='free' OR %s='') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s LIKE '%%plus%%' AND %s NOT LIKE '%%free%%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='free' OR %s='' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='queued' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='running' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='success' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='' OR %s IS NULL THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s='live' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN %s IN ('failed','deactivated','dead') THEN 1 ELSE 0 END), 0)
		FROM accounts WHERE archived = ?`,
			reg, regComplete,
			reg, regComplete,
			reg, regComplete,
			reg, regComplete,
			pwSaved,
			token,
			token,
			expired, live,
			atValid,
			plusEligible, plan,
			eligible,
			eligible, eligible, plan, plan,
			plan, plan,
			plan, plan,
			check,
			check,
			check,
			check,
			check, check,
			live,
			live,
		)

		return db.QueryRowContext(ctx, query, arch).Scan(
			&sum.Total, &sum.Registering, &sum.Interrupted, &sum.RegistrationIncomplete, &sum.RegistrationRecovered,
			&sum.PasswordSaved, &sum.AtPresent, &sum.AtMissing, &sum.AtExpired, &sum.AtValid,
			&sum.Eligible, &sum.Ineligible, &sum.EligibilityUnknown,
			&sum.Plus, &sum.Free,
			&sum.Queued, &sum.Running, &sum.Success, &sum.Failed, &sum.Unchecked,
			&sum.Live, &sum.LiveFailed,
		)
	})
	return sum, err
}

// CountAccounts 账号总数，供概览接口使用。
func (s *Store) CountAccounts(ctx context.Context) (int64, error) {
	var n int64
	err := s.Read(ctx, func(db *sql.DB) error {
		return db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE archived=0`).Scan(&n)
	})
	return n, err
}

// DeleteAccount 删除单个账号。
func (s *Store) DeleteAccount(ctx context.Context, id int64) error {
	_, err := s.DeleteAccounts(ctx, []int64{id})
	return err
}

// UpdateAccountNote 更新单个账号的备注信息。
func (s *Store) UpdateAccountNote(ctx context.Context, id int64, note string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE accounts SET payload=json_set(COALESCE(NULLIF(payload,''),'{}'), '$.note', ?), updated_at=? WHERE id=?`,
			note, now(), id)
		return err
	})
}

// UpdateAccountNotesBulk 批量设置账号备注。
func (s *Store) UpdateAccountNotesBulk(ctx context.Context, ids []int64, note string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		q, args := inClause("UPDATE accounts SET payload=json_set(COALESCE(NULLIF(payload,''),'{}'), '$.note', ?), updated_at=? WHERE id IN (%s)", ids)
		fullArgs := append([]any{note, now()}, args...)
		res, err := tx.ExecContext(ctx, q, fullArgs...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// UpdateAccountArchived 归档或取消归档单个账号。
func (s *Store) UpdateAccountArchived(ctx context.Context, id int64, archived bool) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE accounts SET archived=?, updated_at=? WHERE id=?`,
			boolInt(archived), now(), id)
		return err
	})
}

// UpdateAccountsArchivedBulk 批量归档或取消归档。
func (s *Store) UpdateAccountsArchivedBulk(ctx context.Context, ids []int64, archived bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		q, args := inClause("UPDATE accounts SET archived=?, updated_at=? WHERE id IN (%s)", ids)
		fullArgs := append([]any{boolInt(archived), now()}, args...)
		res, err := tx.ExecContext(ctx, q, fullArgs...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// ChangeAccountEmail 原地把账号主邮箱换成 newEmail。
//
// 换绑成功后旧 AT 立刻作废（OpenAI 在 verify 阶段就吊销了旧 token），
// 所以这里必须同时覆写 access_token：命中新 AT 就写新值，没拿到就写空串，
// 由上层立刻排一次查活把 AT 补回来。previous_email 保留原邮箱便于对账。
func (s *Store) ChangeAccountEmail(ctx context.Context, id int64, newEmail, source, newAT, materialLine string) error {
	if id <= 0 || strings.TrimSpace(newEmail) == "" {
		return fmt.Errorf("账号 ID 或新邮箱为空")
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE accounts SET
			     payload = json_set(
			         COALESCE(NULLIF(payload,''),'{}'),
			         '$.previous_email', email,
			         '$.email_source', ?,
			         '$.email_material', ?,
			         '$.email_change_status', 'success',
			         '$.email_change_error', '',
			         '$.email_changed_at', ?,
			         '$.access_token', ?,
			         '$.token_expired', 0
			     ),
			     email = ?,
			     updated_at = ?
			 WHERE id = ?`,
			source, materialLine, now(), newAT, newEmail, now(), id)
		return err
	})
}

// SetEmailChangeStatus 写换绑过程中的状态位（queued / running / failed），
// 前端账号列表直接读这几个键渲染「换绑中 / 换绑失败」。
func (s *Store) SetEmailChangeStatus(ctx context.Context, id int64, status, message, targetEmail string) error {
	if id <= 0 {
		return fmt.Errorf("账号 ID 为空")
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE accounts SET
			     payload = json_set(
			         COALESCE(NULLIF(payload,''),'{}'),
			         '$.email_change_status', ?,
			         '$.email_change_message', ?,
			         '$.email_change_target', ?,
			         '$.email_change_at', ?
			     ),
			     updated_at = ?
			 WHERE id = ?`,
			status, message, targetEmail, now(), now(), id)
		return err
	})
}

// GetAccountsByIDs 批量读取账号详情。
func (s *Store) GetAccountsByIDs(ctx context.Context, ids []int64) (map[int64]*domain.Account, error) {
	out := map[int64]*domain.Account{}
	if len(ids) == 0 {
		return out, nil
	}
	err := s.Read(ctx, func(db *sql.DB) error {
		q, args := inClause("SELECT id, email, status, archived, created_at, updated_at, payload FROM accounts WHERE id IN (%s)", ids)
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAccount(rows)
			if err != nil {
				return err
			}
			out[a.ID] = a
		}
		return rows.Err()
	})
	return out, err
}

// DeleteAccounts 批量删除，返回实际删除数。
func (s *Store) DeleteAccounts(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var affected int64
	err := s.Write(ctx, func(tx *sql.Tx) error {
		q, args := inClause("DELETE FROM accounts WHERE id IN (%s)", ids)
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

func scanAccount(sc interface{ Scan(...any) error }) (*domain.Account, error) {
	var (
		a        domain.Account
		archived int
		created  string
		updated  string
		payload  string
	)
	if err := sc.Scan(&a.ID, &a.Email, &a.Status, &archived, &created, &updated, &payload); err != nil {
		return nil, err
	}
	a.Archived = archived != 0
	a.CreatedAt = parseTime(created)
	a.UpdatedAt = parseTime(updated)
	a.Payload = parseJSON(payload)
	// status 列与 payload.status 双写历史遗留：早期写路径只改 payload，
	// 导致 status 列永远是 registered。读取时以 payload.status 为准，
	// 这样任何按 WHERE status='dead' 的过滤都能命中真正的废号。
	if v, ok := a.Payload["status"].(string); ok && strings.TrimSpace(v) != "" {
		a.Status = strings.TrimSpace(v)
	}
	return &a, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func inClause(tmpl string, ids []int64) (string, []any) {
	holders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		holders[i] = "?"
		args[i] = id
	}
	return fmt.Sprintf(tmpl, strings.Join(holders, ",")), args
}
