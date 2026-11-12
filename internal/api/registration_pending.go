package api

// 注册断点观测与续跑：逐字对齐上游 webui/app.py:532-564 两个接口，
// 以及 core/registration_health.py 的分类口径、core/registration_service.py:647-736
// submit_registration_resume 的 skip 文案与入队方式。
//
// 上游是只读分类 + ThreadPoolExecutor 提交；这里保持只读分类，入队走 job.Pool。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/job"
	"github.com/turb/gpt-register/internal/store"
)

const (
	registrationPendingDefaultStaleMinutes = 15
	registrationPendingMaxStaleMinutes     = 1440
	registrationPendingDefaultLimit        = 5000
	registrationPendingMaxLimit            = 5000
	registrationResumeMaxIDs               = 5000
	registrationAccountPageSize            = 500
	registrationJobScanPageSize            = 500
	registrationJobScanMaxPages            = 400
)

// registrationHealth 对齐上游 classify_registration_health 的返回字典。
type registrationHealth struct {
	Status                  string
	Pending                 bool
	PasswordCheckpointSaved bool
	UpdatedAt               string
	AgeSeconds              *int64
	Stale                   bool
	Reason                  string
	RecommendedAction       string
}

// classifyRegistrationHealth 逐条对齐上游 core/registration_health.py:26-59。
func classifyRegistrationHealth(acc domain.Account, now time.Time, staleAfterMinutes int) registrationHealth {
	status := strings.ToLower(strings.TrimSpace(acc.Status))
	passwordOK := registrationPasswordCheckpointSaved(acc)
	updated := acc.UpdatedAt
	var age *int64
	if !updated.IsZero() {
		sec := int64(now.Sub(updated).Seconds())
		if sec < 0 {
			sec = 0
		}
		age = &sec
	}
	if staleAfterMinutes < 1 {
		staleAfterMinutes = 1
	}
	stale := status == "registering" && age != nil && *age >= int64(staleAfterMinutes)*60

	var reason, action string
	switch {
	case status == "interrupted":
		reason = "任务已中断，检查记录中的最后错误"
		action = "review_or_resume"
	case stale:
		reason = "超过 " + strconv.Itoa(staleAfterMinutes) + " 分钟没有状态更新"
		action = "inspect_stale_task"
	case status == "registering" && passwordOK:
		reason = "密码检查点已保存，等待后续注册阶段"
		action = "wait_or_resume"
	case status == "registering":
		reason = "注册流程仍在处理中，尚未保存密码检查点"
		action = "wait"
	default:
		reason = "不属于注册待完成状态"
		action = "none"
	}
	return registrationHealth{
		Status:                  status,
		Pending:                 status == "registering" || status == "interrupted",
		PasswordCheckpointSaved: passwordOK,
		UpdatedAt:               acc.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		AgeSeconds:              age,
		Stale:                   stale,
		Reason:                  reason,
		RecommendedAction:       action,
	}
}

// registrationPasswordCheckpointSaved 对齐上游 registration_health.py:28：
// password_ok = password_setup_ok or password_setup_remote_password_present。
func registrationPasswordCheckpointSaved(acc domain.Account) bool {
	if acc.Payload == nil {
		return false
	}
	if truthyAny(acc.Payload["password_setup_ok"]) {
		return true
	}
	if truthyAny(acc.Payload["password_setup_remote_password_present"]) {
		return true
	}
	return false
}

// listAccountsUpTo 按 limit 取未归档账号，向上游 db.list_accounts(limit=..., archived=False) 对齐。
// store 单页上限 500，这里分页累加到 limit 为止。
func (s *Server) listAccountsUpTo(ctx context.Context, limit int) ([]domain.Account, error) {
	out := make([]domain.Account, 0, limit)
	page := 1
	for len(out) < limit {
		size := registrationAccountPageSize
		if remain := limit - len(out); remain < size {
			size = remain
		}
		if size < 1 {
			break
		}
		pageData, err := s.store.ListAccounts(ctx, store.AccountFilter{Page: page, PageSize: size})
		if err != nil {
			return nil, err
		}
		if len(pageData.Items) == 0 {
			break
		}
		out = append(out, pageData.Items...)
		if int64(page*registrationAccountPageSize) >= pageData.Total {
			break
		}
		page++
		if page > 1000 {
			break
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// handleRegistrationPending 对齐上游 GET /api/accounts/registration-pending。
func (s *Server) handleRegistrationPending(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	staleAfter := registrationPendingDefaultStaleMinutes
	if raw := strings.TrimSpace(q.Get("stale_after_minutes")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			fail(w, http.StatusBadRequest, "stale_after_minutes 非法")
			return
		}
		staleAfter = n
	}
	if staleAfter < 1 {
		staleAfter = 1
	}
	if staleAfter > registrationPendingMaxStaleMinutes {
		staleAfter = registrationPendingMaxStaleMinutes
	}

	limit := registrationPendingDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			fail(w, http.StatusBadRequest, "limit 非法")
			return
		}
		limit = n
	}
	if limit < 1 {
		limit = 1
	}
	if limit > registrationPendingMaxLimit {
		limit = registrationPendingMaxLimit
	}

	ctx := r.Context()
	accounts, err := s.listAccountsUpTo(ctx, limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取账号列表失败: "+err.Error())
		return
	}

	now := time.Now()
	items := make([]map[string]any, 0, 16)
	counts := map[string]any{
		"pending":                   0,
		"registering":               0,
		"interrupted":               0,
		"stale":                     0,
		"password_checkpoint_saved": 0,
	}
	registeringCount := 0
	interruptedCount := 0
	staleCount := 0
	checkpointCount := 0

	for _, acc := range accounts {
		h := classifyRegistrationHealth(acc, now, staleAfter)
		if !h.Pending {
			continue
		}
		var ageVal any
		if h.AgeSeconds != nil {
			ageVal = *h.AgeSeconds
		}
		items = append(items, map[string]any{
			"id":                        acc.ID,
			"email":                     acc.Email,
			"status":                    h.Status,
			"pending":                   h.Pending,
			"password_checkpoint_saved": h.PasswordCheckpointSaved,
			"updated_at":                h.UpdatedAt,
			"age_seconds":               ageVal,
			"stale":                     h.Stale,
			"reason":                    h.Reason,
			"recommended_action":        h.RecommendedAction,
		})
		switch h.Status {
		case "registering":
			registeringCount++
		case "interrupted":
			interruptedCount++
		}
		if h.Stale {
			staleCount++
		}
		if h.PasswordCheckpointSaved {
			checkpointCount++
		}
	}

	counts["pending"] = len(items)
	counts["registering"] = registeringCount
	counts["interrupted"] = interruptedCount
	counts["stale"] = staleCount
	counts["password_checkpoint_saved"] = checkpointCount

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"stale_after_minutes": staleAfter,
		"counts":              counts,
		"items":               items,
	})
}

// activeResumeAccountIDs 收集 pending/running/stopping 任务里占用的 resume_account_id，
// 对齐上游 submit_registration_resume 的 active_resume_ids 去重口径。
func (s *Server) activeResumeAccountIDs(ctx context.Context) map[int64]bool {
	out := map[int64]bool{}
	for _, status := range []string{"pending", "running", "stopping"} {
		for page := 1; page <= registrationJobScanMaxPages; page++ {
			jobs, total, err := s.store.ListJobs(ctx, status, page, registrationJobScanPageSize)
			if err != nil {
				return out
			}
			for i := range jobs {
				if rid, ok := registrationPayloadInt64(jobs[i].Payload, "resume_account_id"); ok && rid > 0 {
					out[rid] = true
				}
			}
			if len(jobs) == 0 || int64(page*registrationJobScanPageSize) >= total {
				break
			}
		}
	}
	return out
}

// registrationPayloadInt64 从 payload 里读整数，兼容 float64/int64/json.Number/string。
func registrationPayloadInt64(p map[string]any, key string) (int64, bool) {
	if p == nil {
		return 0, false
	}
	v, ok := p[key]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return 0, false
		}
		return n, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// handleRegistrationResume 对齐上游 POST /api/accounts/registration-resume。
func (s *Server) handleRegistrationResume(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any `json:"account_ids"`
		IDs        []any `json:"ids"`
		Workers    *int  `json:"workers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "account_ids 必须是数组")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是数组")
		return
	}
	if len(raw) > registrationResumeMaxIDs {
		fail(w, http.StatusBadRequest, "单次最多续跑 5000 个账号")
		return
	}
	workers := 1
	if body.Workers != nil {
		workers = *body.Workers
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}

	ctx := r.Context()
	ids, skipped := parseIDList(raw)

	started := make([]map[string]any, 0, len(ids))
	if len(ids) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"started_count": 0,
			"skipped_count": len(skipped),
			"jobs":          started,
			"skipped":       skipped,
			"workers":       workers,
		})
		return
	}

	emailSource := strings.TrimSpace(config.Current().EmailSource)
	if emailSource == "" {
		emailSource = "outlook"
	}
	activeResume := s.activeResumeAccountIDs(ctx)

	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		status := strings.ToLower(strings.TrimSpace(acc.Status))
		if status != "registering" && status != "interrupted" {
			skipped = append(skipped, map[string]any{
				"id":     id,
				"email":  acc.Email,
				"status": status,
				"reason": "状态不需要续跑",
			})
			continue
		}
		if !accountHasVerifiedPassword(acc) {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "没有已确认注册密码"})
			continue
		}
		if activeResume[id] {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "已有续跑任务"})
			continue
		}

		newIDs, serr := s.pool.SubmitWithOptions(ctx, job.JobOptions{
			Count:       1,
			EmailSource: emailSource,
			Email:       acc.Email,
			Payload: map[string]any{
				"resume_account_id": id,
				"resume_from":       "password_checkpoint_saved",
				"account_id":        id,
			},
		})
		if serr != nil || len(newIDs) == 0 {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "排队失败"})
			continue
		}
		activeResume[id] = true
		row := map[string]any{"id": newIDs[0], "account_id": id, "email": acc.Email, "resume_account_id": id}
		if j, jerr := s.store.GetJob(ctx, newIDs[0]); jerr == nil && j != nil {
			row = compactJob(*j)
			row["resume_account_id"] = id
			row["account_id"] = id
		}
		started = append(started, row)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"started_count": len(started),
		"skipped_count": len(skipped),
		"jobs":          started,
		"skipped":       skipped,
		"workers":       workers,
	})
}
