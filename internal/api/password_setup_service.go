package api

// 批量补设密码服务：对齐上游 core/password_setup_service.py 的
// enqueue / _run / is_running / is_queued / _snapshot_missing_password_ids /
// _run_missing_password_batch / start_missing_password_batch / cancel_missing_password_batch，
// 以及 webui/app.py:929-1040 的四个接口。
//
// 上游用 ThreadPoolExecutor(max_workers=1) 串行 + _RUNNING/_QUEUED 进程内集合；
// 这里用 Server 上的 pwMu + pwRunning/pwQueued + 单 goroutine 串行，语义一致。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/store"
)

const (
	passwordSetupBulkMax   = 500
	passwordSetupQueueCap  = 50
	passwordSetupPerAcctTO = 4 * time.Minute
)

// passwordMissingBatchState 对齐上游 _BATCH_STATE 的字段集合。
type passwordMissingBatchState struct {
	Status           string `json:"status"`
	Total            int    `json:"total"`
	Processed        int    `json:"processed"`
	Succeeded        int    `json:"succeeded"`
	Failed           int    `json:"failed"`
	Skipped          int    `json:"skipped"`
	CurrentAccountID *int64 `json:"current_account_id"`
	StartedAt        string `json:"started_at"`
	CompletedAt      string `json:"completed_at"`
	Message          string `json:"message"`
}

func idlePasswordMissingBatchState() *passwordMissingBatchState {
	return &passwordMissingBatchState{Status: "idle"}
}

// passwordSetupMark / passwordSetupClear 维护进程内排队/执行集合。
func (s *Server) passwordSetupMark(queued, running bool, id int64) {
	s.pwMu.Lock()
	defer s.pwMu.Unlock()
	if s.pwRunning == nil {
		s.pwRunning = map[int64]bool{}
	}
	if s.pwQueued == nil {
		s.pwQueued = map[int64]bool{}
	}
	if queued {
		s.pwQueued[id] = true
	} else {
		delete(s.pwQueued, id)
	}
	if running {
		s.pwRunning[id] = true
	} else {
		delete(s.pwRunning, id)
	}
}

// passwordSetupIsRunning 对齐上游 is_running。
func (s *Server) passwordSetupIsRunning(id int64) bool {
	s.pwMu.Lock()
	defer s.pwMu.Unlock()
	return s.pwRunning[id]
}

// passwordSetupIsQueued 对齐上游 is_queued：只算真实排队，不含服务重启后遗留的 queued 状态。
func (s *Server) passwordSetupIsQueued(id int64) bool {
	s.pwMu.Lock()
	defer s.pwMu.Unlock()
	return s.pwQueued[id] && !s.pwRunning[id]
}

// -----------------------------------------------------------------------------
// 单号执行：对齐上游 _run(account_id, trigger, missing_only)
// -----------------------------------------------------------------------------

// runPasswordSetup 给一个账号补设新密码并强制用新密码重新登录验收。
// 返回 (category, message)，category ∈ {success, skipped, failed}。
func (s *Server) runPasswordSetup(ctx context.Context, acc *domain.Account, trigger string, missingOnly bool) (string, string) {
	if acc == nil || acc.Payload == nil {
		return "failed", "账号不存在"
	}
	id := acc.ID
	if missingOnly && accountHasVerifiedPassword(acc) {
		return "skipped", "账号已有登录密码"
	}

	s.passwordSetupMark(false, true, id)
	defer s.passwordSetupMark(false, false, id)

	appendPasswordSetupLog(id, fmt.Sprintf("开始补设密码：%s trigger=%s", acc.Email, trigger), true)
	s.appendLiveLog(acc.Email, fmt.Sprintf("[补设密码] 账号 #%d 开始（trigger=%s）", id, trigger))

	ctx, cancel := context.WithTimeout(ctx, passwordSetupPerAcctTO)
	defer cancel()

	setPwState := func(status, message, errText string, verified bool) {
		fresh, _ := s.store.GetAccount(context.Background(), id)
		if fresh == nil {
			fresh = acc
		}
		if fresh.Payload == nil {
			fresh.Payload = map[string]any{}
		}
		fresh.Payload["password_setup_status"] = status
		fresh.Payload["password_setup_message"] = message
		fresh.Payload["password_setup_login_verified"] = verified
		if errText != "" {
			fresh.Payload["password_setup_error"] = errText
		} else {
			delete(fresh.Payload, "password_setup_error")
		}
		if status == "queued" {
			fresh.Payload["password_setup_queued_at"] = nowRFC3339()
		} else if status == "running" {
			fresh.Payload["password_setup_started_at"] = nowRFC3339()
		} else if status == "success" || status == "failed" || status == "verification_failed" || status == "cancelled" || status == "expired" {
			fresh.Payload["password_setup_completed_at"] = nowRFC3339()
		}
		_, _ = s.store.InsertAccount(context.Background(), *fresh)
	}

	setPwState("running", "正在补设密码", "", false)

	newPassword := generateRegistrationPassword()
	at := extractAccountSecret(acc, "access_token")
	dev := accountDeviceID(acc)
	proxy := s.getProxyForAccount(acc)
	image := accountBrowserProfile(acc, proxy)
	storeAccountBrowserProfile(acc, image)

	// 有 AT 就直接协议改密；没有 AT 先刷一次换到 AT。
	if strings.TrimSpace(at) == "" {
		appendPasswordSetupLog(id, "账号无可用 AT，先刷新一次换取 Access Token", false)
		s.appendLiveLog(acc.Email, fmt.Sprintf("[补设密码] 账号 #%d 无 AT，先刷新", id))
		freshAT, err := s.refreshAccountToken(ctx, acc)
		if err != nil {
			msg := "刷新 AT 失败: " + err.Error()
			setPwState("failed", "补设密码失败：账号无法登录", err.Error(), false)
			appendPasswordSetupLog(id, "失败："+msg, false)
			return "failed", msg
		}
		at = freshAT
	}

	appendPasswordSetupLog(id, "已取得 AT，开始协议提交新密码", false)
	if err := protocol.SetPasswordWithAccessTokenUsingProfile(ctx, at, dev, proxy, newPassword, image); err != nil {
		errText := err.Error()
		msg := "提交新密码失败: " + errText
		setPwState("failed", "补设密码失败：新密码提交未成功", errText, false)
		appendPasswordSetupLog(id, "失败："+msg, false)
		s.appendLiveLog(acc.Email, fmt.Sprintf("[补设密码] 账号 #%d %s", id, msg))
		return "failed", msg
	}
	appendPasswordSetupLog(id, "新密码已提交，开始用新密码强制登录验收", false)

	// 强制用新密码重新登录验收（纯密码链路，不认 session_token）。
	acc.Payload["password"] = newPassword
	acc.Payload["registration_password"] = newPassword
	_, _ = s.store.InsertAccount(ctx, *acc)

	verifyAT, verr := s.verifyPasswordViaProtocol(ctx, acc, newPassword)
	if verr != nil {
		errText := verr.Error()
		wrong := isWrongPasswordError(errText)
		status := "verification_pending"
		msg := "登录验收失败（密码真伪未确定）: " + truncateForLog(errText, 120)
		if wrong {
			status = "verification_failed"
			msg = "密码错误，登录失败"
		}
		setPwState(status, msg, errText, false)
		appendPasswordSetupLog(id, "验收失败："+errText, false)
		s.appendLiveLog(acc.Email, fmt.Sprintf("[补设密码] 账号 #%d 验收失败: %s", id, errText))
		return "failed", msg
	}

	fresh, _ := s.store.GetAccount(ctx, id)
	if fresh == nil {
		fresh = acc
	}
	if fresh.Payload == nil {
		fresh.Payload = map[string]any{}
	}
	fresh.Payload["password"] = newPassword
	fresh.Payload["registration_password"] = newPassword
	fresh.Payload["password_setup_status"] = "success"
	fresh.Payload["password_setup_message"] = "补设密码完成，已通过登录凭据阶段验收"
	fresh.Payload["password_setup_login_verified"] = true
	fresh.Payload["password_setup_ok"] = true
	fresh.Payload["password_setup_verified_at"] = nowRFC3339()
	fresh.Payload["password_setup_completed_at"] = nowRFC3339()
	delete(fresh.Payload, "password_setup_error")
	delete(fresh.Payload, "password_setup_candidate")
	if verifyAT != "" {
		fresh.Payload["access_token"] = verifyAT
	}
	_, _ = s.store.InsertAccount(ctx, *fresh)
	appendPasswordSetupLog(id, "完成：新密码已通过登录验收并写回账号记录", false)
	s.appendLiveLog(acc.Email, fmt.Sprintf("[补设密码] 账号 #%d 补设成功", id))
	return "success", ""
}

// accountHasVerifiedPassword 对齐上游 db.has_registration_password(verified_only=True)。
// 只认独立登录验收标志，候选密码/远端已提交都不算。
func accountHasVerifiedPassword(acc *domain.Account) bool {
	if acc == nil || acc.Payload == nil {
		return false
	}
	pw := ""
	for _, key := range []string{"registration_password", "password"} {
		if v, ok := acc.Payload[key].(string); ok && strings.TrimSpace(v) != "" {
			pw = strings.TrimSpace(v)
			break
		}
	}
	if extra, ok := acc.Payload["extra"].(map[string]any); ok && pw == "" {
		if v, ok := extra["registration_password"].(string); ok {
			pw = strings.TrimSpace(v)
		}
	}
	if pw == "" {
		return false
	}
	if truthyAny(acc.Payload["password_setup_login_verified"]) ||
		truthyAny(acc.Payload["password_change_login_verified"]) ||
		truthyAny(acc.Payload["registration_password_verified"]) {
		return true
	}
	if extra, ok := acc.Payload["extra"].(map[string]any); ok {
		return truthyAny(extra["registration_password_verified"])
	}
	return false
}

// truthyAny 把 payload 里松散的布尔表达归一。
func truthyAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	}
	return false
}

// -----------------------------------------------------------------------------
// 入队 + 后台执行
// -----------------------------------------------------------------------------

// enqueuePasswordSetup 对齐上游 enqueue。返回 {accepted|busy|error}。
func (s *Server) enqueuePasswordSetup(ctx context.Context, acc *domain.Account, trigger string, missingOnly bool) map[string]any {
	if acc == nil {
		return map[string]any{"accepted": false, "error": "账号不存在"}
	}
	if strings.TrimSpace(acc.Email) == "" {
		return map[string]any{"accepted": false, "error": "账号邮箱为空"}
	}
	if missingOnly && accountHasVerifiedPassword(acc) {
		return map[string]any{"accepted": false, "skipped": true, "reason": "password_present", "error": "账号已有登录密码"}
	}

	s.pwMu.Lock()
	if s.pwRunning == nil {
		s.pwRunning = map[int64]bool{}
	}
	if s.pwQueued == nil {
		s.pwQueued = map[int64]bool{}
	}
	if s.pwRunning[acc.ID] || s.pwQueued[acc.ID] {
		s.pwMu.Unlock()
		return map[string]any{"accepted": false, "busy": true, "error": "该账号正在补设密码"}
	}
	if len(s.pwQueued)+len(s.pwRunning) >= passwordSetupQueueCap {
		s.pwMu.Unlock()
		return map[string]any{"accepted": false, "queue_full": true, "error": "补设密码队列已满"}
	}
	s.pwQueued[acc.ID] = true
	s.pwMu.Unlock()

	// 先写排队状态，与上游 update_account_password_setup(status="queued") 等价。
	acc.Payload["password_setup_status"] = "queued"
	acc.Payload["password_setup_message"] = "已入队，等待后台补设密码"
	acc.Payload["password_setup_queued_at"] = nowRFC3339()
	if _, err := s.store.InsertAccount(ctx, *acc); err != nil {
		s.passwordSetupMark(false, false, acc.ID)
		return map[string]any{"accepted": false, "error": "排队状态未写入: " + err.Error()}
	}

	go func(id int64) {
		defer s.passwordSetupMark(false, false, id)
		bg, cancel := context.WithTimeout(context.Background(), passwordSetupPerAcctTO+30*time.Second)
		defer cancel()
		fresh, err := s.store.GetAccount(bg, id)
		if err != nil || fresh == nil {
			appendPasswordSetupLog(id, "账号不存在，跳过", false)
			return
		}
		s.passwordSetupMark(false, true, id)
		_, _ = s.runPasswordSetup(bg, fresh, trigger, missingOnly)
	}(acc.ID)

	return map[string]any{"accepted": true, "log_path": passwordSetupLogPath(acc.ID)}
}

// -----------------------------------------------------------------------------
// HTTP：批量补设密码
// -----------------------------------------------------------------------------

// handlePasswordSetupBulk 对齐上游 POST /api/accounts/password-setup-bulk。
// 400 account_ids 必须是非空数组 / 400 单次最多提交 500 个账号 / 202 汇总。
func (s *Server) handlePasswordSetupBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []json.RawMessage `json:"account_ids"`
		IDs        []json.RawMessage `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > passwordSetupBulkMax {
		fail(w, http.StatusBadRequest, "单次最多提交 500 个账号")
		return
	}

	anyIDs := make([]any, 0, len(raw))
	for _, item := range raw {
		anyIDs = append(anyIDs, item)
	}
	ids, skipped := parseIDList(anyIDs)

	started := []map[string]any{}
	busy := []map[string]any{}
	failed := []map[string]any{}

	ctx := r.Context()
	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		email := strings.TrimSpace(acc.Email)
		if email == "" {
			skipped = append(skipped, map[string]any{"id": id, "reason": "邮箱为空"})
			continue
		}
		queued := s.enqueuePasswordSetup(ctx, acc, "manual_bulk", false)
		item := map[string]any{"id": id, "email": email}
		for k, v := range queued {
			item[k] = v
		}
		if ok, _ := queued["accepted"].(bool); ok {
			item["status"] = "queued"
			started = append(started, item)
		} else if b, _ := queued["busy"].(bool); b {
			busy = append(busy, item)
		} else {
			failed = append(failed, item)
		}
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":            true,
		"started":       started,
		"started_count": len(started),
		"busy":          busy,
		"busy_count":    len(busy),
		"skipped":       skipped,
		"skipped_count": len(skipped),
		"failed":        failed,
		"failed_count":  len(failed),
	})
}

// handlePasswordSetupBulkStatus 对齐上游 GET /api/accounts/password-setup-bulk/status。
// 判定顺序：running → queued → raw queued(重启中断) → success → failed → other。
func (s *Server) handlePasswordSetupBulkStatus(w http.ResponseWriter, r *http.Request) {
	rawIDs := strings.TrimSpace(r.URL.Query().Get("account_ids"))
	ids := []int64{}
	seen := map[int64]bool{}
	for _, part := range strings.Split(rawIDs, ",") {
		n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		ids = append(ids, n)
		if len(ids) >= passwordSetupBulkMax {
			break
		}
	}
	if len(ids) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须包含有效账号 ID")
		return
	}

	items := make([]map[string]any, 0, len(ids))
	counts := map[string]int{"queued": 0, "running": 0, "success": 0, "failed": 0, "other": 0}
	ctx := r.Context()
	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		state, message := "", ""
		if err != nil || acc == nil {
			state, message = "failed", "账号不存在"
		} else {
			rawState := strings.ToLower(strings.TrimSpace(payloadString(acc.Payload, "password_setup_status")))
			message = payloadString(acc.Payload, "password_setup_message")
			if message == "" {
				message = payloadString(acc.Payload, "password_setup_error")
			}
			switch {
			case s.passwordSetupIsRunning(id):
				state = "running"
			case s.passwordSetupIsQueued(id):
				state = "queued"
			case rawState == "queued":
				state, message = "failed", "任务因服务重启已中断，请重新提交"
			case (rawState == "success" || rawState == "checkpoint_saved") && truthyAny(acc.Payload["password_setup_login_verified"]):
				state = "success"
			case rawState == "failed" || rawState == "verification_failed" || rawState == "cancelled" || rawState == "expired":
				state = "failed"
			default:
				state = "other"
			}
		}
		counts[state]++
		items = append(items, map[string]any{"id": id, "status": state, "message": message})
	}

	active := counts["queued"] + counts["running"]
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"total":   len(items),
		"active":  active,
		"queued":  counts["queued"],
		"running": counts["running"],
		"success": counts["success"],
		"failed":  counts["failed"],
		"other":   counts["other"],
		"items":   items,
	})
}

// -----------------------------------------------------------------------------
// HTTP：全量补密码
// -----------------------------------------------------------------------------

// handlePasswordSetupAllMissing 对齐上游 POST /api/accounts/password-setup-all-missing。
func (s *Server) handlePasswordSetupAllMissing(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IncludeArchived bool `json:"include_archived"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)

	ids, err := s.snapshotMissingPasswordIDs(r.Context(), body.IncludeArchived)
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成未设密码账号快照失败: "+err.Error())
		return
	}

	s.pwMu.Lock()
	if s.pwBatch == nil {
		s.pwBatch = idlePasswordMissingBatchState()
	}
	if s.pwBatch.Status == "starting" || s.pwBatch.Status == "running" || s.pwBatch.Status == "stopping" {
		state := *s.pwBatch
		s.pwMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "accepted": false, "status": state,
		})
		return
	}
	batch := &passwordMissingBatchState{
		Status:    "starting",
		Total:     len(ids),
		StartedAt: nowRFC3339(),
		Message:   "已生成未设密码账号快照",
	}
	if len(ids) == 0 {
		batch.Status = "completed"
		batch.CompletedAt = nowRFC3339()
		batch.Message = "没有需要补设密码的账号"
	}
	s.pwBatch = batch
	stateSnapshot := *batch
	s.pwMu.Unlock()

	if len(ids) > 0 {
		go s.runMissingPasswordBatch(ids)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "accepted": true, "started": len(ids) > 0, "status": stateSnapshot,
	})
}

// snapshotMissingPasswordIDs 对齐上游 _snapshot_missing_password_ids：
// 只按 ChatGPT registration_password 判断，逐页扫描。
func (s *Server) snapshotMissingPasswordIDs(ctx context.Context, includeArchived bool) ([]int64, error) {
	ids := []int64{}
	page := 1
	for {
		pageData, err := s.store.ListAccounts(ctx, store.AccountFilter{
			Archived: includeArchived,
			Page:     page,
			PageSize: 200,
		})
		if err != nil {
			return nil, err
		}
		for i := range pageData.Items {
			acc := pageData.Items[i]
			if strings.TrimSpace(acc.Email) == "" {
				continue
			}
			if !accountHasVerifiedPassword(&acc) {
				ids = append(ids, acc.ID)
			}
		}
		if len(pageData.Items) == 0 || int64(page*200) >= pageData.Total {
			break
		}
		page++
		if page > 500 {
			break
		}
	}
	return ids, nil
}

// runMissingPasswordBatch 对齐上游 _run_missing_password_batch：严格串行。
func (s *Server) runMissingPasswordBatch(accountIDs []int64) {
	s.pwMu.Lock()
	if s.pwBatch == nil {
		s.pwBatch = idlePasswordMissingBatchState()
	}
	s.pwBatch.Status = "running"
	s.pwBatch.Total = len(accountIDs)
	s.pwBatch.Message = "正在逐个补设密码"
	s.pwMu.Unlock()

	ctx := context.Background()
	for _, id := range accountIDs {
		s.pwMu.Lock()
		stop := s.pwBatch != nil && s.pwBatch.Status == "stopping"
		if !stop {
			cid := id
			s.pwBatch.CurrentAccountID = &cid
		}
		s.pwMu.Unlock()
		if stop {
			break
		}

		category := "failed"
		acc, err := s.store.GetAccount(ctx, id)
		if err == nil && acc != nil {
			category, _ = s.runPasswordSetup(ctx, acc, "all_missing", true)
		}

		s.pwMu.Lock()
		if s.pwBatch != nil {
			s.pwBatch.Processed++
			switch category {
			case "success":
				s.pwBatch.Succeeded++
			case "skipped":
				s.pwBatch.Skipped++
			default:
				s.pwBatch.Failed++
			}
		}
		s.pwMu.Unlock()
	}

	s.pwMu.Lock()
	if s.pwBatch != nil {
		stopped := s.pwBatch.Status == "stopping"
		if stopped {
			s.pwBatch.Status = "cancelled"
			s.pwBatch.Message = "已停止继续入队；当前任务执行完毕"
		} else {
			s.pwBatch.Status = "completed"
			s.pwBatch.Message = "全部未设密码账号处理完成"
		}
		s.pwBatch.CurrentAccountID = nil
		s.pwBatch.CompletedAt = nowRFC3339()
	}
	s.pwMu.Unlock()
}

// handlePasswordSetupAllMissingStatus 对齐上游 GET .../status。
func (s *Server) handlePasswordSetupAllMissingStatus(w http.ResponseWriter, r *http.Request) {
	s.pwMu.Lock()
	state := idlePasswordMissingBatchState()
	if s.pwBatch != nil {
		copied := *s.pwBatch
		state = &copied
	}
	s.pwMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"status":             state.Status,
		"total":              state.Total,
		"processed":          state.Processed,
		"succeeded":          state.Succeeded,
		"failed":             state.Failed,
		"skipped":            state.Skipped,
		"current_account_id": state.CurrentAccountID,
		"started_at":         state.StartedAt,
		"completed_at":       state.CompletedAt,
		"message":            state.Message,
	})
}

// handlePasswordSetupAllMissingCancel 对齐上游 cancel_missing_password_batch。
func (s *Server) handlePasswordSetupAllMissingCancel(w http.ResponseWriter, r *http.Request) {
	s.pwMu.Lock()
	active := s.pwBatch != nil && (s.pwBatch.Status == "starting" || s.pwBatch.Status == "running" || s.pwBatch.Status == "stopping")
	if active {
		s.pwBatch.Status = "stopping"
		s.pwBatch.Message = "停止请求已记录；不再提交后续账号"
	}
	state := idlePasswordMissingBatchState()
	if s.pwBatch != nil {
		copied := *s.pwBatch
		state = &copied
	}
	s.pwMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"accepted":           active,
		"status":             state.Status,
		"total":              state.Total,
		"processed":          state.Processed,
		"succeeded":          state.Succeeded,
		"failed":             state.Failed,
		"skipped":            state.Skipped,
		"current_account_id": state.CurrentAccountID,
		"started_at":         state.StartedAt,
		"completed_at":       state.CompletedAt,
		"message":            state.Message,
	})
}
