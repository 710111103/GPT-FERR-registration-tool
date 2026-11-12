package api

// 密码候选验收批量服务：对齐上游 core/password_setup_service.py 的
// enqueue_candidate_verification_batch / _run_candidate_verification_batch /
// candidate_verification_batch_status 三段，以及 webui/app.py 的两个接口。
//
// 上游是 ThreadPoolExecutor(max_workers=1) + 模块级 _VERIFY_BATCH_STATE；
// 这里用「Server 上的互斥量 + 单实例状态 + 单 goroutine 串行」等价落地。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
)

const (
	verifyBatchLimit    = 100
	verifyPerAccountTTL = 5 * time.Minute
)

// verifyBatchResult 对齐上游 results[{id, category, error}]。
type verifyBatchResult struct {
	ID       int64  `json:"id"`
	Category string `json:"category"`
	Error    string `json:"error"`
}

// verifyBatchState 对齐上游 _VERIFY_BATCH_STATE 的字段名与语义。
type verifyBatchState struct {
	Status           string              `json:"status"`
	Total            int                 `json:"total"`
	Processed        int                 `json:"processed"`
	CurrentAccountID *int64              `json:"current_account_id"`
	SuccessCount     int                 `json:"success_count"`
	FailedCount      int                 `json:"failed_count"`
	SkippedCount     int                 `json:"skipped_count"`
	Results          []verifyBatchResult `json:"results"`
}

// idleVerifyBatchState 对齐上游初始值。
func idleVerifyBatchState() *verifyBatchState {
	return &verifyBatchState{Status: "idle", Results: []verifyBatchResult{}}
}

// -----------------------------------------------------------------------------
// 账号级密码补设日志（与待办 4/5 共用）
// -----------------------------------------------------------------------------

// passwordSetupLogPath 对齐上游 log_path():
// 注册日志/password-setup/account-<id>.log，Go 侧统一落在 <root>/logs/password-setup/。
func passwordSetupLogPath(accountID int64) string {
	return filepath.Join(config.Current().Root, "logs", "password-setup", fmt.Sprintf("account-%d.log", accountID))
}

// appendPasswordSetupLog 对齐上游 _append_log(): "%H:%M:%S [INFO] line"，clear 为真时覆盖。
func appendPasswordSetupLog(accountID int64, line string, clear bool) {
	path := passwordSetupLogPath(accountID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if clear {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s [INFO] %s\n", time.Now().Format("15:04:05"), line)
}

// passwordSetupLogPathForAccount 读取账号日志正文；缺失时返回空串（对齐上游 log_path 不存在的情形）。
func passwordSetupLogBody(accountID int64) string {
	data, err := os.ReadFile(passwordSetupLogPath(accountID))
	if err != nil || len(data) == 0 {
		return ""
	}
	return string(data)
}

// -----------------------------------------------------------------------------
// 候选密码解析：对齐上游 verify_account_candidate_password 的取密码优先级
// password_setup_candidate → password → extra.registration_password → registration_password
// -----------------------------------------------------------------------------

func candidatePasswordForAccount(acc *domain.Account) string {
	if acc == nil || acc.Payload == nil {
		return ""
	}
	for _, key := range []string{"password_setup_candidate", "password", "registration_password"} {
		if v, ok := acc.Payload[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if extra, ok := acc.Payload["extra"].(map[string]any); ok {
		if v, ok := extra["registration_password"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// isWrongPasswordError 对齐上游 "密码错误" in err / "incorrect email address or password" 判定。
func isWrongPasswordError(msg string) bool {
	if msg == "" {
		return false
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "incorrect email address or password") {
		return true
	}
	for _, marker := range []string{"密码错误", "账号或密码错误", "邮箱或密码错误", "密码不正确"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// 单号验收：对齐上游 verify_account_candidate_password（protocol_only 分支）
// -----------------------------------------------------------------------------

// verifyAccountCandidatePassword 执行一次登录验收，成功即把候选密码转正并刷新 AT。
// 返回 category ∈ {success, skipped, wrong_password, failed} 与给前端看的短文案。
func (s *Server) verifyAccountCandidatePassword(ctx context.Context, accountID int64) (string, string) {
	acc, err := s.store.GetAccount(ctx, accountID)
	if err != nil || acc == nil {
		return "failed", "登录验收失败，查看账号密码状态"
	}
	pwd := candidatePasswordForAccount(acc)
	if pwd == "" {
		appendPasswordSetupLog(accountID, "跳过：该账号未找到待验证的候选密码，请先输入密码", false)
		return "skipped", "未找到候选密码"
	}

	email := acc.Email
	appendPasswordSetupLog(accountID, fmt.Sprintf("开始对候选密码执行登录验证验收: account_id=%d, email=%s", accountID, email), false)
	s.appendLiveLog(email, fmt.Sprintf("[密码验收] 账号 #%d 开始候选密码登录验收", accountID))

	acc.Payload["password"] = pwd
	acc.Payload["registration_password"] = pwd
	_, _ = s.store.InsertAccount(ctx, *acc)

	perCtx, cancel := context.WithTimeout(ctx, verifyPerAccountTTL)
	defer cancel()
	at, refErr := s.refreshAccountToken(perCtx, acc)
	if refErr != nil {
		msg := refErr.Error()
		fresh, _ := s.store.GetAccount(ctx, accountID)
		if fresh == nil {
			fresh = acc
		}
		if fresh.Payload == nil {
			fresh.Payload = map[string]any{}
		}
		if isWrongPasswordError(msg) {
			fresh.Payload["password_setup_status"] = "verification_failed"
			fresh.Payload["password_setup_login_verified"] = false
			fresh.Payload["password_setup_candidate"] = pwd
			fresh.Payload["password_setup_message"] = "密码错误，登录失败"
			fresh.Payload["password_setup_error"] = msg
			_, _ = s.store.InsertAccount(ctx, *fresh)
			appendPasswordSetupLog(accountID, "登录验证验收失败：密码错误", false)
			return "wrong_password", "密码错误"
		}
		fresh.Payload["password_setup_status"] = "verification_pending"
		fresh.Payload["password_setup_login_verified"] = false
		fresh.Payload["password_setup_candidate"] = pwd
		fresh.Payload["password_setup_message"] = "登录验收失败（密码真伪未确定）: " + truncateForLog(msg, 120)
		fresh.Payload["password_setup_error"] = msg
		_, _ = s.store.InsertAccount(ctx, *fresh)
		appendPasswordSetupLog(accountID, "登录验证验收失败: "+msg, false)
		return "failed", "登录验收失败，查看账号密码状态"
	}

	fresh, _ := s.store.GetAccount(ctx, accountID)
	if fresh == nil {
		fresh = acc
	}
	if fresh.Payload == nil {
		fresh.Payload = map[string]any{}
	}
	fresh.Payload["password"] = pwd
	fresh.Payload["registration_password"] = pwd
	fresh.Payload["password_setup_status"] = "success"
	fresh.Payload["password_setup_login_verified"] = true
	fresh.Payload["password_setup_message"] = "登录验收通过"
	fresh.Payload["password_setup_error"] = ""
	delete(fresh.Payload, "password_setup_candidate")
	if at != "" {
		fresh.Payload["access_token"] = at
	}
	fresh.Payload["password_setup_verified_at"] = nowRFC3339()
	_, _ = s.store.InsertAccount(ctx, *fresh)
	appendPasswordSetupLog(accountID, "验证成功：候选密码已转正为正式密码，AT 已同步刷新", false)
	s.appendLiveLog(email, fmt.Sprintf("[密码验收] 账号 #%d 登录验收通过，候选密码已转正", accountID))
	return "success", ""
}

// -----------------------------------------------------------------------------
// 批量入队 + 状态
// -----------------------------------------------------------------------------

// enqueueCandidateVerificationBatch 对齐上游 enqueue_candidate_verification_batch。
// accepted=false 表示已有任务在跑（HTTP 409）。
func (s *Server) enqueueCandidateVerificationBatch(ids []int64) map[string]any {
	if len(ids) == 0 {
		return map[string]any{"accepted": false, "error": "没有可验证的账号"}
	}
	if len(ids) > verifyBatchLimit {
		ids = ids[:verifyBatchLimit]
	}
	s.verifyMu.Lock()
	if s.verifyBatch == nil {
		s.verifyBatch = idleVerifyBatchState()
	}
	if s.verifyBatch.Status == "queued" || s.verifyBatch.Status == "running" {
		s.verifyMu.Unlock()
		return map[string]any{"accepted": false, "error": "已有密码验收任务正在运行"}
	}
	s.verifyBatch = &verifyBatchState{
		Status:    "queued",
		Total:     len(ids),
		Processed: 0,
		Results:   []verifyBatchResult{},
	}
	s.verifyMu.Unlock()

	go s.runCandidateVerificationBatch(ids)
	return map[string]any{"accepted": true, "total": len(ids), "status": "queued"}
}

// runCandidateVerificationBatch 对齐上游 _run_candidate_verification_batch：严格串行。
func (s *Server) runCandidateVerificationBatch(ids []int64) {
	s.verifyMu.Lock()
	if s.verifyBatch == nil {
		s.verifyBatch = idleVerifyBatchState()
	}
	s.verifyBatch.Status = "running"
	s.verifyMu.Unlock()

	ctx := context.Background()
	for _, aid := range ids {
		s.verifyMu.Lock()
		id := aid
		s.verifyBatch.CurrentAccountID = &id
		s.verifyMu.Unlock()

		category, errText := "failed", "登录验收任务异常，查看账号日志"
		func() {
			perCtx, cancel := context.WithTimeout(ctx, verifyPerAccountTTL)
			defer cancel()
			category, errText = s.verifyAccountCandidatePassword(perCtx, aid)
		}()

		s.verifyMu.Lock()
		st := s.verifyBatch
		st.Processed++
		st.Results = append(st.Results, verifyBatchResult{ID: aid, Category: category, Error: errText})
		switch category {
		case "success":
			st.SuccessCount++
		case "skipped":
			st.SkippedCount++
		default:
			st.FailedCount++
		}
		s.verifyMu.Unlock()
	}

	s.verifyMu.Lock()
	if s.verifyBatch != nil {
		s.verifyBatch.CurrentAccountID = nil
		s.verifyBatch.Status = "completed"
	}
	s.verifyMu.Unlock()
}

// candidateVerificationBatchStatus 返回状态深拷贝。
func (s *Server) candidateVerificationBatchStatus() verifyBatchState {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if s.verifyBatch == nil {
		return *idleVerifyBatchState()
	}
	out := *s.verifyBatch
	out.Results = make([]verifyBatchResult, len(s.verifyBatch.Results))
	copy(out.Results, s.verifyBatch.Results)
	if out.Results == nil {
		out.Results = []verifyBatchResult{}
	}
	return out
}

// -----------------------------------------------------------------------------
// HTTP 端点
// -----------------------------------------------------------------------------

// handleVerifyPasswordsBulk 对齐上游 POST /api/accounts/verify-passwords-bulk。
// 400 请提供有效 account_ids / 400 账号 ID 必须是整数 / 409 已有任务 / 202 已入队。
func (s *Server) handleVerifyPasswordsBulk(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&raw); err != nil {
		fail(w, http.StatusBadRequest, "请提供有效 account_ids")
		return
	}
	field, ok := raw["account_ids"]
	if !ok || len(field) == 0 || string(field) == "null" {
		fail(w, http.StatusBadRequest, "请提供有效 account_ids")
		return
	}
	var items []json.RawMessage
	if err := json.Unmarshal(field, &items); err != nil {
		fail(w, http.StatusBadRequest, "请提供有效 account_ids")
		return
	}
	if len(items) == 0 {
		fail(w, http.StatusBadRequest, "请提供有效 account_ids")
		return
	}
	seen := map[int64]bool{}
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		text := strings.TrimSpace(string(item))
		var f float64
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			if jerr := json.Unmarshal(item, &f); jerr != nil || f != float64(int64(f)) {
				fail(w, http.StatusBadRequest, "账号 ID 必须是整数")
				return
			}
			parsed = int64(f)
		}
		if seen[parsed] {
			continue
		}
		seen[parsed] = true
		ids = append(ids, parsed)
		if len(ids) >= verifyBatchLimit {
			break
		}
	}
	result := s.enqueueCandidateVerificationBatch(ids)
	payload := map[string]any{}
	for k, v := range result {
		payload[k] = v
	}
	payload["ok"] = result["accepted"]
	if okv, _ := result["accepted"].(bool); !okv {
		writeJSON(w, http.StatusConflict, payload)
		return
	}
	writeJSON(w, http.StatusAccepted, payload)
}

// handleVerifyPasswordsBulkStatus 对齐上游 GET /api/accounts/verify-passwords-bulk/status。
func (s *Server) handleVerifyPasswordsBulkStatus(w http.ResponseWriter, r *http.Request) {
	flat := flattenVerifyBatchState(s.candidateVerificationBatchStatus())
	flat["ok"] = true
	writeJSON(w, http.StatusOK, flat)
}

// flattenVerifyBatchState 把结构体摊平进 map，保持字段名与上游一致。
func flattenVerifyBatchState(st verifyBatchState) map[string]any {
	return map[string]any{
		"status":             st.Status,
		"total":              st.Total,
		"processed":          st.Processed,
		"current_account_id": st.CurrentAccountID,
		"success_count":      st.SuccessCount,
		"failed_count":       st.FailedCount,
		"skipped_count":      st.SkippedCount,
		"results":            st.Results,
	}
}
