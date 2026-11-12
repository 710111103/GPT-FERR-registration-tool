package api

// Codex 授权补跑服务：对齐上游 core/codex_retry_service.py + webui/app.py
// 的 /api/codex/* 六个接口，以及 core/manual_otp.py 的手动验证码通道。
// 上游是 Python 线程池 + 进程内 set 占位；这里用 goroutine + map 落地。

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
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/codex"
	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/manualotp"
	"github.com/turb/gpt-register/internal/store"
)

const (
	codexStatusRetrying = "retrying"
	codexMaxBulk        = 500
	codexMaxWorkers     = 16
	codexStaleRunning   = 15 * time.Minute
	codexStaleTerminal  = 30 * time.Second
)

// codexRetryState 是一个邮箱的补跑占位。
type codexRetryState struct {
	startedAt time.Time
	cancel    context.CancelFunc
	running   bool
	stopReq   bool
}

// -----------------------------------------------------------------------------
// 基础辅助
// -----------------------------------------------------------------------------

func codexKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// codexSafeEmail 把邮箱里的路径分隔符替换掉，避免日志文件名带出目录穿越。
// 对齐上游 log_path()：只替换 / \ : 三个字符。
func codexSafeEmail(email string) string {
	s := strings.TrimSpace(email)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

// codexRetryLogPath 对齐上游 _LOG_DIR / f"codex-retry-{safe}.log"。
// 上游放在仓库根目录下的「注册日志」；这里统一放 <root>/logs。
func codexRetryLogPath(email string) string {
	return filepath.Join(config.Current().Root, "logs", "codex-retry-"+codexSafeEmail(email)+".log")
}

func orDefaultDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func codexMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// payloadString 从 payload 里安全取字符串。
func payloadString(p map[string]any, key string) string {
	if p == nil {
		return ""
	}
	v, ok := p[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// -----------------------------------------------------------------------------
// 日志写入
// -----------------------------------------------------------------------------

// appendCodexLog 追加一行日志，格式对齐上游 logging.Formatter：
// "%H:%M:%S [LEVEL] message"。
func (s *Server) appendCodexLog(email, level, msg string) {
	if codexKey(email) == "" {
		return
	}
	path := codexRetryLogPath(email)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s [%s] %s\n", time.Now().Format("15:04:05"), level, msg)
}

// clearCodexLog 对齐上游 path.write_text("")。
func clearCodexLog(email string) {
	path := codexRetryLogPath(email)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte{}, 0o644)
}

// -----------------------------------------------------------------------------
// 占位（reserve / release）—— 对齐上游 codex_retry_service.py
// -----------------------------------------------------------------------------

// reservedCodex 进程内防止同一账号被重复补跑。
//
// 对齐上游 reserve()：当占位还在但线程已死/已终态时，先清理脏占位再放行。
// 条件是：(!running && (status != retrying || age > 15min)) ||
//
//	(status 属终态 && (stopReq || age > 30s))
func (s *Server) reservedCodex(ctx context.Context, email string) bool {
	key := codexKey(email)
	if key == "" {
		return false
	}

	// 先读库里当前 codex_status，需要在锁外做 IO，避免持锁查库。
	status := ""
	if acc, err := s.store.GetAccountByEmail(ctx, email); err == nil && acc != nil {
		status = strings.ToLower(payloadString(acc.Payload, "codex_status"))
	}
	terminal := status == "stopped" || status == "failed" || status == "success" ||
		status == "deactivated" || status == "skipped" || status == "cancelled"

	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	if s.codexRetry == nil {
		s.codexRetry = map[string]*codexRetryState{}
	}
	if st, ok := s.codexRetry[key]; ok {
		age := time.Since(st.startedAt)
		alive := st.running
		stopReq := st.stopReq
		if (!alive && (status != codexStatusRetrying || age > codexStaleRunning)) ||
			(terminal && (stopReq || age > codexStaleTerminal)) {
			s.appendCodexLog(email, "WARNING", fmt.Sprintf(
				"[Codex 补跑] 清理脏占位：email=%s status=%s alive=%t stop_requested=%t age=%.1fs",
				email, orDefaultDash(status), alive, stopReq, age.Seconds()))
			delete(s.codexRetry, key)
		} else {
			return false
		}
	}
	s.codexRetry[key] = &codexRetryState{startedAt: time.Now(), running: false}
	return true
}

// releaseCodex 对齐上游 release()：清空占位，同时保留 stop 标记给仍在跑的旧线程看到。
func (s *Server) releaseCodex(email string) {
	key := codexKey(email)
	if key == "" {
		return
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	if st, ok := s.codexRetry[key]; ok {
		// 对齐上游 _clear_state_locked：连带 stop_requested 一起清。
		_ = st
		delete(s.codexRetry, key)
	}
}

// attachCodexCancel 让停止接口能取消正在跑的 goroutine。
func (s *Server) attachCodexCancel(email string, cancel context.CancelFunc) {
	key := codexKey(email)
	if key == "" {
		return
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	if st, ok := s.codexRetry[key]; ok {
		st.cancel = cancel
		st.running = true
		st.startedAt = time.Now()
		return
	}
	s.codexRetry[key] = &codexRetryState{startedAt: time.Now(), cancel: cancel, running: true}
}

// isCodexRetrying 对齐上游 is_retrying()。
func (s *Server) isCodexRetrying(email string) bool {
	key := codexKey(email)
	if key == "" {
		return false
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	_, ok := s.codexRetry[key]
	return ok
}

// codexStopRequested 对齐上游 is_stop_requested()。
func (s *Server) codexStopRequested(email string) bool {
	key := codexKey(email)
	if key == "" {
		return false
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	if st, ok := s.codexRetry[key]; ok {
		return st.stopReq
	}
	return false
}

// requestStopCodex 对齐上游 request_stop()：置 stop 标记 + 取消 goroutine。
// 返回 (是否注入了取消信号, 当时是否处于补跑中)。
func (s *Server) requestStopCodex(email string) (injected, running bool) {
	key := codexKey(email)
	if key == "" {
		return false, false
	}
	s.codexMu.Lock()
	defer s.codexMu.Unlock()
	st, ok := s.codexRetry[key]
	if !ok {
		return false, false
	}
	st.stopReq = true
	if st.cancel != nil {
		st.cancel()
		injected = true
	}
	return injected, true
}

// -----------------------------------------------------------------------------
// 手动验证码通道 —— 对齐上游 core/manual_otp.py
// -----------------------------------------------------------------------------

// waitManualOTP 走统一的进程内手动验证码通道（见 internal/manualotp）。
// Codex 补跑没带 job_id，传 nil 即可。
func (s *Server) waitManualOTP(ctx context.Context, email string, jobID any, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = time.Duration(config.Current().OTPMaxWaitSec) * time.Second
	}
	s.appendCodexLog(email, "INFO", fmt.Sprintf(
		"[ManualOTP] 等待手动输入验证码：email=%s timeout=%s job=%v", email, timeout, jobID))
	s.appendCodexLog(email, "INFO", fmt.Sprintf(
		"[ManualOTP] 请打开邮箱 %s，在 WebUI 账号行点「补跑日志」旁提交 4-8 位验证码", email))
	return manualotp.Wait(ctx, email, jobID, timeout)
}

// -----------------------------------------------------------------------------
// 账号 codex_status 落库 —— 对齐上游 db.update_account_codex_status
// -----------------------------------------------------------------------------

// setAccountCodexStatus 写 payload 里的 codex_status / codex_error。
// InsertAccount 是按 email 整包 upsert，所以必须先读再改再写回。
func (s *Server) setAccountCodexStatus(ctx context.Context, email, status, errMsg string) bool {
	acc, err := s.store.GetAccountByEmail(ctx, email)
	if err != nil || acc == nil {
		return false
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	if status == "" {
		acc.Payload["codex_status"] = ""
	} else {
		acc.Payload["codex_status"] = status
	}
	if strings.TrimSpace(errMsg) == "" {
		acc.Payload["codex_error"] = nil
	} else {
		acc.Payload["codex_error"] = errMsg
	}
	// 对齐上游：deactivated 时同时把查活结果写成废号，避免下次再排队浪费短信。
	if status == "deactivated" {
		acc.Payload["live_check_status"] = "deactivated"
		acc.Payload["live_check_ok"] = false
		acc.Payload["live_check_error"] = errMsg
		acc.Payload["live_checked_at"] = nowRFC3339()
	}
	acc.Payload["codex_updated_at"] = nowRFC3339()
	_, err = s.store.InsertAccount(ctx, *acc)
	return err == nil
}

// -----------------------------------------------------------------------------
// 邮箱取码：从本地邮箱池还原文案，构造 Mailbox
// -----------------------------------------------------------------------------

// codexMailbox 给已注册账号反查邮箱池里那一行，拿到取码所需的 credential。
// 顺序：邮箱池（来源优先）→ 账号 payload 里记录的 email_source → 全局 EMAIL_SOURCE → generic_api。
func (s *Server) codexMailbox(ctx context.Context, email string) (domain.Mailbox, mail.Provider) {
	cfg := config.Current()
	email = strings.TrimSpace(email)

	src := ""
	item, _ := s.store.GetEmailItemByEmail(ctx, email)
	if item != nil && strings.TrimSpace(item.Source) != "" {
		src = strings.ToLower(strings.TrimSpace(item.Source))
	}
	if src == "" {
		if acc, err := s.store.GetAccountByEmail(ctx, email); err == nil && acc != nil {
			for _, k := range []string{"email_source", "source", "driver_source"} {
				if v := payloadString(acc.Payload, k); strings.TrimSpace(v) != "" {
					src = strings.ToLower(strings.TrimSpace(v))
					break
				}
			}
		}
	}
	if src == "" {
		if list := cfg.EmailSources(); len(list) > 0 {
			src = list[0]
		}
	}
	if src == "" {
		src = "generic_api"
	}

	cred := map[string]string{}
	if item != nil {
		for k, v := range item.Payload {
			if sv, ok := v.(string); ok {
				cred[k] = sv
			}
		}
	}
	// PoolProvider 认 credential / code_url 两个键，这里补齐别名，
	// 避免邮箱池行里只写了 "email----code_url" 时取不到码。
	if cred["code_url"] == "" && cred["credential"] != "" {
		cred["code_url"] = cred["credential"]
	}

	box := domain.Mailbox{
		Email:      email,
		Source:     domain.EmailSource(src),
		Credential: cred,
		AcquiredAt: time.Now(),
	}
	if s.mails != nil {
		if p, ok := s.mails.Get(src); ok {
			return box, p
		}
	}
	return box, nil
}

// codexOTPCallback 给 RunCodexOAuth 用的邮箱取码回调。
// USE_EMAIL_SERVICE=true 时先自动取码，失败降级手动输入；关掉时直接走手动输入。
func (s *Server) codexOTPCallback(ctx context.Context, email string) (string, error) {
	cfg := config.Current()
	maxWait := time.Duration(cfg.OTPMaxWaitSec) * time.Second
	poll := time.Duration(cfg.OTPPollSec) * time.Second
	if maxWait <= 0 {
		maxWait = 180 * time.Second
	}
	if poll <= 0 {
		poll = 5 * time.Second
	}

	if !cfg.UseEmailService {
		s.appendCodexLog(email, "INFO", "[Codex] USE_EMAIL_SERVICE=false，走 WebUI 手动验证码通道")
		return s.waitManualOTP(ctx, email, nil, maxWait)
	}

	box, provider := s.codexMailbox(ctx, email)
	if provider == nil {
		s.appendCodexLog(email, "WARNING", fmt.Sprintf(
			"[Codex] 未找到邮箱来源 provider（source=%s），降级为手动验证码输入", box.Source))
		return s.waitManualOTP(ctx, email, nil, maxWait)
	}

	s.appendCodexLog(email, "INFO", fmt.Sprintf(
		"[Codex] 自动取码：source=%s max_wait=%s poll=%s", box.Source, maxWait, poll))
	after := time.Now().Add(-30 * time.Second)
	res, err := mail.WaitCodeWithRetry(ctx, provider, box, after, maxWait, poll,
		func(elapsed, max time.Duration, lastErr error) {
			if lastErr != nil {
				s.appendCodexLog(email, "INFO", fmt.Sprintf(
					"[Codex] 等码中 %ds/%ds：%v", int(elapsed.Seconds()), int(max.Seconds()), lastErr))
			}
		})
	if err == nil && strings.TrimSpace(res.Code) != "" {
		s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex] 自动取到验证码：%s", res.Code))
		return res.Code, nil
	}
	s.appendCodexLog(email, "WARNING", fmt.Sprintf(
		"[Codex] 自动取码失败（%v），降级为 WebUI 手动验证码输入", err))
	return s.waitManualOTP(ctx, email, nil, maxWait)
}

// -----------------------------------------------------------------------------
// 补跑 worker —— 对齐上游 run_worker()
// -----------------------------------------------------------------------------

// runCodexWorker 执行一次 Codex 补跑。调用前必须已经 reservedCodex。
func (s *Server) runCodexWorker(email, batchLabel string, clearLog bool) {
	key := codexKey(email)
	if key == "" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.attachCodexCancel(email, cancel)
	defer s.releaseCodex(email)

	if clearLog {
		clearCodexLog(email)
	}

	// 上游把 logging FileHandler 挂到本线程，日志既进全局也进单邮箱文件。
	codex.SetEmailSink(email, func(msg string) {
		s.appendCodexLog(email, "INFO", msg)
	})
	defer codex.SetEmailSink(email, nil)

	if batchLabel != "" {
		s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] 批量任务：%s", batchLabel))
	}
	s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] 开始：%s", email))
	s.appendCodexLog(email, "INFO",
		"[Codex 补跑] 阶段说明：获取授权地址 → 登录邮箱 → 邮箱 OTP → 手机验证 → 捕获 callback → 提交/保存凭证")

	result := codex.OAuthResult{Email: email, Status: "failed", Message: "Codex 补跑未返回结果"}
	var runErr error
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				runErr = fmt.Errorf("panic: %v", rec)
			}
		}()
		acc, err := s.store.GetAccountByEmail(ctx, email)
		if err != nil || acc == nil {
			runErr = fmt.Errorf("账号不存在: %s", email)
			return
		}
		proxy := s.getProxyForAccount(acc)
		if proxy != "" {
			s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex] 使用代理：%s", proxy))
		} else {
			s.appendCodexLog(email, "INFO", "[Codex] 直连（未配置代理）")
		}
		result, runErr = codex.RunCodexOAuth(ctx, s.store, email, proxy, s.sms, s.codexOTPCallback)
	}()

	// 被用户停止：库里写 stopped，不覆盖成 failed。
	if s.codexStopRequested(email) || (ctx.Err() != nil && !result.OK) {
		s.setAccountCodexStatus(ctx, email, "stopped", "用户手动停止 Codex 补跑")
		s.appendCodexLog(email, "WARNING", fmt.Sprintf("[Codex 补跑] %s 已停止", email))
		s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] 结束：%s", email))
		return
	}

	if runErr != nil {
		s.setAccountCodexStatus(ctx, email, "failed", fmt.Sprintf("%v", runErr))
		s.appendCodexLog(email, "ERROR", fmt.Sprintf("[Codex 补跑] %s 异常：%v", email, runErr))
		s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] 结束：%s", email))
		return
	}

	s.appendCodexLog(email, "INFO", fmt.Sprintf(
		"[Codex 补跑] 结果：status=%s ok=%t file=%s callback=%s",
		result.Status, result.OK, orDefaultDash(result.FilePath), orDefaultDash(result.CallbackURL)))

	switch {
	case result.OK:
		s.setAccountCodexStatus(ctx, email, "success", "")
		s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] %s 成功", email))
	case result.Status == "deactivated":
		s.setAccountCodexStatus(ctx, email, "deactivated", result.Message)
		s.appendCodexLog(email, "WARNING", fmt.Sprintf("[Codex 补跑] %s 账号已废：%s", email, result.Message))
	case result.Status == "stopped":
		s.setAccountCodexStatus(ctx, email, "stopped", result.Message)
		s.appendCodexLog(email, "WARNING", fmt.Sprintf("[Codex 补跑] %s 已停止：%s", email, result.Message))
	default:
		st := result.Status
		if st == "" {
			st = "failed"
		}
		s.setAccountCodexStatus(ctx, email, st, result.Message)
		s.appendCodexLog(email, "WARNING", fmt.Sprintf("[Codex 补跑] %s 失败：%s", email, result.Message))
	}
	s.appendCodexLog(email, "INFO", fmt.Sprintf("[Codex 补跑] 结束：%s", email))
}

// -----------------------------------------------------------------------------
// HTTP 接口
// -----------------------------------------------------------------------------

// POST /api/codex/retry  body {email, browser_direct?}
func (s *Server) handleCodexRetry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email         string `json:"email"`
		BrowserDirect bool   `json:"browser_direct"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" {
		fail(w, http.StatusBadRequest, "email 为空")
		return
	}
	ctx := r.Context()
	acc, err := s.store.GetAccountByEmail(ctx, email)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在: "+email)
		return
	}
	if payloadString(acc.Payload, "live_check_status") == "deactivated" {
		fail(w, http.StatusConflict, "账号已废号，不能补跑 Codex")
		return
	}
	if !s.reservedCodex(ctx, email) {
		fail(w, http.StatusConflict, "该账号正在补跑中，请稍候")
		return
	}
	s.setAccountCodexStatus(ctx, email, codexStatusRetrying, "")
	go s.runCodexWorker(email, "", true)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已在后台开始补跑，~1-2 分钟后刷新查看",
	})
}

// POST /api/codex/retry-bulk  body {account_ids|ids, workers}
func (s *Server) handleCodexRetryBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any `json:"account_ids"`
		IDs        []any `json:"ids"`
		Workers    any   `json:"workers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	if len(ids) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	workers := 1
	if body.Workers != nil {
		switch v := body.Workers.(type) {
		case float64:
			workers = int(v)
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				fail(w, http.StatusBadRequest, "workers 必须是数字")
				return
			}
			workers = n
		default:
			fail(w, http.StatusBadRequest, "workers 必须是数字")
			return
		}
	}
	workers = codexMaxInt(1, workers)
	if workers > codexMaxWorkers {
		workers = codexMaxWorkers
	}
	if len(ids) > codexMaxBulk {
		fail(w, http.StatusBadRequest, "单次最多选择 500 个账号")
		return
	}

	ctx := r.Context()
	selected := make([]map[string]any, 0, len(ids))
	skipped := make([]map[string]any, 0)
	seen := map[int64]bool{}
	for _, raw := range ids {
		var accID int64
		switch v := raw.(type) {
		case float64:
			accID = int64(v)
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				skipped = append(skipped, map[string]any{"id": v, "reason": "ID 非法"})
				continue
			}
			accID = n
		default:
			skipped = append(skipped, map[string]any{"id": raw, "reason": "ID 非法"})
			continue
		}
		if seen[accID] {
			continue
		}
		seen[accID] = true
		acc, err := s.store.GetAccount(ctx, accID)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": accID, "reason": "账号不存在"})
			continue
		}
		email := strings.TrimSpace(acc.Email)
		if email == "" {
			skipped = append(skipped, map[string]any{"id": accID, "reason": "邮箱为空"})
			continue
		}
		if payloadString(acc.Payload, "live_check_status") == "deactivated" {
			skipped = append(skipped, map[string]any{"id": accID, "email": email, "reason": "账号已废号"})
			continue
		}
		if !s.reservedCodex(ctx, email) {
			skipped = append(skipped, map[string]any{"id": accID, "email": email, "reason": "正在补跑中"})
			continue
		}
		selected = append(selected, map[string]any{"id": accID, "email": email})
	}
	if len(selected) == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "error": "没有可补跑的账号", "skipped": skipped,
		})
		return
	}

	batchID := time.Now().Format("20060102-150405")
	for _, item := range selected {
		email := item["email"].(string)
		s.setAccountCodexStatus(ctx, email, codexStatusRetrying, "")
		clearCodexLog(email)
		s.appendCodexLog(email, "INFO", fmt.Sprintf(
			"[Codex 批量补跑] 已加入批量任务 batch=%s workers=%d，等待线程执行", batchID, workers))
	}

	items := make([]map[string]any, len(selected))
	copy(items, selected)
	go func() {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for idx, it := range items {
			email := it["email"].(string)
			label := fmt.Sprintf("%s #%d/%d", batchID, idx+1, len(items))
			wg.Add(1)
			sem <- struct{}{}
			go func(em, lb string) {
				defer wg.Done()
				defer func() { <-sem }()
				defer func() {
					if rec := recover(); rec != nil {
						s.appendCodexLog(em, "ERROR", fmt.Sprintf("[Codex 批量补跑] 子任务异常：%v", rec))
						s.setAccountCodexStatus(context.Background(), em, "failed", fmt.Sprintf("panic: %v", rec))
						s.releaseCodex(em)
					}
				}()
				s.runCodexWorker(em, lb, false)
			}(email, label)
		}
		wg.Wait()
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"message":       fmt.Sprintf("已开始批量补跑 %d 个账号，并发 %d", len(selected), workers),
		"started":       selected,
		"started_count": len(selected),
		"skipped":       skipped,
		"batch_id":      batchID,
	})
}

// POST /api/codex/stop  body {email}
// POST /api/codex/stop-bulk  body {emails|account_ids|ids}
func (s *Server) handleCodexStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if strings.HasSuffix(r.URL.Path, "stop-bulk") {
		var body struct {
			Emails     []any `json:"emails"`
			AccountIDs []any `json:"account_ids"`
			IDs        []any `json:"ids"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
			return
		}
		targets := make([]string, 0)
		if len(body.Emails) > 0 {
			for _, v := range body.Emails {
				if s, ok := v.(string); ok {
					if e := strings.TrimSpace(s); e != "" {
						targets = append(targets, e)
					}
				}
			}
		} else if ids := firstNonEmptyIDs(body.AccountIDs, body.IDs); len(ids) > 0 {
			for _, raw := range ids {
				var accID int64
				switch v := raw.(type) {
				case float64:
					accID = int64(v)
				case string:
					n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
					if err != nil {
						continue
					}
					accID = n
				default:
					continue
				}
				if acc, err := s.store.GetAccount(ctx, accID); err == nil && acc != nil {
					if e := strings.TrimSpace(acc.Email); e != "" {
						targets = append(targets, e)
					}
				}
			}
		} else {
			fail(w, http.StatusBadRequest, "emails 或 account_ids 必须是非空数组")
			return
		}
		if len(targets) > codexMaxBulk {
			fail(w, http.StatusBadRequest, "单次最多停止 500 个")
			return
		}

		stopped := make([]map[string]any, 0)
		skipped := make([]map[string]any, 0)
		seen := map[string]bool{}
		for _, email := range targets {
			key := codexKey(email)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			acc, err := s.store.GetAccountByEmail(ctx, email)
			if err != nil || acc == nil {
				skipped = append(skipped, map[string]any{"email": email, "reason": "账号不存在"})
				continue
			}
			if payloadString(acc.Payload, "codex_status") != codexStatusRetrying && !s.isCodexRetrying(email) {
				skipped = append(skipped, map[string]any{"email": email, "reason": "未处于补跑中"})
				continue
			}
			injected, running := s.requestStopCodex(email)
			s.setAccountCodexStatus(ctx, email, "stopped", "用户手动停止 Codex 补跑")
			s.appendCodexLog(email, "WARNING", fmt.Sprintf(
				"[Codex 补跑] 用户手动停止，已发送停止信号 injected=%t", injected))
			stopped = append(stopped, map[string]any{
				"email": email, "injected": injected, "running": running,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "stopped": stopped, "stopped_count": len(stopped), "skipped": skipped,
		})
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	email := strings.TrimSpace(body.Email)
	if email == "" {
		fail(w, http.StatusBadRequest, "email 为空")
		return
	}
	acc, err := s.store.GetAccountByEmail(ctx, email)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在: "+email)
		return
	}
	injected, running := s.requestStopCodex(email)
	if !running {
		s.setAccountCodexStatus(ctx, email, "stopped", "用户手动停止（未发现运行中的补跑）")
		s.appendCodexLog(email, "WARNING", "[Codex 补跑] 用户手动停止（未发现运行中的补跑）")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "message": "未发现运行中的补跑，已标记为已停止",
			"state": "stopped", "running": false,
		})
		return
	}
	s.setAccountCodexStatus(ctx, email, "stopped", "用户手动停止 Codex 补跑")
	s.appendCodexLog(email, "WARNING", fmt.Sprintf(
		"[Codex 补跑] 用户手动停止，已发送停止信号 injected=%t", injected))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "已发送停止信号",
		"state": "stopped", "running": true, "injected": injected,
	})
}

func firstNonEmptyIDs(a, b []any) []any {
	if len(a) > 0 {
		return a
	}
	return b
}

// GET /api/codex/retry-log?email=
func (s *Server) handleCodexRetryLog(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		fail(w, http.StatusBadRequest, "email 为空")
		return
	}
	running := s.isCodexRetrying(email)
	path := codexRetryLogPath(email)
	if _, err := os.Stat(path); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "log": "", "running": running})
		return
	}
	content, err := readTail(path, 50000)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "log": "", "running": running})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "log": content, "running": running})
}

// POST /api/codex/reset-retrying  body {email, status?}
func (s *Server) handleCodexResetRetrying(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email  string `json:"email"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	email := strings.TrimSpace(body.Email)
	rawStatus := strings.ToLower(strings.TrimSpace(body.Status))
	if rawStatus == "" {
		rawStatus = "failed"
	}
	switch rawStatus {
	case "", "none", "null", "clear":
		rawStatus = "empty"
	}
	if email == "" {
		fail(w, http.StatusBadRequest, "email 为空")
		return
	}
	if rawStatus != "failed" && rawStatus != "skipped" && rawStatus != "empty" {
		fail(w, http.StatusBadRequest, "status 仅支持 failed/skipped/empty")
		return
	}
	ctx := r.Context()
	if acc, err := s.store.GetAccountByEmail(ctx, email); err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在: "+email)
		return
	}
	newStatus := rawStatus
	errMsg := "用户手动重置补跑中状态"
	if rawStatus == "empty" {
		newStatus = ""
		errMsg = ""
	}
	if !s.setAccountCodexStatus(ctx, email, newStatus, errMsg) {
		fail(w, http.StatusNotFound, "账号不存在: "+email)
		return
	}
	s.releaseCodex(email)
	shown := newStatus
	if shown == "" {
		shown = "空"
	}
	s.appendCodexLog(email, "WARNING", fmt.Sprintf(
		"[Codex 补跑] 用户手动重置补跑中状态，当前状态=%s", shown))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": "已重置补跑中状态", "status": newStatus,
	})
}

// POST /api/codex/sync-cpa —— 从 CPA 管理接口拉全部 Codex 凭证并入库。
func (s *Server) handleCodexSyncCPA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	files, err := codex.ListCPACodexAuthFiles(ctx)
	if err != nil {
		fail(w, http.StatusBadGateway, "拉取 CPA 凭证列表失败: "+err.Error())
		return
	}
	synced := 0
	errs := make([]map[string]any, 0)
	for _, f := range files {
		name := ""
		for _, k := range []string{"name", "filename", "file_name", "id"} {
			if v, ok := f[k].(string); ok && strings.TrimSpace(v) != "" {
				name = strings.TrimSpace(v)
				break
			}
		}
		if name == "" {
			errs = append(errs, map[string]any{"file": f, "error": "缺少文件名"})
			continue
		}
		email := ""
		for _, k := range []string{"email", "account_email", "user_email"} {
			if v, ok := f[k].(string); ok && strings.TrimSpace(v) != "" {
				email = strings.TrimSpace(v)
				break
			}
		}
		text, finalName, meta, derr := codex.DownloadCodexAuthText(ctx, name, email, "")
		if derr != nil {
			errs = append(errs, map[string]any{"file": name, "error": derr.Error()})
			continue
		}
		if finalName != "" {
			name = finalName
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(text), &payload); err != nil {
			errs = append(errs, map[string]any{"file": name, "error": "内容不是合法 JSON: " + err.Error()})
			continue
		}
		if email == "" {
			email = payloadString(payload, "email")
		}
		if meta != nil {
			payload["_cpa_meta"] = meta
		}
		payload["_cpa_synced_at"] = nowRFC3339()
		if _, err := s.store.InsertCodexAccount(ctx, store.CodexAccount{
			Filename: name, Email: email, Payload: payload,
		}); err != nil {
			errs = append(errs, map[string]any{"file": name, "error": err.Error()})
			continue
		}
		synced++
	}
	out := map[string]any{
		"ok": true, "synced_count": synced, "total": len(files),
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	writeJSON(w, http.StatusOK, out)
}

// -----------------------------------------------------------------------------
// 手动 OTP 接口 —— 对齐上游 /api/manual-otp 与 /api/manual-otp/waiting
// -----------------------------------------------------------------------------

// GET /api/manual-otp
func (s *Server) handleManualOTPGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "waiting": manualotp.List(),
	})
}

// POST /api/manual-otp  body {email|job_id, code|otp}
func (s *Server) handleManualOTPPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
		OTP   string `json:"otp"`
		JobID any    `json:"job_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(body.OTP)
	}
	email := strings.TrimSpace(body.Email)
	if email == "" && body.JobID != nil {
		var jobID int64
		switch v := body.JobID.(type) {
		case float64:
			jobID = int64(v)
		case string:
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				jobID = n
			}
		}
		if jobID > 0 {
			if j, err := s.store.GetJob(r.Context(), jobID); err == nil && j != nil {
				email = strings.TrimSpace(j.Email)
			}
		}
	}
	if email == "" {
		fail(w, http.StatusBadRequest, "email/job_id 缺失")
		return
	}
	if err := manualotp.Submit(email, code); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": email, "code": code})
}
