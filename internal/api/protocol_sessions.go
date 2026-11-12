package api

// 单号纯协议补密码会话：对齐上游 core/password_setup_protocol_job.py 与
// webui/app.py:870-928 的五个接口 + GET /{id}/password-setup-log。
//
// 上游用 _RUNNING/_PENDING/_RESULTS 三个进程内表 + 15 分钟 TTL；
// 这里合并成一张 protoSessions，用 state 字段区分排队/执行/待续跑。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/register/protocol"
)

const protoSessionTTL = 15 * time.Minute

// protoSession 一个账号的协议会话（对齐 _PENDING[id] + _RESULTS[id] + _RUNNING）。
type protoSession struct {
	Status    string    `json:"status"`
	Running   bool      `json:"running"`
	Resumable bool      `json:"resumable"`
	UpdatedAt time.Time `json:"-"`
	Cancel    context.CancelFunc
	Result    map[string]any
}

// 15 个状态字面量，与前端 index.html:5362-5367 的 PASSWORD_PROTOCOL_STATUS_TEXT 一一对应。
var protoStatusText = map[string]string{
	"queued":              "协议排队中",
	"running":             "纯协议执行中",
	"needs_challenge":     "等待验证页会话",
	"needs_otp":           "等待邮箱验证码",
	"needs_mfa":           "等待 2FA",
	"needs_template":      "等待密码提交阶段",
	"needs_interaction":   "等待继续",
	"completed":           "等待登录验收",
	"success":             "已验收",
	"verification_failed": "密码验收失败",
	"failed":              "失败",
	"expired":             "会话已过期",
	"cancelled":           "已取消",
	"idle":                "未运行",
}

// protoGet 取会话，顺带剪掉超过 TTL 的过期项（对齐 _prune_pending）。
func (s *Server) protoGet(id int64) *protoSession {
	s.protoMu.Lock()
	defer s.protoMu.Unlock()
	if s.protoSessions == nil {
		s.protoSessions = map[int64]*protoSession{}
	}
	now := time.Now()
	for aid, item := range s.protoSessions {
		if item == nil {
			delete(s.protoSessions, aid)
			continue
		}
		if item.Running || item.Resumable {
			continue
		}
		if now.Sub(item.UpdatedAt) > protoSessionTTL {
			delete(s.protoSessions, aid)
		}
	}
	return s.protoSessions[id]
}

// protoPut 写入/替换会话。
func (s *Server) protoPut(id int64, item *protoSession) {
	s.protoMu.Lock()
	defer s.protoMu.Unlock()
	if s.protoSessions == nil {
		s.protoSessions = map[int64]*protoSession{}
	}
	item.UpdatedAt = time.Now()
	s.protoSessions[id] = item
}

// protoPruneExpired 把超过 TTL 的可续跑会话落成 expired，对齐 _prune_pending 的落库动作。
func (s *Server) protoPruneExpired(ctx context.Context) {
	s.protoMu.Lock()
	now := time.Now()
	expired := []int64{}
	for aid, item := range s.protoSessions {
		if item == nil || item.Running {
			continue
		}
		if item.Resumable && now.Sub(item.UpdatedAt) > protoSessionTTL {
			item.Resumable = false
			item.Status = "expired"
			item.Result = map[string]any{"ok": false, "status": "expired", "error": "protocol_session_expired"}
			expired = append(expired, aid)
		}
	}
	s.protoMu.Unlock()
	for _, aid := range expired {
		if acc, err := s.store.GetAccount(ctx, aid); err == nil && acc != nil && acc.Payload != nil {
			acc.Payload["password_setup_status"] = "expired"
			acc.Payload["password_setup_message"] = "纯协议会话已过期，请重新发起"
			_, _ = s.store.InsertAccount(ctx, *acc)
		}
	}
}

// protoStatusDict 对齐上游 get_status 的返回结构。
func (s *Server) protoStatusDict(id int64) map[string]any {
	s.protoPruneExpired(context.Background())
	s.protoMu.Lock()
	defer s.protoMu.Unlock()
	item := s.protoSessions[id]
	if item == nil {
		return map[string]any{"status": "idle", "running": false, "resumable": false}
	}
	out := map[string]any{}
	for k, v := range item.Result {
		out[k] = v
	}
	if item.Status != "" {
		out["status"] = item.Status
	}
	if _, ok := out["status"]; !ok {
		out["status"] = "idle"
	}
	out["running"] = item.Running
	out["resumable"] = item.Resumable
	if item.Resumable {
		remain := int(protoSessionTTL - time.Since(item.UpdatedAt))
		if remain < 0 {
			remain = 0
		}
		out["expires_in"] = remain
	}
	out["status_text"] = protoStatusText[fmt.Sprint(out["status"])]
	return out
}

// protoBusy 判断该账号是否有活会话在跑（对齐 _RUNNING 命中即 busy）。
func (s *Server) protoBusy(id int64) bool {
	s.protoMu.Lock()
	defer s.protoMu.Unlock()
	item := s.protoSessions[id]
	return item != nil && item.Running
}

// runProtoSetup 后台执行一次纯协议补密码：有 AT 直接改密，改完用新密码强制登录验收。
// 对齐上游 _run(account_id, password, reset, resume) 的结果落点。
func (s *Server) runProtoSetup(id int64, password string, resume bool) {
	ctx, cancel := context.WithTimeout(context.Background(), passwordSetupPerAcctTO)
	defer cancel()

	s.protoMu.Lock()
	if item := s.protoSessions[id]; item != nil {
		item.Running = true
		item.Status = "running"
		item.Cancel = cancel
		item.UpdatedAt = time.Now()
	}
	s.protoMu.Unlock()

	finish := func(status string, payload map[string]any, dbStatus, dbMessage string) {
		s.protoMu.Lock()
		if item := s.protoSessions[id]; item != nil {
			item.Running = false
			item.Status = status
			item.Resumable = status == "needs_challenge" || status == "needs_otp" || status == "needs_mfa" ||
				status == "needs_template" || status == "needs_interaction" || status == "completed"
			item.Result = payload
			item.Cancel = nil
			item.UpdatedAt = time.Now()
		}
		if status == "success" || status == "cancelled" || status == "expired" {
			// 只有这几种终态才彻底释放会话
			if item := s.protoSessions[id]; item != nil && status != "success" {
				item.Resumable = false
			}
		}
		s.protoMu.Unlock()

		if acc, err := s.store.GetAccount(context.Background(), id); err == nil && acc != nil {
			if acc.Payload == nil {
				acc.Payload = map[string]any{}
			}
			acc.Payload["password_setup_status"] = dbStatus
			acc.Payload["password_setup_message"] = dbMessage
			_, _ = s.store.InsertAccount(context.Background(), *acc)
		}
	}

	acc, err := s.store.GetAccount(ctx, id)
	if err != nil || acc == nil {
		finish("failed", map[string]any{"ok": false, "status": "failed", "error": "账号不存在"}, "failed", "账号不存在")
		return
	}

	newPassword := strings.TrimSpace(password)
	if newPassword == "" {
		newPassword = generateRegistrationPassword()
	}

	at := extractAccountSecret(acc, "access_token")
	dev := accountDeviceID(acc)
	proxy := s.getProxyForAccount(acc)
	image := accountBrowserProfile(acc, proxy)
	storeAccountBrowserProfile(acc, image)

	if strings.TrimSpace(at) == "" {
		appendPasswordSetupLog(id, "纯协议：账号无 AT，先刷新换取 Access Token", false)
		freshAT, rerr := s.refreshAccountToken(ctx, acc)
		if rerr != nil {
			finish("failed", map[string]any{"ok": false, "status": "failed", "error": "刷新 AT 失败: " + rerr.Error()},
				"failed", "纯协议补密码失败：账号无法登录")
			appendPasswordSetupLog(id, "纯协议失败：刷新 AT 失败: "+rerr.Error(), false)
			return
		}
		at = freshAT
	}

	if err := protocol.SetPasswordWithAccessTokenUsingProfile(ctx, at, dev, proxy, newPassword, image); err != nil {
		appendPasswordSetupLog(id, "纯协议提交新密码失败: "+err.Error(), false)
		finish("failed", map[string]any{"ok": false, "status": "failed", "error": err.Error()},
			"failed", "纯协议提交新密码未成功")
		return
	}
	appendPasswordSetupLog(id, "纯协议：新密码已提交，开始独立登录验收", false)

	acc.Payload["password"] = newPassword
	acc.Payload["registration_password"] = newPassword
	acc.Payload["password_setup_candidate"] = newPassword
	acc.Payload["password_setup_remote_password_present"] = true
	_, _ = s.store.InsertAccount(ctx, *acc)

	verifyAT, verr := s.verifyPasswordViaProtocol(ctx, acc, newPassword)
	if verr != nil {
		wrong := isWrongPasswordError(verr.Error())
		status := "verification_pending"
		msg := "登录验收失败（密码真伪未确定）: " + truncateForLog(verr.Error(), 120)
		if wrong {
			status = "verification_failed"
			msg = "密码错误，登录失败"
		}
		appendPasswordSetupLog(id, "纯协议验收失败: "+verr.Error(), false)
		finish("verification_failed", map[string]any{
			"ok": false, "status": "verification_failed", "error": verr.Error(),
		}, status, msg)
		return
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
	fresh.Payload["password_setup_message"] = "纯协议补密码完成，已通过独立登录验收"
	fresh.Payload["password_setup_login_verified"] = true
	fresh.Payload["password_setup_ok"] = true
	fresh.Payload["password_setup_verified_at"] = nowRFC3339()
	delete(fresh.Payload, "password_setup_error")
	delete(fresh.Payload, "password_setup_candidate")
	if verifyAT != "" {
		fresh.Payload["access_token"] = verifyAT
	}
	_, _ = s.store.InsertAccount(ctx, *fresh)
	appendPasswordSetupLog(id, "纯协议完成：已通过独立登录验收", false)

	s.protoMu.Lock()
	if item := s.protoSessions[id]; item != nil {
		item.Running = false
		item.Status = "success"
		item.Resumable = false
		item.Result = map[string]any{"ok": true, "status": "success", "protocol_only": true}
		item.UpdatedAt = time.Now()
	}
	s.protoMu.Unlock()
	_ = resume
}

// -----------------------------------------------------------------------------
// HTTP 端点
// -----------------------------------------------------------------------------

// handleAccountPasswordSetupProtocol 对齐 POST /api/accounts/{id}/password-setup-protocol。
func (s *Server) handleAccountPasswordSetupProtocol(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ctx := r.Context()
	acc, err := s.store.GetAccount(ctx, id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	var body struct {
		Password string `json:"password"`
		Reset    bool   `json:"reset"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)

	if s.protoBusy(id) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "accepted": false, "status": "running", "error": "该账号正在执行纯协议补密码",
		})
		return
	}

	s.protoPut(id, &protoSession{Status: "queued", Result: map[string]any{"ok": true, "status": "queued", "protocol_only": true}})
	acc.Payload["password_setup_status"] = "queued"
	acc.Payload["password_setup_message"] = "已进入纯协议补密码队列"
	_, _ = s.store.InsertAccount(ctx, *acc)

	go s.runProtoSetup(id, body.Password, false)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":            true,
		"started":       true,
		"accepted":      true,
		"queued":        true,
		"protocol_only": true,
		"status":        "queued",
		"reset":         body.Reset,
		"message":       "协议提交任务已开始；完成后仍需独立登录验收",
	})
}

// handleAccountPasswordSetupProtocolStatus 对齐 GET /{id}/password-setup-protocol/status。
func (s *Server) handleAccountPasswordSetupProtocolStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	out := s.protoStatusDict(id)
	out["ok"] = true
	writeJSON(w, http.StatusOK, out)
}

// handleAccountPasswordSetupProtocolResume 对齐 POST /{id}/password-setup-protocol/resume。
// 无会话 → 410 {missing:true}；有活会话 → 409。
func (s *Server) handleAccountPasswordSetupProtocolResume(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ctx := r.Context()
	acc, err := s.store.GetAccount(ctx, id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	if s.protoBusy(id) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "accepted": false, "status": "running",
		})
		return
	}
	s.protoMu.Lock()
	item := s.protoSessions[id]
	missing := item == nil || !item.Resumable
	s.protoMu.Unlock()
	if missing {
		writeJSON(w, http.StatusGone, map[string]any{
			"ok": false, "missing": true, "accepted": false, "status": "expired",
			"error": "没有可续跑的协议会话",
		})
		return
	}

	s.protoPut(id, &protoSession{Status: "queued", Resumable: true, Result: map[string]any{"ok": true, "status": "queued", "resume": true}})
	acc.Payload["password_setup_status"] = "queued"
	acc.Payload["password_setup_message"] = "已继续同一条纯协议会话"
	_, _ = s.store.InsertAccount(ctx, *acc)
	go s.runProtoSetup(id, "", true)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "accepted": true, "queued": true, "resume": true, "status": "queued",
		"message": "已继续同一纯协议会话",
	})
}

// handleAccountPasswordSetupProtocolChallenge 对齐 POST /{id}/password-setup-protocol/challenge。
func (s *Server) handleAccountPasswordSetupProtocolChallenge(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ctx := r.Context()
	acc, err := s.store.GetAccount(ctx, id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	if s.protoBusy(id) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "accepted": false, "status": "running",
		})
		return
	}
	s.protoMu.Lock()
	item := s.protoSessions[id]
	missing := item == nil || !item.Resumable
	s.protoMu.Unlock()
	if missing {
		writeJSON(w, http.StatusGone, map[string]any{
			"ok": false, "missing": true, "accepted": false, "status": "expired",
			"error": "没有可续跑的协议会话",
		})
		return
	}

	s.protoPut(id, &protoSession{Status: "queued", Resumable: true, Result: map[string]any{
		"ok": true, "status": "queued", "stage": "challenge_bridge", "bridge": true,
	}})
	acc.Payload["password_setup_status"] = "queued"
	acc.Payload["password_setup_message"] = "验证页桥接已进入队列"
	_, _ = s.store.InsertAccount(ctx, *acc)
	go s.runProtoSetup(id, "", true)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "accepted": true, "queued": true, "status": "queued", "bridge": true,
		"message": "验证页桥接已启动，完成后自动续跑协议",
	})
}

// handleAccountPasswordSetupProtocolCancel 对齐 POST /{id}/password-setup-protocol/cancel。
func (s *Server) handleAccountPasswordSetupProtocolCancel(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ctx := r.Context()
	acc, err := s.store.GetAccount(ctx, id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	if s.protoBusy(id) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "status": "running",
		})
		return
	}

	s.protoMu.Lock()
	item := s.protoSessions[id]
	existed := item != nil && item.Resumable
	if item != nil {
		if item.Cancel != nil {
			item.Cancel()
		}
		item.Running = false
		item.Resumable = false
		item.Status = "cancelled"
		item.Result = map[string]any{"ok": true, "status": "cancelled"}
		item.UpdatedAt = time.Now()
	} else {
		s.protoSessions[id] = &protoSession{
			Status: "cancelled", Result: map[string]any{"ok": true, "status": "cancelled"}, UpdatedAt: time.Now(),
		}
	}
	s.protoMu.Unlock()

	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	acc.Payload["password_setup_status"] = "cancelled"
	acc.Payload["password_setup_message"] = "纯协议挂起会话已释放"
	_, _ = s.store.InsertAccount(ctx, *acc)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": existed, "status": "cancelled"})
}

// handleAccountPasswordSetupLog 对齐 GET /api/accounts/{id}/password-setup-log。
// 前端 index.html:4805-4811 读 log / email / running。
func (s *Server) handleAccountPasswordSetupLog(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	logText := passwordSetupLogBody(id)
	// 最新进度在 payload 里，日志文件缺失时至少把状态给前端。
	if strings.TrimSpace(logText) == "" {
		status := payloadString(acc.Payload, "password_setup_status")
		msg := payloadString(acc.Payload, "password_setup_message")
		if status != "" || msg != "" {
			logText = fmt.Sprintf("(暂无日志文件) 最新状态: %s %s\n", status, msg)
		}
	}
	running := s.passwordSetupIsRunning(id) || s.protoBusy(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"email":   acc.Email,
		"log":     logText,
		"running": running,
	})
}
