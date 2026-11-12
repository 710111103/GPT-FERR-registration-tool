package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/register/protocol"
)

// emailChangeSources 是与上游对齐的换绑可用邮箱来源白名单。
// 与 core/email_change_service.py 的允许集合一致：这些来源都能独立取到新邮箱的验证码。
var emailChangeSources = map[string]bool{
	"outlook":           true,
	"generic_api":       true,
	"mailalias":         true,
	"imap":              true,
	"cloudflare_domain": true,
	"cloudflare":        true,
	"gptmail":           true,
	"mailnest":          true,
	"cloudmail":         true,
	"remail":            true,
	"mailtm":            true,
	"tempmailio":        true,
}

// minAccountAgeForEmailChange 与上游 _MIN_ACCOUNT_AGE 一致的 24 小时硬闸。
// 服务端自己也会拒，本地先拦一道，省下一次领邮箱与二十秒登录。
const minAccountAgeForEmailChange = 24 * time.Hour

// emailChangeQueue 串行执行批量换绑。
// 串行是刻意的：换绑链路里有 verify 后的 AT 失效窗口，
// 并发会让同一出口的 PWD/OTP 限流互相踩踏。
func (s *Server) runEmailChangeQueue(items []emailChangeTask) {
	for _, it := range items {
		s.runOneEmailChange(it)
	}
}

type emailChangeTask struct {
	accountID int64
	source    string
}

// runOneEmailChange 对单个账号执行完整换绑：
// 领新邮箱 → begin → （按需密码重认证）→ 等 OTP → verify → 取新 AT → 覆写本地记录。
func (s *Server) runOneEmailChange(task emailChangeTask) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	acc, err := s.store.GetAccount(ctx, task.accountID)
	if err != nil || acc == nil {
		return
	}
	oldEmail := acc.Email
	log := func(msg string) { s.appendLiveLog(oldEmail, "[换绑] "+msg) }

	_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "running", "正在领取新邮箱", "")
	log("任务开始，来源=" + task.source)

	// ---- 1. 领新邮箱 ----
	provider, ok := s.mails.Get(task.source)
	if !ok {
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "邮箱来源 "+task.source+" 未注册", "")
		return
	}
	box, err := provider.Acquire(ctx)
	if err != nil {
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "领取新邮箱失败: "+err.Error(), "")
		return
	}
	newEmail := strings.TrimSpace(box.Email)
	if newEmail == "" || strings.EqualFold(newEmail, oldEmail) {
		_ = provider.Release(ctx, box, "cancelled")
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "领取到的邮箱为空或与当前邮箱相同", "")
		return
	}
	_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "running", "正在发送新邮箱验证码", newEmail)
	log("新邮箱领取成功: " + newEmail)

	// ---- 2. 建会话 ----
	proxyUsed := s.getProxyForAccount(acc)
	image := accountBrowserProfile(acc, proxyUsed)
	storeAccountBrowserProfile(acc, image)
	sess, err := protocol.NewSession(accountSessionOptions(acc, proxyUsed))
	if err != nil {
		_ = provider.Release(ctx, box, "cancelled")
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "创建网络会话失败: "+err.Error(), newEmail)
		return
	}
	defer sess.Close()

	token, _ := acc.Payload["access_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		_ = provider.Release(ctx, box, "cancelled")
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "账号缺少 access_token，先刷新 AT 再换绑", newEmail)
		return
	}

	_ = sess.WarmAuthenticatedSession(ctx, token)

	// ---- 3. begin，命中 reauth 就先重认证 ----
	otpAfter := time.Now()
	_, beginErr := sess.ChangeEmailBegin(ctx, token, newEmail)
	if beginErr != nil {
		if !protocol.IsReauthRequired(beginErr) {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "发送验证码失败: "+beginErr.Error(), newEmail)
			return
		}
		log("服务端要求 Recent Login，开始密码重认证")
		_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "running", "正在对原邮箱重认证", newEmail)
		freshToken, reauthErr := s.reauthForEmailChange(ctx, acc, sess)
		if reauthErr != nil {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "重认证失败: "+reauthErr.Error(), newEmail)
			return
		}
		token = freshToken
		acc.Payload["access_token"] = freshToken
		_, _ = s.store.InsertAccount(ctx, *acc)
		log("重认证通过，用新鲜 AT 重发 begin")
		otpAfter = time.Now()
		if _, err := sess.ChangeEmailBegin(ctx, token, newEmail); err != nil {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "重认证后发送验证码仍失败: "+err.Error(), newEmail)
			return
		}
	}

	// ---- 4. 等新邮箱 OTP ----
	_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "running", "正在等待新邮箱验证码", newEmail)
	log("验证码已发送，等待新邮箱收信")
	otp, otpErr := mail.WaitCodeWithRetry(ctx, provider, box, otpAfter, 180*time.Second, 5*time.Second)
	if otpErr != nil {
		// 首轮超时：重发一次再等第二轮，与上游同一策略。
		if !strings.Contains(strings.ToLower(otpErr.Error()), "超时") &&
			!strings.Contains(strings.ToLower(otpErr.Error()), "timeout") {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "等待验证码失败: "+otpErr.Error(), newEmail)
			return
		}
		log("首轮等待验证码超时，重发验证码并开启第二轮等待")
		otpAfter = time.Now()
		if _, err := sess.ChangeEmailBegin(ctx, token, newEmail); err != nil {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "重发验证码失败: "+err.Error(), newEmail)
			return
		}
		otp, otpErr = mail.WaitCodeWithRetry(ctx, provider, box, otpAfter, 180*time.Second, 5*time.Second)
		if otpErr != nil {
			_ = provider.Release(ctx, box, "cancelled")
			s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "两轮等待均未收到验证码: "+otpErr.Error(), newEmail)
			return
		}
	}
	log("验证码已收到")

	// ---- 5. verify ----
	_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "running", "正在提交新邮箱验证码", newEmail)
	if _, err := sess.ChangeEmailVerify(ctx, token, newEmail, otp.Code); err != nil {
		_ = provider.Release(ctx, box, "cancelled")
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "提交验证码失败: "+err.Error(), newEmail)
		return
	}
	log("验证码校验通过，换绑已在服务端生效")

	// ---- 6. 立刻在当前会话抓新 AT ----
	newAT := ""
	if at, _, sessEmail, err := sess.FetchSessionIdentity(ctx); err == nil && strings.TrimSpace(at) != "" {
		// 会话身份必须已经指向新邮箱，否则说明会话还挂在旧身份上，不能采信。
		if sessEmail == "" || strings.EqualFold(sessEmail, newEmail) {
			newAT = strings.TrimSpace(at)
			log("已即时获取到新邮箱的 Access Token")
		}
	}

	// ---- 7. 覆写本地记录 ----
	material := newEmail + "----" + task.source
	if err := s.store.ChangeAccountEmail(ctx, acc.ID, newEmail, task.source, newAT, material); err != nil {
		s.finishEmailChange(ctx, acc.ID, oldEmail, "failed", "本地账号更新失败: "+err.Error(), newEmail)
		return
	}
	_ = provider.Release(ctx, box, "success")
	_ = s.store.SetEmailChangeStatus(ctx, acc.ID, "success", "换绑完成", newEmail)
	s.appendLiveLog(newEmail, "[换绑] 换绑完成，新邮箱="+newEmail)
	if oldEmail != "" && !strings.EqualFold(oldEmail, newEmail) {
		s.appendLiveLog(oldEmail, "[换绑] 该账号已换绑到 "+newEmail)
	}

	// ---- 8. 没拿到新 AT 就补一次刷新 ----
	if newAT == "" {
		refreshed, err := s.store.GetAccount(ctx, acc.ID)
		if err == nil && refreshed != nil {
			refreshCtx, refreshCancel := context.WithTimeout(context.Background(), 240*time.Second)
			if at, rerr := s.refreshAccountToken(refreshCtx, refreshed); rerr == nil && at != "" {
				s.appendLiveLog(newEmail, "[换绑] 换绑后 AT 已刷新成功")
			} else if rerr != nil {
				s.appendLiveLog(newEmail, "[换绑] 换绑后刷新 AT 未通过: "+rerr.Error())
			}
			refreshCancel()
		}
	}
}

// reauthForEmailChange 用密码 + TOTP 走一次纯协议登录，拿到带新鲜 pwd_auth_time 的 AT。
// 复用注册时的 oai-did，避免被判成异地新设备。
func (s *Server) reauthForEmailChange(ctx context.Context, acc *domain.Account, sess *protocol.Session) (string, error) {
	email := acc.Email
	password := extractAccountSecret(acc, "password")
	if password == "" {
		password = extractAccountSecret(acc, "registration_password")
	}
	if password == "" {
		return "", fmt.Errorf("账号没有保存密码，无法完成 Recent Login 重认证")
	}
	totp := extractAccountSecret(acc, "totp_secret")

	drv, ok := s.drivers.Lookup("protocol")
	if !ok {
		return "", fmt.Errorf("未注册协议驱动")
	}
	protoDriver, ok := drv.(*protocol.Driver)
	if !ok {
		return "", fmt.Errorf("驱动类型不支持协议登录")
	}

	proxyUsed := s.getProxyForAccount(acc)
	image := accountBrowserProfile(acc, proxyUsed)
	at, _, err := protoDriver.LoginWithPasswordUsingProfileLogged(ctx, email, password, totp, accountDeviceID(acc), proxyUsed, image,
		func(msg string) { s.appendLiveLog(email, "[换绑重认证] "+msg) })
	if err != nil {
		return "", err
	}
	// 重认证用的是新会话，旧 sess 需要重新预热才能承接后续 begin。
	_ = sess.WarmAuthenticatedSession(ctx, at)
	return at, nil
}

// finishEmailChange 收尾：写回失败/状态位并记日志。
func (s *Server) finishEmailChange(ctx context.Context, id int64, email, status, message, target string) {
	_ = s.store.SetEmailChangeStatus(ctx, id, status, message, target)
	if email != "" {
		s.appendLiveLog(email, "[换绑] "+status+"："+message)
	}
}

// checkEmailChangeEligibility 做 24h 闸与来源校验，返回错误文案。
func (s *Server) checkEmailChangeEligibility(acc *domain.Account, source string) string {
	if acc == nil {
		return "账号不存在"
	}
	if !emailChangeSources[strings.ToLower(strings.TrimSpace(source))] {
		return "不支持的邮箱来源: " + source
	}
	if !acc.CreatedAt.IsZero() {
		eligibleAt := acc.CreatedAt.Add(minAccountAgeForEmailChange)
		if time.Now().Before(eligibleAt) {
			remain := eligibleAt.Sub(time.Now())
			minutes := int(remain.Minutes()) + 1
			h, m := minutes/60, minutes%60
			text := fmt.Sprintf("%d分钟", m)
			if h > 0 {
				text = fmt.Sprintf("%d小时%d分钟", h, m)
			}
			return fmt.Sprintf("账号创建未满 24 小时，服务端暂不允许换绑；最早可在 %s 操作，约剩余%s",
				eligibleAt.Format("2006-01-02 15:04:05"), text)
		}
	}
	return ""
}

// handleChangeEmail 单账号换绑：POST /api/accounts/{id}/change-email  body {source}
// 契约对齐上游 webui/app.py：无号 404、无 AT 400、来源非法 400、已在跑 409、入队 202。
func (s *Server) handleChangeEmail(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id == 0 {
		fail(w, http.StatusBadRequest, "非法账号 ID")
		return
	}
	var body struct {
		Source string `json:"source"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	if strings.TrimSpace(body.Source) == "" {
		body.Source = "outlook"
	}

	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	if reason := s.checkEmailChangeEligibility(acc, body.Source); reason != "" {
		fail(w, http.StatusBadRequest, reason)
		return
	}
	if at, _ := acc.Payload["access_token"].(string); strings.TrimSpace(at) == "" {
		fail(w, http.StatusBadRequest, "账号缺少 access_token，先刷新 AT 再换绑")
		return
	}
	if st, _ := acc.Payload["email_change_status"].(string); st == "queued" || st == "running" {
		fail(w, http.StatusConflict, "该账号已有换绑任务在执行")
		return
	}

	_ = s.store.SetEmailChangeStatus(r.Context(), id, "queued", "已入队，等待后台换绑", "")
	go s.runEmailChangeQueue([]emailChangeTask{{accountID: id, source: body.Source}})

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":         true,
		"id":         id,
		"email":      acc.Email,
		"source":     body.Source,
		"started":    true,
		"started_at": time.Now().Format("2006-01-02 15:04:05"),
	})
}

// handleEmailChangeBulk 批量换绑：POST /api/accounts/change-email-bulk  body {source, account_ids}
// 契约对齐上游：{ok, started[], started_count, skipped[], skipped_count, busy[], busy_count, failed[], failed_count}
func (s *Server) handleEmailChangeBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Source     string  `json:"source"`
		AccountIDs []int64 `json:"account_ids"`
		IDs        []int64 `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if strings.TrimSpace(body.Source) == "" {
		body.Source = "outlook"
	}
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	if len(ids) == 0 {
		fail(w, http.StatusBadRequest, "缺少 account_ids")
		return
	}
	if len(ids) > 500 {
		ids = ids[:500]
	}

	started := []map[string]any{}
	skipped := []map[string]any{}
	busy := []map[string]any{}
	failed := []map[string]any{}
	var queue []emailChangeTask

	for _, id := range ids {
		acc, err := s.store.GetAccount(r.Context(), id)
		if err != nil || acc == nil {
			failed = append(failed, map[string]any{"id": id, "email": "", "error": "账号不存在"})
			continue
		}
		if reason := s.checkEmailChangeEligibility(acc, body.Source); reason != "" {
			skipped = append(skipped, map[string]any{"id": acc.ID, "email": acc.Email, "reason": reason})
			continue
		}
		if at, _ := acc.Payload["access_token"].(string); strings.TrimSpace(at) == "" {
			skipped = append(skipped, map[string]any{"id": acc.ID, "email": acc.Email, "reason": "账号缺少 access_token，先刷新 AT"})
			continue
		}
		if st, _ := acc.Payload["email_change_status"].(string); st == "queued" || st == "running" {
			busy = append(busy, map[string]any{"id": acc.ID, "email": acc.Email, "reason": "换绑任务进行中"})
			continue
		}
		_ = s.store.SetEmailChangeStatus(r.Context(), acc.ID, "queued", "已入队，等待后台换绑", "")
		queue = append(queue, emailChangeTask{accountID: acc.ID, source: body.Source})
		started = append(started, map[string]any{"id": acc.ID, "email": acc.Email})
	}

	if len(queue) > 0 {
		go s.runEmailChangeQueue(queue)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":            true,
		"source":        body.Source,
		"started":       started,
		"started_count": len(started),
		"skipped":       skipped,
		"skipped_count": len(skipped),
		"busy":          busy,
		"busy_count":    len(busy),
		"failed":        failed,
		"failed_count":  len(failed),
	})
}

// emailChangeMaterial 生成上游同款「邮箱----来源」素材行，供换绑记录对账。
func emailChangeMaterial(email, source string) string {
	return strings.TrimSpace(email) + "----" + strings.TrimSpace(source)
}

var _ = config.Current
var _ = emailChangeMaterial
