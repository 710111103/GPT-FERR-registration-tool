package codex

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/sms"
	"github.com/turb/gpt-register/internal/store"
)

// OAuthResult 与上游 _codex_result 同形态（core/codex_oauth.py:87-106）。
type OAuthResult struct {
	OK          bool   `json:"ok"`
	Email       string `json:"email"`
	Status      string `json:"status"` // success / deactivated / skipped / failed
	Message     string `json:"message,omitempty"`
	Phone       string `json:"phone,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	CallbackURL string `json:"callback_url,omitempty"`
	PlanType    string `json:"plan_type,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
}

// maxEmailOTPAttempts 对齐上游 run_codex_oauth L1443：邮箱 OTP 最多等 3 轮。
const maxEmailOTPAttempts = 3

// RunCodexOAuth 执行 Codex 协议级 OAuth 授权，全链路对齐上游
// core/codex_oauth.py:run_codex_oauth (L1400-1572)。
//
// 链路：
//
//	0  bootstrap authorize（建 auth.openai.com 会话）
//	1  POST /api/accounts/authorize/continue   提交邮箱，带 sentinel
//	2  POST /api/accounts/email-otp/validate   提交邮箱码，带 sentinel
//	3  POST /api/accounts/add-phone/send       发短信
//	4  POST /api/accounts/phone-otp/validate   提交短信码
//	5  解 oai-client-auth-session cookie 取 workspace_id
//	6  POST /api/accounts/workspace/select     选 workspace
//	7  逐跳跟随重定向直到 localhost:1455/auth/callback
//	8  校验 state、取出 code
//	9  POST /oauth/token                       换三件套
//	10 解 id_token 取 email / account_id / plan
//	11 落库 codex-{email}[-{plan}].json
func RunCodexOAuth(
	ctx context.Context,
	st *store.Store,
	email string,
	proxyURL string,
	smsProvider sms.Provider,
	onEmailOTP func(ctx context.Context, email string) (string, error),
) (OAuthResult, error) {
	res := OAuthResult{Email: email, Status: "failed"}

	email = strings.TrimSpace(email)
	if email == "" {
		res.Status = "skipped"
		res.Message = "email 为空"
		return res, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	solver := sentinel.NewSynthetic()
	deviceID, image := codexBrowserIdentity(ctx, st, email, proxyURL)
	logCodexE(email, "[Codex] 浏览器画像：TLS=%s UA=Chrome/%s 语言=%s 时区=%s 屏幕=%s oai-did=%s",
		image.TLSProfile, image.ChromeMajor, image.Language, image.Timezone, image.Screen, deviceID)
	flow, err := newCodexFlow(ctx, email, proxyURL, solver, deviceID, image, func(format string, args ...any) {
		logCodexE(email, "%s", fmt.Sprintf(format, args...))
	})
	if err != nil {
		res.Message = err.Error()
		return res, err
	}
	defer flow.sess.Close()

	source := strings.ToLower(strings.TrimSpace(configCodexAuthSource()))

	// CPA / sub2 模式：授权地址由外部生成，本地不持有 verifier。
	if source == "cpa" || source == "sub2" {
		return runExternalAuthSource(ctx, st, flow, source, email, smsProvider, onEmailOTP)
	}

	// ---- local 模式：本地 PKCE 全链路（默认）----
	if err := flow.bootstrapAuthorize(ctx); err != nil {
		return finishWithErr(res, err)
	}
	if err := flow.submitEmail(ctx); err != nil {
		return finishWithErr(res, err)
	}

	otpCode, err := waitEmailOTP(ctx, flow, onEmailOTP, email)
	if err != nil {
		return finishWithErr(res, err)
	}
	if err := flow.submitEmailOTP(ctx, otpCode); err != nil {
		return finishWithErr(res, err)
	}

	if smsProvider != nil {
		phone, perr := flow.verifyPhone(ctx, smsProvider)
		if perr != nil {
			return finishWithErr(res, perr)
		}
		res.Phone = phone
	} else {
		logCodexE(email, "[Codex] 未配置接码平台，跳过手机验证步骤")
	}

	callbackURL, err := flow.selectWorkspaceAndGetCallback(ctx)
	if err != nil {
		return finishWithErr(res, err)
	}
	res.CallbackURL = callbackURL

	code, err := extractCode(callbackURL, flow.state)
	if err != nil {
		return finishWithErr(res, err)
	}
	logCodexE(email, "[Codex] 已拿到 authorization code: %s...", head(code, 24))

	tr, err := flow.exchangeCode(ctx, code)
	if err != nil {
		return finishWithErr(res, err)
	}
	claims := parseIDToken(tr.IDToken)
	effectiveEmail := claims.Email
	if effectiveEmail == "" {
		effectiveEmail = email
	}
	storage := buildStorage(tr, claims)
	filename := credentialFilename(effectiveEmail, claims.PlanType)

	if _, err := st.InsertCodexAccount(ctx, store.CodexAccount{
		Filename: filename,
		Email:    effectiveEmail,
		Payload:  storage,
	}); err != nil {
		return finishWithErr(res, fmt.Errorf("写入 codex_accounts 失败: %w", err))
	}

	res.OK = true
	res.Status = "success"
	res.Email = effectiveEmail
	res.FilePath = "sqlite://codex_accounts/" + filename
	res.PlanType = claims.PlanType
	res.AccountID = claims.AccountID
	res.Message = fmt.Sprintf("plan=%s", orDefault(claims.PlanType, "unknown"))
	logCodexE(effectiveEmail, "[Codex] 成功: %s plan=%s account_id=%s → %s",
		effectiveEmail, orDefault(claims.PlanType, "unknown"), orDefault(claims.AccountID, "unknown"), filename)
	return res, nil
}

// codexBrowserIdentity 恢复账号注册时的设备身份；只有账号不存在或字段缺失时才补齐。
func codexBrowserIdentity(ctx context.Context, st *store.Store, email, proxyURL string) (string, protocol.BrowserProfile) {
	deviceID := ""
	image := protocol.BrowserProfile{}
	if st != nil {
		acc, err := st.GetAccountByEmail(ctx, email)
		if err != nil {
			logCodexE(email, "[Codex] 读取账号浏览器画像失败，将按代理地区补齐: %v", err)
		} else if acc != nil {
			image = protocol.BrowserProfileFromPayload(acc.Payload)
			if value, ok := acc.Payload["device_id"].(string); ok {
				deviceID = strings.TrimSpace(value)
			}
		}
	}
	image = image.Complete(proxyURL)
	if deviceID == "" {
		deviceID = sentinel.DeviceID()
	}
	return deviceID, image
}

// waitEmailOTP 对齐上游 L1443-1462：
// 最多 3 轮，每轮超时后重新 submitEmail 触发重发再继续等。
func waitEmailOTP(ctx context.Context, flow *codexFlow, onEmailOTP func(context.Context, string) (string, error), email string) (string, error) {
	if onEmailOTP == nil {
		return "", fmt.Errorf("邮箱 OTP 提供器为空，无法继续 Codex 授权")
	}
	var lastErr error
	for attempt := 1; attempt <= maxEmailOTPAttempts; attempt++ {
		logCodexE(email, "[Codex] 等待邮箱 OTP: %s（第 %d/%d 次）", email, attempt, maxEmailOTPAttempts)
		code, err := onEmailOTP(ctx, email)
		if err == nil && strings.TrimSpace(code) != "" {
			return strings.TrimSpace(code), nil
		}
		lastErr = err
		if attempt >= maxEmailOTPAttempts {
			break
		}
		logCodexE(email, "[Codex] 邮箱 OTP 未到，重新提交邮箱触发重发后继续等待: %v", err)
		if rerr := flow.submitEmail(ctx); rerr != nil {
			logCodexE(email, "[Codex] 重发邮箱触发失败: %v", rerr)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("邮箱 OTP 为空")
	}
	return "", fmt.Errorf("邮箱 OTP 等待 %d 轮仍失败: %w", maxEmailOTPAttempts, lastErr)
}

// runExternalAuthSource 处理 cpa / sub2 两种外部授权地址来源。
// 对齐上游 L1411-1420 / L1476-1521：授权地址由外部生成，本地只把
// callback URL 交回去，不持有 verifier，不本地换 token。
func runExternalAuthSource(
	ctx context.Context,
	st *store.Store,
	flow *codexFlow,
	source, email string,
	smsProvider sms.Provider,
	onEmailOTP func(context.Context, string) (string, error),
) (OAuthResult, error) {
	res := OAuthResult{Email: email, Status: "failed"}

	authURL, state, err := requestExternalAuthorizeURL(ctx, source)
	if err != nil {
		res.Message = err.Error()
		return res, err
	}
	flow.authURL = authURL
	flow.state = state
	logCodexE(email, "[Codex][%s] 外部授权地址: %s", strings.ToUpper(source), authURL)

	if err := flow.bootstrapAuthorize(ctx); err != nil {
		return finishWithErr(res, err)
	}
	if err := flow.submitEmail(ctx); err != nil {
		return finishWithErr(res, err)
	}
	otpCode, err := waitEmailOTP(ctx, flow, onEmailOTP, email)
	if err != nil {
		return finishWithErr(res, err)
	}
	if err := flow.submitEmailOTP(ctx, otpCode); err != nil {
		return finishWithErr(res, err)
	}
	if smsProvider != nil {
		phone, perr := flow.verifyPhone(ctx, smsProvider)
		if perr != nil {
			return finishWithErr(res, perr)
		}
		res.Phone = phone
	}
	callbackURL, err := flow.selectWorkspaceAndGetCallback(ctx)
	if err != nil {
		return finishWithErr(res, err)
	}
	res.CallbackURL = callbackURL
	if _, err := extractCode(callbackURL, state); err != nil {
		return finishWithErr(res, err)
	}

	msg, err := submitExternalCallback(ctx, source, callbackURL, email)
	if err != nil {
		return finishWithErr(res, err)
	}

	filename := credentialFilename(email, "")
	payload := map[string]any{
		"email":         email,
		"type":          "codex",
		"auth_source":   source,
		"callback_url":  callbackURL,
		"auth_url":      authURL,
		"state":         state,
		"submitted_at":  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"submit_result": msg,
		"phone":         res.Phone,
	}
	if _, ierr := st.InsertCodexAccount(ctx, store.CodexAccount{
		Filename: filename,
		Email:    email,
		Payload:  payload,
	}); ierr != nil {
		return finishWithErr(res, fmt.Errorf("写入 codex_accounts 失败: %w", ierr))
	}
	res.OK = true
	res.Status = "success"
	res.FilePath = "sqlite://codex_accounts/" + filename
	res.Message = orDefault(msg, source+" callback submitted")
	logCodexE(email, "[Codex][%s] 成功: %s → %s", strings.ToUpper(source), email, filename)
	return res, nil
}

// requestExternalAuthorizeURL 向 CPA / sub2 管理接口要授权地址。
func requestExternalAuthorizeURL(ctx context.Context, source string) (authURL, state string, err error) {
	switch source {
	case "cpa":
		payload, cerr := cpaRequestJSON(ctx, "GET", "/v0/management/codex-auth-url", nil)
		if cerr != nil {
			return "", "", cerr
		}
		data, _ := payload["data"].(map[string]any)
		authURL = firstNonEmpty(
			cpaStr(payload, "url"), cpaStr(payload, "auth_url"), cpaStr(payload, "authUrl"),
			cpaStr(data, "url"), cpaStr(data, "auth_url"), cpaStr(data, "authUrl"),
		)
		state = firstNonEmpty(
			cpaStr(payload, "state"), cpaStr(payload, "auth_state"), cpaStr(payload, "authState"),
			cpaStr(data, "state"), cpaStr(data, "auth_state"), cpaStr(data, "authState"),
			stateFromURL(authURL),
		)
	case "sub2":
		return "", "", fmt.Errorf("[Codex][sub2] SUB2API_API_BASE 未配置，改用 local 模式")
	default:
		return "", "", fmt.Errorf("未知授权来源: %s", source)
	}
	if !strings.HasPrefix(authURL, "http") {
		return "", "", fmt.Errorf("[Codex][%s] 未返回有效 auth_url", source)
	}
	if state == "" {
		return "", "", fmt.Errorf("[Codex][%s] 授权地址缺少 state", source)
	}
	return authURL, state, nil
}

// submitExternalCallback 把 callback URL 交回 CPA。
// 对齐上游 _submit_cpa_callback (L637-675)：重试 5 次，间隔 6s。
func submitExternalCallback(ctx context.Context, source, callbackURL, email string) (string, error) {
	if source != "cpa" {
		return "", fmt.Errorf("[Codex][%s] 回调提交通道未实现", source)
	}
	body := map[string]any{
		"provider":     "codex",
		"redirect_url": callbackURL,
	}
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		payload, err := cpaRequestJSON(ctx, "POST", "/v0/management/oauth-callback", body)
		if err == nil {
			msg := firstNonEmpty(cpaStr(payload, "message"), cpaStr(payload, "status_message"))
			return orDefault(msg, "CPA callback submitted"), nil
		}
		lastErr = err
		logCodexE(email, "[Codex][CPA] callback 提交失败 (第 %d/5 次): %v", attempt, err)
		if attempt >= 5 {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(6 * time.Second):
		}
	}
	return "", fmt.Errorf("[Codex][CPA] callback 提交失败: %w", lastErr)
}

// finishWithErr 统一把错误翻译成 OAuthResult：
// 终局错误 → deactivated；其余 → failed。
func finishWithErr(res OAuthResult, err error) (OAuthResult, error) {
	if une := asAccountUnusable(err); une != nil {
		res.Status = "deactivated"
		res.Message = fmt.Sprintf("账号已废（%s）", une.Code)
		logCodexE(res.Email, "[Codex] 账号已废（%s）：%s", une.Code, res.Email)
		return res, nil
	}
	res.Status = "failed"
	res.Message = err.Error()
	logCodexE(res.Email, "[Codex] 失败：%s，%v", res.Email, err)
	return res, err
}

// asAccountUnusable 从 error 链里挖 *AccountUnusableError。
func asAccountUnusable(err error) *protocol.AccountUnusableError {
	for err != nil {
		if une, ok := err.(*protocol.AccountUnusableError); ok {
			return une
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return nil
		}
		err = u.Unwrap()
	}
	return nil
}

// stateFromURL 从授权地址的 query 里抠 state。
func stateFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// logf 允许外部注入日志实现；默认走标准库输出。
var logf = func(msg string) { fmt.Println(msg) }

// SetLogFunc 注入日志函数（由调度层在启动时接上任务日志）。
func SetLogFunc(fn func(string)) {
	if fn != nil {
		logf = fn
	}
}

// logCodex 统一格式化输出，与上游 logger.info 的 %s 占位一致。
func logCodex(format string, args ...any) {
	if logf == nil {
		return
	}
	if len(args) == 0 {
		logf(format)
		return
	}
	logf(fmt.Sprintf(format, args...))
}

// -----------------------------------------------------------------------------
// 按邮箱维度的日志分流
//
// 上游 codex_retry_service.run_worker 用 logging.FileHandler + addFilter(threadName)
// 把单线程日志精确写进 注册日志/codex-retry-<email>.log。Go 版没有 thread-local 日志，
// 批量补跑若共用全局 logf 会写成一锅粥。这里用 email 维度 sink 表做到同等隔离：
// worker 起跑挂 sink，收尾摘 sink；日志既进全局 logf，也进该邮箱独有的 sink。
// -----------------------------------------------------------------------------

var (
	sinkMu sync.RWMutex
	sinks  = map[string]func(string){}
)

func sinkKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// SetEmailSink 给某个邮箱挂一个日志接收器；fn 传 nil 表示摘除。
func SetEmailSink(email string, fn func(string)) {
	k := sinkKey(email)
	if k == "" {
		return
	}
	sinkMu.Lock()
	defer sinkMu.Unlock()
	if fn == nil {
		delete(sinks, k)
		return
	}
	sinks[k] = fn
}

// logCodexE 带 email 的日志：先走全局 logf，再分发给该邮箱的 sink。
func logCodexE(email, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	logCodex("%s", msg)
	k := sinkKey(email)
	if k == "" {
		return
	}
	sinkMu.RLock()
	fn := sinks[k]
	sinkMu.RUnlock()
	if fn != nil {
		fn(msg)
	}
}
