package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/sms"
)

// Codex 协议常量，与上游 config/codex.py:16-29 同源。
// 注意：这里的 redirect_uri 是 Codex CLI 标准回调 localhost:1455，
// 与注册链路用的 https://chatgpt.com/api/auth/callback/openai 是两套，不能混。
const (
	codexClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexAuthURL     = "https://auth.openai.com/oauth/authorize"
	codexTokenURL    = "https://auth.openai.com/oauth/token"
	codexRedirectURI = "http://localhost:1455/auth/callback"
	codexScope       = "openid email profile offline_access"

	codexAuthBase = "https://auth.openai.com"
	codexSentinel = "https://sentinel.openai.com/backend-api/sentinel/req"

	codexMaxRedirects = 15
	codexPhoneRetries = 5
	codexSMSWait      = 120 * time.Second
	codexSMSPoll      = 5 * time.Second

	// Codex OAuth 网络层重试。与上游 codex_oauth._with_net_retry 对齐：
	// 只重试 EOF/TLS/代理/超时等临时网络错误，业务 4xx 不重试。
	codexNetMaxAttempts = 3
	codexNetBackoffBase = 2 * time.Second
)

// codexFlow 持有一条 Codex 授权链的全部状态。
// 生命周期与一次 RunCodexOAuth 调用一致：所有中间态（state / verifier / cookie）
// 都封在这里，天然隔离，不会与注册链路互相污染。
type codexFlow struct {
	sess      *protocol.Session
	solver    sentinel.Solver
	deviceID  string
	email     string
	state     string
	verifier  string
	challenge string
	authURL   string
	logf      func(format string, args ...any)
}

func (f *codexFlow) log(format string, args ...any) {
	if f.logf != nil {
		f.logf(format, args...)
	}
}

// newCodexFlow 建会话 + 生成 PKCE + 拼授权地址。
// 对齐上游 run_codex_oauth 的 local 分支：L1421-1424。
func newCodexFlow(ctx context.Context, email, proxyURL string, solver sentinel.Solver, deviceID string, image protocol.BrowserProfile, logf func(string, ...any)) (*codexFlow, error) {
	if strings.TrimSpace(deviceID) == "" {
		deviceID = sentinel.DeviceID()
	}
	image = image.Complete(proxyURL)
	sess, err := protocol.NewSession(protocol.SessionOptions{
		UserAgent:   image.UserAgent,
		Language:    image.Language,
		Timezone:    image.Timezone,
		Screen:      image.Screen,
		DeviceID:    deviceID,
		Proxy:       proxyURL,
		ProfileName: image.TLSProfile,
	})
	if err != nil {
		return nil, fmt.Errorf("创建 TLS 会话失败: %w", err)
	}
	verifier, challenge, err := pkceS256()
	if err != nil {
		sess.Close()
		return nil, err
	}
	state, err := randomState()
	if err != nil {
		sess.Close()
		return nil, err
	}
	f := &codexFlow{
		sess:      sess,
		solver:    solver,
		deviceID:  deviceID,
		email:     email,
		state:     state,
		verifier:  verifier,
		challenge: challenge,
		logf:      logf,
	}
	if f.solver == nil {
		f.solver = sentinel.NewSynthetic()
	}
	f.authURL = f.buildAuthorizeURL(state, challenge)
	return f, nil
}

// buildAuthorizeURL 对齐上游 _build_authorize_url (L163-177)。
func (f *codexFlow) buildAuthorizeURL(state, challenge string) string {
	q := url.Values{}
	q.Set("client_id", codexClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", codexRedirectURI)
	q.Set("scope", codexScope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "login")
	q.Set("id_token_add_organizations", "true")
	q.Set("codex_cli_simplified_flow", "true")
	// 前端同源参数，对齐上游 _ensure_oai_context_url (L180-200)
	q.Set("ext-oai-did", f.deviceID)
	q.Set("auth_session_logging_id", randomToken(16))
	q.Set("screen_hint", "login_or_signup")
	return codexAuthURL + "?" + q.Encode()
}

// bootstrapAuthorize 对齐上游 _bootstrap_authorize (L786-812)：
// GET 授权地址并跟随重定向落到登录页，建立 auth.openai.com 会话。
func (f *codexFlow) bootstrapAuthorize(ctx context.Context) error {
	f.log("[Codex] 跟随授权地址建立会话: %s", f.authURL)
	cur := f.authURL
	for hop := 0; hop < codexMaxRedirects; hop++ {
		extra := map[string]string{
			"Referer":        "https://chatgpt.com/",
			"Sec-Fetch-Site": "cross-site",
		}
		label := fmt.Sprintf("bootstrap authorize 第 %d 跳", hop)
		resp, err := retryCodexNetwork(
			ctx,
			label,
			codexNetMaxAttempts,
			codexNetBackoffBase,
			waitCodexRetry,
			f.log,
			func() (*http.Response, error) {
				return f.sess.RequestCtx(ctx, http.MethodGet, cur, "", extra)
			},
		)
		if err != nil {
			return fmt.Errorf("%s失败: %w", label, err)
		}
		loc, status := protocol.ReadContinue(resp)
		if protocol.IsAuthErrorURL(loc) {
			if une := protocol.DetectAccountUnusable(loc); une != nil {
				return une
			}
			return fmt.Errorf("授权页落到错误页: %s", protocol.ParseAuthErrorPayload(loc))
		}
		if status >= 300 && status < 400 && loc != "" {
			cur = absAuthURL(loc)
			continue
		}
		if status >= 400 {
			return fmt.Errorf("bootstrap authorize 被拒绝 (状态码 %d)", status)
		}
		f.log("[Codex] authorize 落点成功 (状态码 %d)", status)
		return nil
	}
	return fmt.Errorf("bootstrap authorize 超过 %d 跳", codexMaxRedirects)
}

// retryCodexNetwork 对 OAuth 网络请求做有限次指数退避重试。
// 只处理临时网络错误；HTTP 状态码由调用方判断，不能在这里盲目重试。
func retryCodexNetwork(
	ctx context.Context,
	label string,
	maxAttempts int,
	backoffBase time.Duration,
	wait func(context.Context, time.Duration) error,
	logf func(string, ...any),
	fn func() (*http.Response, error),
) (*http.Response, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := fn()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isTransientCodexNetworkError(err) {
			return nil, err
		}
		if attempt >= maxAttempts {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		delay := backoffBase * time.Duration(1<<(attempt-1))
		if logf != nil {
			logf("[Codex] %s 临时性网络错误 (第 %d/%d 次): %v，%s 后重试",
				label, attempt, maxAttempts, err, delay)
		}
		if err := wait(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func waitCodexRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isTransientCodexNetworkError 与上游 _is_transient_network_error 同义：
// 代理抖动、TLS 握手失败、连接重置和超时都可重试。
func isTransientCodexNetworkError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"eof",
		"tls",
		"ssl",
		"wrong version number",
		"connection reset",
		"connection refused",
		"connection aborted",
		"timed out",
		"timeout",
		"proxyconnect",
		"proxy connection",
		"proxy error",
		"network is unreachable",
		"no route to host",
		"broken pipe",
		"empty reply from server",
		"server closed idle connection",
		"http2: client connection lost",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// sentinelToken 对齐上游 request_sentinel_token + build_sentinel_header (openai_auth.py:336/410)。
// 返回 openai-sentinel-token 头的值；失败返回空串由调用方降级为不带 token。
func (f *codexFlow) sentinelToken(ctx context.Context, flow string) string {
	req := sentinel.Request{
		UserAgent: f.sess.UserAgent,
		Language:  f.sess.Language,
		Languages: sentinel.LanguagesFor(f.sess.Language),
		Timezone:  f.sess.Timezone,
		Screen:    f.sess.Screen,
		DeviceID:  f.deviceID,
		Flow:      flow,
	}
	p, err := f.solver.Requirements(ctx, req)
	if err != nil || p == "" {
		f.log("[Sentinel] flow=%s requirements 生成失败: %v", flow, err)
		return ""
	}
	body, _ := json.Marshal(map[string]string{"p": p, "flow": flow})
	resp, err := f.sess.RequestCtx(ctx, http.MethodPost, codexSentinel, string(body), map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://sentinel.openai.com",
		"Referer":      "https://sentinel.openai.com/",
	})
	if err != nil {
		f.log("[Sentinel] flow=%s 请求挑战失败: %v", flow, err)
		return ""
	}
	var ch sentinel.Challenge
	raw, status := readAllBody(resp)
	if status != 200 {
		f.log("[Sentinel] flow=%s 返回状态码 %d", flow, status)
		return ""
	}
	if err := json.Unmarshal(raw, &ch); err != nil || ch.Token == "" {
		f.log("[Sentinel] flow=%s 挑战解析失败或无 token", flow)
		return ""
	}
	token, err := f.solver.Solve(ctx, req, ch, p)
	if err != nil {
		f.log("[Sentinel] flow=%s solve 失败: %v", flow, err)
		return ""
	}
	f.log("[Sentinel] flow=%s token 生成成功 (len=%d)", flow, len(token))
	return token
}

// submitEmail 对齐上游 _submit_email (L819-836)。
func (f *codexFlow) submitEmail(ctx context.Context) error {
	token := f.sentinelToken(ctx, "authorize_continue")
	payload, _ := json.Marshal(map[string]any{
		"username": map[string]string{"kind": "email", "value": f.email},
	})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       codexAuthBase,
		"Referer":      codexAuthBase + "/log-in",
	}
	if token != "" {
		headers["Openai-Sentinel-Token"] = token
	}
	resp, err := f.sess.RequestCtx(ctx, http.MethodPost, codexAuthBase+"/api/accounts/authorize/continue", string(payload), headers)
	if err != nil {
		return fmt.Errorf("提交邮箱失败: %w", err)
	}
	raw, status := readAllBody(resp)
	loc, _ := decodeContinue(raw, status)
	if protocol.IsAuthErrorURL(loc) {
		if une := protocol.DetectAccountUnusable(loc); une != nil {
			return une
		}
		return fmt.Errorf("提交邮箱落到错误页: %s", protocol.ParseAuthErrorPayload(loc))
	}
	if status != 200 && status != 204 {
		if une := detectUnusableFromBody(raw); une != nil {
			return une
		}
		return fmt.Errorf("提交邮箱被拒绝 status=%d: %s", status, truncate(string(raw), 300))
	}
	f.log("[Codex] 已提交邮箱 %s，等待邮箱 OTP", f.email)
	return nil
}

// submitEmailOTP 对齐上游 _submit_email_otp (L843-871)。
func (f *codexFlow) submitEmailOTP(ctx context.Context, code string) error {
	token := f.sentinelToken(ctx, "email_otp_validate")
	payload, _ := json.Marshal(map[string]string{"code": code})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       codexAuthBase,
		"Referer":      codexAuthBase + "/email-verification",
	}
	if token != "" {
		headers["Openai-Sentinel-Token"] = token
	}
	resp, err := f.sess.RequestCtx(ctx, http.MethodPost, codexAuthBase+"/api/accounts/email-otp/validate", string(payload), headers)
	if err != nil {
		return fmt.Errorf("提交邮箱验证码失败: %w", err)
	}
	raw, status := readAllBody(resp)
	loc, _ := decodeContinue(raw, status)
	if protocol.IsAuthErrorURL(loc) {
		if une := protocol.DetectAccountUnusable(loc); une != nil {
			return une
		}
	}
	if status != 200 {
		if une := detectUnusableFromBody(raw); une != nil {
			return une
		}
		return fmt.Errorf("邮箱验证码校验失败 status=%d: %s", status, truncate(string(raw), 300))
	}
	f.log("[Codex] 邮箱验证码通过")
	return nil
}

// verifyPhone 对齐上游 _do_phone_verification (L892-990)：
// add-phone/send → 等短信 → phone-otp/validate，失败换号重试。
func (f *codexFlow) verifyPhone(ctx context.Context, provider sms.Provider) (string, error) {
	if provider == nil {
		return "", fmt.Errorf("未配置接码平台，Codex 授权需要手机验证")
	}
	referer := codexAuthBase + "/add-phone"
	for attempt := 1; attempt <= codexPhoneRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		actID, phone, err := provider.AcquireNumber(ctx, "openai", "")
		if err != nil {
			if err == sms.ErrNoBalance {
				return "", err
			}
			f.log("[Codex] 取号失败 (尝试 %d/%d): %v", attempt, codexPhoneRetries, err)
			continue
		}
		f.log("[Codex] 手机验证尝试 %d/%d，号码=+%s", attempt, codexPhoneRetries, phone)

		sendBody, _ := json.Marshal(map[string]string{
			"phone_number": "+" + strings.TrimPrefix(phone, "+"),
			"channel":      "sms",
		})
		sendResp, sendErr := f.sess.RequestCtx(ctx, http.MethodPost, codexAuthBase+"/api/accounts/add-phone/send", string(sendBody), map[string]string{
			"Content-Type": "application/json",
			"Origin":       codexAuthBase,
			"Referer":      referer,
		})
		if sendErr != nil {
			f.log("[Codex] add-phone/send 网络失败: %v", sendErr)
			_ = provider.Cancel(ctx, actID)
			continue
		}
		sendRaw, sendStatus := readAllBody(sendResp)
		if sendStatus != 200 && sendStatus != 204 {
			f.log("[Codex] add-phone/send 拒绝 status=%d: %s", sendStatus, truncate(string(sendRaw), 240))
			_ = provider.Cancel(ctx, actID)
			continue
		}

		code, waitErr := provider.WaitSMSCode(ctx, actID, codexSMSWait, codexSMSPoll)
		if waitErr != nil || code == "" {
			f.log("[Codex] 号码 +%s 未收到短信，换号", phone)
			_ = provider.Cancel(ctx, actID)
			continue
		}

		valBody, _ := json.Marshal(map[string]string{"code": code})
		valResp, valErr := f.sess.RequestCtx(ctx, http.MethodPost, codexAuthBase+"/api/accounts/phone-otp/validate", string(valBody), map[string]string{
			"Content-Type": "application/json",
			"Origin":       codexAuthBase,
			"Referer":      codexAuthBase + "/phone-verification",
		})
		if valErr != nil {
			f.log("[Codex] phone-otp/validate 网络失败: %v", valErr)
			_ = provider.Cancel(ctx, actID)
			continue
		}
		valRaw, valStatus := readAllBody(valResp)
		if valStatus != 200 {
			f.log("[Codex] phone-otp/validate 失败 status=%d: %s", valStatus, truncate(string(valRaw), 240))
			_ = provider.Cancel(ctx, actID)
			continue
		}
		_ = provider.Complete(ctx, actID)
		f.log("[Codex] 手机号验证通过: +%s", phone)
		return phone, nil
	}
	return "", fmt.Errorf("手机验证重试 %d 次仍失败", codexPhoneRetries)
}

// workspaceID 对齐上游 _get_workspace_id (L997-1028)：
// 从 oai-client-auth-session cookie 第一段 base64 解 workspaces[0].id。
func (f *codexFlow) workspaceID() (string, error) {
	raw := f.sess.GetCookie("oai-client-auth-session")
	if raw == "" {
		return "", fmt.Errorf("找不到 oai-client-auth-session cookie，无法取 workspace_id")
	}
	first := raw
	if i := strings.Index(raw, "."); i > 0 {
		first = raw[:i]
	}
	payload := decodeJWTSegment(first)
	if len(payload) == 0 {
		return "", fmt.Errorf("oai-client-auth-session cookie 解不出 JSON")
	}
	workspaces, _ := payload["workspaces"].([]any)
	if len(workspaces) == 0 {
		return "", fmt.Errorf("cookie 里无 workspaces 字段")
	}
	firstWS, _ := workspaces[0].(map[string]any)
	wid, _ := firstWS["id"].(string)
	if wid == "" {
		return "", fmt.Errorf("workspaces[0] 无 id")
	}
	f.log("[Codex] workspace_id=%s", wid)
	return wid, nil
}

// selectWorkspaceAndGetCallback 对齐上游 _select_workspace_and_get_callback (L1031-1069)。
func (f *codexFlow) selectWorkspaceAndGetCallback(ctx context.Context) (string, error) {
	wid, err := f.workspaceID()
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"workspace_id": wid})
	resp, err := f.sess.RequestCtx(ctx, http.MethodPost, codexAuthBase+"/api/accounts/workspace/select", string(body), map[string]string{
		"Content-Type": "application/json",
		"Origin":       codexAuthBase,
		"Referer":      codexAuthBase + "/sign-in-with-chatgpt/codex/consent",
	})
	if err != nil {
		return "", fmt.Errorf("workspace/select 失败: %w", err)
	}
	raw, status := readAllBody(resp)
	loc := resp.Header.Get("Location")

	if loc != "" && isLocalhostCallback(loc) {
		return loc, nil
	}
	if next := pickNextURL(raw); next != "" {
		return f.followUntilCallback(ctx, next)
	}
	if loc != "" {
		return f.followUntilCallback(ctx, loc)
	}
	return "", fmt.Errorf("workspace/select 后找不到下一跳 URL: status=%d, body=%s", status, truncate(string(raw), 300))
}

// followUntilCallback 对齐上游 _follow_until_callback (L1072-1091)。
func (f *codexFlow) followUntilCallback(ctx context.Context, start string) (string, error) {
	cur := absAuthURL(start)
	for hop := 0; hop < codexMaxRedirects; hop++ {
		if isLocalhostCallback(cur) {
			return cur, nil
		}
		resp, err := f.sess.RequestCtx(ctx, http.MethodGet, cur, "", map[string]string{
			"Referer": codexAuthBase + "/",
		})
		if err != nil {
			return "", fmt.Errorf("callback 第 %d 跳失败: %w", hop, err)
		}
		loc, status := protocol.ReadContinue(resp)
		if protocol.IsAuthErrorURL(loc) {
			if une := protocol.DetectAccountUnusable(loc); une != nil {
				return "", une
			}
			return "", fmt.Errorf("callback 链路落到错误页: %s", protocol.ParseAuthErrorPayload(loc))
		}
		if loc == "" {
			return "", fmt.Errorf("callback 跟随中断: status=%d body=%s", status, truncate(loc, 200))
		}
		if isLocalhostCallback(loc) {
			return loc, nil
		}
		cur = absAuthURL(loc)
	}
	return "", fmt.Errorf("callback 跟随超过 %d 跳", codexMaxRedirects)
}

// extractCode 对齐上游 _extract_code (L694-710)：校验 state、丢掉 error 参数。
func extractCode(callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("解析 callback URL 失败: %w", err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		return "", fmt.Errorf("授权服务器返回错误: error=%s, desc=%s", e, q.Get("error_description"))
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("redirect_uri 缺少 code 参数: %s", callbackURL)
	}
	if got := q.Get("state"); got != "" && got != state {
		return "", fmt.Errorf("state 不匹配（疑似 CSRF）: expected=%s, got=%s", head(state, 8), head(got, 8))
	}
	return code, nil
}

// ---- 小工具 ----

func absAuthURL(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "/") {
		return codexAuthBase + raw
	}
	return codexAuthBase + "/" + raw
}

// isLocalhostCallback 对齐上游 _is_redirect_uri (L682-691)。
func isLocalhostCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return (u.Scheme == "http" || u.Scheme == "https") &&
		(host == "localhost" || host == "127.0.0.1") &&
		u.Port() == "1455" &&
		u.Path == "/auth/callback"
}

// readAllBody 读完并关闭响应体，返回内容和状态码。
func readAllBody(resp *http.Response) ([]byte, int) {
	if resp == nil {
		return nil, 0
	}
	if resp.Body == nil {
		return nil, resp.StatusCode
	}
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if len(buf) > 1<<20 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = resp.Body.Close()
	return buf, resp.StatusCode
}

// decodeContinue 从已读出的响应体里找 continue_url / external_url / url / page.*，
// 与 protocol.ReadContinue 同语义，区别是不再消费 Body（Body 已读完）。
func decodeContinue(raw []byte, status int) (string, int) {
	if len(raw) == 0 {
		return "", status
	}
	var payload struct {
		ContinueURL string `json:"continue_url"`
		ExternalURL string `json:"external_url"`
		URL         string `json:"url"`
		Page        struct {
			ContinueURL string `json:"continue_url"`
			ExternalURL string `json:"external_url"`
			URL         string `json:"url"`
		} `json:"page"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", status
	}
	for _, cand := range []string{
		payload.ContinueURL, payload.ExternalURL, payload.URL,
		payload.Page.ContinueURL, payload.Page.ExternalURL, payload.Page.URL,
	} {
		if strings.TrimSpace(cand) != "" {
			return strings.TrimSpace(cand), status
		}
	}
	return "", status
}

// pickNextURL 对齐上游 workspace/select 之后的 JSON 字段探测。
func pickNextURL(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return ""
	}
	for _, key := range []string{"redirect_url", "continue_url", "url", "next", "location"} {
		if v, ok := data[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// detectUnusableFromBody 从响应体里识别账号终局错误码。
// 错误体形如 {"error":{"code":"account_deactivated","message":"..."}}。
func detectUnusableFromBody(raw []byte) *protocol.AccountUnusableError {
	if len(raw) == 0 {
		return nil
	}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	for _, cand := range []string{payload.Error.Code, payload.Error.Type, payload.Code} {
		if protocol.IsDeadAccountCode(cand) {
			return &protocol.AccountUnusableError{Code: protocol.CorpseCode(cand)}
		}
	}
	low := strings.ToLower(string(raw))
	for _, marker := range []string{
		"account_deactivated", "account_deleted", "account_banned",
		"account_suspended", "email_address_changed",
	} {
		if strings.Contains(low, marker) {
			return &protocol.AccountUnusableError{Code: marker}
		}
	}
	return nil
}

// decodeJWTSegment base64url 解一段为 JSON map，失败返回 nil。
func decodeJWTSegment(seg string) map[string]any {
	if seg == "" {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		if decoded, err = base64.URLEncoding.DecodeString(seg); err != nil {
			if decoded, err = base64.StdEncoding.DecodeString(seg); err != nil {
				return nil
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(decoded, &out); err != nil {
		return nil
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
