package protocol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/twofa"
)

// Driver 是纯协议注册驱动。
type Driver struct {
	Solver sentinel.Solver
	// ProfileName 指定 TLS 指纹，空则 Chrome 152。
	ProfileName string
	// Password 固定注册密码，空则自动生成。
	Password string
}

// 2026-09-09/09-12 HAR：authorize URL 与 signin 查询串必须带这组上下文参数。
// 上游 core/chatgpt_auth.py 的 _CC_CAPS / _AUTH_RETURN_TARGET_CATEGORY / _SCREEN_HINT 同源。
const (
	// ccCapsValue 是 NextAuth 生成 authorize URL 时前端声明的登录方式能力集。
	// 缺它时 auth.openai.com 会退回无 ccaps 的旧授权页，落地页类型判定随之漂移。
	ccCapsValue = "login_methods chatgpt_login_finalizer_v1"
	// authReturnTargetCategory 决定 OAuth 完成后回到 chatgpt_home 而非通用首页。
	authReturnTargetCategory = "chatgpt_home"
	// signupScreenHint 是 2026-09-12 起前端的注册入口标识。
	// 旧值 login_or_signup 会被服务端判进遗留密码注册路径，白烧一个邮箱。
	signupScreenHint = "signup"
	// loginScreenHint 是登录链路入口标识（已有账号走 log-in）。
	loginScreenHint = "login"
	// passkeyClientCapabilities 是 orig-ferr 独有的一段 passkey 能力声明。
	passkeyClientCapabilities = "11111"
	// handoffURL 是 2026-09-12 注册抓包新增的「标记认证开始」端点。
	handoffURL = chatGPTBase + "/unauth-mweb/auth/handoff"
	// navigateAccept 是上游 get_auth_navigate_headers / get_chatgpt_navigate_headers
	// 的 accept 原值：带 image/apng 与 signed-exchange，缺这两段会被判定为非浏览器导航。
	navigateAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)

// Name 实现 register.Driver。
func (d *Driver) Name() string { return "protocol" }

// markAuthenticationStarted 复刻上游步骤0：在 GET /api/auth/csrf 之前先打一枪
// POST https://chatgpt.com/unauth-mweb/auth/handoff，带上贯穿整条链路的
// auth_session_logging_id。服务端用它标记「本次认证已开始」。
//
// 这是提示性请求：非 200/204 只记日志，阻断权交给后续真实步骤。
func (d *Driver) markAuthenticationStarted(ctx context.Context, sess *Session) bool {
	if sess.AuthSessionLoggingID == "" {
		sess.AuthSessionLoggingID = sentinel.DeviceID()
	}
	body := `{"authSessionLoggingId":"` + sess.AuthSessionLoggingID + `","authenticationStarted":true}`
	headers := map[string]string{
		"Accept":         "*/*",
		"Content-Type":   "application/json",
		"Origin":         chatGPTBase,
		"Referer":        chatGPTBase + "/",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
	}
	resp, err := sess.RequestCtx(ctx, http.MethodPost, handoffURL, body, headers)
	if err != nil {
		dbg("[步骤0] handoff 异常（不阻断链路）: %v", err)
		return false
	}
	status := resp.StatusCode
	drain(resp)
	if status == 200 || status == 204 {
		dbg("[步骤0] handoff 成功: HTTP %d loggingId=%s", status, sess.AuthSessionLoggingID)
		return true
	}
	dbg("[步骤0] handoff 非预期状态 HTTP %d loggingId=%s", status, sess.AuthSessionLoggingID)
	return false
}

// ensureAuthorizeContext 对 NextAuth 返回的 authorize URL 做最后兜底：
// 补齐 ext-oai-did / auth_session_logging_id / screen_hint / login_hint /
// ccaps / auth_return_target_category。
//
// 为什么要它：NextAuth 在重定向生成阶段会丢掉部分自定义 query（尤其是 ccaps），
// 一旦丢失，auth.openai.com 就按旧授权页处理，后续 continue 落点类型全变。
// 上游 core/chatgpt_auth.py 的 _ensure_authorize_context 同一语义。
func ensureAuthorizeContext(authorizeURL string, sess *Session, email, screenHint string) string {
	if strings.TrimSpace(authorizeURL) == "" {
		return authorizeURL
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return authorizeURL
	}
	if !strings.HasSuffix(u.Hostname(), "auth.openai.com") {
		return authorizeURL
	}
	if screenHint == "" {
		screenHint = signupScreenHint
	}
	q := u.Query()
	required := map[string]string{
		"ext-oai-did":                 sess.DeviceID,
		"auth_session_logging_id":     sess.AuthSessionLoggingID,
		"screen_hint":                 screenHint,
		"login_hint":                  email,
		"ccaps":                       ccCapsValue,
		"auth_return_target_category": authReturnTargetCategory,
	}
	changed := false
	for k, v := range required {
		if v == "" {
			continue
		}
		if strings.TrimSpace(q.Get(k)) == "" {
			q.Set(k, v)
			changed = true
		}
	}
	if !changed {
		return authorizeURL
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Register 执行完整注册链路：
//
//	authorize → 提交邮箱 → (可选) 设密码 → 邮箱 OTP → about-you → 换 session
//
// 每一步失败都会把 Stage 更新到对应阶段，便于调度层归因。
func (d *Driver) Register(ctx context.Context, req register.Request) (res register.Result, err error) {
	res = register.Result{
		Email: req.Email,
		Name:  req.Name,
		Stage: domain.NewStage(),
	}
	if d.Solver == nil {
		d.Solver = sentinel.NewSynthetic()
	}

	proxy := req.Proxy
	// 空代理是合法的：调度层在 NO_PROXY=true 时刻意传入空串，
	// 用于本机验证链路是否通畅。生产环境应始终配置代理。

	seed := sentinel.FingerprintSeed(req.Email)
	deviceID := sentinel.DeviceIDFromSeed(seed)
	res.DeviceID = deviceID

	sess, err := NewSession(SessionOptions{
		DeviceID:    deviceID,
		Proxy:       proxy,
		ProfileName: d.ProfileName,
	})
	if err != nil {
		return res, err
	}
	defer sess.Close()
	defer func() {
		traffic := sess.Traffic()
		res.Traffic = &traffic
	}()
	res.ProxyUsed = proxy

	// 1. 走 NextAuth 拿到 authorize URL
	//
	// OpenAI 不直接接受手拼的 /authorize 参数（会返回 unknown_parameter）。
	// 正确链路是：GET /api/auth/csrf 取 csrfToken → POST /api/auth/signin/openai
	// 由服务端返回 {"url": "https://auth.openai.com/..."}，再跟随它。
	authURL, err := d.signinOpenAI(ctx, sess, req.Email, signupScreenHint)
	if err != nil {
		res.Stage.Fail("authorize", "network")
		return res, err
	}

	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		resp, err = sess.RequestCtx(ctx, http.MethodGet, authURL, "", map[string]string{
			"Referer":        chatGPTBase + "/",
			"Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Dest": "document",
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		res.Stage.Fail("authorize", "network")
		return res, fmt.Errorf("跟随授权页失败: %w", err)
	}
	// 跟随 302 重定向到实际登录/注册落地页（让 auth.openai.com 会话 Cookie 落地）
	authLoc, authStatus := readContinue(resp)
	if authStatus >= 300 && authStatus < 400 && authLoc != "" {
		if strings.HasPrefix(authLoc, "/") {
			authLoc = authBase + authLoc
		}
		resp2, err2 := sess.RequestCtx(ctx, http.MethodGet, authLoc, "", map[string]string{
			"Referer": authURL,
		})
		if err2 == nil {
			drain(resp2)
		}
	}

	// 2. 生成 Sentinel 需求串与 token
	sentReq := sentinel.Request{
		UserAgent: sess.UserAgent,
		Language:  sess.Language,
		Languages: sentinel.LanguagesFor(sess.Language),
		Timezone:  sess.Timezone,
		Screen:    sess.Screen,
		DeviceID:  sess.DeviceID,
		Flow:      "authorize_continue",
	}
	p, err := d.Solver.Requirements(ctx, sentReq)
	if err != nil {
		return res, fmt.Errorf("生成 sentinel requirements 失败: %w", err)
	}
	ch, err := d.fetchChallenge(ctx, sess, p)
	if err != nil {
		// Sentinel 失败不一定致命，继续尝试不带 token
		ch = sentinel.Challenge{}
	}
	token := ""
	if ch.Token != "" {
		token, err = d.Solver.Solve(ctx, sentReq, ch, p)
		if err != nil {
			token = ""
		}
	}

	// 3. 提交邮箱与密码
	//
	// 端点是 /api/accounts/user/register（不是 authorize/continue），
	// 请求体固定为 {password, username}，且必须携带 openai-sentinel-token。
	password := d.Password
	if password == "" {
		password = randomPassword()
	}
	body, _ := json.Marshal(map[string]string{
		"password": password,
		"username": req.Email,
	})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       authBase,
		"Referer":      authBase + "/create-account/password",
	}
	if token != "" {
		headers["Openai-Sentinel-Token"] = token
	}
	resp, err = sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/user/register", string(body), headers)
	if err != nil {
		res.Stage.Fail("email", "network")
		return res, fmt.Errorf("提交邮箱失败: %w", err)
	}
	loc, status := readContinue(resp)
	if status >= 400 {
		res.Stage.Fail("email", "rejected")
		return res, fmt.Errorf("提交邮箱被拒绝（状态 %d）：%s", status, truncateText(loc, 300))
	}
	// 邮箱表单已提交，密码暂存，待验证码及个人资料验证通过后才算真正建号成功
	res.Password = password

	// 4. 触发验证码发送：GET continue_url（通常是 /api/accounts/email-otp/send）
	if loc == "" {
		loc = authBase + "/api/accounts/email-otp/send"
	}
	if strings.HasPrefix(loc, "/") {
		loc = authBase + loc
	}
	resp, err = sess.RequestCtx(ctx, http.MethodGet, loc, "", map[string]string{
		"Referer": authBase + "/create-account/password",
	})
	if err != nil {
		res.Stage.Fail("otp_send", "network")
		return res, fmt.Errorf("触发验证码发送失败: %w", err)
	}
	drain(resp)
	res.Stage.OTPSent = true

	// 5. 等邮箱验证码
	if req.OTP == nil {
		return res, fmt.Errorf("未提供验证码回调")
	}
	code, err := req.OTP(ctx, req.Email)
	if err != nil {
		res.Stage.Fail("otp", "otp")
		return res, fmt.Errorf("获取邮箱验证码失败: %w", err)
	}
	otpContinueURL, err := d.verifyOTP(ctx, sess, code, token)
	if err != nil {
		// 验证码被拒绝时注册尚未完成。清掉后面阶段可能残留的成功标记，
		// 防止编排层把暂存密码当成“已建号”保存下来。
		res.Stage.OTPVerified = false
		res.Stage.AccountCreated = false
		res.Stage.PasswordSet = false
		res.Stage.Fail("otp", "otp")
		return res, fmt.Errorf("校验验证码失败: %w", err)
	}
	res.Stage.OTPVerified = true

	callbackURL := otpContinueURL
	if strings.TrimSpace(callbackURL) == "" {
		res.Stage.Fail("callback", "missing_url")
		return res, fmt.Errorf("验证码提交后未返回有效的跳转地址")
	}

	// 6. 如果返回关于个人资料页面 (about-you)，调用 create_account
	if strings.Contains(otpContinueURL, "about-you") || strings.Contains(otpContinueURL, "about_you") {
		createSentReq := sentinel.Request{
			UserAgent: sess.UserAgent,
			Language:  sess.Language,
			Languages: sentinel.LanguagesFor(sess.Language),
			Timezone:  sess.Timezone,
			Screen:    sess.Screen,
			DeviceID:  sess.DeviceID,
			Flow:      "oauth_create_account",
		}
		createToken := ""
		if cp, cerr := d.Solver.Requirements(ctx, createSentReq); cerr == nil {
			if cch, cerr := d.fetchChallenge(ctx, sess, cp); cerr == nil && cch.Token != "" {
				createToken, _ = d.Solver.Solve(ctx, createSentReq, cch, cp)
			}
		}
		if createToken == "" {
			createToken = token
		}
		createdContinueURL, err := d.createAccount(ctx, sess, req.Name, req.Birthday, createToken)
		if err != nil {
			res.Stage.Fail("about_you", "profile")
			return res, fmt.Errorf("提交个人资料创建账户失败: %w", err)
		}
		if createdContinueURL != "" {
			callbackURL = createdContinueURL
		}
	}
	res.Stage.AccountCreated = true
	res.Stage.PasswordSet = true

	// 7. 逐跳跟随 OAuth callback，建立 ChatGPT session 状态
	if err := d.followOAuthCallback(ctx, sess, callbackURL); err != nil {
		if errors.Is(err, ErrOTPRejected) {
			res.Stage.OTPVerified = false
			res.Stage.AccountCreated = false
			res.Stage.PasswordSet = false
			res.Stage.Fail("otp", "otp_rejected")
			return res, fmt.Errorf("OAuth 回调确认验证码被拒绝: %w", err)
		}
		res.Stage.Fail("callback", "network")
		return res, fmt.Errorf("OAuth 回调跟随失败: %w", err)
	}

	// 8. 读 session，拿 accessToken (多轮自适应重试)
	at, st, err := d.fetchSession(ctx, sess, req.Email)
	if err != nil {
		res.Stage.Fail("session", "credential")
		return res, fmt.Errorf("读取会话 token 失败: %w", err)
	}
	res.AccessToken = at
	res.SessionToken = st
	res.Stage.CredentialAcquired = true

	// 8.5 注册成功后立刻打一次 chatgpt.com/ 保持会话
	pingResp, pingErr := sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/", "", map[string]string{
		"Referer": chatGPTBase + "/auth/login",
	})
	if pingErr == nil {
		drain(pingResp)
	}

	// 9. 如果开启了 2FA，在当前活会话下原地绑定（免受近期登录态 401 限制，免收二次验证码）
	if config.Current().Enable2FA && at != "" {
		totpSecret, err := twofa.Setup2FAWithLanguage(ctx, sess, at, sess.DeviceID, sess.Language)
		if err == nil && totpSecret != "" {
			res.TOTPSecret = totpSecret
		}
	}

	// 把本次注册真正使用的设备指纹带回调度层入库，后续刷新 AT 必须复用它
	image := sess.Profile()
	res.Extra = map[string]any{
		"device_id":            sess.DeviceID,
		"browser_tls_profile":  image.TLSProfile,
		"browser_chrome_major": image.ChromeMajor,
		"browser_user_agent":   image.UserAgent,
		"browser_language":     image.Language,
		"browser_timezone":     image.Timezone,
		"browser_screen":       image.Screen,
	}

	return res, nil
}

// fetchChallenge 向 sentinel 服务请求挑战。
func (d *Driver) fetchChallenge(ctx context.Context, sess *Session, p string) (sentinel.Challenge, error) {
	body, _ := json.Marshal(map[string]string{"p": p, "flow": "authorize_continue"})
	resp, err := sess.RequestCtx(ctx, http.MethodPost, sentinelReq, string(body), map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://sentinel.openai.com",
	})
	if err != nil {
		return sentinel.Challenge{}, err
	}
	defer drain(resp)
	if resp.StatusCode != 200 {
		return sentinel.Challenge{}, fmt.Errorf("sentinel 返回 %d", resp.StatusCode)
	}
	var ch sentinel.Challenge
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		return sentinel.Challenge{}, err
	}
	return ch, nil
}

// setPassword 在新版 create-account/password 页面提交密码。
func (d *Driver) setPassword(ctx context.Context, sess *Session, password string) error {
	body, _ := json.Marshal(map[string]string{"password": password})
	resp, err := sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/password/set", string(body),
		map[string]string{"Content-Type": "application/json", "Origin": authBase})
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("状态码 %d", resp.StatusCode)
	}
	return nil
}

// verifyOTP 提交邮箱验证码，并返回跳转 continue_url。
func (d *Driver) verifyOTP(ctx context.Context, sess *Session, code, sentinelToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{"code": code})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       authBase,
		"Referer":      authBase + "/email-verification",
	}
	if sentinelToken != "" {
		headers["Openai-Sentinel-Token"] = sentinelToken
	}
	resp, err := sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/email-otp/validate", string(body), headers)
	if err != nil {
		return "", err
	}
	loc, status := readContinue(resp)
	if rejected := detectOTPRejected(loc); rejected != nil {
		return "", rejected
	}
	if status >= 400 || strings.TrimSpace(loc) == "" {
		if strings.TrimSpace(loc) == "" {
			return "", &OTPRejectedError{Code: "missing_continue_url"}
		}
		return "", fmt.Errorf("状态码 %d: %s", status, loc)
	}
	return loc, nil
}

// createAccount 提交用户昵称与生日，完成账户建立。
func (d *Driver) createAccount(ctx context.Context, sess *Session, name string, birthday time.Time, sentinelToken string) (string, error) {
	if name == "" {
		name = "Alex"
	}
	if birthday.IsZero() {
		birthday = time.Date(1996, 5, 12, 0, 0, 0, 0, time.UTC)
	}
	body, _ := json.Marshal(map[string]string{
		"name":      name,
		"birthdate": birthday.Format("2006-01-02"),
	})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       authBase,
		"Referer":      authBase + "/about-you",
	}
	if sentinelToken != "" {
		headers["Openai-Sentinel-Token"] = sentinelToken
	}
	resp, err := sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/create_account", string(body), headers)
	if err != nil {
		return "", err
	}
	loc, status := readContinue(resp)
	if status >= 400 {
		return "", fmt.Errorf("创建账户资料失败 (状态码 %d): %s", status, loc)
	}
	return loc, nil
}

// followOAuthCallback 逐跳跟随 OAuth callback，让 chatgpt.com 设置登录态 Cookie。
func (d *Driver) followOAuthCallback(ctx context.Context, sess *Session, continueURL string) error {
	if strings.TrimSpace(continueURL) == "" {
		return fmt.Errorf("OAuth 回调地址为空，未拿到登录跳转 URL")
	}
	currentURL := continueURL
	if strings.HasPrefix(currentURL, "/") {
		currentURL = authBase + currentURL
	}
	prevURL := authBase + "/about-you"
	for hop := 1; hop <= 12; hop++ {
		headers := map[string]string{
			"Referer":                   prevURL,
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    navigateAccept,
		}
		if strings.Contains(currentURL, "chatgpt.com") && strings.Contains(prevURL, "auth.openai.com") {
			headers["Sec-Fetch-Site"] = "cross-site"
		} else {
			headers["Sec-Fetch-Site"] = "same-origin"
		}

		resp, err := sess.RequestCtx(ctx, http.MethodGet, currentURL, "", headers)
		if err != nil {
			return fmt.Errorf("OAuth 回调第 %d 跳失败: %w", hop, err)
		}
		loc, status := readContinue(resp)
		dbg("OAuth hop %d status=%d url=%s loc=%s", hop, status, currentURL, truncateText(loc, 160))

		// OpenAI 有时在验证码提交后继续跳转，才在 OAuth 错误页返回
		// wrong_email_otp_code。必须在普通错误页分支前识别，否则调度层会把
		// 验证码终局拒绝误判成可重试的网络/回调问题。
		if rejected := detectOTPRejected(currentURL); rejected != nil {
			dbg("OAuth 终局判定(验证码拒绝): code=%s requestId=%s", rejected.Code, rejected.RequestID)
			return rejected
		}
		if rejected := detectOTPRejected(loc); rejected != nil {
			dbg("OAuth 终局判定(验证码拒绝/重定向): code=%s requestId=%s", rejected.Code, rejected.RequestID)
			return rejected
		}

		// 命中 auth.openai.com/error?payload=... 时按结构化 payload 判定。
		// OpenAI 的 error 页本身返回 200 且没有 "error=" 子串（query 键是 payload），
		// 旧逻辑把它当终点页 return nil，才导致后面 fetchSession 空转 6 次。
		if isAuthErrorURL(currentURL) {
			if une := detectAccountUnusable(currentURL); une != nil {
				dbg("OAuth 终局判定: code=%s requestId=%s", une.Code, une.RequestID)
				return une
			}
			info := decodeAuthError(currentURL)
			return fmt.Errorf("OAuth 回调返回错误页: code=%s kind=%s msg=%s url=%s",
				info.Code, info.Kind, truncateText(info.Message, 200), truncateText(currentURL, 300))
		}
		if isAuthErrorURL(loc) {
			if une := detectAccountUnusable(loc); une != nil {
				dbg("OAuth 终局判定(重定向): code=%s requestId=%s", une.Code, une.RequestID)
				return une
			}
			info := decodeAuthError(loc)
			return fmt.Errorf("OAuth 回调重定向到错误页: code=%s kind=%s msg=%s url=%s",
				info.Code, info.Kind, truncateText(info.Message, 200), truncateText(loc, 300))
		}

		// 403 且落在 chatgpt.com 的 Cloudflare 托管跳上：改用真实无头 Chromium 承接剩余跳转。
		// 纯协议客户端（tls-client 无论哪个 profile）在这一跳的 TLS/JA3 指纹都会被 CF 拦，
		// 上游 core/browser_environment.py:follow_oauth_callback_with_headless_browser 同语义。
		if status == 403 && strings.Contains(currentURL, "chatgpt.com") {
			dbg("OAuth hop %d 命中 CF 403，切无头浏览器承接: %s", hop, truncateText(currentURL, 160))
			if berr := d.followOAuthCallbackInBrowser(ctx, sess, currentURL); berr != nil {
				return fmt.Errorf("OAuth 回调第 %d 跳 CF 403，浏览器承接失败: %w", hop, berr)
			}
			dbg("OAuth 回调经浏览器承接完成")
			return nil
		}

		if status >= 400 {
			return fmt.Errorf("OAuth 回调第 %d 跳失败 (HTTP %d, URL: %s)", hop, status, currentURL)
		}

		if status < 300 || loc == "" {
			// 到达 chatgpt.com 终点页面，执行一次首页轻量访问确保所有会话 Cookie 落地
			if strings.Contains(currentURL, "chatgpt.com") {
				_r, _ := sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/", "", map[string]string{
					"Referer": currentURL,
				})
				drain(_r)
			}
			return nil
		}
		if !strings.HasPrefix(loc, "http") {
			if strings.HasPrefix(loc, "/") {
				u, _ := url.Parse(currentURL)
				loc = u.Scheme + "://" + u.Host + loc
			}
		}
		prevURL = currentURL
		currentURL = loc
	}
	return nil
}

// fetchSession 从 chatgpt.com 的会话接口读取 accessToken，带自动指数退避重试。
func (d *Driver) fetchSession(ctx context.Context, sess *Session, wantEmail string) (string, string, error) {
	// 浏览器兜底已经拿到 AT 时直接返回，不再走 6 轮轮询。
	if at, st := sess.BrowserSession(); at != "" {
		dbg("fetchSession 直接采用浏览器兜底结果（AT 长度 %d）", len(at))
		return at, st, nil
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return "", "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 750 * time.Millisecond):
			}
		}
		headers := sess.NextAuthHeaders(chatGPTBase + "/")

		resp, err := sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/api/auth/session", "", headers)
		if err != nil {
			lastErr = err
			continue
		}
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("会话接口返回 %d: %s", resp.StatusCode, truncateText(string(bodyBytes), 150))
			// 401/403 是确定性失效（Cookie 未落地 / 号被停），重试只浪费时间；
			// 只有 5xx、429 这类瞬时错误才退避重试。
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return "", "", lastErr
			}
			if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 422 {
				return "", "", lastErr
			}
			continue
		}
		var payload struct {
			AccessToken  string `json:"accessToken"`
			SessionToken string `json:"sessionToken"`
			User         struct {
				Email string `json:"email"`
				ID    string `json:"id"`
			} `json:"user"`
		}
		_ = json.Unmarshal(bodyBytes, &payload)
		if strings.TrimSpace(string(bodyBytes)) == "{}" {
			return "", "", ErrNoSessionEstablished
		}

		// 会话身份校验：session_token 指向别人时，换回来的 AT 属于别的账号
		if payload.AccessToken != "" && wantEmail != "" && payload.User.Email != "" &&
			!strings.EqualFold(strings.TrimSpace(payload.User.Email), strings.TrimSpace(wantEmail)) {
			lastErr = fmt.Errorf("会话身份错位：期望 %s，实际 %s", wantEmail, payload.User.Email)
			continue
		}

		st := payload.SessionToken
		if st == "" {
			st = sess.GetSessionTokenCookie()
		}

		if payload.AccessToken != "" {
			return payload.AccessToken, st, nil
		}

		// 若已捕获到 sessionToken 证明登录回调已生效，但 /api/auth/session 短暂返回空对象，
		// 尝试用 sessionToken 走极速通道换取 AT
		if st != "" && attempt >= 2 {
			if fastAT, fastErr := d.refreshAccessTokenFromSessionToken(ctx, st, sess.DeviceID, sess.Proxy, sess.Profile()); fastErr == nil && fastAT != "" {
				return fastAT, st, nil
			}
		}

		dbg("fetchSession 第 %d 次返回 %d，body=%s，cookies=%v", attempt, resp.StatusCode, truncateText(string(bodyBytes), 120), sess.CookieNames())
		lastErr = fmt.Errorf("会话中没有 accessToken (返回: %s, 尝试 %d/6)", truncateText(string(bodyBytes), 80), attempt)

	}
	return "", "", lastErr
}

// RefreshAccessTokenFromSessionToken 使用已有 session_token 快速刷新 accessToken。
func (d *Driver) RefreshAccessTokenFromSessionToken(ctx context.Context, sessionToken, deviceID, proxy string) (string, error) {
	return d.refreshAccessTokenFromSessionToken(ctx, sessionToken, deviceID, proxy, d.BrowserProfile(proxy))
}

// RefreshAccessTokenFromSessionTokenUsingProfile 使用账号注册时固化的画像刷新 AT。
// session_token 与 oai-did/TLS 身份绑定，续跑和查活不能重新生成默认浏览器环境。
func (d *Driver) RefreshAccessTokenFromSessionTokenUsingProfile(ctx context.Context, sessionToken, deviceID, proxy string, image BrowserProfile) (string, error) {
	image = image.Complete(proxy)
	return d.refreshAccessTokenFromSessionToken(ctx, sessionToken, deviceID, proxy, image)
}

func (d *Driver) refreshAccessTokenFromSessionToken(ctx context.Context, sessionToken, deviceID, proxy string, image BrowserProfile) (string, error) {
	if strings.TrimSpace(sessionToken) == "" {
		return "", fmt.Errorf("sessionToken 不能为空")
	}
	// oai-did 必须与注册时一致：OpenAI 把 session 绑在设备指纹上，
	// 换一个新的 UUID 去换 AT，/api/auth/session 直接回 {} 或 401。
	if strings.TrimSpace(deviceID) == "" {
		deviceID = sentinel.DeviceID()
	}
	sess, err := NewSession(SessionOptions{
		UserAgent:   image.UserAgent,
		Language:    image.Language,
		Timezone:    image.Timezone,
		Screen:      image.Screen,
		DeviceID:    deviceID,
		Proxy:       proxy,
		ProfileName: image.TLSProfile,
	})
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// 本会话用完即清，避免分片 cookie 残留在 jar 里污染下一轮换取
	defer sess.ClearSessionTokenCookie(".chatgpt.com")

	// 1. 设置 oai-did 与 session-token
	sess.SetCookie("oai-did", sess.DeviceID, ".chatgpt.com")
	sess.SetSessionTokenCookie(sessionToken, ".chatgpt.com")

	// 2. 访问轻量 csrf 接口获取 cf 认证和 NextAuth 状态
	csrfResp, _ := sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/api/auth/csrf", "", map[string]string{
		"Accept":  "application/json",
		"Referer": chatGPTBase + "/",
	})
	drain(csrfResp)

	at, _, err := d.fetchSession(ctx, sess, "")
	return at, err
}

// LoginWithPasswordLogged 支持进度日志回调的纯协议登录。
func (d *Driver) LoginWithPasswordLogged(ctx context.Context, email, password, totpSecret, deviceID, proxy string, onLog func(string)) (string, string, error) {
	return d.LoginWithPasswordUsingProfileLogged(ctx, email, password, totpSecret, deviceID, proxy, d.BrowserProfile(proxy), onLog)
}

// LoginWithPasswordUsingProfileLogged 使用调用方指定的画像登录。
// 账号续跑时应传入注册时落库的画像，避免代理地区或配置变化后身份漂移。
func (d *Driver) LoginWithPasswordUsingProfileLogged(ctx context.Context, email, password, totpSecret, deviceID, proxy string, image BrowserProfile, onLog func(string)) (string, string, error) {
	log := func(msg string) {
		if onLog != nil {
			onLog(msg)
		}
	}
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if email == "" {
		return "", "", fmt.Errorf("邮箱不能为空")
	}
	if password == "" {
		return "", "", fmt.Errorf("密码不能为空")
	}
	if d.Solver == nil {
		d.Solver = sentinel.NewSynthetic()
	}

	// 复用账号注册时的 oai-did，否则登录链路会被判为异地新设备
	if strings.TrimSpace(deviceID) == "" {
		deviceID = sentinel.DeviceID()
	}
	log("[1/5] 初始化 TLS 指纹客户端并分配出口代理...")
	image = image.Complete(proxy)
	log(fmt.Sprintf("环境画像：TLS=%s UA=Chrome/%s 语言=%s 时区=%s 屏幕=%s", image.TLSProfile, image.ChromeMajor, image.Language, image.Timezone, image.Screen))
	sess, err := NewSession(SessionOptions{
		UserAgent:   image.UserAgent,
		Language:    image.Language,
		Timezone:    image.Timezone,
		Screen:      image.Screen,
		DeviceID:    deviceID,
		Proxy:       proxy,
		ProfileName: image.TLSProfile,
	})
	if err != nil {
		return "", "", err
	}
	defer sess.Close()

	// 1. NextAuth signin
	log("[2/5] 请求 NextAuth 授权初始化 (GET /api/auth/csrf -> POST /api/auth/signin/openai)...")
	authURL, err := d.signinOpenAI(ctx, sess, email, loginScreenHint)
	if err != nil {
		return "", "", fmt.Errorf("登录授权初始化失败: %w", err)
	}

	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return "", "", ctx.Err()
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		resp, err = sess.RequestCtx(ctx, http.MethodGet, authURL, "", map[string]string{
			"Referer":        chatGPTBase + "/",
			"Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Dest": "document",
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", "", fmt.Errorf("访问授权页面失败: %w", err)
	}
	loc, status := readContinue(resp)
	if status >= 300 && status < 400 && loc != "" {
		if strings.HasPrefix(loc, "/") {
			loc = authBase + loc
		}
		resp2, err2 := sess.RequestCtx(ctx, http.MethodGet, loc, "", map[string]string{
			"Referer": authURL,
		})
		if err2 == nil {
			drain(resp2)
		}
	}

	// 2. 提交邮箱进入登录状态 (POST /api/accounts/authorize/continue)
	log("[3/5] 正在生成 Sentinel 防护挑战并向 OpenAI 提交登录邮箱...")
	sentReq := sentinel.Request{
		UserAgent: sess.UserAgent,
		Language:  sess.Language,
		Languages: sentinel.LanguagesFor(sess.Language),
		Timezone:  sess.Timezone,
		Screen:    sess.Screen,
		DeviceID:  sess.DeviceID,
		Flow:      "authorize_continue",
	}
	p, err := d.Solver.Requirements(ctx, sentReq)
	token := ""
	if err == nil {
		ch, err := d.fetchChallenge(ctx, sess, p)
		if err == nil && ch.Token != "" {
			token, _ = d.Solver.Solve(ctx, sentReq, ch, p)
		}
	}

	authContinueBody, _ := json.Marshal(map[string]any{
		"username": map[string]string{
			"value": email,
			"kind":  "email",
		},
		"screen_hint": "login",
	})
	authContinueHeaders := map[string]string{
		"Content-Type": "application/json",
		"Referer":      authBase + "/log-in",
	}
	if token != "" {
		authContinueHeaders["Openai-Sentinel-Token"] = token
	}
	resp, err = sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/authorize/continue", string(authContinueBody), authContinueHeaders)
	if err != nil {
		return "", "", fmt.Errorf("提交登录邮箱失败: %w", err)
	}
	authStepLoc, authStepStatus := readContinue(resp)
	if isAuthErrorURL(authStepLoc) {
		if une := detectAccountUnusable(authStepLoc); une != nil {
			return "", "", une
		}
		return "", "", fmt.Errorf("登录邮箱探测落到错误页: %s", parseAuthErrorPayload(authStepLoc))
	}
	if authStepStatus >= 400 {
		return "", "", fmt.Errorf("登录邮箱探测被拒绝 (状态码 %d): %s", authStepStatus, truncateText(authStepLoc, 200))
	}
	authStepLower := strings.ToLower(authStepLoc)
	if strings.Contains(authStepLower, "/email") || strings.Contains(authStepLower, "otp") || strings.Contains(authStepLower, "create-account") || strings.Contains(authStepLower, "signup") {
		return "", "", fmt.Errorf("该账号在 OpenAI 侧尚未完成注册（OpenAI 拦截并提示“输入验证码即可创建你的账户”，需先在收件箱获取验证码并在浏览器中完成验证）")
	}

	// 重新计算密码步骤的 Sentinel Token
	token2 := ""
	sentReq.Flow = "password_verify"
	if p2, err2 := d.Solver.Requirements(ctx, sentReq); err2 == nil {
		if ch2, err2 := d.fetchChallenge(ctx, sess, p2); err2 == nil && ch2.Token != "" {
			token2, _ = d.Solver.Solve(ctx, sentReq, ch2, p2)
		}
	}
	if token2 == "" {
		token2 = token
	}

	// 3. 提交密码 (POST /api/accounts/password/verify)
	log("[4/5] 正在向 OpenAI 验证账号密码...")
	body, _ := json.Marshal(map[string]string{
		"password": password,
	})
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       authBase,
		"Referer":      authBase + "/log-in/password",
	}
	if token2 != "" {
		headers["Openai-Sentinel-Token"] = token2
	}
	resp, err = sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/password/verify", string(body), headers)
	if err != nil {
		return "", "", fmt.Errorf("提交登录密码失败: %w", err)
	}
	loc, status = readContinue(resp)
	if isAuthErrorURL(loc) {
		if une := detectAccountUnusable(loc); une != nil {
			return "", "", une
		}
		return "", "", fmt.Errorf("密码验证未通过: %s", parseAuthErrorPayload(loc))
	}
	if status == 401 {
		return "", "", fmt.Errorf("密码验证未通过 (401 凭据不匹配或该账号尚未在官方完成邮箱验证)")
	}
	if status >= 400 {
		return "", "", fmt.Errorf("密码验证被拒绝 (状态码 %d): %s", status, truncateText(loc, 200))
	}

	continueURL := loc

	// 4. 处理 MFA 挑战 (/mfa-challenge/{factor_id})
	//
	// 上游两条链路对 MFA 的形态不同，此前的实现把两条揉在一起：既先发
	// issue_challenge，又对 verify 摘掉 sentinel，结果 verify 稳定 403：
	//   · core/account_liveness.py  _mfa_issue_challenge + _mfa_verify，两者都 pop sentinel
	//   · 协议/auth_flow.py        submit_mfa_totp，**只发 verify**，带 password_verify 的 sentinel
	//                           且同源不发 Origin（_common_headers 只在跨源补 Origin）
	// 浏览器真机走的是 auth_flow.py 那条（密码页 → 直接 submit TOTP），所以
	// 这里优先直连 verify，失败再退回 account_liveness.py 的 issue 前置形态。
	if strings.Contains(continueURL, "/mfa-challenge/") {
		log("[4.5/5] 账号已开启 2FA，正在计算 TOTP 动态码并提交二次验证...")
		if totpSecret == "" {
			return "", "", fmt.Errorf("账号启用了 2FA 但未保存 totp_secret，无法完成二次验证")
		}
		factorID := extractMFAFactorID(continueURL)
		dbg("mfa 进入 _challenge factor_id=%q continue=%s", factorID, truncateText(continueURL, 300))

		type mfaAttempt struct {
			name     string
			withSent bool
			issueFst bool
		}
		var mfaLoc string
		var mfaStatus int
		var mfaRaw string
		solved := false

		for _, att := range []mfaAttempt{
			{name: "direct_sentinel", withSent: true},
			{name: "issue_nosentinel", issueFst: true},
		} {
			fid := factorID
			if att.issueFst {
				issueLoc, issueStatus, issueRaw := d.postMFAIssueChallenge(ctx, sess, fid)
				dbg("mfa issue_challenge[%s] factor=%s status=%d loc=%s body=%s",
					att.name, fid, issueStatus, truncateText(issueLoc, 200), truncateText(issueRaw, 1200))
				if newID := mfaFactorIDFromBody(issueRaw); newID != "" && newID != fid {
					dbg("mfa issue_challenge 回包给了新 factor id: %s -> %s", fid, newID)
					fid = newID
				}
				if issueLoc != "" && strings.Contains(issueLoc, "/mfa-challenge/") {
					if id2 := extractMFAFactorID(issueLoc); id2 != "" {
						fid = id2
					}
				}
				if issueStatus >= 400 {
					mfaStatus, mfaRaw = issueStatus, issueRaw
					continue
				}
			}
			// 跨 TOTP 时间窗再试：本地时钟与服务端偏差一个窗口时，
			// 当前窗口的码会被判错，回退/前滚各一个窗口即可覆盖。
			for _, offset := range []int{0, -1, 1} {
				code, cerr := twofa.GenerateCode(totpSecret, time.Now().Add(time.Duration(offset)*30*time.Second))
				if cerr != nil {
					return "", "", fmt.Errorf("计算 TOTP 动态码失败: %w", cerr)
				}
				sent := ""
				if att.withSent {
					sent = token2
				}
				mfaLoc, mfaStatus, mfaRaw = d.postMFAVerify(ctx, sess, fid, code, sent)
				dbg("mfa verify[%s offset=%d] factor=%s code=%s sentinel=%t status=%d loc=%s body=%s",
					att.name, offset, fid, code, sent != "", mfaStatus,
					truncateText(mfaLoc, 240), truncateText(mfaRaw, 900))
				if mfaStatus >= 200 && mfaStatus < 300 && !isAuthErrorURL(mfaLoc) {
					solved = true
					break
				}
				// 响应体已经是终局停用码：立刻终结，别拿同一个 session 反复重试
				// （第二次会退化成 409 invalid_state，掩盖真实原因）。
				if containsDeadMarker(mfaRaw) {
					if une := deadMarkerFromText(mfaRaw, authBase+"/mfa-challenge/"+fid); une != nil {
						return "", "", une
					}
				}
				// 409 invalid_state = 登录会话已废，换时间窗也没用，直接跳出重试
				if mfaStatus == 409 {
					break
				}
			}
			if solved {
				break
			}
		}

		if !solved {
			// 403 时账号可能已被停用：按 account_liveness._check_mfa_account_unusable
			// 回读一步 MFA 文档，看页面里是否带终局停用码。
			if mfaStatus == 403 || mfaStatus == 400 {
				if une := d.probeMFAUnusable(ctx, sess, factorID); une != nil {
					return "", "", une
				}
			}
			if isAuthErrorURL(mfaLoc) {
				if une := detectAccountUnusable(mfaLoc); une != nil {
					return "", "", une
				}
				return "", "", fmt.Errorf("2FA 验证落到错误页: %s", parseAuthErrorPayload(mfaLoc))
			}
			return "", "", fmt.Errorf("2FA 验证失败 (状态码 %d): %s", mfaStatus, truncateText(mfaRaw, 300))
		}
		if mfaLoc != "" {
			continueURL = mfaLoc
		}
		dbg("mfa 通过，continue=%s", truncateText(continueURL, 300))
	}

	// 5. 跟随 OAuth 回调
	log("[5/5] 密码验证成功，正在跟随 OAuth 回调握手并建立 ChatGPT 会话...")
	if err := d.followOAuthCallback(ctx, sess, continueURL); err != nil {
		return "", "", fmt.Errorf("OAuth 回调失败: %w", err)
	}

	// 6. 获取 session
	log("正在从 chatgpt.com 提取最新 Access Token 与 Session...")
	at, st, err := d.fetchSession(ctx, sess, email)
	if err != nil {
		return "", "", fmt.Errorf("获取会话 token 失败: %w", err)
	}

	log("Access Token 提取成功！")
	return at, st, nil
}

// LoginWithPassword 使用已有账号的邮箱与密码执行纯协议登录，可处理 TOTP 二次验证，返回新 accessToken 与 sessionToken。
func (d *Driver) LoginWithPassword(ctx context.Context, email, password, totpSecret, deviceID, proxy string) (string, string, error) {
	return d.LoginWithPasswordLogged(ctx, email, password, totpSecret, deviceID, proxy, nil)
}

// signinOpenAI 复刻 Python 版 core/chatgpt_auth.py 的三步：
//
//	GET  https://chatgpt.com/api/auth/csrf        拿 csrfToken
//	POST https://chatgpt.com/api/auth/signin/openai 拿 authorize URL
//
// 第一步同时建立 NextAuth 会话 cookie，第二步才被接受。
func (d *Driver) signinOpenAI(ctx context.Context, sess *Session, email, screenHint string) (string, error) {
	if screenHint == "" {
		screenHint = signupScreenHint
	}
	var (
		csrfToken string
		lastErr   error
	)
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		// 步骤0：标记认证开始（上游真机在 GET /api/auth/csrf 之前先打这一枪）
		d.markAuthenticationStarted(ctx, sess)

		// 先访问首页，拿 cf cookie 与 NextAuth 会话
		resp, err := sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/", "", nil)
		if err != nil {
			lastErr = fmt.Errorf("打开 chatgpt.com 失败: %w", err)
			continue
		}
		drain(resp)

		// 1. csrf
		resp, err = sess.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/api/auth/csrf", "", sess.NextAuthHeaders(chatGPTBase+"/"))
		if err != nil {
			lastErr = fmt.Errorf("获取 csrf 失败: %w", err)
			continue
		}
		var csrf struct {
			Token string `json:"csrfToken"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err := json.Unmarshal(body, &csrf); err != nil || csrf.Token == "" {
			lastErr = fmt.Errorf("解析 csrf 失败: %w", err)
			continue
		}
		csrfToken = csrf.Token
		break
	}
	if csrfToken == "" {
		return "", lastErr
	}

	// 2. signin，服务端返回 authorize URL
	//
	// 查询串必须与 2026-09-12 真机抓包同形态，否则服务端会落进遗留密码注册路径：
	//
	//	prompt=login & ext-oai-did & auth_session_logging_id & screen_hint=signup
	//	& login_hint & ext-passkey-client-capabilities=11111 & ccaps=... & auth_return_target_category
	q := url.Values{}
	q.Set("prompt", "login")
	q.Set("ext-oai-did", sess.DeviceID)
	q.Set("auth_session_logging_id", sess.AuthSessionLoggingID)
	q.Set("screen_hint", screenHint)
	q.Set("login_hint", email)
	q.Set("ext-passkey-client-capabilities", passkeyClientCapabilities)
	q.Set("ccaps", ccCapsValue)
	q.Set("auth_return_target_category", authReturnTargetCategory)
	signinURL := chatGPTBase + "/api/auth/signin/openai?" + q.Encode()

	form := url.Values{}
	form.Set("callbackUrl", "/")
	form.Set("csrfToken", csrfToken)
	form.Set("json", "true")

	resp, err := sess.RequestCtx(ctx, http.MethodPost, signinURL, form.Encode(), map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Origin":         chatGPTBase,
		"Accept":         "*/*",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
		"Referer":        chatGPTBase + "/",
	})
	if err != nil {
		return "", fmt.Errorf("发起 signin 失败: %w", err)
	}
	var signed struct {
		URL string `json:"url"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err := json.Unmarshal(body, &signed); err != nil {
		return "", fmt.Errorf("解析 signin 响应失败: %w（状态 %d）", err, resp.StatusCode)
	}
	if signed.URL == "" {
		return "", fmt.Errorf("signin 未返回 authorize URL（状态 %d）", resp.StatusCode)
	}
	// 兜底补齐上下文参数（NextAuth 重定向阶段会丢 ccaps 等自定义 query）
	return ensureAuthorizeContext(signed.URL, sess, email, screenHint), nil
}

// ErrNoSessionEstablished 表示服务端未建立会话（/api/auth/session 返回 {}）。
var ErrNoSessionEstablished = errors.New("服务端未建立登录会话（/api/auth/session 返回 {}）")

// ErrOTPRejected 表示 OpenAI 明确拒绝了本次邮箱验证码。
// 这是注册流程的终局失败：不得尝试密码恢复登录，也不得把注册密码保存成账号。
var ErrOTPRejected = errors.New("邮箱验证码被 OpenAI 拒绝")

// OTPRejectedError 携带 OpenAI 返回的结构化验证码错误信息。
type OTPRejectedError struct {
	Code      string
	RequestID string
	RawURL    string
}

func (e *OTPRejectedError) Error() string {
	msg := "邮箱验证码被 OpenAI 拒绝"
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.RequestID != "" {
		msg += " (requestId=" + e.RequestID + ")"
	}
	return msg
}

func (e *OTPRejectedError) Unwrap() error { return ErrOTPRejected }

// ErrAccountUnusable 账号侧终局错误：OpenAI 已停用/删除/封禁该号，
// 重试刷新 AT 无意义。上游 core/openai_auth.py 的 _ACCOUNT_DEAD_CODES 同源语义。
var ErrAccountUnusable = errors.New("账号已被 OpenAI 停用或删除")

// deadAccountCodes 与上游 _ACCOUNT_DEAD_CODES 对齐（小写比较）。
var deadAccountCodes = map[string]bool{
	"account_deactivated":   true,
	"account_deleted":       true,
	"account_banned":        true,
	"email_address_changed": true,
	"account_suspended":     true,
}

// AccountUnusableError 携带 OpenAI 返回的结构化错误码与 requestId，
// 上层据此把账号标成 dead 并停止重试。
type AccountUnusableError struct {
	Code      string
	RequestID string
	RawURL    string
}

func (e *AccountUnusableError) Error() string {
	msg := fmt.Sprintf("账号已被 OpenAI 停用/删除: %s", e.Code)
	if e.RequestID != "" {
		msg += " (requestId=" + e.RequestID + ")"
	}
	return msg
}

func (e *AccountUnusableError) Unwrap() error { return ErrAccountUnusable }

// authErrorInfo 是 auth.openai.com/error?payload=... 解出来的结构化字段。
type authErrorInfo struct {
	Code      string
	Kind      string
	RequestID string
	Message   string
}

// decodeAuthError 从 error 页 URL 的 payload（base64 后的 JSON）抽结构化错误。
// OpenAI 的错误页形如 https://auth.openai.com/error?payload=eyJlcnJvckNvZGUiOiJhY2NvdW50X2RlYWN0aXZhdGVkIi4uLn0
func decodeAuthError(rawURL string) authErrorInfo {
	var info authErrorInfo
	u, err := url.Parse(rawURL)
	if err != nil {
		return info
	}
	payloadB64 := u.Query().Get("payload")
	if payloadB64 == "" {
		return info
	}
	decoded, derr := base64.StdEncoding.DecodeString(payloadB64)
	if derr != nil {
		decoded, derr = base64.URLEncoding.DecodeString(payloadB64)
	}
	if derr != nil {
		decoded, derr = base64.RawURLEncoding.DecodeString(payloadB64)
	}
	if derr != nil {
		return info
	}
	var data struct {
		ErrorCode string `json:"errorCode"`
		Kind      string `json:"kind"`
		RequestID string `json:"requestId"`
		Message   string `json:"message"`
		Desc      string `json:"errorDescription"`
		Error     struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(decoded, &data) != nil {
		return info
	}
	info.Code = data.ErrorCode
	if info.Code == "" {
		info.Code = data.Error.Code
	}
	if info.Code == "" {
		info.Kind = data.Kind
		info.Code = data.Kind
	}
	info.Kind = data.Kind
	info.RequestID = data.RequestID
	info.Message = data.Message
	if info.Message == "" {
		info.Message = data.Desc
	}
	if info.Message == "" {
		info.Message = data.Error.Message
	}
	return info
}

// detectOTPRejected 识别 OpenAI 验证码错误页。旧逻辑把错误页当成普通回调，
// 让驱动先设置了 OTPVerified/AccountCreated，编排层随后又用暂存密码登录并落库。
func detectOTPRejected(rawURL string) *OTPRejectedError {
	if !isAuthErrorURL(rawURL) {
		return nil
	}
	info := decodeAuthError(rawURL)
	code := strings.ToLower(strings.TrimSpace(info.Code))
	kind := strings.ToLower(strings.TrimSpace(info.Kind))
	message := strings.ToLower(strings.TrimSpace(info.Message))
	rejected := code == "wrong_email_otp_code" ||
		code == "invalid_email_otp_code" ||
		code == "email_otp_code_invalid" ||
		strings.Contains(code, "wrong_email_otp") ||
		strings.Contains(kind, "wrong_email_otp") ||
		strings.Contains(message, "wrong_email_otp_code")
	if !rejected {
		return nil
	}
	return &OTPRejectedError{Code: code, RequestID: info.RequestID, RawURL: rawURL}
}

// isAuthErrorURL 判断某跳 URL 是否已经落到 OpenAI 的错误页。
// 注意：错误页长这样 https://auth.openai.com/error?payload=...，里面没有 "error=" 子串，
// 之前用 strings.Contains(url, "error=") 匹配不到，导致错误页被当成终点页吞掉，
// 然后 fetchSession 空转 6 次报 "会话中没有 accessToken"。
func isAuthErrorURL(raw string) bool {
	if raw == "" {
		return false
	}
	low := strings.ToLower(raw)
	if strings.Contains(low, "/error?") || strings.Contains(low, "/error/") || strings.HasSuffix(low, "/error") {
		return true
	}
	if strings.Contains(low, "error=") || strings.Contains(low, "error_code=") || strings.Contains(low, "errorcode=") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	if q.Get("payload") != "" && (q.Get("error") != "" || strings.Contains(u.Path, "error") || strings.Contains(low, "auth.openai.com")) {
		return true
	}
	return false
}

// detectAccountUnusable 命中终局错误码时返回 AccountUnusableError，否则返回 nil。
func detectAccountUnusable(rawURL string) *AccountUnusableError {
	info := decodeAuthError(rawURL)
	code := strings.ToLower(strings.TrimSpace(info.Code))
	kind := strings.ToLower(strings.TrimSpace(info.Kind))
	for _, cand := range []string{code, kind} {
		if cand == "" {
			continue
		}
		if deadAccountCodes[cand] {
			return &AccountUnusableError{Code: cand, RequestID: info.RequestID, RawURL: rawURL}
		}
	}
	// Kind=AccountDeactivated 这类驼峰值，转小写后是 accountdeactivated，再兜一层文本匹配
	low := strings.ToLower(rawURL + " " + info.Code + " " + info.Kind + " " + info.Message)
	for _, marker := range []string{
		"accountdeactivated", "accountdeleted", "accountbanned", "accountsuspended",
		"account_deactivated", "account_deleted", "account_banned", "account_suspended",
		"account has been deactivated", "account has been deleted", "account has been banned",
		"account was deactivated", "account was deleted", "account was banned",
	} {
		if strings.Contains(low, marker) {
			c := strings.ReplaceAll(marker, " ", "_")
			if c == "accountdeactivated" {
				c = "account_deactivated"
			} else if c == "accountdeleted" {
				c = "account_deleted"
			} else if c == "accountbanned" {
				c = "account_banned"
			} else if c == "accountsuspended" {
				c = "account_suspended"
			}
			return &AccountUnusableError{Code: c, RequestID: info.RequestID, RawURL: rawURL}
		}
	}
	return nil
}

// truncateText 截断长文本，避免日志里塞进整个错误页。
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// readContinue 读取响应体里的 continue_url 或 Location 头，全面兼容 OpenAI 嵌套 page 结构。
func readContinue(resp *http.Response) (string, int) {
	if resp == nil {
		return "", 0
	}
	defer drain(resp)
	status := resp.StatusCode
	if loc := resp.Header.Get("Location"); loc != "" {
		return loc, status
	}
	if resp.Body == nil {
		return "", status
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(bodyBytes) == 0 {
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
			Type        string `json:"type"`
		} `json:"page"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		for _, u := range []string{
			payload.ContinueURL,
			payload.ExternalURL,
			payload.URL,
			payload.Page.ContinueURL,
			payload.Page.ExternalURL,
			payload.Page.URL,
		} {
			if strings.TrimSpace(u) != "" {
				return strings.TrimSpace(u), status
			}
		}
	}
	return "", status
}

// drain 读完并关闭响应体，保证连接能复用。
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

func randomState() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseAuthErrorPayload(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	payloadB64 := u.Query().Get("payload")
	if payloadB64 == "" {
		return rawURL
	}
	info := decodeAuthError(rawURL)
	code := strings.ToLower(strings.TrimSpace(info.Code))
	switch code {
	case "":
	case "invalid_username_or_password":
		return "OpenAI 提示账号或密码错误（若该账号在 OpenAI 未完成首封收件箱验证码确认，OpenAI 尚未真正建号）"
	case "account_deactivated":
		return "account_deactivated: OpenAI 已停用该账号（终局，停止重试）"
	case "account_deleted":
		return "account_deleted: OpenAI 已删除该账号（终局，停止重试）"
	case "account_banned":
		return "account_banned: OpenAI 已封禁该账号（终局，停止重试）"
	case "email_address_changed":
		return "email_address_changed: OpenAI 记录里该邮箱已变更（终局，停止重试）"
	case "account_suspended":
		return "account_suspended: OpenAI 已暂停该账号（终局，停止重试）"
	default:
		return info.Code
	}
	decoded, derr := base64.StdEncoding.DecodeString(payloadB64)
	if derr != nil {
		decoded, derr = base64.RawURLEncoding.DecodeString(payloadB64)
	}
	if derr != nil {
		return rawURL
	}
	return string(decoded)
}

// pkce 生成 S256 的 code_verifier 与 challenge。
func pkce() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// randomPassword 生成 14 位强度足够的密码。
func randomPassword() string {
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lower = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const symbols = "!@#$%^&*"
	all := upper + lower + digits + symbols
	b := make([]byte, 14)
	for i := range b {
		n, _ := randInt(len(all))
		b[i] = all[n]
	}
	return string(b)
}

func randInt(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	v := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if v < 0 {
		v = -v
	}
	return v % n, nil
}

var _ = url.Parse
