// Package protocol 是纯协议注册驱动：不启动浏览器窗口，用带 TLS 指纹的
// HTTP 客户端完成 OpenAI 的邮箱注册链路。
//
// 与 Python 版 main.py 协议分支的对应关系：
//
//	curl_cffi impersonate  -> bogdanfinn/tls-client 的 Chrome profile
//	core/session.py        -> 本包的 Session
//	core/sentinel.py       -> internal/sentinel 的 Solver
//	core/openai_auth.py    -> 本包的 authorize / otp / about-you 步骤
package protocol

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/sentinel"
)

const (
	authBase    = "https://auth.openai.com"
	chatGPTBase = "https://chatgpt.com"
	sentinelReq = "https://sentinel.openai.com/backend-api/sentinel/req"

	// OpenAI 公开客户端常量。与 Python 版 config/openai_protocol.py 同源，
	// 但这两个 build 值会随线上发布变化，需要定期核对。
	openAIClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	openAIScope       = "openid profile email offline_access"
	openAIAudience    = "https://api.openai.com/v1"
	openAIRedirectURI = "https://chatgpt.com/api/auth/callback/openai"
)

// Session 封装一次注册使用的 HTTP 状态：cookie jar、UA、设备 ID、代理。
// Python 版用全局 ThreadLocal 共享，Go 版按任务独立构造，天然隔离。
type Session struct {
	Client      tlsclient.HttpClient
	Jar         tlsclient.CookieJar
	TLSProfile  string
	ChromeMajor string
	UserAgent   string
	Language    string
	Timezone    string
	Screen      string
	DeviceID    string
	// AuthSessionLoggingID 贯穿整条认证链路的日志 ID（UUID v4）。
	// 上游 session.auth_session_logging_id 同源：handoff 与 signin 查询串必须带同一个值。
	AuthSessionLoggingID string
	Proxy                string
	mu                   sync.Mutex
	lastStatus           int
	requestCount         int64
	failedCount          int64
	// browserAT / browserST 存放无头 Chromium 兜底跑完 OAuth 回调后取回的会话凭据。
	// 纯协议链路在 CF 托管的那一跳拿不到 AT 时，由浏览器层写入这里，
	// fetchSession 优先读它，避免再空转 6 次。
	browserAT string
	browserST string
}

// SessionOptions 构造会话的参数。
type SessionOptions struct {
	UserAgent string
	Language  string
	Timezone  string
	Screen    string
	DeviceID  string
	// AuthSessionLoggingID 为空时由 NewSession 生成 UUID v4。
	AuthSessionLoggingID string
	Proxy                string
	// Profile 为空时由调用方（NewSession）按 ProfileName 解析。
	ProfileName string
	Timeout     time.Duration
	// InsecureSkipVerify 仅用于本地自签名 TLS 测试；生产默认必须校验证书。
	InsecureSkipVerify bool
}

// RegionFromProxy 从代理字符串提取地区并返回最匹配的 locale 与 timezone。
// 例如代理中包含 -region-DE- 则自动匹配 de-DE 与 Europe/Berlin。
func RegionFromProxy(proxy string) (language string, timezone string) {
	upper := strings.ToUpper(proxy)
	reg := ""
	if m := regexp.MustCompile(`(?i)(?:REGION|COUNTRY)[-_]([A-Z]{2})`).FindStringSubmatch(upper); len(m) == 2 {
		reg = strings.ToUpper(m[1])
	} else if m := regexp.MustCompile(`[-_:]([A-Z]{2})[-_:]`).FindStringSubmatch(upper); len(m) == 2 {
		reg = m[1]
	}

	switch reg {
	case "DE":
		return "de-DE", "Europe/Berlin"
	case "GB", "UK":
		return "en-GB", "Europe/London"
	case "FR":
		return "fr-FR", "Europe/Paris"
	case "NL":
		return "nl-NL", "Europe/Amsterdam"
	case "JP":
		return "ja-JP", "Asia/Tokyo"
	case "SG":
		return "en-SG", "Asia/Singapore"
	case "VN":
		return "vi-VN", "Asia/Ho_Chi_Minh"
	case "IN":
		return "en-IN", "Asia/Kolkata"
	case "BR":
		return "pt-BR", "America/Sao_Paulo"
	case "CA":
		return "en-CA", "America/Toronto"
	case "AU":
		return "en-AU", "Australia/Sydney"
	default:
		return "en-US", "America/New_York"
	}
}

// NewSession 创建一个带浏览器指纹的会话。
func NewSession(opt SessionOptions) (*Session, error) {
	// 从一份临时画像统一归一化，确保只传 UA 的调用也不会把 UA 与 TLS
	// 拆成两个不同主版本。Complete 会优先按 UA 反推可用的 TLS profile。
	profileImage := BrowserProfile{
		TLSProfile: opt.ProfileName,
		UserAgent:  opt.UserAgent,
		Language:   opt.Language,
		Timezone:   opt.Timezone,
		Screen:     opt.Screen,
	}.Complete(opt.Proxy)
	if opt.UserAgent == "" {
		opt.UserAgent = profileImage.UserAgent
	}
	opt.Language = profileImage.Language
	opt.Timezone = profileImage.Timezone
	if opt.Screen == "" {
		opt.Screen = profileImage.Screen
	}
	profile := resolveProfile(profileImage.TLSProfile)
	if opt.Timeout <= 0 {
		opt.Timeout = 60 * time.Second
	}
	if strings.TrimSpace(opt.DeviceID) == "" {
		opt.DeviceID = sentinel.DeviceID()
	}

	jar := newJar()
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profile),
		tlsclient.WithTimeoutSeconds(int(opt.Timeout.Seconds())),
		tlsclient.WithNotFollowRedirects(), // 重定向链路要逐步观察，不能自动跟
		tlsclient.WithDisableHttp3(),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithBandwidthTracker(),
	}
	if opt.InsecureSkipVerify {
		opts = append(opts, tlsclient.WithInsecureSkipVerify())
	}
	if opt.Proxy != "" {
		// 代理在任务调度阶段已经选定并轮换过一次 sid。这里只做格式规范化，
		// 保证 TLS 会话、日志和后续步骤使用完全相同的 sticky session。
		opt.Proxy = config.NormalizeProxyURLStable(opt.Proxy)
		opts = append(opts, tlsclient.WithProxyUrl(opt.Proxy))
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("创建 TLS 客户端失败: %w", err)
	}

	sess := &Session{
		Client:               client,
		Jar:                  jar,
		TLSProfile:           profileImage.TLSProfile,
		ChromeMajor:          profileImage.ChromeMajor,
		UserAgent:            opt.UserAgent,
		Language:             opt.Language,
		Timezone:             opt.Timezone,
		Screen:               opt.Screen,
		DeviceID:             opt.DeviceID,
		AuthSessionLoggingID: opt.AuthSessionLoggingID,
		Proxy:                opt.Proxy,
	}
	if sess.AuthSessionLoggingID == "" {
		sess.AuthSessionLoggingID = sentinel.DeviceID()
	}

	for _, domain := range []string{".chatgpt.com", ".auth.openai.com", ".sentinel.openai.com", "chatgpt.com", "auth.openai.com", "sentinel.openai.com"} {
		sess.SetCookie("oai-did", sess.DeviceID, domain)
		sess.SetCookie("oai-locale", opt.Language, domain)
	}

	return sess, nil
}

// resolveProfile 按名称取 TLS 指纹 profile，未知名称回退到 Chrome 152。
// 这里只暴露少量经过实测的 profile，避免调用方传入已下线的版本。
func resolveProfile(name string) profiles.ClientProfile {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome_124":
		return profiles.Chrome_124
	case "chrome_131":
		return profiles.Chrome_131
	case "chrome_144":
		return profiles.Chrome_144
	case "chrome_146":
		return profiles.Chrome_146
	case "chrome_150":
		return profiles.Chrome_150
	case "chrome_152":
		return profiles.Chrome_152
	default:
		return profiles.Chrome_152
	}
}

// Profile 返回会话正在使用的完整浏览器画像快照。
func (s *Session) Profile() BrowserProfile {
	return BrowserProfile{
		TLSProfile:  s.TLSProfile,
		ChromeMajor: s.ChromeMajor,
		UserAgent:   s.UserAgent,
		Language:    s.Language,
		Timezone:    s.Timezone,
		Screen:      s.Screen,
	}
}

// Close 释放连接。
func (s *Session) Close() {
	if s.Client != nil {
		s.Client.CloseIdleConnections()
	}
}

// setBrowserSession 记录浏览器兜底取回的会话凭据。
func (s *Session) setBrowserSession(at, st string) {
	s.mu.Lock()
	s.browserAT = at
	s.browserST = st
	s.mu.Unlock()
}

// BrowserSession 读取浏览器兜底取回的会话凭据，未命中返回空串。
func (s *Session) BrowserSession() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browserAT, s.browserST
}

// Request 发一个请求，自动带上浏览器通用头与 cookie。
// 无 ctx 版本走 Background，供不需要取消语义的短请求使用。
func (s *Session) Request(method, rawURL string, body string, extra map[string]string) (*http.Response, error) {
	return s.RequestCtx(context.Background(), method, rawURL, body, extra)
}

// RequestCtx 是 Request 的 ctx 版本：ctx 真正下传到 TLS 客户端，
// 取消/超时能立刻打断连接，不依赖各调用点手工 select ctx.Done()。
func (s *Session) RequestCtx(ctx context.Context, method, rawURL string, body string, extra map[string]string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}

	h := s.baseHeaders()
	for k, v := range extra {
		h.Set(k, v)
	}
	if h.Get("Content-Type") == "" && body != "" {
		h.Set("Content-Type", "application/json")
	}
	// 如果是 XHR/Fetch 请求（如 /api/auth/session），必须摘掉 Upgrade-Insecure-Requests 浏览器页面导航专有头
	if h.Get("Sec-Fetch-Dest") == "empty" || h.Get("Accept") == "application/json" {
		h.Del("Upgrade-Insecure-Requests")
	}
	req.Header = h
	// fhttp 需要显式的 header 顺序（模仿浏览器）
	req.Header.Set("User-Agent", s.UserAgent)
	req.Header.Set("Accept-Language", s.acceptLanguage())

	resp, err := s.Client.Do(req)
	if err != nil {
		s.mu.Lock()
		s.requestCount++
		s.failedCount++
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Lock()
	s.lastStatus = resp.StatusCode
	s.requestCount++
	if resp.StatusCode >= http.StatusBadRequest {
		s.failedCount++
	}
	s.mu.Unlock()
	return resp, nil
}

// Traffic returns counters for the complete TLS client session. The totals
// include TLS, HTTP, and proxy framing that the client itself observes.
func (s *Session) Traffic() domain.Traffic {
	t := domain.Traffic{Available: true, Source: "protocol_tls"}
	if s.Client != nil {
		if tracker := s.Client.GetBandwidthTracker(); tracker != nil {
			t.UploadBytes = tracker.GetWriteBytes()
			t.DownloadBytes = tracker.GetReadBytes()
			t.TotalBytes = t.UploadBytes + t.DownloadBytes
		}
	}
	s.mu.Lock()
	t.RequestCount = s.requestCount
	t.FailedCount = s.failedCount
	s.mu.Unlock()
	return t
}

func (s *Session) baseHeaders() http.Header {
	image := s.Profile()
	h := http.Header{}
	h.Set("User-Agent", s.UserAgent)
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", s.acceptLanguage())
	h.Set("Sec-Ch-Ua", image.ClientHints())
	h.Set("Sec-Ch-Ua-Mobile", "?0")
	h.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Upgrade-Insecure-Requests", "1")
	return h
}

// NextAuthHeaders 返回 chatgpt.com 的 `/api/auth/*` 与 `/api/auth/session` 请求头。
// 上游 core/session.py get_nextauth_headers 同源：accept 用 */*（不是 application/json），
// content-type 为 application/json，Sec-Fetch 三件套 + Referer + Priority。
// Priority 是 Chromium 的 fetch 优先级头，缺它会在高负载边缘节点被排进慢队列。
func (s *Session) NextAuthHeaders(referer string) map[string]string {
	if referer == "" {
		referer = chatGPTBase + "/"
	}
	return map[string]string{
		"Accept":         "*/*",
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
		"Referer":        referer,
		"Priority":       "u=1, i",
	}
}

// MWebHeaders 返回 chatgpt.com `/unauth-mweb/*` 的请求头。
// 上游 get_chatgpt_mweb_headers 同源：这组端点在抓包里不带任何 oai-* 上下文头，
// 只有 UA + Client Hints + Sec-Fetch 四件套 + origin。
func (s *Session) MWebHeaders(referer string) map[string]string {
	if referer == "" {
		referer = chatGPTBase + "/"
	}
	return map[string]string{
		"Accept":         "*/*",
		"Content-Type":   "application/json",
		"Origin":         chatGPTBase,
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
		"Referer":        referer,
	}
}

func (s *Session) acceptLanguage() string {
	return s.Profile().AcceptLanguage()
}

// GetCookie 遍历所有域下的 Cookie 查找指定名称的 Cookie 值。
func (s *Session) GetCookie(name string) string {
	if s.Jar == nil {
		return ""
	}
	for _, cookies := range s.Jar.GetAllCookies() {
		for _, c := range cookies {
			if c != nil && c.Name == name && c.Value != "" {
				return c.Value
			}
		}
	}
	return ""
}

// GetSessionTokenCookie 提取 NextAuth 的 session-token，支持常规与分片 cookie（.0, .1 等）。
func (s *Session) GetSessionTokenCookie() string {
	if s.Jar == nil {
		return ""
	}
	for _, base := range []string{"__Secure-next-auth.session-token", "next-auth.session-token"} {
		if v := s.GetCookie(base); v != "" {
			return v
		}
		var chunks []string
		for i := 0; i < 10; i++ {
			v := s.GetCookie(fmt.Sprintf("%s.%d", base, i))
			if v == "" {
				break
			}
			chunks = append(chunks, v)
		}
		if len(chunks) > 0 {
			return strings.Join(chunks, "")
		}
	}
	return ""
}

// SetCookie 为指定域名写入一个 Cookie。
func (s *Session) SetCookie(name, value, domain string) {
	if s.Jar == nil {
		return
	}
	host := strings.TrimPrefix(domain, ".")
	u, err := url.Parse("https://" + host)
	if err != nil {
		return
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
	}
	s.Jar.SetCookies(u, []*http.Cookie{cookie})
}

// sessionTokenCookieBase 是 NextAuth 的会话 cookie 名（Secure 前缀版）。
const sessionTokenCookieBase = "__Secure-next-auth.session-token"

// sessionTokenChunkSize 是 NextAuth 的分片大小：超长 JWT 按 3000 字节切块。
const sessionTokenChunkSize = 3000

// SplitSessionToken 按 NextAuth 线上规则切分 session-token：
// 单块返回 [完整值]，多块返回 [0:3000, 3000:6000, ...]。
func SplitSessionToken(value string) []string {
	if value == "" {
		return nil
	}
	var chunks []string
	for i := 0; i < len(value); i += sessionTokenChunkSize {
		end := i + sessionTokenChunkSize
		if end > len(value) {
			end = len(value)
		}
		chunks = append(chunks, value[i:end])
	}
	return chunks
}

// SetSessionTokenCookie 按 NextAuth 规则写入 session-token：
//
//	单块  -> 只写 __Secure-next-auth.session-token
//	多块  -> 只写 __Secure-next-auth.session-token.0/.1/...，base 坚决跳过
//
// 上游 core/account_liveness.py:515-524 是同一套二选一规则；base 与分片同时
// 存在会让服务端解密走错分支，/api/auth/session 直接返回 {}。
func (s *Session) SetSessionTokenCookie(value, domain string) {
	if s.Jar == nil || value == "" {
		return
	}
	chunks := SplitSessionToken(value)
	if len(chunks) <= 1 {
		s.SetCookie(sessionTokenCookieBase, value, domain)
		return
	}
	for i, c := range chunks {
		s.SetCookie(fmt.Sprintf("%s.%d", sessionTokenCookieBase, i), c, domain)
	}
}

// ClearSessionTokenCookie 清掉 session-token 的 base 与全部分片。
// 上游在同一处 finally 里做同样清理，防止脏会话污染后续完整 OAuth 登录。
func (s *Session) ClearSessionTokenCookie(domain string) {
	if s.Jar == nil {
		return
	}
	s.expireCookie(sessionTokenCookieBase, domain)
	for i := 0; i < 16; i++ {
		s.expireCookie(fmt.Sprintf("%s.%d", sessionTokenCookieBase, i), domain)
	}
}

// expireCookie 以 MaxAge=-1 让 jar 立即丢弃该 cookie。
func (s *Session) expireCookie(name, domain string) {
	host := strings.TrimPrefix(domain, ".")
	u, err := url.Parse("https://" + host)
	if err != nil {
		return
	}
	s.Jar.SetCookies(u, []*http.Cookie{{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	}})
}

// authorizeURL 构造 OAuth authorize 链接。
// screen_hint=login_or_signup 让服务端在邮箱存在时直接走登录、不存在时走注册。
func authorizeURL(state, challenge string) string {
	q := url.Values{}
	q.Set("client_id", openAIClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", openAIRedirectURI)
	q.Set("scope", openAIScope)
	q.Set("audience", openAIAudience)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("screen_hint", "login_or_signup")
	return authBase + "/authorize?" + q.Encode()
}
