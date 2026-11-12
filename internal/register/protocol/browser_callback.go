package protocol

// 无头 Chromium 承接 OAuth 回调。
//
// 为什么需要这一层：chatgpt.com/api/auth/callback/openai 这一跳由 Cloudflare
// 托管，对 TLS 指纹客户端在 hop=2 直接回 403。上游
// core/browser_environment.py:follow_oauth_callback_with_headless_browser 的做法是：
// 把协议会话已有 Cookie 灌进真实 Chromium，让浏览器自己跑完回调并在页面内
// fetch("/api/auth/session") 取 accessToken，最后把新 Cookie 同步回协议会话。
// 这里用 chromedp 复刻同一套流程。出口代理经本地转发器注入
// Proxy-Authorization，绕开 Chrome 对带账号密码 --proxy-server 的不稳定支持。

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"

	httpf "github.com/bogdanfinn/fhttp"
)

// browserCallbackTimeout 是整条浏览器回调的硬上限。
// 覆盖启动 Chromium + 代理握手 + 首跳 + 8 轮页面内轮询。
const browserCallbackTimeout = 150 * time.Second

// browserSessionProbe 是页面内 fetch('/api/auth/session') 的返回结构。
type browserSessionProbe struct {
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	AT     string `json:"at"`
	ST     string `json:"st"`
	Email  string `json:"email"`
	Error  string `json:"error"`
}

func (p browserSessionProbe) statusText() string {
	if p.OK {
		return fmt.Sprintf("ok/200 user=%s", p.Email)
	}
	if p.Status != 0 {
		return fmt.Sprintf("http-%d", p.Status)
	}
	return "js-error"
}

// chromeExecPath 定位 Chromium 内核可执行文件。
// 优先级：TURB_CHROME_PATH > Chrome > Edge > Linux 常见路径。
func chromeExecPath() string {
	if v := strings.TrimSpace(os.Getenv("TURB_CHROME_PATH")); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v
		}
	}
	candidates := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`/usr/bin/google-chrome`,
		`/usr/bin/chromium`,
		`/usr/bin/chromium-browser`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// followOAuthCallbackInBrowser 用真实无头 Chromium 完成 continueURL 之后的
// 全部跳转，并从页面内取回 accessToken / sessionToken（写进 sess 的 browser 槽）。
func (d *Driver) followOAuthCallbackInBrowser(ctx context.Context, sess *Session, continueURL string) error {
	if sess == nil {
		return fmt.Errorf("协议会话为空")
	}
	if strings.TrimSpace(continueURL) == "" {
		return fmt.Errorf("浏览器回调缺少 continueURL")
	}
	execPath := chromeExecPath()
	if execPath == "" {
		return fmt.Errorf("未找到 Chromium 内核可执行文件（可用 TURB_CHROME_PATH 指定）")
	}

	bctx, cancel := context.WithTimeout(ctx, browserCallbackTimeout)
	defer cancel()

	// 本地认证转发器：把上游代理的账号密码在 CONNECT 里注入
	chromeProxy := ""
	if p := strings.TrimSpace(sess.Proxy); p != "" {
		addr, stop, err := startAuthForwardProxy(p)
		if err != nil {
			dbg("[浏览器回调] 本地代理转发器启动失败: %v", err)
		} else {
			chromeProxy = addr
			defer stop()
		}
	}

	userDir, err := os.MkdirTemp("", "turb-chrome-*")
	if err != nil {
		return fmt.Errorf("创建临时浏览器目录失败: %w", err)
	}
	defer os.RemoveAll(userDir)

	ua := strings.TrimSpace(sess.UserAgent)
	if ua == "" {
		major := strings.TrimSpace(sess.ChromeMajor)
		if major == "" {
			major = "152"
		}
		ua = userAgentForChromeMajor(major)
	}
	language := strings.TrimSpace(sess.Language)
	if language == "" {
		language = "en-US"
	}
	timezone := strings.TrimSpace(sess.Timezone)
	if timezone == "" {
		timezone = "America/New_York"
	}
	screenWidth, screenHeight := sess.Profile().ScreenSize()

	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.ExecPath(execPath),
		chromedp.UserDataDir(userDir),
		chromedp.UserAgent(ua),
		chromedp.WindowSize(int(screenWidth), int(screenHeight)),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("lang", language),
		chromedp.Env("TZ="+timezone),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
	)
	if chromeProxy != "" {
		opts = append(opts, chromedp.ProxyServer("http://"+chromeProxy))
		dbg("[浏览器回调] Chromium 出口代理 = 127.0.0.1 转发 -> %s", redactProxy(sess.Proxy))
	} else {
		dbg("[浏览器回调] Chromium 直连（会话未配置代理）")
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(bctx, opts...)
	defer cancelAlloc()
	brCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// 0. 先空跑一次，确保 browser + page target 都起来
	if _, bootErr := chromedp.Run(brCtx, chromedp.Navigate("about:blank")); bootErr != nil {
		return fmt.Errorf("启动 Chromium 失败: %w", bootErr)
	}

	// 把协议会话画像同步到真实 Chromium。只在启动参数里改 UA/lang 不够：
	// navigator.language、Intl 时区、Sec-CH-UA-* 和 screen.* 必须一起覆盖，
	// 否则同一任务会在协议请求与浏览器兜底之间露出两套身份。
	if err := applyBrowserProfile(brCtx, sess, ua, language, timezone, screenWidth, screenHeight); err != nil {
		return fmt.Errorf("应用 Chromium 浏览器画像失败: %w", err)
	}

	// 1. 把协议会话已有 Cookie 全量灌进浏览器
	injected, injErr := injectCookies(brCtx, sess)
	if injErr != nil {
		dbg("[浏览器回调] Cookie 注入失败: %v", injErr)
	}
	dbg("[浏览器回调] 已注入 %d 个 Cookie，开始导航", injected)

	// 2. 导航到 continueURL，交给 Chromium 自己跑完 OAuth 回调
	_, navErr := chromedp.Run(brCtx, chromedp.Navigate(continueURL))
	finalURL := ""
	if loc, lerr := chromedp.Run(brCtx, chromedp.Location()); lerr == nil {
		finalURL = loc
	}
	if navErr != nil {
		dbg("[浏览器回调] 首跳导航异常(继续轮询): %v, 当前落点=%s", navErr, truncateText(finalURL, 200))
	} else {
		dbg("[浏览器回调] 真实落点: %s", truncateText(finalURL, 200))
	}

	// 3. 在页面内轮询 /api/auth/session，最多 8 轮 × 1.5s
	const sessionPollJS = `(async () => {
  try {
    const r = await fetch('/api/auth/session', {credentials:'include', cache:'no-store'});
    if (!r.ok) return {ok:false, status:r.status};
    const d = await r.json();
    return {ok:true, status:r.status,
      at:(d && d.accessToken) || '',
      st:(d && d.sessionToken) || '',
      email:(d && d.user && d.user.email) || ''};
  } catch (e) { return {ok:false, error:String(e)}; }
})()`

	var at, st string
	for poll := 1; poll <= 8; poll++ {
		raw, evalErr := chromedp.Run(brCtx, chromedp.Evaluate[[]byte](sessionPollJS, chromedp.EvalAwaitPromise))
		if evalErr != nil {
			dbg("[浏览器回调] 轮询 %d 执行异常: %v", poll, evalErr)
		} else {
			var probe browserSessionProbe
			if uerr := json.Unmarshal(raw, &probe); uerr != nil {
				dbg("[浏览器回调] 轮询 %d 解析失败: %v raw=%s", poll, uerr, truncateText(string(raw), 120))
			} else if probe.AT != "" {
				at, st = probe.AT, probe.ST
				dbg("[浏览器回调] 页面内取到 accessToken (user=%s, 轮次 %d)", probe.Email, poll)
				break
			} else {
				dbg("[浏览器回调] 轮询 %d 未取到 AT (state=%s, err=%s)", poll, probe.statusText(), truncateText(probe.Error, 80))
			}
		}
		select {
		case <-bctx.Done():
			return fmt.Errorf("浏览器回调超时: %w", bctx.Err())
		case <-time.After(1500 * time.Millisecond):
		}
	}

	// 4. 无论是否拿到 AT，都把浏览器里的 Cookie 同步回协议会话
	synced := syncCookiesBack(brCtx, sess)
	dbg("[浏览器回调] 已同步 %d 个 Cookie 回协议会话", synced)

	if at == "" {
		loc := finalURL
		if l2, lerr := chromedp.Run(brCtx, chromedp.Location()); lerr == nil {
			loc = l2
		}
		return fmt.Errorf("浏览器回调后仍未取到 accessToken，落点: %s", truncateText(loc, 200))
	}

	if st == "" {
		st = sess.GetSessionTokenCookie()
	}
	sess.setBrowserSession(at, st)

	// 5. 顺手在浏览器上下文里做一次首页轻量访问，确保所有 Cookie 落地
	_, _ = chromedp.Run(brCtx, chromedp.Navigate(chatGPTBase+"/"))
	_ = syncCookiesBack(brCtx, sess)
	return nil
}

func applyBrowserProfile(ctx context.Context, sess *Session, userAgent, language, timezone string, width, height int64) error {
	major := strings.TrimSpace(sess.ChromeMajor)
	if major == "" {
		_, major = canonicalTLSProfile(sess.TLSProfile)
	}
	fullVersion := major + ".0.0.0"
	brands := []*emulation.UserAgentBrandVersion{
		{Brand: "Chromium", Version: major},
		{Brand: "Not(A:Brand", Version: "24"},
		{Brand: "Google Chrome", Version: major},
	}
	fullBrands := []*emulation.UserAgentBrandVersion{
		{Brand: "Chromium", Version: fullVersion},
		{Brand: "Not(A:Brand", Version: "24.0.0.0"},
		{Brand: "Google Chrome", Version: fullVersion},
	}
	metadata := &emulation.UserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullBrands,
		Platform:        "Windows",
		PlatformVersion: "10.0.0",
		Architecture:    "x86",
		Bitness:         "64",
		Mobile:          false,
		Wow64:           false,
	}
	image := sess.Profile()
	acceptLanguage := image.AcceptLanguage()
	locale := strings.ReplaceAll(language, "-", "_")

	return chromedp.Do(ctx, chromedp.Func(func(callCtx context.Context, _ *chromedp.Target) error {
		if _, err := chromedp.Call(callCtx, emulation.SetUserAgentOverride, emulation.SetUserAgentOverrideParams{
			UserAgent:         userAgent,
			AcceptLanguage:    acceptLanguage,
			Platform:          "Win32",
			UserAgentMetadata: metadata,
		}); err != nil {
			return fmt.Errorf("设置 UA/Client Hints: %w", err)
		}
		if _, err := chromedp.Call(callCtx, emulation.SetLocaleOverride, emulation.SetLocaleOverrideParams{Locale: locale}); err != nil {
			return fmt.Errorf("设置 locale: %w", err)
		}
		if _, err := chromedp.Call(callCtx, emulation.SetTimezoneOverride, emulation.SetTimezoneOverrideParams{TimezoneID: timezone}); err != nil {
			return fmt.Errorf("设置时区: %w", err)
		}
		if _, err := chromedp.Call(callCtx, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{
			Width:             width,
			Height:            height,
			DeviceScaleFactor: 1,
			Mobile:            false,
			ScreenWidth:       width,
			ScreenHeight:      height,
		}); err != nil {
			return fmt.Errorf("设置屏幕尺寸: %w", err)
		}
		return nil
	}))
}

// injectCookies 把 tls-client 会话里的 Cookie 全量写进 Chromium。
//
// 逐条写入而不是整批写入：CDP 的 Storage.setCookies 是原子操作，一条非法
// （典型是 __Host- 前缀 cookie 带了 domain，或 domain 与 url 不匹配）会让整批
// 全部失败并回 -32602 Invalid cookie fields。逐条写 + 单条容错才能保证必填的
// next-auth.state / pkce.code_verifier 一定落地——缺了它们，浏览器跑到
// /api/auth/callback/openai 只会得到 error=OAuthCallback。
func injectCookies(ctx context.Context, sess *Session) (int, error) {
	if sess.Jar == nil {
		return 0, nil
	}
	set, skipped, firstErr := 0, 0, error(nil)
	for hostKey, list := range sess.Jar.GetAllCookies() {
		host := strings.TrimPrefix(strings.TrimSpace(hostKey), ".")
		if host == "" || !strings.Contains(host, ".") {
			continue
		}
		for _, c := range list {
			if c == nil || c.Name == "" || c.Value == "" {
				continue
			}
			path := strings.TrimSpace(c.Path)
			if path == "" {
				path = "/"
			}
			param := &network.CookieParam{
				Name:     c.Name,
				Value:    c.Value,
				URL:      "https://" + host + path,
				Secure:   true,
				HTTPOnly: c.HttpOnly,
				SameSite: network.CookieSameSiteLax,
			}
			// __Host- 前缀按 RFC6265bis 必须 host-only（无 Domain 属性），
			// 带上 Domain 会被 Chromium 直接判非法。
			if dom := strings.TrimSpace(c.Domain); dom != "" && !strings.HasPrefix(c.Name, "__Host-") {
				param.Domain = dom
			}
			if _, err := chromedp.CallBrowser(ctx, storage.SetCookies, storage.SetCookiesParams{
				Cookies: []*network.CookieParam{param},
			}); err != nil {
				skipped++
				if firstErr == nil {
					firstErr = fmt.Errorf("cookie %s@%s: %w", c.Name, host, err)
				}
				continue
			}
			set++
		}
	}
	dbg("[浏览器回调] Cookie 注入结果: 成功 %d 条，跳过 %d 条（首条错误: %v）", set, skipped, firstErr)
	return set, firstErr
}

// syncCookiesBack 把 Chromium 里当前所有 Cookie 同步回 tls-client 会话。
func syncCookiesBack(ctx context.Context, sess *Session) int {
	if sess.Jar == nil {
		return 0
	}
	res, err := chromedp.CallBrowser(ctx, storage.GetCookies, storage.GetCookiesParams{})
	if err != nil {
		dbg("[浏览器回调] 读取浏览器 Cookie 失败: %v", err)
		return 0
	}
	n := 0
	for _, c := range res.Cookies {
		if c == nil || c.Name == "" || c.Value == "" {
			continue
		}
		domain := strings.TrimSpace(c.Domain)
		if domain == "" {
			continue
		}
		host := strings.TrimPrefix(domain, ".")
		u, perr := url.Parse("https://" + host + "/")
		if perr != nil {
			continue
		}
		expires := time.Time{}
		if c.Expires > 0 {
			expires = time.Unix(int64(c.Expires), 0)
		}
		path := strings.TrimSpace(c.Path)
		if path == "" {
			path = "/"
		}
		sess.Jar.SetCookies(u, []*httpf.Cookie{{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   domain,
			Path:     path,
			Secure:   true,
			HttpOnly: c.HTTPOnly,
			Expires:  expires,
		}})
		n++
	}
	return n
}

// redactProxy 打日志时隐去代理账号密码。
func redactProxy(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Host
}

// ---------------------------------------------------------------------------
// 本地认证转发器
// ---------------------------------------------------------------------------

// startAuthForwardProxy 起一个本地 HTTP 代理，把请求转发给带账号密码的上游代理。
// 返回 (本地监听地址 host:port, 关闭函数, 错误)。
func startAuthForwardProxy(upstream string) (string, func(), error) {
	u, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil {
		return "", nil, err
	}
	if u.Host == "" {
		return "", nil, fmt.Errorf("上游代理地址无效: %s", upstream)
	}
	upHost := u.Host
	if !strings.Contains(upHost, ":") {
		upHost += ":8080"
	}
	authHeader := ""
	if u.User != nil {
		pw, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
		authHeader = "Basic " + token
	}
	upURL := u

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(upURL),
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 20 * time.Second,
	}
	defer func() { go transport.CloseIdleConnections() }()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleConnectTunnel(w, r, upHost, authHeader)
			return
		}
		outReq := r.Clone(r.Context())
		outReq.RequestURI = ""
		if outReq.URL.Scheme == "" {
			outReq.URL.Scheme = "http"
		}
		if outReq.URL.Host == "" {
			outReq.URL.Host = r.Host
		}
		if authHeader != "" {
			outReq.Header.Set("Proxy-Authorization", authHeader)
		}
		resp, rerr := transport.RoundTrip(outReq)
		if rerr != nil {
			http.Error(w, rerr.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
	return ln.Addr().String(), stop, nil
}

// handleConnectTunnel 处理 CONNECT：向上游代理建隧道并双向转发。
func handleConnectTunnel(w http.ResponseWriter, r *http.Request, upHost, authHeader string) {
	upConn, err := net.DialTimeout("tcp", upHost, 20*time.Second)
	if err != nil {
		http.Error(w, "上游代理连接失败: "+err.Error(), http.StatusBadGateway)
		return
	}

	var sb strings.Builder
	sb.WriteString("CONNECT " + r.Host + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + r.Host + "\r\n")
	if authHeader != "" {
		sb.WriteString("Proxy-Authorization: " + authHeader + "\r\n")
	}
	sb.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := io.WriteString(upConn, sb.String()); err != nil {
		_ = upConn.Close()
		http.Error(w, "上游代理写入失败", http.StatusBadGateway)
		return
	}

	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = upConn.Close()
		http.Error(w, "上游代理响应解析失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = upConn.Close()
		http.Error(w, "上游代理拒绝 CONNECT: "+resp.Status, http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upConn.Close()
		http.Error(w, "连接不支持接管", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		_ = upConn.Close()
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = upConn.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upConn, clientBuf)
		if tc, ok := upConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upReader)
		_ = clientConn.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = upConn.Close()
}
