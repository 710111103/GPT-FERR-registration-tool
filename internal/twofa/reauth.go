package twofa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

const (
	chatGPTBase = "https://chatgpt.com"
	authBase    = "https://auth.openai.com"
)

// ReauthWithPassword 执行密码重认证，获得带有新鲜 pwd_auth_time 的 accessToken 和活动会话。
//
// 原理：OpenAI 的 2FA enroll 接口强制要求 token 必须内嵌 5 分钟以内的 pwd_auth_time，
// 否则直接返回 401。通过密码重认证可换取带有新鲜登录态的新 token。
func ReauthWithPassword(ctx context.Context, sess Requester, email, password, deviceID string) (string, error) {
	if email == "" || password == "" {
		return "", fmt.Errorf("邮箱或密码为空，无法执行密码重认证")
	}

	// 1. 获取重认证专属 CSRF Token
	resp, err := sess.Request(http.MethodGet, chatGPTBase+"/api/auth/csrf", "", map[string]string{
		"Accept":  "application/json",
		"Referer": chatGPTBase + "/",
	})
	if err != nil {
		return "", fmt.Errorf("获取重认证 CSRF 失败: %w", err)
	}
	var csrf struct {
		Token string `json:"csrfToken"`
	}
	csrfBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	_ = resp.Body.Close()
	if err := json.Unmarshal(csrfBody, &csrf); err != nil || csrf.Token == "" {
		return "", fmt.Errorf("解析重认证 CSRF 失败")
	}

	// 2. 发起携带 reauth=password 的 signin 请求
	q := url.Values{}
	q.Set("connection", "password")
	q.Set("login_hint", email)
	q.Set("reauth", "password")
	q.Set("max_age", "0")
	if deviceID != "" {
		q.Set("ext-oai-did", deviceID)
	}
	signinURL := chatGPTBase + "/api/auth/signin/openai?" + q.Encode()

	form := url.Values{}
	form.Set("callbackUrl", chatGPTBase+"/")
	form.Set("csrfToken", csrf.Token)
	form.Set("json", "true")

	resp, err = sess.Request(http.MethodPost, signinURL, form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin":       chatGPTBase,
		"Referer":      chatGPTBase + "/",
	})
	if err != nil {
		return "", fmt.Errorf("发起重认证 signin 失败: %w", err)
	}
	var signed struct {
		URL string `json:"url"`
	}
	signedBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	_ = resp.Body.Close()
	if err := json.Unmarshal(signedBody, &signed); err != nil || signed.URL == "" {
		return "", fmt.Errorf("获取重认证 authorize URL 失败")
	}

	// 3. 访问 authorize URL，建立 auth.openai.com 登录页会话
	resp, err = sess.Request(http.MethodGet, signed.URL, "", map[string]string{
		"Referer": chatGPTBase + "/",
	})
	if err != nil {
		return "", fmt.Errorf("访问授权页失败: %w", err)
	}
	drain(resp)

	// 4. 提交密码以完成重认证
	pwBody, _ := json.Marshal(map[string]string{"password": password})
	resp, err = sess.Request(http.MethodPost, authBase+"/api/accounts/password/verify", string(pwBody), map[string]string{
		"Content-Type": "application/json",
		"Origin":       authBase,
		"Referer":      authBase + "/log-in/password",
	})
	if err != nil {
		return "", fmt.Errorf("提交密码验证请求失败: %w", err)
	}
	var pwResult struct {
		ContinueURL string `json:"continue_url"`
		Error       string `json:"error"`
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		pwResult.ContinueURL = loc
	}
	resBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("密码验证被拒绝（HTTP %d）: %s", resp.StatusCode, string(resBody))
	}
	_ = json.Unmarshal(resBody, &pwResult)
	if pwResult.ContinueURL == "" {
		return "", fmt.Errorf("重认证未返回回调地址")
	}

	// 5. 逐跳跟随回调重定向，让 chatgpt.com 设置全新的登录态 Cookie
	currentURL := pwResult.ContinueURL
	if strings.HasPrefix(currentURL, "/") {
		currentURL = authBase + currentURL
	}
	prevURL := authBase + "/log-in/password"
	for hop := 1; hop <= 10; hop++ {
		resp, err := sess.Request(http.MethodGet, currentURL, "", map[string]string{
			"Referer": prevURL,
		})
		if err != nil {
			slog.Warn("[2FA Reauth] hop error", "hop", hop, "err", err)
			break
		}
		loc := resp.Header.Get("Location")
		slog.Info("[2FA Reauth]", "hop", hop, "status", resp.StatusCode, "url", currentURL, "loc", loc)
		drain(resp)
		if loc == "" || resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
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

	// 6. 拉取拥有新鲜 pwd_auth_time 的 accessToken
	resp, err = sess.Request(http.MethodGet, chatGPTBase+"/api/auth/session", "", map[string]string{
		"Accept":  "application/json",
		"Referer": chatGPTBase + "/",
	})
	if err != nil {
		return "", fmt.Errorf("读取新会话失败: %w", err)
	}
	sessionBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	_ = resp.Body.Close()
	slog.Info("[2FA Reauth] session response", "status", resp.StatusCode, "body", string(sessionBody))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("会话接口返回状态码 %d", resp.StatusCode)
	}
	var sessionData struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(sessionBody, &sessionData); err != nil || sessionData.AccessToken == "" {
		return "", fmt.Errorf("新会话中未能提取 accessToken")
	}

	return sessionData.AccessToken, nil
}
