package genericapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
)

// Client 封装通用 API 邮箱取信客户端。
type Client struct {
	Timeout       time.Duration
	SettleSeconds int
	Proxy         string
}

// NewClient 创建通用 API 客户端。
func NewClient(proxy string) *Client {
	return &Client{
		Timeout:       20 * time.Second,
		SettleSeconds: 3,
		Proxy:         proxy,
	}
}

// FetchCode 轮询 codeURL 取验证码，支持缓存打散和稳定窗口（settle）机制。
func (c *Client) FetchCode(ctx context.Context, codeURL string, email string, after time.Time) (domain.OTPResult, error) {
	if codeURL == "" {
		return domain.OTPResult{}, fmt.Errorf("取码地址为空")
	}

	pollURL := codeURL
	if strings.Contains(pollURL, "%s") {
		pollURL = fmt.Sprintf(pollURL, url.QueryEscape(email))
	} else if !strings.Contains(pollURL, "?") {
		pollURL = pollURL + "?email=" + url.QueryEscape(email)
	}

	// 添加 cache buster 避免经过代理时的强缓存
	bustedURL := addCacheBuster(pollURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bustedURL, nil)
	if err != nil {
		return domain.OTPResult{}, err
	}

	req.Header.Set("Accept", "application/json,text/html,text/plain,*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	req.Header.Set("Cache-Control", "no-cache, no-store, max-age=0")
	req.Header.Set("Pragma", "no-cache")

	client := c.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return domain.OTPResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.OTPResult{}, fmt.Errorf("GET %s 返回 %d", truncateURL(bustedURL), resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return domain.OTPResult{}, err
	}

	// 上游取件源对本轮已断链的邮箱会回 {"code":null,"status":"waiting","auth":"error"}。
	// 这是「该邮箱收信链路在服务端已失效」的静态标记，不是「暂时还没收到码」，
	// 当成空结果会一路空转到 OTP_MAX_WAIT 才超时，注册任务白等 180 秒。
	var probe struct {
		Auth   string `json:"auth"`
		Status string `json:"status"`
	}
	if json.Unmarshal(bodyBytes, &probe) == nil && strings.EqualFold(strings.TrimSpace(probe.Auth), "error") {
		return domain.OTPResult{}, &AuthError{Email: email, Status: probe.Status}
	}

	code, src := ExtractOTPFromText(string(bodyBytes), after)
	if code == "" {
		return domain.OTPResult{}, nil
	}

	return domain.OTPResult{
		Code:     code,
		Received: time.Now(),
		Source:   src,
	}, nil
}

// AuthError 表示上游取件源判定该邮箱的收信链路已失效（auth:"error"）。
// 与「暂时没收到验证码」区分开，让注册流程立刻换邮箱重试而不是空转轮询。
type AuthError struct {
	Email  string
	Status string
}

func (e *AuthError) Error() string {
	return "取码源返回 auth:error（邮箱 " + e.Email + " 的收信链路已在服务端失效，status=" + e.Status + "）"
}

func (c *Client) httpClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}
	if c.Proxy != "" {
		proxyClean := config.NormalizeProxyURL(c.Proxy)
		if u, err := url.Parse(proxyClean); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   c.Timeout,
	}
}

func addCacheBuster(rawURL string) string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	if strings.Contains(rawURL, "?") {
		return rawURL + "&_ts=" + ts
	}
	return rawURL + "?_ts=" + ts
}

func truncateURL(u string) string {
	if len(u) <= 80 {
		return u
	}
	return u[:77] + "..."
}
