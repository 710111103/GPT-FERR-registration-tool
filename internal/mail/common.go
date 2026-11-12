package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// otpPattern 匹配 OpenAI 六位验证码。邮件正文里通常以 "123456" 或 123456 出现。
var otpPattern = regexp.MustCompile(`\b(\d{6})\b`)

// ExtractOTP 从文本里提取六位验证码。多个候选时取第一个。
// 与 Python 版 otp_utils 的提取规则保持一致：优先带引号的、其次独立六位数字。
func ExtractOTP(text string) string {
	if text == "" {
		return ""
	}
	// 优先匹配邮件里常见的 "123456" 引号包裹形式
	quoted := regexp.MustCompile(`["'` + "`" + `]\s*(\d{6})\s*["'` + "`" + `]`).FindStringSubmatch(text)
	if len(quoted) == 2 {
		return quoted[1]
	}
	if m := otpPattern.FindStringSubmatch(text); len(m) == 2 {
		// 排除明显是年份或时间戳的片段
		if !strings.HasPrefix(m[1], "19") && !strings.HasPrefix(m[1], "20") {
			return m[1]
		}
	}
	return ""
}

// httpClient 是各 Provider 共用的 HTTP 客户端。超时给足，因为部分邮箱 API 很慢。
func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// jsonGet 发一个 GET 并把 JSON 解到 dst。
func jsonGet(ctx context.Context, url string, headers map[string]string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s 返回 %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// textGet 发一个 GET 并返回原始响应文本（兼容纯文本、HTML 与 JSON 输出）。
func textGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s 返回 %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// jsonPost 发一个 POST JSON。
func jsonPost(ctx context.Context, url string, headers map[string]string, body any, dst any) error {
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s 返回 %d", url, resp.StatusCode)
	}
	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// persistStore 是内存态邮箱凭据的落盘器，供 mail.tm / temp-mail.io 这类
// "注册后可复用" 的来源在进程重启后恢复。
type persistStore struct {
	mu   sync.Mutex
	path string
}

func (s *persistStore) load(dst any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadJSONFile(s.path, dst)
}

func (s *persistStore) save(src any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return saveJSONFile(s.path, src)
}

var _ = domain.SourceMailTM
