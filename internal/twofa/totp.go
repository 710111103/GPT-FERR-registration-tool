package twofa

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// Requester 抽象发起带会话请求的能力，解除与 protocol 包的循环依赖。
type Requester interface {
	Request(method, rawURL string, body string, extra map[string]string) (*http.Response, error)
}

// GenerateCode 计算给定 Base32 密钥在时间 t 的 6 位标准 TOTP 动态码（RFC 6238）。
func GenerateCode(secret string, t time.Time) (string, error) {
	clean := strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		// 尝试补齐 padding 后再解
		if padLen := 8 - (len(clean) % 8); padLen < 8 {
			clean += strings.Repeat("=", padLen)
		}
		key, err = base32.StdEncoding.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("解码 TOTP secret 失败: %w", err)
		}
	}

	counter := uint64(t.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	code := truncated % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// CurrentCode 计算当前时刻的 6 位标准 TOTP 动态码。
func CurrentCode(secret string) (string, error) {
	return GenerateCode(secret, time.Now())
}

// Setup2FA 原地向 ChatGPT 后端注册并激活 2FA (TOTP)。
// 保留旧签名供兼容调用；需要复用账号画像时使用 Setup2FAWithLanguage。
func Setup2FA(ctx context.Context, sess Requester, accessToken string, deviceID string) (string, error) {
	return Setup2FAWithLanguage(ctx, sess, accessToken, deviceID, "en-US")
}

// Setup2FAWithLanguage 使用账号画像中的语言注册并激活 TOTP。
// oai-language 不能固定成 en-US，否则非英语账号会在 2FA 请求层暴露身份漂移。
func Setup2FAWithLanguage(ctx context.Context, sess Requester, accessToken string, deviceID string, language string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("accessToken 不能为空")
	}
	language = strings.TrimSpace(language)
	if language == "" {
		language = "en-US"
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/json",
		"Referer":       "https://chatgpt.com/",
		"Accept":        "application/json",
		"oai-language":  language,
	}
	if deviceID != "" {
		headers["oai-device-id"] = deviceID
	}

	// 1. Enroll
	enrollBody := `{"factor_type":"totp"}`
	resp, err := sess.Request(http.MethodPost, "https://chatgpt.com/backend-api/accounts/mfa/enroll", enrollBody, headers)
	if err != nil {
		return "", fmt.Errorf("2FA enroll 失败: %w", err)
	}
	defer drain(resp)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("2FA enroll 返回状态 %d", resp.StatusCode)
	}

	var enrollResp struct {
		Secret    string `json:"secret"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return "", fmt.Errorf("解析 2FA enroll 响应失败: %w", err)
	}
	if enrollResp.Secret == "" || enrollResp.SessionID == "" {
		return "", fmt.Errorf("2FA enroll 缺少 secret 或 session_id")
	}

	// 2. 生成 TOTP 码
	totpCode, err := GenerateCode(enrollResp.Secret, time.Now())
	if err != nil {
		return "", err
	}

	// 3. 激活
	actBody, _ := json.Marshal(map[string]string{
		"code":        totpCode,
		"factor_type": "totp",
		"session_id":  enrollResp.SessionID,
	})
	resp2, err := sess.Request(http.MethodPost, "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment", string(actBody), headers)
	if err != nil {
		return "", fmt.Errorf("2FA activate 失败: %w", err)
	}
	defer drain(resp2)

	if resp2.StatusCode != 200 {
		return "", fmt.Errorf("2FA activate 返回状态 %d", resp2.StatusCode)
	}

	var actResp struct {
		Success bool `json:"success"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&actResp)
	if !actResp.Success {
		return "", fmt.Errorf("2FA activate 返回 success=false")
	}

	return enrollResp.Secret, nil
}

func drain(r *http.Response) {
	if r != nil && r.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
	}
}
