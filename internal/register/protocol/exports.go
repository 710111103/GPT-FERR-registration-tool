package protocol

import (
	"context"
	"fmt"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// 本文件只做转发包装：把 AT 链路里已经实现并做过真机验证的错误页解析能力
// 开放给 internal/codex 复用。driver.go 的既有逻辑一行未改。

// DecodeAuthError 返回错误页 URL 里 payload 解出的结构化字段。
func DecodeAuthError(rawURL string) (code, kind, requestID, message string) {
	info := decodeAuthError(rawURL)
	return info.Code, info.Kind, info.RequestID, info.Message
}

// IsAuthErrorURL 判断某个 URL 是否已经落到 OpenAI 错误页。
func IsAuthErrorURL(raw string) bool {
	return isAuthErrorURL(raw)
}

// DetectAccountUnusable 命中终局错误码时返回 *AccountUnusableError。
func DetectAccountUnusable(rawURL string) *AccountUnusableError {
	return detectAccountUnusable(rawURL)
}

// ReadContinue 读取响应体里的 continue_url/external_url/url 或 Location 头。
// 返回值第二项是 HTTP 状态码。
func ReadContinue(resp *http.Response) (string, int) {
	return readContinue(resp)
}

// ParseAuthErrorPayload 把错误页 URL 转成可读文案。
func ParseAuthErrorPayload(rawURL string) string {
	return parseAuthErrorPayload(rawURL)
}

// IsDeadAccountCode 判断某个错误码是否属于 OpenAI 终局码（小写比较）。
func IsDeadAccountCode(code string) bool {
	return deadAccountCodes[strings.ToLower(strings.TrimSpace(code))]
}

// CorpseCode 归一化错误码，便于跨包日志统一。
func CorpseCode(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// SetPasswordWithAccessToken 用账号已有 AT 建立已认证会话并直接设置登录密码。
// 对应上游 core/password_setup_service.py 的「协议改密」步骤：
// warm 会话 → POST /api/accounts/password/set。改密本身不做登录验收，
// 验收由调用方用新密码重新走一遍 LoginWithPasswordLogged 完成。
func SetPasswordWithAccessToken(ctx context.Context, accessToken, deviceID, proxy, password string) error {
	return SetPasswordWithAccessTokenUsingProfile(ctx, accessToken, deviceID, proxy, password, BrowserProfile{}.Complete(proxy))
}

// SetPasswordWithAccessTokenUsingProfile 使用账号注册时固化的画像建立已认证会话。
func SetPasswordWithAccessTokenUsingProfile(ctx context.Context, accessToken, deviceID, proxy, password string, image BrowserProfile) error {
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("access_token 为空")
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("新密码为空")
	}
	image = image.Complete(proxy)
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
		return err
	}
	defer sess.Close()
	if err := sess.WarmAuthenticatedSession(ctx, accessToken); err != nil {
		return fmt.Errorf("建立已认证会话失败: %w", err)
	}
	d := &Driver{}
	if err := d.setPassword(ctx, sess, password); err != nil {
		return fmt.Errorf("提交新密码失败: %w", err)
	}
	return nil
}
