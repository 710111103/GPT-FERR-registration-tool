package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// -----------------------------------------------------------------------------
// 邮箱换绑（change_email）纯协议链路
//
// 上游契约 core/email_change_service.py：
//
//	POST https://chatgpt.com/backend-api/accounts/change_email/begin   {"email": new_email}
//	POST https://chatgpt.com/backend-api/accounts/change_email/verify  {"email": new_email, "code": otp}
//
// 两个端点都要求 Authorization: Bearer <access_token> + oai-device-id + Origin。
// 服务端在「距上次登录过久」时会先回 reauth_required / recent login required，
// 这时必须对**原邮箱**做一次重认证拿到带新鲜登录态的 AT，再用新 AT 重发 begin。
// -----------------------------------------------------------------------------

// EmailChangeReauthError 表示服务端要求 Recent Login 重认证。
type EmailChangeReauthError struct {
	Path    string
	Message string
}

func (e *EmailChangeReauthError) Error() string {
	return fmt.Sprintf("服务端要求重认证（%s）: %s", e.Path, e.Message)
}

// IsReauthRequired 判断错误文本是否属于 Recent Login 要求。
func IsReauthRequired(err error) bool {
	if err == nil {
		return false
	}
	var target *EmailChangeReauthError
	if asEmailChangeReauth(err, &target) {
		return true
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "reauth_required") || strings.Contains(low, "recent login required")
}

func asEmailChangeReauth(err error, target **EmailChangeReauthError) bool {
	for err != nil {
		if e, ok := err.(*EmailChangeReauthError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// emailChangeHeaders 组装换绑端点请求头。
// 与 twofa.Setup2FA 同一形态：NextAuth 的 */* 接受头 + Bearer + oai-device-id + Origin。
func (s *Session) emailChangeHeaders(token string) map[string]string {
	h := s.NextAuthHeaders(chatGPTBase + "/")
	h["Authorization"] = "Bearer " + token
	h["Origin"] = chatGPTBase
	if s.DeviceID != "" {
		h["oai-device-id"] = s.DeviceID
	}
	lang := s.Language
	if lang == "" {
		lang = "en-US"
	}
	h["oai-language"] = lang
	return h
}

// emailChangeErrorText 把非 200 回包压成一段可读文本，优先取 error.message / error.code。
func emailChangeErrorText(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "空响应体"
	}
	var payload struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		switch v := payload.Error.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case map[string]any:
			if m, ok := v["message"].(string); ok && strings.TrimSpace(m) != "" {
				return strings.TrimSpace(m)
			}
			if c, ok := v["code"].(string); ok && strings.TrimSpace(c) != "" {
				return strings.TrimSpace(c)
			}
		}
		if strings.TrimSpace(payload.Message) != "" {
			return strings.TrimSpace(payload.Message)
		}
		if strings.TrimSpace(payload.Detail) != "" {
			return strings.TrimSpace(payload.Detail)
		}
	}
	if len(trimmed) > 500 {
		trimmed = trimmed[:500]
	}
	return trimmed
}

// postEmailChange 发一次换绑端点请求。
// 业务 4xx（含 reauth_required）直接返回错误不重试；网络错误与 5xx/429 由调用方决定重试。
func (s *Session) postEmailChange(ctx context.Context, path, token string, payload map[string]any) (map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化换绑请求失败: %w", err)
	}
	resp, err := s.RequestCtx(ctx, http.MethodPost, chatGPTBase+path, string(body), s.emailChangeHeaders(token))
	if err != nil {
		return nil, fmt.Errorf("%s 网络请求失败: %w", path, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	msg := emailChangeErrorText(raw)
	if resp.StatusCode != 200 {
		if IsReauthRequired(fmt.Errorf("%s", msg)) {
			return nil, &EmailChangeReauthError{Path: path, Message: msg}
		}
		return nil, fmt.Errorf("%s 返回 %d: %s", path, resp.StatusCode, msg)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s 回包不是合法 JSON: %s", path, strings.TrimSpace(string(raw))[:minInt(len(strings.TrimSpace(string(raw))), 200)])
	}
	// 上游 _post 的判定：success 必须为真，否则整条链失败。
	if ok, has := out["success"].(bool); has && !ok {
		if IsReauthRequired(fmt.Errorf("%s", msg)) {
			return nil, &EmailChangeReauthError{Path: path, Message: msg}
		}
		return nil, fmt.Errorf("%s 返回失败: %s", path, msg)
	}
	return out, nil
}

// ChangeEmailBegin 请求服务端向 newEmail 发送换绑验证码。
// 命中 Recent Login 要求时返回 *EmailChangeReauthError，调用方重认证后重发。
func (s *Session) ChangeEmailBegin(ctx context.Context, token, newEmail string) (map[string]any, error) {
	newEmail = strings.TrimSpace(newEmail)
	if token == "" {
		return nil, fmt.Errorf("access_token 为空，无法发起换绑")
	}
	if newEmail == "" {
		return nil, fmt.Errorf("新邮箱为空，无法发起换绑")
	}
	return s.postEmailChange(ctx, "/backend-api/accounts/change_email/begin", token,
		map[string]any{"email": newEmail})
}

// ChangeEmailVerify 提交新邮箱收到的验证码，完成换绑。
// 成功后旧 AT 立刻失效，必须由调用方重新取会话拿新 AT。
func (s *Session) ChangeEmailVerify(ctx context.Context, token, newEmail, code string) (map[string]any, error) {
	newEmail = strings.TrimSpace(newEmail)
	code = strings.TrimSpace(code)
	if token == "" {
		return nil, fmt.Errorf("access_token 为空，无法提交换绑验证码")
	}
	if newEmail == "" || code == "" {
		return nil, fmt.Errorf("新邮箱或验证码为空")
	}
	return s.postEmailChange(ctx, "/backend-api/accounts/change_email/verify", token,
		map[string]any{"email": newEmail, "code": code})
}

// FetchSessionIdentity 读取 /api/auth/session，返回 accessToken / sessionToken / user.email。
// 换绑 verify 之后立刻调用它，能在当前存活会话里直接拿到新 AT，省掉一次慢速查活。
func (s *Session) FetchSessionIdentity(ctx context.Context) (string, string, string, error) {
	headers := s.NextAuthHeaders(chatGPTBase + "/")
	resp, err := s.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/api/auth/session", "", headers)
	if err != nil {
		return "", "", "", fmt.Errorf("读取会话失败: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", "", fmt.Errorf("会话接口返回 %d: %s", resp.StatusCode, emailChangeErrorText(raw))
	}
	var payload struct {
		AccessToken  string `json:"accessToken"`
		SessionToken string `json:"sessionToken"`
		User         struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", "", fmt.Errorf("会话回包解析失败: %w", err)
	}
	st := strings.TrimSpace(payload.SessionToken)
	if st == "" {
		st = s.GetSessionTokenCookie()
	}
	return strings.TrimSpace(payload.AccessToken), st, strings.TrimSpace(payload.User.Email), nil
}

// WarmAuthenticatedSession 用现有 AT 预热 chatgpt.com 登录态：
// 先打首页拿 cf cookie，再读一次 /api/auth/session 把 NextAuth 上下文坐实。
// 上游 account_liveness._warm_authenticated_session 同源，失败只记日志不阻断。
func (s *Session) WarmAuthenticatedSession(ctx context.Context, token string) error {
	if resp, err := s.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/", "", nil); err == nil {
		drain(resp)
	} else {
		return fmt.Errorf("预热首页失败: %w", err)
	}
	headers := s.NextAuthHeaders(chatGPTBase + "/")
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	if resp, err := s.RequestCtx(ctx, http.MethodGet, chatGPTBase+"/api/auth/session", "", headers); err == nil {
		drain(resp)
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
