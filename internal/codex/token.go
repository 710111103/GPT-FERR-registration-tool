package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// tokenResponse 是 /oauth/token 的响应体。
type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// idClaims 是从 id_token 解出的关键声明。
type idClaims struct {
	Email     string `json:"email"`
	AccountID string `json:"account_id"`
	PlanType  string `json:"plan_type"`
}

// exchangeCode 对齐上游 exchange_codex_token (L1098-1129)：
// POST https://auth.openai.com/oauth/token，form-urlencoded。
func (f *codexFlow) exchangeCode(ctx context.Context, code string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", codexClientID)
	form.Set("code", code)
	form.Set("redirect_uri", codexRedirectURI)
	form.Set("code_verifier", f.verifier)

	f.log("[Codex] 用 authorization code 换 token (code=%s...)", head(code, 16))
	resp, err := f.sess.RequestCtx(ctx, http.MethodPost, codexTokenURL, form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
		"Origin":       "https://auth.openai.com",
		"Referer":      codexAuthBase + "/",
	})
	if err != nil {
		return nil, fmt.Errorf("换 token 请求失败: %w", err)
	}
	raw, status := readAllBody(resp)
	if status != 200 {
		return nil, fmt.Errorf("换 token 失败 status=%d: %s", status, truncate(string(raw), 300))
	}
	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("解析 token 响应失败: %w (body=%s)", err, truncate(string(raw), 200))
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token 响应缺少 access_token: %s", truncate(string(raw), 200))
	}
	f.log("[Codex] 换 token 成功 expires_in=%d access_token=%s...", tr.ExpiresIn, head(tr.AccessToken, 16))
	return &tr, nil
}

// parseIDToken 对齐上游 _parse_id_token (L1136-1158)：base64 解第二段，不验签。
// email 顶层优先，回退 https://api.openai.com/profile 里的 email。
func parseIDToken(idToken string) idClaims {
	var out idClaims
	if idToken == "" {
		return out
	}
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return out
	}
	claims := decodeJWTSegment(parts[1])
	if len(claims) == 0 {
		return out
	}
	auth, _ := claims["https://api.openai.com/auth"].(map[string]any)
	profile, _ := claims["https://api.openai.com/profile"].(map[string]any)

	if v, ok := claims["email"].(string); ok {
		out.Email = v
	}
	if out.Email == "" && profile != nil {
		if v, ok := profile["email"].(string); ok {
			out.Email = v
		}
	}
	if auth != nil {
		if v, ok := auth["chatgpt_account_id"].(string); ok {
			out.AccountID = v
		}
		if v, ok := auth["chatgpt_plan_type"].(string); ok {
			out.PlanType = v
		}
	}
	return out
}

// buildStorage 对齐上游 build_codex_storage (L1161-1175)：
// 组装 CLIProxyAPI CodexTokenStorage JSON 结构。
func buildStorage(tr *tokenResponse, claims idClaims) map[string]any {
	now := time.Now().UTC()
	expired := now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	return map[string]any{
		"id_token":      tr.IDToken,
		"access_token":  tr.AccessToken,
		"refresh_token": tr.RefreshToken,
		"account_id":    claims.AccountID,
		"last_refresh":  now.Format("2006-01-02T15:04:05Z"),
		"email":         claims.Email,
		"type":          "codex",
		"expired":       expired.Format("2006-01-02T15:04:05Z"),
	}
}

// credentialFilename 对齐上游 _credential_file_name (L1183-1189)：
// plan 为空 → codex-{email}.json；否则 codex-{email}-{plan}.json。
func credentialFilename(email, planType string) string {
	email = strings.TrimSpace(email)
	plan := strings.ToLower(strings.TrimSpace(planType))
	if plan == "" {
		return fmt.Sprintf("codex-%s.json", email)
	}
	return fmt.Sprintf("codex-%s-%s.json", email, plan)
}
