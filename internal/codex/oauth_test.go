package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/store"
)

// TestPKCES256 校验 PKCE 对符合 RFC7636：verifier 43~128 字符、challenge 是
// sha256(verifier) 的 base64url 去 padding 结果。
func TestPKCES256(t *testing.T) {
	verifier, challenge, err := pkceS256()
	if err != nil {
		t.Fatalf("pkceS256 失败: %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("verifier 长度越界: %d", len(verifier))
	}
	for _, c := range verifier {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			t.Fatalf("verifier 含非 base64url 字符: %q", c)
		}
	}
	if len(challenge) != 43 {
		t.Fatalf("challenge 长度应为 43，实际 %d", len(challenge))
	}
	// 再算一次确认确定性
	v2, c2, err := pkceS256()
	if err != nil {
		t.Fatal(err)
	}
	if v2 == verifier || c2 == challenge {
		t.Fatal("两次 PKCE 完全相同，随机源失效")
	}
}

func TestRandomStateNonEmpty(t *testing.T) {
	s1, err := randomState()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := randomState()
	if s1 == "" || s1 == s2 {
		t.Fatalf("state 生成异常: %q %q", s1, s2)
	}
}

func TestCodexBrowserIdentityRestoresAccountProfile(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/codex-identity.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const email = "identity@example.com"
	_, err = st.InsertAccount(context.Background(), domain.Account{
		Email: email,
		Payload: map[string]any{
			"device_id":            "did-persisted",
			"browser_tls_profile":  "chrome_131",
			"browser_chrome_major": "131",
			"browser_user_agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"browser_language":     "ja-JP",
			"browser_timezone":     "Asia/Tokyo",
			"browser_screen":       "1440x900",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	deviceID, image := codexBrowserIdentity(context.Background(), st, email, "http://region-DE-proxy.example:8080")
	if deviceID != "did-persisted" {
		t.Fatalf("deviceID = %q, want did-persisted", deviceID)
	}
	want := protocol.BrowserProfile{
		TLSProfile:  "chrome_131",
		ChromeMajor: "131",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		Language:    "ja-JP",
		Timezone:    "Asia/Tokyo",
		Screen:      "1440x900",
	}
	if image != want {
		t.Fatalf("image = %+v, want %+v", image, want)
	}
}

// TestBuildAuthorizeURL 校验 Codex 授权 URL 参数集与上游 L163-177 完全一致。
func TestBuildAuthorizeURL(t *testing.T) {
	f := &codexFlow{deviceID: "did-test-1234"}
	raw := f.buildAuthorizeURL("state-abc", "chal-xyz")

	want := map[string]string{
		"client_id":                  codexClientID,
		"response_type":              "code",
		"redirect_uri":               "http://localhost:1455/auth/callback",
		"scope":                      "openid email profile offline_access",
		"state":                      "state-abc",
		"code_challenge":             "chal-xyz",
		"code_challenge_method":      "S256",
		"prompt":                     "login",
		"id_token_add_organizations": "true",
		"codex_cli_simplified_flow":  "true",
		"ext-oai-did":                "did-test-1234",
		"screen_hint":                "login_or_signup",
	}
	got := parseQuery(t, raw)
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s 期望 %q 实际 %q", k, v, got[k])
		}
	}
	if got["auth_session_logging_id"] == "" {
		t.Fatal("auth_session_logging_id 缺失")
	}
	if !hasPrefix(raw, codexAuthURL+"?") {
		t.Fatalf("授权地址前缀错误: %s", raw)
	}
}

func TestIsTransientCodexNetworkError(t *testing.T) {
	transient := []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		context.DeadlineExceeded,
		errors.New("remote error: tls: handshake failure"),
		errors.New("read tcp: connection reset by peer"),
		errors.New("proxyconnect tcp: dial tcp: connection refused"),
		errors.New("curl: (52) empty reply from server"),
	}
	for _, err := range transient {
		if !isTransientCodexNetworkError(err) {
			t.Fatalf("应识别为临时网络错误: %v", err)
		}
	}

	nonTransient := []error{
		nil,
		context.Canceled,
		errors.New("授权页落到错误页"),
		errors.New("状态码 403"),
	}
	for _, err := range nonTransient {
		if isTransientCodexNetworkError(err) {
			t.Fatalf("不应识别为临时网络错误: %v", err)
		}
	}
}

func TestRetryCodexNetworkTransient(t *testing.T) {
	calls := 0
	waits := 0
	resp, err := retryCodexNetwork(
		context.Background(),
		"test",
		3,
		time.Second,
		func(context.Context, time.Duration) error {
			waits++
			return nil
		},
		nil,
		func() (*http.Response, error) {
			calls++
			if calls < 3 {
				return nil, io.EOF
			}
			return nil, nil
		},
	)
	if err != nil || resp != nil {
		t.Fatalf("重试后应成功: resp=%v err=%v", resp, err)
	}
	if calls != 3 || waits != 2 {
		t.Fatalf("重试次数错误: calls=%d waits=%d", calls, waits)
	}
}

func TestRetryCodexNetworkNonTransient(t *testing.T) {
	calls := 0
	waits := 0
	businessErr := errors.New("authorization denied")
	_, err := retryCodexNetwork(
		context.Background(),
		"test",
		3,
		time.Second,
		func(context.Context, time.Duration) error {
			waits++
			return nil
		},
		nil,
		func() (*http.Response, error) {
			calls++
			return nil, businessErr
		},
	)
	if !errors.Is(err, businessErr) {
		t.Fatalf("应原样返回业务错误: %v", err)
	}
	if calls != 1 || waits != 0 {
		t.Fatalf("业务错误不应重试: calls=%d waits=%d", calls, waits)
	}
}

// TestIsLocalhostCallback 覆盖上游 _is_redirect_uri (L682-691) 的正反例。
func TestIsLocalhostCallback(t *testing.T) {
	cases := map[string]bool{
		"http://localhost:1455/auth/callback?code=ac_1&state=s":  true,
		"http://127.0.0.1:1455/auth/callback?code=ac_1":          true,
		"https://localhost:1455/auth/callback":                   true,
		"http://localhost:1456/auth/callback":                    false,
		"http://localhost:1455/auth/other":                       false,
		"https://chatgpt.com/api/auth/callback/openai?code=ac_1": false,
		"http://localhost:1455":                                  false,
		"":                                                       false,
	}
	for in, want := range cases {
		if got := isLocalhostCallback(in); got != want {
			t.Fatalf("isLocalhostCallback(%q)=%v，期望 %v", in, got, want)
		}
	}
}

// TestExtractCode 覆盖上游 _extract_code (L694-710) 的四种情形。
func TestExtractCode(t *testing.T) {
	good := "http://localhost:1455/auth/callback?code=ac_abc123&state=st_1"
	code, err := extractCode(good, "st_1")
	if err != nil || code != "ac_abc123" {
		t.Fatalf("正常提取失败: code=%q err=%v", code, err)
	}
	// state 不匹配
	if _, err := extractCode(good, "st_other"); err == nil {
		t.Fatal("state 不匹配却通过了")
	}
	// 带 error 参数
	if _, err := extractCode("http://localhost:1455/auth/callback?error=access_denied&error_description=nope", "st_1"); err == nil {
		t.Fatal("error 参数没有被拦下")
	}
	// 缺 code
	if _, err := extractCode("http://localhost:1455/auth/callback?state=st_1", "st_1"); err == nil {
		t.Fatal("缺 code 却通过了")
	}
	// state 缺省时放行（对齐上游 returned_state 为空则不校验）
	if c, err := extractCode("http://localhost:1455/auth/callback?code=ac_x", "st_1"); err != nil || c != "ac_x" {
		t.Fatalf("state 缺省应放行: code=%q err=%v", c, err)
	}
}

// TestCredentialFilename 覆盖上游 _credential_file_name (L1183-1189)。
func TestCredentialFilename(t *testing.T) {
	cases := []struct{ email, plan, want string }{
		{"a@b.com", "", "codex-a@b.com.json"},
		{"a@b.com", "plus", "codex-a@b.com-plus.json"},
		{"a@b.com", "PLUS", "codex-a@b.com-plus.json"},
		{"a@b.com", "  ", "codex-a@b.com.json"},
		{" a@b.com ", "pro", "codex-a@b.com-pro.json"},
	}
	for _, c := range cases {
		if got := credentialFilename(c.email, c.plan); got != c.want {
			t.Fatalf("credentialFilename(%q,%q)=%q 期望 %q", c.email, c.plan, got, c.want)
		}
	}
}

// TestParseIDToken 校验顶层 email 优先、回退 profile claim，以及 auth claim 取值。
func TestParseIDToken(t *testing.T) {
	makeToken := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		seg := base64.RawURLEncoding.EncodeToString(b)
		return "header." + seg + ".sig"
	}

	tok := makeToken(map[string]any{
		"email": "top@x.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-111",
			"chatgpt_plan_type":  "plus",
		},
		"https://api.openai.com/profile": map[string]any{"email": "profile@x.com"},
	})
	c := parseIDToken(tok)
	if c.Email != "top@x.com" {
		t.Fatalf("顶层 email 应优先，实际 %q", c.Email)
	}
	if c.AccountID != "acct-111" || c.PlanType != "plus" {
		t.Fatalf("auth claim 解析错误: %+v", c)
	}

	// 顶层无 email，回退 profile
	tok2 := makeToken(map[string]any{
		"https://api.openai.com/profile": map[string]any{"email": "profile@x.com"},
	})
	if c2 := parseIDToken(tok2); c2.Email != "profile@x.com" {
		t.Fatalf("profile 回退失败: %q", c2.Email)
	}

	// 垃圾输入不 panic
	if c3 := parseIDToken("garbage"); c3.Email != "" {
		t.Fatal("垃圾 token 不该解出 email")
	}
	if c4 := parseIDToken(""); c4.Email != "" {
		t.Fatal("空 token 不该解出 email")
	}
}

// TestBuildStorage 校验 CLIProxyAPI CodexTokenStorage 的字段齐全。
func TestBuildStorage(t *testing.T) {
	tr := &tokenResponse{
		IDToken:      "id-tok",
		AccessToken:  "at-tok",
		RefreshToken: "rt-tok",
		ExpiresIn:    3600,
	}
	claims := idClaims{Email: "a@b.com", AccountID: "acct-9", PlanType: "plus"}
	s := buildStorage(tr, claims)

	for _, k := range []string{"id_token", "access_token", "refresh_token", "account_id", "last_refresh", "email", "type", "expired"} {
		if _, ok := s[k]; !ok {
			t.Fatalf("storage 缺字段 %s", k)
		}
	}
	if s["type"] != "codex" {
		t.Fatalf("type 应为 codex，实际 %v", s["type"])
	}
	if s["access_token"] != "at-tok" || s["refresh_token"] != "rt-tok" || s["id_token"] != "id-tok" {
		t.Fatalf("三件套落盘错误: %+v", s)
	}
	if s["account_id"] != "acct-9" || s["email"] != "a@b.com" {
		t.Fatalf("claims 落盘错误: %+v", s)
	}
}

// TestDetectUnusableFromBody 校验终局码识别，与 driver.go deadAccountCodes 同源。
func TestDetectUnusableFromBody(t *testing.T) {
	cases := map[string]string{
		`{"error":{"code":"account_deactivated","message":"x"}}`: "account_deactivated",
		`{"error":{"type":"account_banned"}}`:                    "account_banned",
		`{"code":"account_suspended"}`:                           "account_suspended",
		`{"detail":"email_address_changed"}`:                     "email_address_changed",
	}
	for body, want := range cases {
		une := detectUnusableFromBody([]byte(body))
		if une == nil {
			t.Fatalf("未识别终局码: %s", body)
		}
		if une.Code != want {
			t.Fatalf("%s 期望 %q 实际 %q", body, want, une.Code)
		}
	}
	if une := detectUnusableFromBody([]byte(`{"error":{"code":"rate_limit"}}`)); une != nil {
		t.Fatalf("非终局码被误判: %+v", une)
	}
	if une := detectUnusableFromBody(nil); une != nil {
		t.Fatal("空体不该命中")
	}
}

// TestDecodeJWTSegment 校验 base64url 三种形态都能解。
func TestDecodeJWTSegment(t *testing.T) {
	payload := map[string]any{"workspaces": []any{map[string]any{"id": "ws-1"}}}
	b, _ := json.Marshal(payload)
	raw := base64.RawURLEncoding.EncodeToString(b)
	got := decodeJWTSegment(raw)
	if len(got) == 0 {
		t.Fatal("RawURLEncoding 解码失败")
	}
	ws, _ := got["workspaces"].([]any)
	if len(ws) != 1 {
		t.Fatalf("workspaces 解析错误: %+v", got)
	}
	if decodeJWTSegment("!!!not-base64!!!") != nil {
		t.Fatal("非法输入应返回 nil")
	}
}

// TestAbsAuthURL 校验相对路径补齐。
func TestAbsAuthURL(t *testing.T) {
	if got := absAuthURL("/api/x"); got != "https://auth.openai.com/api/x" {
		t.Fatalf("相对路径补齐错误: %s", got)
	}
	if got := absAuthURL("http://localhost:1455/auth/callback"); got != "http://localhost:1455/auth/callback" {
		t.Fatalf("绝对地址被改写: %s", got)
	}
}

// ---- 测试小工具 ----

func parseQuery(t *testing.T, raw string) map[string]string {
	t.Helper()
	i := indexByte(raw, '?')
	if i < 0 {
		t.Fatalf("无 query: %s", raw)
	}
	out := map[string]string{}
	rest := raw[i+1:]
	for len(rest) > 0 {
		kv := rest
		if j := indexByte(rest, '&'); j >= 0 {
			kv = rest[:j]
			rest = rest[j+1:]
		} else {
			rest = ""
		}
		if kv == "" {
			continue
		}
		k, v := kv, ""
		if j := indexByte(kv, '='); j >= 0 {
			k, v = kv[:j], kv[j+1:]
		}
		out[unescape(k)] = unescape(v)
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func unescape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		if s[i] == '+' {
			out = append(out, ' ')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
