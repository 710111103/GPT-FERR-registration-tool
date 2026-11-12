package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudMailError CloudMail 服务请求或邮箱取码失败。
type CloudMailError struct{ Msg string }

func (e *CloudMailError) Error() string { return e.Msg }

func cloudMailErrf(format string, args ...any) error {
	return &CloudMailError{Msg: fmt.Sprintf(format, args...)}
}

const cloudMailRequestTimeout = 20 * time.Second

// CloudMailBaseURL 归一化 CloudMail API 地址。
func CloudMailBaseURL(value string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(value), "/")
	if base == "" {
		return "", cloudMailErrf("CloudMail API 地址未配置，请填写 CLOUDMAIL_API_BASE（例如 https://你的worker自定义域）。")
	}
	lower := strings.ToLower(base)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		base = "https://" + base
	}
	return base, nil
}

// CloudMailTokenPathCandidates 返回要尝试的取 token 路径（去重，补前导斜杠）。
func CloudMailTokenPathCandidates(path string) []string {
	first := strings.TrimSpace(path)
	out := make([]string, 0, 2)
	for _, item := range []string{first, "/api/public/genToken"} {
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, "/") {
			item = "/" + item
		}
		dup := false
		for _, seen := range out {
			if seen == item {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, item)
		}
	}
	return out
}

// CloudMailExtractToken 从各种响应结构里抽 token。
func CloudMailExtractToken(payload any) (string, error) {
	m, _ := payload.(map[string]any)
	var candidates []any
	if m != nil {
		candidates = append(candidates, m["token"], m["accessToken"], m["access_token"])
		if data, ok := m["data"].(map[string]any); ok {
			candidates = append(candidates, data["token"], data["accessToken"], data["access_token"], data["authorization"])
		}
		if data, ok := m["data"].(string); ok {
			candidates = append(candidates, data)
		}
	}
	for _, item := range candidates {
		if s, ok := item.(string); ok {
			if tok := strings.TrimSpace(s); tok != "" {
				return tok, nil
			}
		}
	}
	raw, _ := json.Marshal(payload)
	text := string(raw)
	if len(text) > 200 {
		text = text[:200]
	}
	return "", cloudMailErrf("CloudMail 生成 Token 成功但响应中未找到 token: %s", text)
}

// cloudMailPostToken 向某个路径 POST 换取 token。
func cloudMailPostToken(ctx context.Context, url, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: cloudMailRequestTimeout}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", cloudMailErrf("CloudMail 响应不是 JSON: HTTP %d", resp.StatusCode)
	}
	code, hasCode := payload["code"]
	codeOK := !hasCode || code == nil || code == float64(200) || code == "200"
	if resp.StatusCode >= 400 || !codeOK {
		msg, _ := payload["message"].(string)
		if msg == "" {
			text := string(raw)
			if len(text) > 160 {
				text = text[:160]
			}
			msg = text
		}
		return "", cloudMailErrf("HTTP %d; code=%v; %s", resp.StatusCode, code, msg)
	}
	return CloudMailExtractToken(payload)
}

// CloudMailGenToken 用 CloudMail 管理员邮箱/密码生成 Authorization Token。
func CloudMailGenToken(ctx context.Context, baseURL, email, password, path string) (string, error) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return "", cloudMailErrf("CloudMail 管理员邮箱或密码为空")
	}
	base, err := CloudMailBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	lastError := ""
	for _, tokenPath := range CloudMailTokenPathCandidates(path) {
		token, err := cloudMailPostToken(ctx, base+tokenPath, email, password)
		if err == nil {
			return token, nil
		}
		lastError = fmt.Sprintf("%s: %s", tokenPath, err.Error())
	}
	return "", cloudMailErrf("CloudMail 生成 Token 失败: %s", lastError)
}

// cloudMailRequestRaw 调 CloudMail 接口并返回 JSON。
func cloudMailRequestRaw(ctx context.Context, baseURL, method, path string, body map[string]any, token string) (map[string]any, error) {
	url := baseURL + path
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = strings.NewReader(string(buf))
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), url, reader)
	if err != nil {
		return nil, cloudMailErrf("CloudMail 请求失败 (%s): %s", path, err.Error())
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: cloudMailRequestTimeout}).Do(req)
	if err != nil {
		return nil, cloudMailErrf("CloudMail 请求失败 (%s): %s", path, err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, cloudMailErrf("CloudMail 响应不是 JSON (%s): HTTP %d", path, resp.StatusCode)
	}
	code, hasCode := payload["code"]
	codeOK := !hasCode || code == nil || code == float64(200) || code == "200"
	if resp.StatusCode >= 400 || !codeOK {
		msg, _ := payload["message"].(string)
		if msg == "" {
			text := string(raw)
			if len(text) > 200 {
				text = text[:200]
			}
			msg = text
		}
		return nil, cloudMailErrf("CloudMail 请求失败 (%s): HTTP %d; code=%v; %s", path, resp.StatusCode, code, msg)
	}
	return payload, nil
}

// CloudMailNormalizeDomains 把各种域名输入归一化成小写去重列表。
func CloudMailNormalizeDomains(raw any) []string {
	var parts []any
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		s := strings.ReplaceAll(v, ";", "\n")
		s = strings.ReplaceAll(s, ",", "\n")
		for _, line := range strings.Split(s, "\n") {
			parts = append(parts, line)
		}
	case map[string]any:
		for _, key := range []string{"domain", "name", "value", "emailDomain"} {
			if vv, ok := v[key]; ok && vv != nil {
				if s, ok := vv.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
		}
	case []any:
		parts = v
	case []string:
		for _, s := range v {
			parts = append(parts, s)
		}
	default:
		parts = []any{v}
	}
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		var candidates []any
		if m, ok := item.(map[string]any); ok {
			for _, key := range []string{"domain", "name", "value", "emailDomain"} {
				if vv, ok := m[key]; ok {
					candidates = append(candidates, vv)
				}
			}
		} else {
			candidates = []any{item}
		}
		for _, cand := range candidates {
			s, _ := cand.(string)
			domain := strings.ToLower(strings.TrimLeft(strings.TrimSpace(s), "@"))
			if domain == "" || !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
				continue
			}
			dup := false
			for _, seen := range out {
				if seen == domain {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, domain)
			}
		}
	}
	return out
}

// CloudMailExtractDomains 从响应体里抽域名列表。
func CloudMailExtractDomains(payload any) []string {
	m, ok := payload.(map[string]any)
	if !ok {
		return CloudMailNormalizeDomains(payload)
	}
	data, hasData := m["data"]
	if !hasData {
		data = m
	}
	candidates := make([]any, 0, 7)
	if dm, ok := data.(map[string]any); ok {
		for _, key := range []string{"domainList", "domains", "domain", "emailDomains", "mailDomains", "availDomains"} {
			candidates = append(candidates, dm[key])
		}
	}
	candidates = append(candidates, data)
	for _, item := range candidates {
		if domains := CloudMailNormalizeDomains(item); len(domains) > 0 {
			return domains
		}
	}
	return nil
}

// CloudMailFetchDomains 从 CloudMail 平台获取可用邮箱域名列表。
// 先读公开配置 /api/setting/websiteConfig，再退化为管理员登录后读 /api/setting/query。
func CloudMailFetchDomains(ctx context.Context, baseURL, adminEmail, password, token string) ([]string, error) {
	base, err := CloudMailBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	errorsList := make([]string, 0, 2)

	payload, err := cloudMailRequestRaw(ctx, base, "GET", "/api/setting/websiteConfig", nil, "")
	if err == nil {
		if domains := CloudMailExtractDomains(payload); len(domains) > 0 {
			return domains, nil
		}
		errorsList = append(errorsList, "/api/setting/websiteConfig: 响应中没有 domainList")
	} else {
		errorsList = append(errorsList, "/api/setting/websiteConfig: "+err.Error())
	}

	loginToken := strings.TrimSpace(token)
	if loginToken == "" {
		if strings.TrimSpace(adminEmail) == "" || strings.TrimSpace(password) == "" {
			errorsList = append(errorsList, "/api/setting/query: CloudMail 管理员邮箱或密码为空，无法登录获取域名列表")
			return nil, cloudMailErrf("CloudMail 自动获取域名失败：%s", strings.Join(errorsList, "；"))
		}
		loginPayload, lerr := cloudMailRequestRaw(ctx, base, "POST", "/api/login",
			map[string]any{"email": adminEmail, "password": password}, "")
		if lerr != nil {
			errorsList = append(errorsList, "/api/setting/query: "+lerr.Error())
			return nil, cloudMailErrf("CloudMail 自动获取域名失败：%s", strings.Join(errorsList, "；"))
		}
		loginToken, lerr = CloudMailExtractToken(loginPayload)
		if lerr != nil {
			errorsList = append(errorsList, "/api/setting/query: "+lerr.Error())
			return nil, cloudMailErrf("CloudMail 自动获取域名失败：%s", strings.Join(errorsList, "；"))
		}
	}

	payload, err = cloudMailRequestRaw(ctx, base, "GET", "/api/setting/query", nil, loginToken)
	if err == nil {
		if domains := CloudMailExtractDomains(payload); len(domains) > 0 {
			return domains, nil
		}
		errorsList = append(errorsList, "/api/setting/query: 响应中没有 domainList")
	} else {
		errorsList = append(errorsList, "/api/setting/query: "+err.Error())
	}
	return nil, cloudMailErrf("CloudMail 自动获取域名失败：%s", strings.Join(errorsList, "；"))
}
