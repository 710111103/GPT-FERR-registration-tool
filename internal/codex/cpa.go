package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
)

// cpaOrigin 返回 CPA 管理接口的 origin（scheme://host:port）。
func cpaOrigin() (string, error) {
	raw := strings.TrimSpace(config.Current().CPAManagementURL)
	if raw == "" {
		return "", fmt.Errorf("[Codex][CPA] 尚未配置 CPA_MANAGEMENT_URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("[Codex][CPA] CPA_MANAGEMENT_URL 格式无效: %s", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("[Codex][CPA] CPA_MANAGEMENT_URL 格式无效: %s", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// cpaKey 返回管理密钥。
func cpaKey() (string, error) {
	key := strings.TrimSpace(config.Current().CPAManagementKey)
	if key == "" {
		return "", fmt.Errorf("[Codex][CPA] 尚未配置 CPA_MANAGEMENT_KEY")
	}
	return key, nil
}

// CPARequestRaw 调用 CPA 管理接口并返回原始响应体。
// responseType 取 "text"（默认）或 "bytes"。
func CPARequestRaw(ctx context.Context, method, path string, body map[string]any, responseType string) ([]byte, error) {
	origin, err := cpaOrigin()
	if err != nil {
		return nil, err
	}
	key, err := cpaKey()
	if err != nil {
		return nil, err
	}
	timeout := config.Current().CPARequestTimeout
	if timeout <= 0 {
		timeout = 30
	}

	var reader io.Reader
	if body != nil {
		buf, merr := json.Marshal(body)
		if merr != nil {
			return nil, merr
		}
		reader = strings.NewReader(string(buf))
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), origin+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Management-Key", key)

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := ""
		var payload map[string]any
		if json.Unmarshal(raw, &payload) == nil {
			for _, k := range []string{"error", "message", "detail", "reason"} {
				if v, ok := payload[k].(string); ok && strings.TrimSpace(v) != "" {
					msg = v
					break
				}
			}
		}
		if msg == "" {
			txt := string(raw)
			if len(txt) > 300 {
				txt = txt[:300]
			}
			msg = txt
		}
		return nil, fmt.Errorf("[Codex][CPA] 管理接口失败 %s %s status=%d: %s",
			strings.ToUpper(method), path, resp.StatusCode, msg)
	}
	return raw, nil
}

// cpaRequestJSON 调管理接口并按 JSON 解析。
func cpaRequestJSON(ctx context.Context, method, path string, body map[string]any) (map[string]any, error) {
	raw, err := CPARequestRaw(ctx, method, path, body, "text")
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("[Codex][CPA] 管理接口响应不是 JSON %s %s: %v", method, path, err)
	}
	return out, nil
}

// cpaStr 取字符串字段并 trim。
func cpaStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// ListCPACodexAuthFiles 读取 CPA auth-files 列表，只返回可识别为 codex 的凭证。
func ListCPACodexAuthFiles(ctx context.Context) ([]map[string]any, error) {
	payload, err := cpaRequestJSON(ctx, "GET", "/v0/management/auth-files", nil)
	if err != nil {
		return nil, err
	}
	var files []any
	if list, ok := payload["files"].([]any); ok {
		files = list
	}
	out := make([]map[string]any, 0, len(files))
	for _, item := range files {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := cpaStr(m, "name")
		ftype := strings.ToLower(cpaStr(m, "type"))
		emailLower := strings.ToLower(cpaStr(m, "email"))
		nameLower := strings.ToLower(name)
		if ftype == "codex" || strings.HasPrefix(nameLower, "codex-") || strings.Contains(nameLower, "codex") {
			copied := make(map[string]any, len(m))
			for k, v := range m {
				copied[k] = v
			}
			copied["name"] = name
			if emailLower != "" {
				copied["email"] = emailLower
			} else {
				copied["email"] = cpaStr(m, "email")
			}
			out = append(out, copied)
		}
	}
	return out, nil
}

// FindCPACodexAuthFile 按本地文件名或邮箱匹配 CPA 侧的 codex auth 文件。
func FindCPACodexAuthFile(ctx context.Context, email, localFilename string) (map[string]any, error) {
	emailL := strings.ToLower(strings.TrimSpace(email))
	localNameL := strings.ToLower(strings.TrimSpace(localFilename))
	localStemL := localNameL
	if strings.HasSuffix(localStemL, ".json") {
		localStemL = localStemL[:len(localStemL)-5]
	}
	files, err := ListCPACodexAuthFiles(ctx)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	score := func(item map[string]any) int {
		nameL := strings.ToLower(cpaStr(item, "name"))
		itemEmailL := strings.ToLower(cpaStr(item, "email"))
		s := 0
		if localNameL != "" && nameL == localNameL {
			if 100 > s {
				s = 100
			}
		}
		if localStemL != "" && strings.HasPrefix(nameL, localStemL) {
			if 80 > s {
				s = 80
			}
		}
		if emailL != "" && itemEmailL == emailL {
			if 70 > s {
				s = 70
			}
		}
		if emailL != "" && strings.Contains(nameL, emailL) {
			if 60 > s {
				s = 60
			}
		}
		if strings.HasSuffix(localStemL, "-cpa-callback") {
			base := localStemL[:len(localStemL)-len("-cpa-callback")]
			if base != "" && strings.HasPrefix(nameL, base+"-") {
				if 75 > s {
					s = 75
				}
			}
		}
		return s
	}
	var best map[string]any
	bestScore := 0
	for _, item := range files {
		if sc := score(item); sc > bestScore {
			bestScore = sc
			best = item
		}
	}
	if bestScore <= 0 {
		return nil, nil
	}
	return best, nil
}

// DownloadCodexAuthText 从 CPA auth-files 下载一个 Codex JSON 文本。
// 返回（美化后的 JSON 文本, 下载文件名, 匹配到的文件元数据）。
func DownloadCodexAuthText(ctx context.Context, cpaName, email, localFilename string) (string, string, map[string]any, error) {
	var meta map[string]any
	name := strings.TrimSpace(cpaName)
	if name != "" {
		meta = map[string]any{"name": name}
	} else {
		found, err := FindCPACodexAuthFile(ctx, email, localFilename)
		if err != nil {
			return "", "", nil, err
		}
		meta = found
		name = cpaStr(found, "name")
	}
	if name == "" {
		target := email
		if target == "" {
			target = localFilename
		}
		if target == "" {
			target = cpaName
		}
		if target == "" {
			target = "未知"
		}
		return "", "", nil, fmt.Errorf("[Codex][CPA] 未在 CPA auth-files 中找到匹配的 Codex 凭证: %s", target)
	}
	path := "/v0/management/auth-files/download?name=" + url.QueryEscape(name)
	raw, err := CPARequestRaw(ctx, "GET", path, nil, "text")
	if err != nil {
		return "", "", nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", nil, fmt.Errorf("[Codex][CPA] CPA 下载内容不是有效 JSON: %s", name)
	}
	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return "", "", nil, err
	}
	if meta == nil {
		meta = map[string]any{"name": name}
	}
	return string(pretty) + "\n", name, meta, nil
}
