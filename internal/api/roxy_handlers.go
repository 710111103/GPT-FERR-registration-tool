package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
)

// -----------------------------------------------------------------------------
// Roxy 浏览器 API 客户端（对齐上游 core/roxybrowser_client.py）
// -----------------------------------------------------------------------------

func roxyAPIBase() string {
	cfg := config.Current()
	return strings.TrimRight(strings.TrimSpace(cfg.RoxyAPIBase), "/")
}

// roxyIsUnlimitedAPI 判定是否本地无限窗口 API（_reverse/roxy-api.mjs）。
func roxyIsUnlimitedAPI(base string) bool {
	return strings.HasSuffix(strings.TrimRight(base, "/"), ":50001")
}

func roxyJoinURL(base, path string) string {
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

// roxyTryRequest 宽松请求：失败返回错误串，不抛。
func roxyTryRequest(ctx context.Context, base, token, method, path string) (map[string]any, string) {
	if base == "" {
		return nil, "ROXY_API_BASE 为空，先在配置里填上 Roxy API 地址"
	}
	methodU := strings.ToUpper(strings.TrimSpace(method))
	if methodU == "" {
		methodU = http.MethodGet
	}
	var bodyReader io.Reader
	if methodU == http.MethodPost {
		bodyReader = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequestWithContext(ctx, methodU, roxyJoinURL(base, path), bodyReader)
	if err != nil {
		return nil, "构造请求失败: " + err.Error()
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if methodU == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if tk := strings.TrimSpace(token); tk != "" {
		req.Header.Set("Authorization", "Bearer "+tk)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	text := string(raw)
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		payload = map[string]any{"raw": text}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		trunc := text
		if len(trunc) > 500 {
			trunc = trunc[:500]
		}
		return nil, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, trunc)
	}
	if code, ok := payload["code"]; ok {
		bad := true
		switch v := code.(type) {
		case nil:
			bad = false
		case float64:
			bad = v != 0 && v != 200
		case string:
			bad = strings.TrimSpace(v) != "" && v != "0" && v != "200"
		}
		_, okTrue := payload["ok"].(bool)
		okVal, _ := payload["ok"].(bool)
		_, sucTrue := payload["success"].(bool)
		sucVal, _ := payload["success"].(bool)
		if bad && !(okTrue && okVal) && !(sucTrue && sucVal) {
			msg := cxRoxyStr(payload, "msg", "message", "error")
			if msg == "" {
				b, _ := json.Marshal(payload)
				msg = string(b)
				if len(msg) > 500 {
					msg = msg[:500]
				}
			}
			return nil, "接口返回失败: " + msg
		}
	}
	return payload, ""
}

func cxRoxyStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s := strings.TrimSpace(fmt.Sprint(v)); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func roxyPickID(item map[string]any) string {
	return cxRoxyStr(item, "workspaceId", "workspace_id", "workspaceID",
		"teamId", "team_id", "teamID",
		"companyId", "company_id", "orgId", "org_id",
		"id", "value", "key")
}

func roxyPickName(item map[string]any) string {
	return cxRoxyStr(item, "workspaceName", "workspace_name",
		"teamName", "team_name",
		"companyName", "company_name",
		"orgName", "org_name",
		"name", "label", "title", "remark")
}

func roxyLooksLikeWorkspace(item map[string]any) bool {
	joined := ""
	hasID, hasName := false, false
	for k := range item {
		lk := strings.ToLower(k)
		joined += lk + " "
		if lk == "id" {
			hasID = true
		}
		if lk == "name" {
			hasName = true
		}
	}
	for _, kw := range []string{"workspace", "team", "company", "org"} {
		if strings.Contains(joined, kw) {
			return true
		}
	}
	return hasID && hasName
}

// roxyExtractWorkspaceItems 对齐上游 _extract_workspace_items。
func roxyExtractWorkspaceItems(payload map[string]any) []map[string]any {
	out := make([]map[string]any, 0, 16)
	if payload == nil {
		return out
	}
	var rows []any
	if data, ok := payload["data"].(map[string]any); ok {
		for _, key := range []string{"rows", "list", "records"} {
			if v, ok := data[key].([]any); ok && len(v) > 0 {
				rows = v
				break
			}
		}
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		wid := cxRoxyStr(row, "id", "workspaceId", "workspace_id")
		if wid == "" {
			continue
		}
		wname := cxRoxyStr(row, "workspaceName", "workspace_name", "name")
		if wname == "" {
			wname = wid
		}
		var projects []any
		for _, key := range []string{"project_details", "projectDetails", "projects"} {
			if v, ok := row[key].([]any); ok && len(v) > 0 {
				projects = v
				break
			}
		}
		if len(projects) > 0 {
			for _, praw := range projects {
				proj, ok := praw.(map[string]any)
				if !ok {
					continue
				}
				pid := cxRoxyStr(proj, "projectId", "project_id", "id")
				pname := cxRoxyStr(proj, "projectName", "project_name", "name")
				if pname == "" {
					pname = pid
				}
				label := wname + " (" + wid + ")"
				if pid != "" {
					label = wname + " / " + pname + " (" + wid + "/" + pid + ")"
				}
				out = append(out, map[string]any{
					"id":          wid,
					"name":        wname,
					"projectId":   pid,
					"projectName": pname,
					"label":       label,
					"raw":         map[string]any{"workspace": row, "project": proj},
				})
			}
			continue
		}
		out = append(out, map[string]any{
			"id":          wid,
			"name":        wname,
			"projectId":   "",
			"projectName": "",
			"label":       wname + " (" + wid + ")",
			"raw":         row,
		})
	}
	if len(out) > 0 {
		return out
	}

	// 兜底递归抽取
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			wid := roxyPickID(v)
			if wid != "" && roxyLooksLikeWorkspace(v) {
				name := roxyPickName(v)
				if name == "" {
					name = wid
				}
				out = append(out, map[string]any{
					"id":          wid,
					"name":        name,
					"projectId":   "",
					"projectName": "",
					"label":       name + " (" + wid + ")",
					"raw":         v,
				})
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(payload)

	dedup := make(map[string]map[string]any, len(out))
	order := make([]string, 0, len(out))
	for _, item := range out {
		raw, _ := item["raw"].(map[string]any)
		hasDirID := false
		hasWS := false
		for k := range raw {
			lk := strings.ToLower(k)
			if lk == "dirid" {
				hasDirID = true
			}
			if lk == "workspaceid" || lk == "teamid" || lk == "companyid" {
				hasWS = true
			}
		}
		if hasDirID && !hasWS {
			continue
		}
		key := fmt.Sprintf("%v::%v", item["id"], item["projectId"])
		if _, seen := dedup[key]; !seen {
			order = append(order, key)
		}
		dedup[key] = item
	}
	final := make([]map[string]any, 0, len(order))
	for _, key := range order {
		final = append(final, dedup[key])
	}
	return final
}

// roxyWorkspaceCandidates 生成候选 (method, path) 列表并去重。
func roxyWorkspaceCandidates() [][2]string {
	cfg := config.Current()
	cands := make([][2]string, 0, 26)
	configuredPath := strings.TrimSpace(cfg.RoxyWorkspaceListPath)
	configuredMethod := strings.ToUpper(strings.TrimSpace(cfg.RoxyWorkspaceListMethod))
	if configuredMethod == "" {
		configuredMethod = http.MethodGet
	}
	if configuredPath != "" {
		cands = append(cands, [2]string{configuredMethod, configuredPath})
	}
	defaults := [][2]string{
		{"GET", "/browser/workspace"}, {"POST", "/browser/workspace"},
		{"GET", "/workspace/list"}, {"POST", "/workspace/list"},
		{"GET", "/workspace"}, {"POST", "/workspace"},
		{"GET", "/team/list"}, {"POST", "/team/list"},
		{"GET", "/team"}, {"POST", "/team"},
		{"GET", "/workspaces"},
		{"GET", "/teams"},
		{"GET", "/user/workspace/list"}, {"POST", "/user/workspace/list"},
		{"GET", "/user/team/list"}, {"POST", "/user/team/list"},
		{"GET", "/api/workspace/list"}, {"POST", "/api/workspace/list"},
		{"GET", "/api/team/list"}, {"POST", "/api/team/list"},
		{"GET", "/browser/workspace/list"}, {"POST", "/browser/workspace/list"},
		{"GET", "/browser/team/list"}, {"POST", "/browser/team/list"},
	}
	cands = append(cands, defaults...)
	seen := make(map[string]bool, len(cands))
	uniq := make([][2]string, 0, len(cands))
	for _, c := range cands {
		k := c[0] + " " + c[1]
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, c)
	}
	return uniq
}

// handleRoxyWorkspaces GET /api/roxy/workspaces
func (s *Server) handleRoxyWorkspaces(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	base := roxyAPIBase()
	if roxyIsUnlimitedAPI(base) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"path":   "(local unlimited api)",
			"method": "N/A",
			"items":  []any{},
			"raw":    map[string]any{"local_unlimited": true},
			"note":   "本地无限窗口 API 不走服务端，无需工作区/项目 ID",
		})
		return
	}
	if base == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"items": []any{},
			"errors": []map[string]any{{
				"method": "N/A",
				"path":   "N/A",
				"error":  "ROXY_API_BASE 为空，先在配置里填上 Roxy API 地址（形如 http://127.0.0.1:50100）",
			}},
		})
		return
	}
	token := strings.TrimSpace(cfg.RoxyAPIToken)
	type errItem struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Error   string `json:"error"`
		Payload any    `json:"payload,omitempty"`
	}
	errorsList := make([]errItem, 0, 8)
	for _, cand := range roxyWorkspaceCandidates() {
		method, path := cand[0], cand[1]
		payload, errStr := roxyTryRequest(r.Context(), base, token, method, path)
		if errStr != "" {
			errorsList = append(errorsList, errItem{Method: method, Path: path, Error: errStr})
			continue
		}
		items := roxyExtractWorkspaceItems(payload)
		if len(items) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":     true,
				"path":   path,
				"method": method,
				"items":  items,
				"raw":    payload,
			})
			return
		}
		errorsList = append(errorsList, errItem{
			Method:  method,
			Path:    path,
			Error:   "响应中未解析到团队/工作区列表",
			Payload: payload,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     false,
		"items":  []any{},
		"errors": errorsList,
		"note":   "所有候选路径都试过了，检查 ROXY_API_BASE / ROXY_API_TOKEN 是否正确，以及 Roxy 客户端是否已登录",
	})
}
