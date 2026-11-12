package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/mail"
)

// cxFirst 返回第一个非空（去空格后）值。
func cxFirst(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// handleCloudmailGenToken POST /api/cloudmail/gen-token
// 请求: {api_base, admin_email|email, password, path}
// 响应: {ok, token, message}
func (s *Server) handleCloudmailGenToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIBase    string `json:"api_base"`
		AdminEmail string `json:"admin_email"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		Path       string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cfg := config.Current()
	updates := map[string]string{}
	if v := strings.TrimSpace(body.APIBase); v != "" {
		updates["CLOUDMAIL_API_BASE"] = v
	}
	if v := cxFirst(body.AdminEmail, body.Email); v != "" {
		updates["CLOUDMAIL_ADMIN_EMAIL"] = v
	}
	if body.Password != "" {
		updates["CLOUDMAIL_PASSWORD"] = body.Password
	}
	if v := strings.TrimSpace(body.Path); v != "" {
		updates["CLOUDMAIL_TOKEN_PATH"] = v
	}
	if len(updates) > 0 {
		if err := writeEnv(cfg.Root, updates); err != nil {
			fail(w, http.StatusInternalServerError, "保存 CloudMail 配置失败: "+err.Error())
			return
		}
		_ = config.Reload()
		cfg = config.Current()
	}

	baseURL := cxFirst(body.APIBase, cfg.CloudMailAPIBase)
	adminEmail := cxFirst(body.AdminEmail, body.Email, cfg.CloudMailAdminEmail)
	password := cxFirst(body.Password, cfg.CloudMailPassword)
	tokenPath := cxFirst(body.Path, cfg.CloudMailTokenPath)
	switch {
	case baseURL == "":
		fail(w, http.StatusBadRequest, "CLOUDMAIL_API_BASE 为空，先在配置里填上 CloudMail 服务地址")
		return
	case adminEmail == "":
		fail(w, http.StatusBadRequest, "CLOUDMAIL_ADMIN_EMAIL 为空，先填上 CloudMail 管理员邮箱")
		return
	case password == "":
		fail(w, http.StatusBadRequest, "CLOUDMAIL_PASSWORD 为空，先填上 CloudMail 管理员密码")
		return
	}

	token, err := mail.CloudMailGenToken(r.Context(), baseURL, adminEmail, password, tokenPath)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := writeEnv(cfg.Root, map[string]string{"CLOUDMAIL_AUTH_TOKEN": token}); err != nil {
		fail(w, http.StatusInternalServerError, "保存 CloudMail Token 失败: "+err.Error())
		return
	}
	_ = config.Reload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"token":   token,
		"message": "CloudMail Token 已生成，当前 CloudMail 配置已落盘",
	})
}

// handleCloudmailDomains POST /api/cloudmail/domains
// 请求: {api_base, admin_email|email, password, token}
// 响应: {ok, domains, count, message}
func (s *Server) handleCloudmailDomains(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIBase    string `json:"api_base"`
		AdminEmail string `json:"admin_email"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		Token      string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cfg := config.Current()
	updates := map[string]string{}
	if v := strings.TrimSpace(body.APIBase); v != "" {
		updates["CLOUDMAIL_API_BASE"] = v
	}
	if v := cxFirst(body.AdminEmail, body.Email); v != "" {
		updates["CLOUDMAIL_ADMIN_EMAIL"] = v
	}
	if body.Password != "" {
		updates["CLOUDMAIL_PASSWORD"] = body.Password
	}
	if v := strings.TrimSpace(body.Token); v != "" {
		updates["CLOUDMAIL_AUTH_TOKEN"] = v
	}
	if len(updates) > 0 {
		if err := writeEnv(cfg.Root, updates); err != nil {
			fail(w, http.StatusInternalServerError, "保存 CloudMail 配置失败: "+err.Error())
			return
		}
		_ = config.Reload()
		cfg = config.Current()
	}

	baseURL := cxFirst(body.APIBase, cfg.CloudMailAPIBase)
	adminEmail := cxFirst(body.AdminEmail, body.Email, cfg.CloudMailAdminEmail)
	password := cxFirst(body.Password, cfg.CloudMailPassword)
	token := cxFirst(body.Token, cfg.CloudMailAuthToken)

	domains, err := mail.CloudMailFetchDomains(r.Context(), baseURL, adminEmail, password, token)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	if len(domains) == 0 {
		fail(w, http.StatusBadGateway, "CloudMail 响应里没有解析到任何可用域名")
		return
	}
	if err := writeEnv(cfg.Root, map[string]string{"CLOUDMAIL_DOMAINS": strings.Join(domains, "\n")}); err != nil {
		fail(w, http.StatusInternalServerError, "保存域名列表失败: "+err.Error())
		return
	}
	_ = config.Reload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"domains": domains,
		"count":   len(domains),
		"message": "CloudMail 域名已拉取并写入 CLOUDMAIL_DOMAINS",
	})
}
