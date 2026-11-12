package codex

import (
	"strings"

	"github.com/turb/gpt-register/internal/config"
)

// configCodexAuthSource 读 CODEX_AUTH_URL_SOURCE。
// 与上游 _codex_auth_url_source (core/codex_oauth.py:207-208) 同语义：
// 空值按 local 处理（本地 PKCE 全链路）。
func configCodexAuthSource() string {
	v := strings.ToLower(strings.TrimSpace(config.Current().CodexAuthURLSource))
	if v == "" {
		return "local"
	}
	return v
}
