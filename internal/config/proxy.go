package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sidRegex = regexp.MustCompile(`(?i)-sid-[^-@:/]+-t-`)

// RotateProxySession 为支持 `-sid-...-t-...` (如 1024proxy, cliproxy 等) 动态会话的代理生成全新随机会话 ID，防止会话 2 分钟过期失效。
func RotateProxySession(proxy string) string {
	if proxy == "" || !strings.Contains(strings.ToLower(proxy), "-sid-") {
		return proxy
	}
	randomID := fmt.Sprintf("%08x", (time.Now().UnixNano()^0x55aa55aa)&0xffffffff)
	return sidRegex.ReplaceAllString(proxy, fmt.Sprintf("-sid-%s-t-", randomID))
}

// NormalizeProxyURL 规范化代理地址格式，并为动态会话代理生成新的 sid。
//
// 兼容常见代理商导出格式与特殊输入：
//   - 动态会话代理自动更新 sid (如 1024proxy 的 -sid-xxx-t-2)
//   - 去除首尾空白、反斜杠与成对引号（例如 \"host:port...\"）
//   - 已带 scheme（http://, https://, socks5://）的直接保留
//   - host:port:username:password  -> http://user:pass@host:port (URL 编码 user 和 pass)
//   - username:password:host:port  -> http://user:pass@host:port
//   - host:port                    -> http://host:port
func NormalizeProxyURL(raw string) string {
	return normalizeProxyURL(raw, true)
}

// NormalizeProxyURLStable 规范化代理地址，但保留已有 sid。
// 任务选定代理后应使用本函数，避免同一任务在不同阶段意外切换出口会话。
func NormalizeProxyURLStable(raw string) string {
	return normalizeProxyURL(raw, false)
}

func normalizeProxyURL(raw string, rotateSession bool) string {
	text := strings.TrimSpace(raw)
	// 递归清理外层可能包裹的 \"、' 或 ` 引号及反斜杠
	for {
		clean := strings.Trim(text, `\"'`+"` \t\r\n")
		if clean == text {
			break
		}
		text = clean
	}
	if text == "" {
		return ""
	}

	if rotateSession {
		// 动态会话代理自动轮换新鲜 sid
		text = RotateProxySession(text)
	}

	if strings.Contains(text, "://") {
		return text
	}

	parts := strings.Split(text, ":")
	if len(parts) == 4 {
		// 格式一：host:port:username:password
		if port, err := strconv.Atoi(parts[1]); err == nil && port >= 1 && port <= 65535 {
			host := parts[0]
			portStr := parts[1]
			user := url.QueryEscape(parts[2])
			pass := url.QueryEscape(parts[3])
			return fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, portStr)
		}
		// 格式二：username:password:host:port
		if port, err := strconv.Atoi(parts[3]); err == nil && port >= 1 && port <= 65535 {
			user := url.QueryEscape(parts[0])
			pass := url.QueryEscape(parts[1])
			host := parts[2]
			portStr := parts[3]
			return fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, portStr)
		}
	}
	if len(parts) == 2 {
		// 格式三：host:port
		if port, err := strconv.Atoi(parts[1]); err == nil && port >= 1 && port <= 65535 {
			return "http://" + text
		}
	}
	return "http://" + text
}
