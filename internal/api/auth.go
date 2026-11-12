// Package api 暴露与 Python 版完全兼容的 HTTP 接口。
//
// 兼容性是硬要求：前端 index.html（43 万字节原生 JS）不改一行即可使用。
// 因此路由路径、参数名、JSON 字段名全部与 webui/app.py 对齐。
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// auth 实现授权码鉴权。
// 与 webui/auth.py 一致：支持 Cookie、X-Auth-Code 头、Authorization: Bearer 三种方式。
type auth struct {
	code      string
	generated bool
	secret    []byte
	mu        sync.RWMutex
}

const cookieName = "turb_auth"

func newAuth(code, secret string) *auth {
	a := &auth{}
	code = strings.TrimSpace(code)
	if code == "" {
		code = "123456"
		a.generated = true
	}
	a.code = code
	if secret == "" {
		// 未配置时从授权码派生，修改授权码会使旧会话失效——与 Python 版同样的语义。
		sum := sha256.Sum256([]byte("turb-gpt-register:" + code))
		a.secret = sum[:]
	} else {
		a.secret = []byte(secret)
	}
	return a
}

// Code 返回当前授权码，供启动日志打印（仅当是自动生成时）。
func (a *auth) Code() string { return a.code }

// Generated 表示授权码是自动生成的。
func (a *auth) Generated() bool { return a.generated }

// token 派生会话 cookie 值。
func (a *auth) token() string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte("session"))
	return hex.EncodeToString(m.Sum(nil))
}

// check 判断请求是否已通过鉴权。
func (a *auth) check(r *http.Request) bool {
	// 1. Header
	if v := r.Header.Get("X-Auth-Code"); v != "" && hmac.Equal([]byte(v), []byte(a.code)) {
		return true
	}
	// 2. Bearer
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if hmac.Equal([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(a.code)) {
			return true
		}
	}
	// 3. Cookie
	if c, err := r.Cookie(cookieName); err == nil {
		if hmac.Equal([]byte(c.Value), []byte(a.token())) {
			return true
		}
	}
	return false
}

// issueCookie 登录成功后下发会话 cookie。
func (a *auth) issueCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    a.token(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
}

// clearCookie 退出登录。
func (a *auth) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

// middleware 保护除 /login、/api/login 与静态资源外的全部路由。
func (a *auth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/login" || p == "/api/login" || p == "/favicon.ico" || strings.HasPrefix(p, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if a.check(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(p, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok": false, "error": "未授权，请先登录或提供 X-Auth-Code",
			})
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

// writeJSON 统一 JSON 输出。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail 输出错误 JSON。
func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}
