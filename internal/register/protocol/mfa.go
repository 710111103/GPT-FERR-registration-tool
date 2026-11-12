package protocol

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// extractMFAFactorID 从 /mfa-challenge/{factor_id} 里取 factor_id。
// 上游 account_liveness._extract_factor_id 同源：优先回包 payload.factor_id，
// 没有才退到 continue_url 的最后一段（要先切掉 query，否则会带 ?... 后缀）。
func extractMFAFactorID(continueURL string) string {
	raw := strings.TrimSpace(continueURL)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		if idx := strings.Index(u.Path, "/mfa-challenge/"); idx >= 0 {
			seg := strings.Trim(u.Path[idx+len("/mfa-challenge/"):], "/")
			if seg != "" {
				return seg
			}
		}
	}
	if idx := strings.Index(raw, "/mfa-challenge/"); idx >= 0 {
		seg := raw[idx+len("/mfa-challenge/"):]
		seg = strings.TrimSpace(strings.Split(seg, "?")[0])
		seg = strings.Trim(seg, "/")
		return seg
	}
	return ""
}

// mfaFactorIDFromBody 从 issue_challenge 回包的 mfa_challenge_factors[] 里取真实 factor id，
// 结构形如 {"oai-client-auth-session":{"mfa_challenge_factors":[{"id":"...","type":"totp"}]}}。
func mfaFactorIDFromBody(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "mfa_challenge_factors") {
		return ""
	}
	var probe struct {
		Session struct {
			Factors []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"mfa_challenge_factors"`
		} `json:"oai-client-auth-session"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return ""
	}
	for _, f := range probe.Session.Factors {
		if strings.TrimSpace(f.ID) != "" {
			return strings.TrimSpace(f.ID)
		}
	}
	return ""
}

// mfaJSONHeaders 还原上游 auth_flow._common_headers 的真机形态：
// Accept: application/json、Referer 固定 mfa-challenge、Sec-Fetch 三件套、
// priority，**同源不发 Origin**（抓包里 auth.openai.com 的同源 POST 全都没有 Origin）。
func mfaJSONHeaders(sentinelToken string) map[string]string {
	h := map[string]string{
		"Accept":         "application/json",
		"Content-Type":   "application/json",
		"Referer":        authBase + "/mfa-challenge",
		"Sec-Fetch-Dest": "empty",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Site": "same-origin",
		"Priority":       "u=1, i",
	}
	if sentinelToken != "" {
		h["Openai-Sentinel-Token"] = sentinelToken
	}
	return h
}

// postMFAVerify 提交 TOTP。返回 (continue_url, status, rawBody)。
func (d *Driver) postMFAVerify(ctx context.Context, sess *Session, factorID, code, sentinelToken string) (string, int, string) {
	body, _ := json.Marshal(map[string]string{
		"code": code,
		"type": "totp",
		"id":   factorID,
	})
	resp, err := sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/mfa/verify", string(body), mfaJSONHeaders(sentinelToken))
	if err != nil {
		return "", 0, err.Error()
	}
	raw, status := readRawBody(resp)
	loc := ""
	if l := resp.Header.Get("Location"); l != "" {
		loc = l
	}
	if loc == "" {
		loc = parseContinueFromBytes([]byte(raw))
	}
	return loc, status, raw
}

// postMFAIssueChallenge 申请 fresh challenge（account_liveness 链路形态：不带 sentinel）。
func (d *Driver) postMFAIssueChallenge(ctx context.Context, sess *Session, factorID string) (string, int, string) {
	body, _ := json.Marshal(map[string]any{
		"id":                    factorID,
		"type":                  "totp",
		"force_fresh_challenge": false,
	})
	resp, err := sess.RequestCtx(ctx, http.MethodPost, authBase+"/api/accounts/mfa/issue_challenge", string(body), mfaJSONHeaders(""))
	if err != nil {
		return "", 0, err.Error()
	}
	raw, status := readRawBody(resp)
	loc := resp.Header.Get("Location")
	if loc == "" {
		loc = parseContinueFromBytes([]byte(raw))
	}
	return loc, status, raw
}

// probeMFAUnusable 在 403/400 后回读 MFA 文档，命中终局停用码就转成 AccountUnusableError。
func (d *Driver) probeMFAUnusable(ctx context.Context, sess *Session, factorID string) *AccountUnusableError {
	if factorID == "" {
		return nil
	}
	resp, err := sess.RequestCtx(ctx, http.MethodGet, authBase+"/mfa-challenge/"+factorID, "", map[string]string{
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Referer":        authBase + "/log-in/password",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "same-origin",
	})
	if err != nil {
		dbg("mfa 页面诊断不可用: %v", err)
		return nil
	}
	raw, _ := readRawBody(resp)
	dbg("mfa 页面诊断(len=%d) 命中停用码=%t", len(raw), containsDeadMarker(raw))
	if !containsDeadMarker(raw) {
		return nil
	}
	low := strings.ToLower(raw)
	for _, marker := range []string{"account_deactivated", "account_deleted", "account_banned", "account_suspended"} {
		if strings.Contains(low, marker) {
			return &AccountUnusableError{Code: marker, RawURL: authBase + "/mfa-challenge/" + factorID}
		}
	}
	return &AccountUnusableError{Code: "account_deactivated", RawURL: authBase + "/mfa-challenge/" + factorID}
}

func containsDeadMarker(raw string) bool {
	low := strings.ToLower(raw)
	for _, marker := range []string{
		"account_deactivated", "account_deleted", "account_banned", "account_suspended",
		"account has been deactivated", "account has been deleted", "account has been banned",
		"account was deactivated", "account was deleted", "account was banned",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// readRawBody 读完响应体并关闭，返回 (rawBody, statusCode)。限 1MiB 防炸。
func readRawBody(resp *http.Response) (string, int) {
	if resp == nil {
		return "", 0
	}
	status := resp.StatusCode
	if resp.Body == nil {
		return "", status
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	return string(b), status
}

// parseContinueFromBytes 从响应体 JSON 里抽 continue_url/external_url/url（含嵌套 page）。
func parseContinueFromBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var payload struct {
		ContinueURL string `json:"continue_url"`
		ExternalURL string `json:"external_url"`
		URL         string `json:"url"`
		Page        struct {
			ContinueURL string `json:"continue_url"`
			ExternalURL string `json:"external_url"`
			URL         string `json:"url"`
		} `json:"page"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return ""
	}
	for _, u := range []string{
		payload.ContinueURL, payload.ExternalURL, payload.URL,
		payload.Page.ContinueURL, payload.Page.ExternalURL, payload.Page.URL,
	} {
		if strings.TrimSpace(u) != "" {
			return strings.TrimSpace(u)
		}
	}
	return ""
}

// deadMarkerFromText 从响应体文本里抽终局停用码并包成 AccountUnusableError。
// 优先级：正文里明确写的 code 字段 > 文本标记兜底。
func deadMarkerFromText(raw, rawURL string) *AccountUnusableError {
	low := strings.ToLower(raw)
	if low == "" {
		return nil
	}
	for _, code := range []string{"account_deactivated", "account_deleted", "account_banned", "account_suspended"} {
		if strings.Contains(low, `"`+code+`"`) {
			return &AccountUnusableError{Code: code, RawURL: rawURL}
		}
	}
	if !containsDeadMarker(raw) {
		return nil
	}
	for _, code := range []string{"account_deactivated", "account_deleted", "account_banned", "account_suspended"} {
		if strings.Contains(low, code) {
			return &AccountUnusableError{Code: code, RawURL: rawURL}
		}
	}
	return &AccountUnusableError{Code: "account_deactivated", RawURL: rawURL}
}
