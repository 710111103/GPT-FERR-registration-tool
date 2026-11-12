package api

// 支付方式 / 账单 / 订阅只读查询。
// 逐字对齐上游 core/payment_info.py、core/payment_check_service.py、
// core/db.py 的 claim/mark/update 三件套，以及 webui/app.py:1414-1548 的五条路由。
//
// 端点均经 tools/capture_payments.py 抓包确认（2026-09-18）：
//
//	GET /backend-api/payments/payment_methods?account_id=<uuid>
//	GET /backend-api/payments/billing_info?account_id=<uuid>
//	GET /backend-api/payments/transaction-history?account_id=<uuid>&limit=20
//	GET /backend-api/invoices?account_id=<uuid>
//	GET /backend-api/subscriptions?account_id=<uuid>
//	GET /backend-api/wham/usage                                  ← 不带 account_id
//	GET /backend-api/payments/customer_portal                     ← 不带 account_id
//	GET /backend-api/accounts/check/v4-2023-04-27                 ← 不带 account_id

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
)

const (
	payPathMethods        = "/backend-api/payments/payment_methods"
	payPathBillingInfo    = "/backend-api/payments/billing_info"
	payPathTransactions   = "/backend-api/payments/transaction-history"
	payPathInvoices       = "/backend-api/invoices"
	payPathSubscriptions  = "/backend-api/subscriptions"
	payPathCodexUsage     = "/backend-api/wham/usage"
	payPathCustomerPortal = "/backend-api/payments/customer_portal"
	payPathAccountsCheck  = "/backend-api/accounts/check/v4-2023-04-27"
	payPathCheckout       = "/backend-api/payments/checkout"
	payPathCoupon         = "/backend-api/promo_campaign/check_coupon"
	stripePaymentPageInit = "https://api.stripe.com/v1/payment_pages/%s/init"
	upiTrialCampaignID    = "plus-1-month-free"
	stripePublishableKey  = "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n"
)

// payTSFormat 对齐 Python datetime.isoformat(timespec="seconds")：2026-11-10T19:20:33。
const payTSFormat = "2006-01-02T15:04:05"

func payNow() string { return time.Now().Format(payTSFormat) }

// -----------------------------------------------------------------------------
// Token 解析
// -----------------------------------------------------------------------------

// normalizeToken 对齐 core/chatgpt_plan.py:66 normalize_token：
// 去引号 → 去 authorization: 前缀 → 去 bearer 前缀。
func normalizeToken(token string) string {
	t := strings.TrimSpace(token)
	t = strings.Trim(t, "\"")
	t = strings.Trim(t, "'")
	if strings.HasPrefix(strings.ToLower(t), "authorization:") {
		if parts := strings.SplitN(t, ":", 2); len(parts) == 2 {
			t = strings.TrimSpace(parts[1])
		}
	}
	if len(t) >= 7 && strings.EqualFold(t[:7], "bearer ") {
		t = strings.TrimSpace(t[7:])
	}
	return t
}

// decodeJWTPayload 仅本地解析 JWT payload，不校验签名。
func decodeJWTPayload(token string) map[string]any {
	t := normalizeToken(token)
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return nil
	}
	seg := parts[1]
	if pad := len(seg) % 4; pad != 0 {
		seg += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// tokenClaims 对齐 core/chatgpt_plan.py:192 token_claims。
// 返回 email / user_name / user_id / account_id / claim_plan_type / exp /
// token_expires_at / token_expired。
func tokenClaims(token string) map[string]any {
	payload := decodeJWTPayload(token)
	out := map[string]any{
		"email":            nil,
		"user_name":        nil,
		"user_id":          nil,
		"account_id":       nil,
		"claim_plan_type":  nil,
		"exp":              nil,
		"token_expires_at": nil,
		"token_expired":    nil,
	}
	if payload == nil {
		return out
	}
	auth, _ := payload["https://api.openai.com/auth"].(map[string]any)
	profile, _ := payload["https://api.openai.com/profile"].(map[string]any)
	if profile != nil {
		if v, ok := profile["email"]; ok {
			out["email"] = v
		}
		if v, ok := profile["name"]; ok {
			out["user_name"] = v
		}
	}
	if auth != nil {
		for _, key := range []string{"chatgpt_user_id", "user_id"} {
			if v, ok := auth[key]; ok && v != nil {
				out["user_id"] = v
				break
			}
		}
		if v, ok := auth["chatgpt_account_id"]; ok {
			out["account_id"] = v
		}
		if v, ok := auth["chatgpt_plan_type"]; ok {
			out["claim_plan_type"] = v
		}
	}
	if exp, ok := payload["exp"]; ok {
		out["exp"] = exp
		if f, ok := toFloat(exp); ok {
			t := time.Unix(int64(f), 0).UTC()
			out["token_expires_at"] = t.Format("2006-01-02T15:04:05Z")
			out["token_expired"] = float64(time.Now().Unix()) >= f
		}
	}
	return out
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func claimsStr(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	if v, ok := claims[key]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}

func claimsMeta(claims map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range claims {
		if k == "payload" {
			continue
		}
		out[k] = v
	}
	return out
}

// -----------------------------------------------------------------------------
// 代理路由（对齐 core/chatgpt_plan.py:118 resolve_plan_check_route）
// -----------------------------------------------------------------------------

type payRoute struct {
	Proxy          string
	Mode           string
	NetworkRoute   string
	ProxyUsed      any
	FallbackReason any
}

func (r payRoute) meta() map[string]any {
	return map[string]any{
		"proxy_mode":            r.Mode,
		"network_route":         r.NetworkRoute,
		"proxy_used":            r.ProxyUsed,
		"proxy_fallback_reason": r.FallbackReason,
	}
}

// maskProxy 对齐 _mask_proxy：只露 scheme/账号占位/host/port。
func maskProxy(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	candidate := v
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Hostname() == "" {
		return "***"
	}
	scheme := ""
	if u.Scheme != "" {
		scheme = u.Scheme + "://"
	}
	auth := ""
	if u.User != nil && u.User.Username() != "" {
		auth = "***:***@"
	}
	port := ""
	if p := u.Port(); p != "" {
		port = ":" + p
	}
	out := scheme + auth + u.Hostname() + port
	if out == "" {
		return "***"
	}
	return out
}

// localProxyStatus 对齐 _local_proxy_status：只对回环地址做端口预探测。
// 返回 (isLocal, available, reason)。
func localProxyStatus(raw string) (bool, bool, string) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return false, false, ""
	}
	candidate := v
	if !strings.Contains(candidate, "://") {
		candidate = "//" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return false, false, fmt.Sprintf("代理地址解析失败（%T）", err)
	}
	host := u.Hostname()
	if host == "" {
		return false, false, "代理地址解析失败（空 host）"
	}
	isLoop := strings.EqualFold(host, "localhost")
	if !isLoop {
		if ip := net.ParseIP(host); ip != nil {
			isLoop = ip.IsLoopback()
		}
	}
	if !isLoop {
		return false, true, ""
	}
	port := u.Port()
	if port == "" {
		return true, false, "本地代理未配置端口"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return true, false, fmt.Sprintf("本地代理 %s:%s 未监听（dial 失败）", host, port)
	}
	_ = conn.Close()
	return true, true, ""
}

// pickProxyFromPool 按纳秒轮换代理池，与 getProxyForAccount 同策略。
func pickProxyFromPool(pool []string) string {
	if len(pool) == 0 {
		return ""
	}
	idx := time.Now().UnixNano() % int64(len(pool))
	if idx < 0 {
		idx = -idx
	}
	return pool[idx]
}

// resolvePaymentRoute 解析支付查询的实际网络路径。
// explicit 非 nil 表示调用方显式覆盖；空字符串代表直连。
func resolvePaymentRoute(explicit *string) (payRoute, error) {
	if explicit != nil {
		selected := strings.TrimSpace(*explicit)
		r := payRoute{
			Proxy:        selected,
			Mode:         "request",
			NetworkRoute: "proxy",
			ProxyUsed:    nil,
		}
		if selected == "" {
			r.NetworkRoute = "direct"
		} else {
			r.ProxyUsed = maskProxy(selected)
		}
		return r, nil
	}

	mode := strings.ToLower(strings.TrimSpace(os.Getenv("PLAN_CHECK_PROXY_MODE")))
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "proxy" && mode != "direct" {
		return payRoute{}, fmt.Errorf("PLAN_CHECK_PROXY_MODE=%q 无效，可选 auto / proxy / direct", mode)
	}
	if mode == "direct" {
		return payRoute{Mode: mode, NetworkRoute: "direct"}, nil
	}

	cfg := config.Current()
	selected := strings.TrimSpace(cfg.PlanCheckProxy)
	if selected == "" {
		selected = strings.TrimSpace(pickProxyFromPool(cfg.ProxyPool))
	}
	if selected == "" {
		if mode == "proxy" {
			return payRoute{}, fmt.Errorf("套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY 或 PROXY_POOL")
		}
		return payRoute{
			Mode:           mode,
			NetworkRoute:   "direct",
			FallbackReason: "未配置套餐查询代理或代理池",
		}, nil
	}

	isLocal, available, reason := localProxyStatus(selected)
	if mode == "auto" && isLocal && !available {
		return payRoute{
			Mode:           mode,
			NetworkRoute:   "direct_fallback",
			ProxyUsed:      maskProxy(selected),
			FallbackReason: reason,
		}, nil
	}
	return payRoute{
		Proxy:        selected,
		Mode:         mode,
		NetworkRoute: "proxy",
		ProxyUsed:    maskProxy(selected),
	}, nil
}

// -----------------------------------------------------------------------------
// 单端点请求与归类
// -----------------------------------------------------------------------------

// paymentGet 发一条只读 GET。返回 (status, payload, 截断正文, 传输错误文本)。
func paymentGet(ctx context.Context, sess *protocol.Session, token string, claims map[string]any,
	path string, query url.Values, extra map[string]string) (*int, any, string, string) {

	base := "https://chatgpt.com" + path
	if qs := query.Encode(); qs != "" {
		base += "?" + qs
	}
	headers := map[string]string{
		"Authorization":         "Bearer " + normalizeToken(token),
		"Accept":                "application/json",
		"Referer":               "https://chatgpt.com/",
		"Origin":                "https://chatgpt.com",
		"Sec-Fetch-Site":        "same-origin",
		"Sec-Fetch-Mode":        "cors",
		"Sec-Fetch-Dest":        "empty",
		"x-openai-target-path":  path,
		"x-openai-target-route": path,
	}
	if id := claimsStr(claims, "account_id"); id != "" {
		headers["chatgpt-account-id"] = id
	}
	for k, v := range extra {
		headers[k] = v
	}

	resp, err := sess.RequestCtx(ctx, http.MethodGet, base, "", headers)
	if err != nil {
		return nil, nil, "", truncateForLog(fmt.Sprintf("%T: %s", err, err.Error()), 160)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	text := truncateForLog(string(body), 400)
	var payload any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			payload = nil
		}
	}
	status := resp.StatusCode
	return &status, payload, text, ""
}

// classifyPayment 对齐 core/payment_info.py:88 _classify。
// 抓包确认：路由不存在返回 {"detail":"Not Found"}；业务层空数据返回
// {"detail":"No subscription found for account"} —— 两者都是 404，必须区分。
func classifyPayment(status *int, payload any, errText string) (string, string) {
	if status == nil {
		if errText == "" {
			return "error", "请求异常"
		}
		return "error", errText
	}
	detail := ""
	if m, ok := payload.(map[string]any); ok {
		if d, ok := m["detail"]; ok && d != nil {
			detail = strings.TrimSpace(fmt.Sprint(d))
		}
	}
	code := *status
	if code >= 200 && code < 300 {
		return "ok", ""
	}
	if code == 404 {
		if strings.EqualFold(detail, "not found") || detail == "" {
			if detail == "" {
				return "missing", "路由不存在"
			}
			return "missing", detail
		}
		return "empty", detail
	}
	if code == 400 && strings.Contains(detail, "must be supplied") {
		return "error", detail
	}
	if detail == "" {
		return "error", fmt.Sprintf("HTTP %d", code)
	}
	return "error", detail
}

// -----------------------------------------------------------------------------
// 试用资格与结账支付方式探测（对齐 core/chatgpt_plan.py）
// -----------------------------------------------------------------------------

var countryCurrencies = map[string]string{
	"BR": "BRL", "IN": "INR", "JP": "JPY", "KR": "KRW", "VN": "VND",
	"US": "USD", "GB": "GBP", "DE": "EUR", "FR": "EUR", "NL": "EUR",
}

var countryDefaultPaymentMethods = map[string][]string{
	"IN": {"card", "upi", "netbanking"},
	"JP": {"card", "paypal", "konbini", "payeasy"},
	"US": {"card", "paypal", "link", "apple_pay", "google_pay", "cashapp"},
	"BR": {"card", "pix", "boleto"},
	"KR": {"card", "kakao_pay", "toss_pay", "payco"},
	"NL": {"card", "ideal", "paypal", "klarna"},
	"GB": {"card", "paypal", "revolut_pay", "bacs_debit"},
	"DE": {"card", "paypal", "sofort", "giropay", "sepa_debit", "klarna"},
	"FR": {"card", "paypal", "sepa_debit"},
	"IT": {"card", "paypal", "satispay", "sepa_debit"},
	"ES": {"card", "paypal", "bizum", "sepa_debit"},
	"PL": {"card", "blik", "p24"},
	"BE": {"card", "bancontact", "paypal", "sepa_debit"},
	"AT": {"card", "eps", "paypal", "sepa_debit"},
	"CH": {"card", "twint", "paypal"},
	"AU": {"card", "paypal", "apple_pay", "google_pay"},
	"CA": {"card", "paypal", "interac"},
	"SG": {"card", "paynow", "grabpay", "paypal"},
	"MY": {"card", "grabpay", "fpx"},
	"TH": {"card", "promptpay"},
	"ID": {"card", "gopay", "ovo"},
	"PH": {"card", "gcash", "maya"},
	"VN": {"card", "momo", "zalopay"},
	"MX": {"card", "oxxo", "spei"},
	"HK": {"card", "alipay_hk", "wechat_pay", "octopus"},
	"TW": {"card", "line_pay", "jkobank"},
}

var knownPaymentMethodNames = map[string]bool{
	"card": true, "credit_card": true, "debit_card": true, "paypal": true,
	"apple_pay": true, "google_pay": true, "link": true, "pix": true, "upi": true,
	"netbanking": true, "kakao_pay": true, "toss_pay": true, "payco": true,
	"konbini": true, "payeasy": true, "ideal": true, "sofort": true, "giropay": true,
	"bancontact": true, "eps": true, "p24": true, "przelewy24": true, "blik": true,
	"grabpay": true, "paynow": true, "fpx": true, "promptpay": true, "gopay": true,
	"ovo": true, "gcash": true, "maya": true, "momo": true, "zalopay": true,
	"oxxo": true, "spei": true, "boleto": true, "alipay": true, "alipay_hk": true,
	"wechat_pay": true, "octopus": true, "line_pay": true, "jkobank": true,
	"klarna": true, "cashapp": true, "revolut_pay": true, "sepa_debit": true,
	"bacs_debit": true, "satispay": true, "bizum": true, "twint": true, "interac": true,
}

// paymentHeaders 构造套餐/支付相关只读请求的公共头。
func paymentHeaders(token string, claims map[string]any, path string) map[string]string {
	headers := map[string]string{
		"Authorization":         "Bearer " + normalizeToken(token),
		"Accept":                "application/json",
		"Referer":               "https://chatgpt.com/",
		"Origin":                "https://chatgpt.com",
		"Sec-Fetch-Site":        "same-origin",
		"Sec-Fetch-Mode":        "cors",
		"Sec-Fetch-Dest":        "empty",
		"x-openai-target-path":  path,
		"x-openai-target-route": path,
	}
	if id := claimsStr(claims, "account_id"); id != "" {
		headers["chatgpt-account-id"] = id
	}
	return headers
}

// proxyCountry 从代理 URL 里解析 -region-XX / -country-XX 提示，识别不到返回空串。
func proxyCountry(proxy string) string {
	upper := strings.ToUpper(proxy)
	if m := regexp.MustCompile(`(?:REGION|COUNTRY)[-_]([A-Z]{2})`).FindStringSubmatch(upper); len(m) == 2 {
		return m[1]
	}
	if m := regexp.MustCompile(`[-_:]([A-Z]{2})[-_:]`).FindStringSubmatch(upper); len(m) == 2 {
		return m[1]
	}
	return ""
}

// couponResult 表示官方只读 check_coupon 接口的判定结果。
type couponResult struct {
	Eligible bool
	Redeemed bool
	Days     int
	State    string
}

// checkPlusCouponDirect 官方只读试用券判定，是「是否真的能领 Plus 免费试用」的权威口径。
func checkPlusCouponDirect(ctx context.Context, sess *protocol.Session, token string, claims map[string]any) couponResult {
	out := couponResult{Days: 30}
	rawURL := "https://chatgpt.com" + payPathCoupon + "?coupon=plus-1-month-free&is_coupon_from_query_param=true"
	resp, err := sess.RequestCtx(ctx, http.MethodGet, rawURL, "", paymentHeaders(token, claims, payPathCoupon))
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return out
	}
	state := strVal(data["state"])
	if state == "" {
		state = strVal(data["status"])
	}
	out.State = strings.ToLower(strings.TrimSpace(state))
	if r := asMapAny(data["redemption"]); r != nil {
		if v, ok := r["redeemed"].(bool); ok {
			out.Redeemed = v
		}
		if d, ok := toFloat(r["promotion_length_days"]); ok && d > 0 {
			out.Days = int(d)
		}
	}
	out.Eligible = out.State == "eligible"
	return out
}

func collectPaymentMethods(payload any) []string {
	valueKeys := map[string]bool{
		"payment_method": true, "payment_methods": true, "payment_method_types": true,
		"supported_payment_methods": true, "allowed_payment_methods": true,
	}
	mappingKeys := map[string]bool{
		"payment_method_specs": true, "payment_method_options": true, "payment_method_configurations": true,
	}
	var methods []string
	seen := map[string]bool{}
	add := func(v any) {
		name := strings.ToLower(strings.TrimSpace(strVal(v)))
		if name != "" && knownPaymentMethodNames[name] && !seen[name] {
			seen[name] = true
			methods = append(methods, name)
		}
	}
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if depth > 8 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if mappingKeys[key] {
				for name := range t {
					add(name)
				}
			}
			for ck, cv := range t {
				if ck == "type" {
					if s, ok := cv.(string); ok {
						add(s)
					}
				}
				walk(cv, strings.ToLower(ck), depth+1)
			}
		case []any:
			for _, c := range t {
				if cm, ok := c.(map[string]any); ok {
					if tv, has := cm["type"]; has {
						add(tv)
						continue
					}
				} else if valueKeys[key] {
					if s, ok := c.(string); ok {
						add(s)
						continue
					}
				}
				walk(c, key, depth+1)
			}
		default:
			if valueKeys[key] {
				if s, ok := v.(string); ok {
					add(s)
				}
			}
		}
	}
	walk(payload, "", 0)
	return methods
}

func firstNumericAny(payload any, keys []string, depth int) any {
	if depth > 8 || payload == nil {
		return nil
	}
	switch v := payload.(type) {
	case map[string]any:
		for k, val := range v {
			lk := strings.ToLower(k)
			for _, key := range keys {
				if lk != key {
					continue
				}
				switch n := val.(type) {
				case float64:
					return n
				case int:
					return n
				case int64:
					return n
				case json.Number:
					if f, err := n.Float64(); err == nil {
						return f
					}
				}
			}
		}
		for _, val := range v {
			if found := firstNumericAny(val, keys, depth+1); found != nil {
				return found
			}
		}
	case []any:
		for _, val := range v {
			if found := firstNumericAny(val, keys, depth+1); found != nil {
				return found
			}
		}
	}
	return nil
}

func probeBlocked(country string, blocked bool, errMsg string) map[string]any {
	if blocked {
		errMsg = "支付检测受风控拦截"
	}
	res := map[string]any{
		"payment_probe_ok":      false,
		"payment_probe_blocked": blocked,
		"payment_probe_error":   errMsg,
	}
	if country == "IN" {
		res["upi_trial_eligible"] = false
		res["upi_method_available"] = false
		res["upi_trial_verified"] = false
		if blocked {
			res["upi_trial_status"] = "blocked"
		} else {
			res["upi_trial_status"] = "error"
		}
	}
	return res
}

// checkoutSentinelToken 生成 flow=chatgpt_checkout 的 openai-sentinel-token；失败返回空串。
func checkoutSentinelToken(ctx context.Context, sess *protocol.Session, solver sentinel.Solver) string {
	if solver == nil || sess == nil {
		return ""
	}
	req := sentinel.Request{
		UserAgent: sess.UserAgent,
		Language:  sess.Language,
		Languages: sentinel.LanguagesFor(sess.Language),
		Timezone:  sess.Timezone,
		Screen:    sess.Screen,
		DeviceID:  sess.DeviceID,
		Flow:      "chatgpt_checkout",
	}
	p, err := solver.Requirements(ctx, req)
	if err != nil || p == "" {
		return ""
	}
	body, _ := json.Marshal(map[string]string{"p": p, "flow": "chatgpt_checkout"})
	resp, err := sess.RequestCtx(ctx, http.MethodPost, "https://sentinel.openai.com/backend-api/sentinel/req", string(body), map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://sentinel.openai.com",
	})
	if err != nil {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var ch sentinel.Challenge
	if resp.StatusCode != 200 || json.Unmarshal(raw, &ch) != nil || ch.Token == "" {
		return ""
	}
	tok, err := solver.Solve(ctx, req, ch, p)
	if err != nil {
		return ""
	}
	return tok
}

// probeTrialPaymentMethods 创建结账预览并枚举该地区实际开放的支付方式。
// 金额为 0 才算真免费试用；印度 UPI 需同时满足金额 0 或官方券判定。
func probeTrialPaymentMethods(ctx context.Context, sess *protocol.Session, token string, claims map[string]any, country, campaignID, sentinelToken string, couponConfirmed bool) map[string]any {
	country = strings.ToUpper(strings.TrimSpace(country))
	currency := countryCurrencies[country]
	if currency == "" {
		currency = "USD"
	}

	headers := paymentHeaders(token, claims, payPathCheckout)
	headers["Content-Type"] = "application/json"
	if sentinelToken != "" {
		headers["openai-sentinel-token"] = sentinelToken
	}
	payload, _ := json.Marshal(map[string]any{
		"entry_point": "all_plans_pricing_modal",
		"plan_name":   "chatgptplusplan",
		"billing_details": map[string]string{
			"country":  country,
			"currency": currency,
		},
		"promo_campaign": map[string]any{
			"promo_campaign_id":          campaignID,
			"is_coupon_from_query_param": false,
		},
		"checkout_ui_mode": "custom",
		"cancel_url":       "https://chatgpt.com/#pricing",
	})

	resp, err := sess.RequestCtx(ctx, http.MethodPost, "https://chatgpt.com"+payPathCheckout, string(payload), headers)
	if err != nil {
		return probeBlocked(country, false, fmt.Sprintf("结账请求失败: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var e map[string]any
		_ = json.Unmarshal(raw, &e)
		detail := strings.TrimSpace(strVal(e["detail"]))
		if detail == "" {
			detail = strings.TrimSpace(strVal(e["message"]))
		}
		if detail == "" {
			detail = strings.TrimSpace(strVal(e["error"]))
		}
		blocked := strings.Contains(strings.ToLower(detail), "unusual activity")

		// 回退：只读地区定价配置拿真实货币代码。
		pricingCurrency := currency
		if cfgResp, cfgErr := sess.RequestCtx(ctx, http.MethodGet, "https://chatgpt.com/backend-api/checkout_pricing_config/configs/"+country, "", headers); cfgErr == nil {
			if raw2, _ := io.ReadAll(io.LimitReader(cfgResp.Body, 1<<20)); len(raw2) > 0 {
				var cfgData map[string]any
				if json.Unmarshal(raw2, &cfgData) == nil {
					if cc := asMapAny(cfgData["currency_config"]); cc != nil {
						if s := strVal(cc["symbol_code"]); s != "" {
							pricingCurrency = strings.ToUpper(s)
						}
					}
				}
			}
			cfgResp.Body.Close()
		}

		fallback := countryDefaultPaymentMethods[country]
		if len(fallback) == 0 {
			fallback = []string{"card"}
		}
		res := probeBlocked(country, blocked, fmt.Sprintf("结账接口 HTTP %d", resp.StatusCode))
		res["checkout_currency"] = pricingCurrency
		res["trial_payment_methods"] = fallback
		return res
	}

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var checkout map[string]any
	_ = json.Unmarshal(raw, &checkout)
	sessionID := strVal(checkout["checkout_session_id"])
	if sessionID == "" {
		sessionID = strVal(checkout["session_id"])
	}
	if sessionID == "" {
		sessionID = strVal(checkout["id"])
	}

	methods := collectPaymentMethods(checkout)
	initData := map[string]any{}
	if strings.HasPrefix(sessionID, "cs_") {
		form := url.Values{}
		form.Set("browser_locale", "en-US")
		form.Set("browser_timezone", "UTC")
		form.Set("elements_session_client[elements_init_source]", "custom_checkout")
		form.Set("elements_session_client[referrer_host]", "chatgpt.com")
		form.Set("elements_session_client[stripe_js_id]", fmt.Sprintf("%d", time.Now().UnixNano()))
		form.Set("elements_session_client[locale]", "en")
		form.Set("key", stripePublishableKey)
		if initResp, initErr := sess.RequestCtx(ctx, http.MethodPost, fmt.Sprintf(stripePaymentPageInit, sessionID), form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); initErr == nil {
			if initResp.StatusCode >= 200 && initResp.StatusCode < 300 {
				if raw2, _ := io.ReadAll(io.LimitReader(initResp.Body, 1<<20)); json.Unmarshal(raw2, &initData) == nil {
					if m := collectPaymentMethods(initData); len(m) > 0 {
						methods = m
					}
				}
			}
			initResp.Body.Close()
		}
	}

	amount := firstNumericAny(initData, []string{"amount_due", "amount_total", "total_amount_due"}, 0)
	if amount == nil {
		amount = firstNumericAny(checkout, []string{"amount_due", "amount_total", "total_amount_due"}, 0)
	}
	amountMinor := 0.0
	if amount != nil {
		if f, ok := toFloat(amount); ok {
			amountMinor = f
		}
	}
	detectedCurrency := strings.ToUpper(strVal(initData["currency"]))
	if detectedCurrency == "" {
		detectedCurrency = strings.ToUpper(strVal(checkout["currency"]))
	}
	if detectedCurrency == "" {
		detectedCurrency = currency
	}

	upiAvailable := false
	for _, m := range methods {
		if m == "upi" {
			upiAvailable = true
		}
	}
	isZero := amountMinor == 0
	upiTrial := country == "IN" && campaignID != "" && upiAvailable && (isZero || couponConfirmed)

	res := map[string]any{
		"payment_probe_ok":      true,
		"trial_payment_methods": methods,
		"checkout_session_kind": "openai",
		"checkout_currency":     detectedCurrency,
		"checkout_amount_minor": amountMinor,
	}
	if strings.HasPrefix(sessionID, "cs_") {
		res["checkout_session_kind"] = "stripe"
	}
	if country == "IN" {
		res["upi_trial_eligible"] = upiTrial
		res["upi_method_available"] = upiAvailable
		res["upi_trial_verified"] = upiTrial
		if upiTrial {
			res["upi_trial_status"] = "verified"
		} else {
			res["upi_trial_status"] = "paid_only"
		}
	}
	return res
}
