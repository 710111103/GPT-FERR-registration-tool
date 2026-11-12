package genericapi

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"
)

var (
	codeRegex    = regexp.MustCompile(`\b(\d{6})\b`)
	tagRegex     = regexp.MustCompile(`<[^>]+>`)
	styleRegex   = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	scriptRegex  = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	jsonCodeReg  = regexp.MustCompile(`(?i)["']code["']\s*:\s*["'](\d{6})["']`)
	datedCodeReg = regexp.MustCompile(`(?is)["'](?:date|receivedAt|received_at)["']\s*:\s*["']([^"']+)["'][\s\S]*?["']code["']\s*:\s*["'](\d{6})["']`)

	contextWords = []string{
		"code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード", "otp", "openai", "chatgpt",
	}

	// 常见的非验证码 6 位数字干扰（CSS、通用模板占位符）
	noiseCodes = map[string]bool{
		"000000": true, "123456": true, "202123": true, "353740": true,
		"100000": true, "999999": true,
	}
)

type candidate struct {
	code       string
	receivedAt time.Time
	source     string
}

// ExtractOTPFromText 从各类通用取件 API 的响应体中智能提取 6 位验证码。
// 兼容各类供应商的格式：纯文本、纯数字、JSON、包含 JSON 的 HTML、
// 以及专用于 iCloud 取件页面的 <div class="card"> 模板。
func ExtractOTPFromText(raw string, after time.Time) (string, string) {
	text := decodeDataURI(raw)
	if text == "" {
		return "", ""
	}

	// 1. 优先尝试解析 iCloud 取信 HTML 网页卡片布局 (<div class="card">)
	if strings.Contains(text, "card") && strings.Contains(text, "dt") {
		if code, src := extractFromHTMLCards(text, after); code != "" {
			return code, src
		}
	}

	// 2. 尝试解析嵌入在 HTML 或 JSON 中的结构化 messages 字段 (mailalias/dr 常见)
	if code, src := extractEmbeddedMessagesJSON(text, after); code != "" {
		return code, src
	}

	// 3. 尝试去除 script/style 后用带上下文权重的正则提取
	// 无时间戳的正文无法证明是本次请求之后收到的邮件。注册时传入了 after
	// 就绝不能回退到这类候选，否则会把收件箱里的旧验证码当成新验证码提交。
	if after.IsZero() {
		clean := stripStylesAndScripts(text)
		if code := extractWeightedCode(clean); code != "" {
			return code, "weighted_body"
		}

		// 4. 通用兜底：提取拉平后的 JSON 或纯文本
		if code := extractFallback(text); code != "" {
			return code, "fallback_regex"
		}
	}

	return "", ""
}

func extractFromHTMLCards(text string, after time.Time) (string, string) {
	doc, err := xhtml.Parse(strings.NewReader(text))
	if err != nil {
		return "", ""
	}
	var candidates []candidate
	var walkCards func(*xhtml.Node)
	walkCards = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "div" && elementHasClass(node, "card") {
			var dtNode, bdNode *xhtml.Node
			var findParts func(*xhtml.Node)
			findParts = func(cur *xhtml.Node) {
				if cur.Type == xhtml.ElementNode && cur.Data == "div" {
					if dtNode == nil && elementHasClass(cur, "dt") {
						dtNode = cur
					}
					if bdNode == nil && elementHasClass(cur, "bd") {
						bdNode = cur
					}
				}
				for child := cur.FirstChild; child != nil; child = child.NextSibling {
					findParts(child)
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				findParts(child)
			}

			var msgTime time.Time
			if dtNode != nil {
				msgTime = parseTimeFlex(strings.TrimSpace(nodeText(dtNode)))
			}
			bdText := ""
			if bdNode != nil {
				bdText = nodeText(bdNode)
			}
			if code := extractWeightedCode(bdText); code != "" {
				candidates = append(candidates, candidate{
					code:       code,
					receivedAt: msgTime,
					source:     "html_card",
				})
			}
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walkCards(child)
		}
	}
	walkCards(doc)

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].receivedAt.After(candidates[j].receivedAt)
	})

	for _, c := range candidates {
		if !after.IsZero() && (c.receivedAt.IsZero() || c.receivedAt.Add(2*time.Second).Before(after)) {
			continue
		}
		return c.code, c.source
	}
	return "", ""
}

func elementHasClass(node *xhtml.Node, want string) bool {
	for _, attr := range node.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, class := range strings.Fields(attr.Val) {
			if class == want {
				return true
			}
		}
	}
	return false
}

func nodeText(node *xhtml.Node) string {
	var sb strings.Builder
	var walk func(*xhtml.Node)
	walk = func(cur *xhtml.Node) {
		if cur.Type == xhtml.TextNode {
			sb.WriteString(cur.Data)
			sb.WriteByte(' ')
		}
		for child := cur.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(sb.String()), " ")
}

func extractEmbeddedMessagesJSON(text string, after time.Time) (string, string) {
	decoded := html.UnescapeString(text)
	matches := datedCodeReg.FindAllStringSubmatch(decoded, -1)
	var candidates []candidate
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		dateStr := m[1]
		code := m[2]
		if noiseCodes[code] {
			continue
		}
		t := parseTimeFlex(dateStr)
		candidates = append(candidates, candidate{code: code, receivedAt: t, source: "embedded_json"})
	}
	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].receivedAt.After(candidates[j].receivedAt)
		})
		for _, c := range candidates {
			if !after.IsZero() && (c.receivedAt.IsZero() || c.receivedAt.Add(2*time.Second).Before(after)) {
				continue
			}
			return c.code, c.source
		}
	}

	// 没有日期字段时无法确认邮件是在本次验证码发送之后到达的。
	// 这类 json_key_code 回退曾把收件箱里的旧验证码返回给 OpenAI，必须仅在
	// 调用方没有时间约束（after 为零值）时使用。
	if !after.IsZero() {
		return "", ""
	}
	if codeMatch := jsonCodeReg.FindStringSubmatch(decoded); len(codeMatch) >= 2 {
		if !noiseCodes[codeMatch[1]] {
			return codeMatch[1], "json_key_code"
		}
	}
	return "", ""
}

func extractWeightedCode(text string) string {
	codes := codeRegex.FindAllString(text, -1)
	if len(codes) == 0 {
		return ""
	}
	lower := strings.ToLower(text)
	var valid []string
	for _, c := range codes {
		if noiseCodes[c] {
			continue
		}
		// 优先匹配前后 80 字符包含验证码关键词的候选
		idx := strings.Index(lower, c)
		if idx >= 0 {
			start := idx - 80
			if start < 0 {
				start = 0
			}
			end := idx + 86
			if end > len(lower) {
				end = len(lower)
			}
			window := lower[start:end]
			for _, kw := range contextWords {
				if strings.Contains(window, kw) {
					return c
				}
			}
		}
		valid = append(valid, c)
	}
	if len(valid) > 0 {
		// 没有上下文时，邮件正文中最后一个出现的通常是验证码
		return valid[len(valid)-1]
	}
	return ""
}

func extractFallback(text string) string {
	var m any
	if err := json.Unmarshal([]byte(text), &m); err == nil {
		flat := flattenAny(m)
		if code := extractWeightedCode(flat); code != "" {
			return code
		}
	}
	codes := codeRegex.FindAllString(text, -1)
	for i := len(codes) - 1; i >= 0; i-- {
		if !noiseCodes[codes[i]] {
			return codes[i]
		}
	}
	return ""
}

func stripStylesAndScripts(s string) string {
	s = styleRegex.ReplaceAllString(s, " ")
	s = scriptRegex.ReplaceAllString(s, " ")
	return s
}

func cleanHTML(s string) string {
	s = tagRegex.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func decodeDataURI(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") {
		idx := strings.Index(s, ",")
		if idx > 0 {
			meta := s[:idx]
			payload := s[idx+1:]
			if strings.Contains(meta, ";base64") {
				if dec, err := base64.StdEncoding.DecodeString(payload); err == nil {
					return string(dec)
				}
			}
			if unq, err := url.QueryUnescape(payload); err == nil {
				return unq
			}
		}
	}
	return s
}

func parseTimeFlex(s string) time.Time {
	s = strings.TrimSpace(s)
	zonedFormats := []string{
		time.RFC1123Z, time.RFC1123, time.RFC3339Nano,
	}
	for _, f := range zonedFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	// 供应商常返回不带时区的本地时间。若这里按 UTC 解析，在 Asia/Shanghai
	// 会凭空多出 8 小时，导致旧邮件也被误判为“未来/新鲜”的邮件。
	localFormats := []string{
		"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006/01/02 15:04:05",
		"2006-01-02 15:04", "2006-01-02T15:04",
	}
	for _, f := range localFormats {
		if t, err := time.ParseInLocation(f, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func flattenAny(v any) string {
	var sb strings.Builder
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			sb.WriteString(t)
			sb.WriteString(" ")
		case []any:
			for _, item := range t {
				walk(item)
			}
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	return sb.String()
}
