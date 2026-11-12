package protocol

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/sentinel"
)

// BrowserProfile 描述一次协议会话最终使用的浏览器身份。
// TLS、UA、Client Hints、语言和时区必须从同一份画像派生，避免各层各自默认。
type BrowserProfile struct {
	TLSProfile  string
	ChromeMajor string
	UserAgent   string
	Language    string
	Timezone    string
	Screen      string
}

var chromeMajorFromUA = regexp.MustCompile(`(?i)\bChrome/(\d+)`)

// BrowserProfileFromPayload 读取账号注册时固化的浏览器画像。
// API、套餐探测、2FA、换绑和 Codex 授权都通过这里恢复身份，禁止各自生成默认值。
func BrowserProfileFromPayload(payload map[string]any) BrowserProfile {
	if payload == nil {
		return BrowserProfile{}
	}
	payloadString := func(key string) string {
		value, _ := payload[key].(string)
		return strings.TrimSpace(value)
	}
	return BrowserProfile{
		TLSProfile:  payloadString("browser_tls_profile"),
		ChromeMajor: payloadString("browser_chrome_major"),
		UserAgent:   payloadString("browser_user_agent"),
		Language:    payloadString("browser_language"),
		Timezone:    payloadString("browser_timezone"),
		Screen:      payloadString("browser_screen"),
	}
}

// StoreTo 把最终画像写回账号 payload，供后续刷新、探活和换绑继续复用。
func (p BrowserProfile) StoreTo(payload map[string]any) {
	if payload == nil {
		return
	}
	payload["browser_tls_profile"] = p.TLSProfile
	payload["browser_chrome_major"] = p.ChromeMajor
	payload["browser_user_agent"] = p.UserAgent
	payload["browser_language"] = p.Language
	payload["browser_timezone"] = p.Timezone
	payload["browser_screen"] = p.Screen
}

// ResolveBrowserProfile 将显式配置与代理地区兜底合并为一个完整画像。
func ResolveBrowserProfile(proxy, tlsProfile, locale, timezone string) BrowserProfile {
	canonical, major := canonicalTLSProfile(tlsProfile)
	locale = strings.TrimSpace(locale)
	timezone = strings.TrimSpace(timezone)
	// 旧账号可能只保存了语言或时区。优先从已有的那一项补出地区组合，
	// 避免日语语言被当前美国代理补成纽约时区这类明显漂移。
	if timezone == "" && locale != "" {
		timezone = timezoneForLanguage(locale)
	}
	if locale == "" && timezone != "" {
		locale = languageForTimezone(timezone)
	}
	if locale == "" || timezone == "" {
		regionLocale, regionTimezone := RegionFromProxy(proxy)
		if locale == "" {
			locale = regionLocale
		}
		if timezone == "" {
			timezone = regionTimezone
		}
	}
	return BrowserProfile{
		TLSProfile:  canonical,
		ChromeMajor: major,
		UserAgent:   userAgentForChromeMajor(major),
		Language:    locale,
		Timezone:    timezone,
		Screen:      "1920x1080",
	}
}

// Complete 用代理地区补全缺失字段，但保留调用方已经确认的画像。
// 续跑旧账号时必须走这里：即使当前配置已换成别的 Chrome 版本或地区，
// 账号也应继续使用注册时那套身份。
func (p BrowserProfile) Complete(proxy string) BrowserProfile {
	cfg := config.Current()
	tlsProfile := firstNonEmpty(p.TLSProfile, cfg.ProtocolTLSProfile)
	chromeMajor := strings.TrimSpace(p.ChromeMajor)
	// UA 是线上请求实际暴露的版本，发生旧字段冲突时以 UA 为准，
	// 再反推同一主版本的 TLS profile，避免出现 Chrome/131 + chrome_152。
	if strings.TrimSpace(p.UserAgent) != "" {
		if match := chromeMajorFromUA.FindStringSubmatch(p.UserAgent); len(match) == 2 {
			chromeMajor = match[1]
		}
	}
	if chromeMajor != "" && supportedChromeMajor(chromeMajor) {
		tlsProfile = "chrome_" + chromeMajor
	}
	base := ResolveBrowserProfile(
		proxy,
		tlsProfile,
		firstNonEmpty(p.Language, cfg.ProtocolLocale),
		firstNonEmpty(p.Timezone, cfg.ProtocolTimezone),
	)
	if strings.TrimSpace(p.UserAgent) != "" {
		base.UserAgent = p.UserAgent
	}
	if chromeMajor != "" {
		base.ChromeMajor = chromeMajor
	}
	if strings.TrimSpace(p.Screen) != "" {
		base.Screen = p.Screen
	}
	return base
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func supportedChromeMajor(major string) bool {
	switch strings.TrimSpace(major) {
	case "124", "131", "144", "146", "150", "152":
		return true
	default:
		return false
	}
}

var localeTimezonePairs = []struct {
	language string
	timezone string
}{
	{"en-US", "America/New_York"},
	{"en-GB", "Europe/London"},
	{"de-DE", "Europe/Berlin"},
	{"fr-FR", "Europe/Paris"},
	{"nl-NL", "Europe/Amsterdam"},
	{"ja-JP", "Asia/Tokyo"},
	{"en-SG", "Asia/Singapore"},
	{"vi-VN", "Asia/Ho_Chi_Minh"},
	{"en-IN", "Asia/Kolkata"},
	{"pt-BR", "America/Sao_Paulo"},
	{"en-CA", "America/Toronto"},
	{"en-AU", "Australia/Sydney"},
	{"es-ES", "Europe/Madrid"},
	{"es-MX", "America/Mexico_City"},
	{"it-IT", "Europe/Rome"},
	{"pt-PT", "Europe/Lisbon"},
	{"zh-CN", "Asia/Shanghai"},
	{"zh-TW", "Asia/Taipei"},
	{"ko-KR", "Asia/Seoul"},
	{"ru-RU", "Europe/Moscow"},
	{"tr-TR", "Europe/Istanbul"},
	{"id-ID", "Asia/Jakarta"},
	{"th-TH", "Asia/Bangkok"},
	{"pl-PL", "Europe/Warsaw"},
	{"sv-SE", "Europe/Stockholm"},
	{"da-DK", "Europe/Copenhagen"},
	{"fi-FI", "Europe/Helsinki"},
	{"nb-NO", "Europe/Oslo"},
	{"cs-CZ", "Europe/Prague"},
	{"hu-HU", "Europe/Budapest"},
	{"ar-SA", "Asia/Riyadh"},
}

func timezoneForLanguage(language string) string {
	key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(language), "_", "-"))
	if i := strings.IndexByte(key, '-'); i < 0 {
		key += map[string]string{
			"en": "-us", "de": "-de", "fr": "-fr", "nl": "-nl", "ja": "-jp",
			"vi": "-vn", "pt": "-br", "es": "-es", "it": "-it", "zh": "-cn",
			"ko": "-kr", "ru": "-ru", "tr": "-tr", "id": "-id", "th": "-th",
			"pl": "-pl", "sv": "-se", "da": "-dk", "fi": "-fi", "nb": "-no",
			"cs": "-cz", "hu": "-hu", "ar": "-sa",
		}[key]
	}
	for _, pair := range localeTimezonePairs {
		if strings.EqualFold(key, pair.language) {
			return pair.timezone
		}
	}
	return ""
}

func languageForTimezone(timezone string) string {
	timezone = strings.TrimSpace(timezone)
	for _, pair := range localeTimezonePairs {
		if strings.EqualFold(timezone, pair.timezone) {
			return pair.language
		}
	}
	return ""
}

// ClientHints 返回与 ChromeMajor 一致的低熵 Client Hints。
func (p BrowserProfile) ClientHints() string {
	return fmt.Sprintf(`"Chromium";v="%s", "Not(A:Brand";v="24", "Google Chrome";v="%s"`, p.ChromeMajor, p.ChromeMajor)
}

// AcceptLanguage 返回与 navigator.languages 同源的请求头值。
// 两层共用 sentinel.LanguagesFor，避免请求头、Client Hints 和 Sentinel
// 对同一条会话给出不同的语言集合。
func (p BrowserProfile) AcceptLanguage() string {
	languages := sentinel.LanguagesFor(p.Language)
	weights := []string{"", "0.9", "0.8", "0.7"}
	parts := make([]string, 0, len(languages))
	for i, language := range languages {
		q := ""
		if i < len(weights) {
			q = weights[i]
		}
		if q == "" {
			parts = append(parts, language)
			continue
		}
		parts = append(parts, language+";q="+q)
	}
	return strings.Join(parts, ",")
}

// ScreenSize 返回画像中的屏幕尺寸；非法值回退到 1920x1080。
func (p BrowserProfile) ScreenSize() (int64, int64) {
	width, height := int64(1920), int64(1080)
	var parsedWidth, parsedHeight int64
	if _, err := fmt.Sscanf(strings.ToLower(strings.TrimSpace(p.Screen)), "%dx%d", &parsedWidth, &parsedHeight); err == nil &&
		parsedWidth >= 800 && parsedHeight >= 600 {
		return parsedWidth, parsedHeight
	}
	return width, height
}

// BrowserProfile 返回驱动在指定代理下将使用的最终画像。
func (d *Driver) BrowserProfile(proxy string) BrowserProfile {
	cfg := config.Current()
	profileName := strings.TrimSpace(d.ProfileName)
	if profileName == "" {
		profileName = cfg.ProtocolTLSProfile
	}
	return ResolveBrowserProfile(proxy, profileName, cfg.ProtocolLocale, cfg.ProtocolTimezone)
}

func userAgentForChromeMajor(major string) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + major + ".0.0.0 Safari/537.36"
}

func canonicalTLSProfile(name string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome_124", "124":
		return "chrome_124", "124"
	case "chrome_131", "131":
		return "chrome_131", "131"
	case "chrome_144", "144":
		return "chrome_144", "144"
	case "chrome_146", "146":
		return "chrome_146", "146"
	case "chrome_150", "150":
		return "chrome_150", "150"
	default:
		return "chrome_152", "152"
	}
}
