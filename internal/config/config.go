// Package config 提供类型化配置与原子热重载。
//
// 与 Python 版的关键差异：Python 用 apply_env_overrides(globals()) 在模块加载时
// 把 .env 值写进模块全局变量，改配置必须重新 import；Go 版把整份 Config 放在
// atomic.Pointer 里，Reload 时整体替换，任何持有快照的代码都不会看到半更新的状态。
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// Config 是运行时全部可调项的只读快照。
// 新增字段时请同时在 loadFromEnv 里给默认值，否则零值可能不等于预期行为。
type Config struct {
	// ---- 注册 ----
	RegistrationDriver string // protocol / oss_protocol / roxy / ant / cloak / browser_use / skyvern
	CodexOAuthDriver   string // 同上，或 same_as_registration
	CodexAuthURLSource string // cpa / sub2 / local
	EnableCodexAuto    bool
	SMSProvider        string // 5sim / grizzly / l / h
	SMSAPIKey          string
	Enable2FA          bool
	RegisterPassword   string // 留空则自动生成

	// ---- 邮箱 ----
	UseEmailService       bool
	EmailSource           string // 逗号分隔，按顺序兜底
	RegisterEmail         string
	OTPMaxWaitSec         int
	OTPPollSec            int
	MailTMPersistPath     string
	TempMailIOPersistPath string

	// ---- MailCode 域名邮箱 ----
	MailCodeAPIKey             string
	MailCodeProductID          string
	MailCodeRequestTimeout     int
	MailCodeChannelWaitSeconds int

	// ---- Plus 试用提链 ----
	ExtractLinkAPIBase        string
	ExtractLinkCDK            string
	ExtractLinkType           string
	ExtractLinkWorkers        int
	ExtractLinkQueueLimit     int
	ExtractLinkRequestTimeout int
	ExtractLinkEventTimeout   int

	// ---- CloudMail 邮箱 ----
	CloudMailAPIBase        string
	CloudMailAdminEmail     string
	CloudMailPassword       string
	CloudMailTokenPath      string
	CloudMailAuthToken      string
	CloudMailDomains        []string
	CloudMailAutoAddUser    bool
	CloudMailRandomLocalLen int

	// ---- Codex CPA 管理接口 ----
	CPAManagementURL  string
	CPAManagementKey  string
	CPARequestTimeout int

	// ---- 代理 ----
	ProxyPool        []string
	ProtocolProxy    string
	PlanCheckProxy   string
	PlanCheckWorkers int
	// CountryProxies 每行 "US=http://..."，多地区查套餐按国家走对应代理。
	CountryProxies []string
	// PlanCheckCouponAuthoritative 为 true 时，官方 check_coupon 返回非 eligible
	// 会压掉 accounts/check 里偏乐观的试用资格判定。
	PlanCheckCouponAuthoritative bool
	// NoProxy 为 true 时所有请求直连，调试用。
	NoProxy bool
	// ProtocolTLSProfile / Locale / Timezone 控制纯协议注册会话的浏览器画像。
	// 留空 locale/timezone 时按代理中的地区标识推断；TLS 默认 Chrome 152。
	ProtocolTLSProfile string
	ProtocolLocale     string
	ProtocolTimezone   string

	// ---- 浏览器 ----
	RoxyAPIBase               string
	RoxyAPIToken              string
	RoxyWorkspace             string
	RoxyProject               string
	RoxyHeadless              bool
	RoxyDeleteProfileAfterRun bool
	RoxyWorkspaceListPath     string
	RoxyWorkspaceListMethod   string

	CloakHeadless        bool
	CloakHumanize        bool
	CloakGeoIP           bool
	CloakLocale          string
	CloakTimezone        string
	CloakFingerprintSeed string

	// ---- 省流量 ----
	DataSaverMode           bool
	DataSaverBlockedTypes   []string
	DataSaverBlockedURLs    []string
	TrafficDetailLog        bool
	JSCoverageLog           bool
	TrafficDetailMaxEntries int
	JSCoverageMaxEntries    int

	// ---- Sentinel ----
	SentinelSolver     string // synthetic / sdk_js / quickjs
	NodeBin            string
	SentinelRunnerPath string

	// ---- WebUI ----
	WebUIAuthCode      string
	WebUISessionSecret string
	BindHost           string
	BindPort           int

	// ---- 能力开关（吸收自 turb-oss 快照）----
	PromoCheckDriver string // off / browser / protocol
	EnableMailTM     bool
	EnableTempMailIO bool

	// Root 是项目根目录，用于定位 .env、sqlite、日志、sentinel 脚本。
	Root string
}

var current atomic.Pointer[Config]

// Current 返回当前配置快照指针。调用方不应修改其内容。
func Current() *Config {
	if c := current.Load(); c != nil {
		return c
	}
	// 未显式 Init 时返回一套默认值，避免 nil 解引用。
	c := defaults()
	current.Store(c)
	return c
}

func defaults() *Config {
	return &Config{
		RegistrationDriver:           "protocol",
		CodexOAuthDriver:             "protocol",
		CodexAuthURLSource:           "local",
		SMSProvider:                  "grizzly",
		EnableCodexAuto:              false,
		Enable2FA:                    false,
		UseEmailService:              false,
		EmailSource:                  "outlook",
		OTPMaxWaitSec:                180,
		OTPPollSec:                   5,
		MailTMPersistPath:            "tools/mailtm_accounts.json",
		TempMailIOPersistPath:        "tools/tempmailio_accounts.json",
		MailCodeProductID:            "product_a3783a0ead074b4091631b9ad04153f9",
		MailCodeRequestTimeout:       20,
		MailCodeChannelWaitSeconds:   60,
		ExtractLinkType:              "pix",
		ExtractLinkWorkers:           3,
		ExtractLinkQueueLimit:        500,
		ExtractLinkRequestTimeout:    30,
		ExtractLinkEventTimeout:      180,
		CloudMailTokenPath:           "/api/public/genToken",
		CloudMailAutoAddUser:         true,
		CloudMailRandomLocalLen:      12,
		CPARequestTimeout:            30,
		RoxyWorkspaceListPath:        "/browser/workspace",
		RoxyWorkspaceListMethod:      "GET",
		RoxyAPIBase:                  "http://127.0.0.1:50100",
		RoxyHeadless:                 true,
		RoxyDeleteProfileAfterRun:    true,
		CloakHeadless:                true,
		CloakHumanize:                true,
		CloakGeoIP:                   true,
		DataSaverBlockedTypes:        []string{"image", "media"},
		TrafficDetailMaxEntries:      2000,
		JSCoverageMaxEntries:         1000,
		SentinelSolver:               "sdk_js",
		NodeBin:                      "node",
		SentinelRunnerPath:           "sentinel/sentinel-runner.js",
		BindHost:                     "127.0.0.1",
		BindPort:                     5000,
		PromoCheckDriver:             "off",
		PlanCheckWorkers:             2,
		PlanCheckCouponAuthoritative: true,
		ProtocolTLSProfile:           "chrome_152",
	}
}

// Init 从 root 目录的 .env 与环境变量装载配置。
// 优先级：进程环境变量 > .env 文件 > 内置默认值。
func Init(root string) error {
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	env, err := readDotEnv(filepath.Join(root, ".env"))
	if err != nil {
		return fmt.Errorf("读取 .env 失败: %w", err)
	}
	c := defaults()
	c.Root = root
	c.loadFromEnv(env)
	current.Store(c)
	return nil
}

// Reload 重新读取 .env 并整体替换快照。WebUI 保存配置后调用。
func Reload() error {
	old := Current()
	return Init(old.Root)
}

func readDotEnv(path string) (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // .env 不存在是合法状态
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		// 双引号包裹的值由 writeEnv 用 %q 写入，这里按 Go 转义规则还原，
		// 否则多行值会被读成一行字面量 \\n、Windows 路径会残留双反斜杠。
		// 单引号只去壳，保持原样（代理密码里可能含 # 等字符）。
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			if unq, uerr := strconv.Unquote(v); uerr == nil {
				v = unq
			} else {
				v = v[1 : len(v)-1]
			}
		} else if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, sc.Err()
}

// loadFromEnv 把 .env 与进程环境合并进配置。环境变量优先。
func (c *Config) loadFromEnv(env map[string]string) {
	get := func(key string) (string, bool) {
		if v, ok := os.LookupEnv(key); ok {
			return v, true
		}
		v, ok := env[key]
		return v, ok
	}
	str := func(key string, dst *string) {
		if v, ok := get(key); ok && v != "" {
			*dst = v
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := get(key); ok {
			if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				*dst = b
			}
		}
	}
	integer := func(key string, dst *int) {
		if v, ok := get(key); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				*dst = n
			}
		}
	}
	list := func(key string, dst *[]string) {
		v, ok := get(key)
		if !ok {
			return
		}
		*dst = parseList(v)
	}

	str("REGISTRATION_DRIVER", &c.RegistrationDriver)
	str("CODEX_OAUTH_DRIVER", &c.CodexOAuthDriver)
	str("CODEX_AUTH_URL_SOURCE", &c.CodexAuthURLSource)
	boolean("ENABLE_CODEX_AUTO", &c.EnableCodexAuto)
	str("SMS_PROVIDER", &c.SMSProvider)
	str("SMS_API_KEY", &c.SMSAPIKey)
	boolean("ENABLE_2FA", &c.Enable2FA)
	str("REGISTER_PASSWORD", &c.RegisterPassword)

	boolean("USE_EMAIL_SERVICE", &c.UseEmailService)
	str("EMAIL_SOURCE", &c.EmailSource)
	str("REGISTER_EMAIL", &c.RegisterEmail)
	integer("OTP_MAX_WAIT", &c.OTPMaxWaitSec)
	integer("OTP_POLL_INTERVAL", &c.OTPPollSec)
	str("MAILTM_PERSIST_PATH", &c.MailTMPersistPath)
	str("TEMPMAILIO_PERSIST_PATH", &c.TempMailIOPersistPath)

	str("MAILCODE_API_KEY", &c.MailCodeAPIKey)
	str("MAILCODE_PRODUCT_ID", &c.MailCodeProductID)
	integer("MAILCODE_REQUEST_TIMEOUT", &c.MailCodeRequestTimeout)
	integer("MAILCODE_CHANNEL_WAIT_SECONDS", &c.MailCodeChannelWaitSeconds)

	str("EXTRACT_LINK_API_BASE", &c.ExtractLinkAPIBase)
	str("EXTRACT_LINK_CDK", &c.ExtractLinkCDK)
	str("EXTRACT_LINK_TYPE", &c.ExtractLinkType)
	integer("EXTRACT_LINK_WORKERS", &c.ExtractLinkWorkers)
	integer("EXTRACT_LINK_QUEUE_LIMIT", &c.ExtractLinkQueueLimit)
	integer("EXTRACT_LINK_REQUEST_TIMEOUT", &c.ExtractLinkRequestTimeout)
	integer("EXTRACT_LINK_EVENT_TIMEOUT", &c.ExtractLinkEventTimeout)

	str("CLOUDMAIL_API_BASE", &c.CloudMailAPIBase)
	str("CLOUDMAIL_ADMIN_EMAIL", &c.CloudMailAdminEmail)
	str("CLOUDMAIL_PASSWORD", &c.CloudMailPassword)
	str("CLOUDMAIL_TOKEN_PATH", &c.CloudMailTokenPath)
	str("CLOUDMAIL_AUTH_TOKEN", &c.CloudMailAuthToken)
	boolean("CLOUDMAIL_AUTO_ADD_USER", &c.CloudMailAutoAddUser)
	integer("CLOUDMAIL_RANDOM_LOCAL_LENGTH", &c.CloudMailRandomLocalLen)
	if v, ok := get("CLOUDMAIL_DOMAINS"); ok {
		c.CloudMailDomains = parseMultilineList(v)
	}
	if c.CloudMailRandomLocalLen < 6 || c.CloudMailRandomLocalLen > 32 {
		c.CloudMailRandomLocalLen = 12
	}
	if strings.TrimSpace(c.CloudMailTokenPath) == "" {
		c.CloudMailTokenPath = "/api/public/genToken"
	}

	str("CPA_MANAGEMENT_URL", &c.CPAManagementURL)
	str("CPA_MANAGEMENT_KEY", &c.CPAManagementKey)
	integer("CPA_REQUEST_TIMEOUT", &c.CPARequestTimeout)
	if c.CPARequestTimeout <= 0 {
		c.CPARequestTimeout = 30
	}

	list("PROXY_POOL", &c.ProxyPool)
	str("PROTOCOL_PROXY", &c.ProtocolProxy)
	str("PLAN_CHECK_PROXY", &c.PlanCheckProxy)
	integer("PLAN_CHECK_WORKERS", &c.PlanCheckWorkers)
	list("COUNTRY_PROXIES", &c.CountryProxies)
	boolean("PLAN_CHECK_COUPON_AUTHORITATIVE", &c.PlanCheckCouponAuthoritative)
	boolean("NO_PROXY", &c.NoProxy)
	str("PROTOCOL_TLS_PROFILE", &c.ProtocolTLSProfile)
	str("PROTOCOL_LOCALE", &c.ProtocolLocale)
	str("PROTOCOL_TIMEZONE", &c.ProtocolTimezone)
	for i := range c.ProxyPool {
		c.ProxyPool[i] = NormalizeProxyURL(c.ProxyPool[i])
	}
	for i := range c.CountryProxies {
		if idx := strings.Index(c.CountryProxies[i], "="); idx > 0 {
			c.CountryProxies[i] = strings.ToUpper(strings.TrimSpace(c.CountryProxies[i][:idx])) + "=" + NormalizeProxyURL(c.CountryProxies[i][idx+1:])
		}
	}
	if c.ProtocolProxy != "" {
		c.ProtocolProxy = NormalizeProxyURL(c.ProtocolProxy)
	}
	if c.PlanCheckProxy != "" {
		c.PlanCheckProxy = NormalizeProxyURL(c.PlanCheckProxy)
	}
	c.PlanCheckWorkers = clampInt(c.PlanCheckWorkers, 1, 16, 2)

	str("ROXY_API_BASE", &c.RoxyAPIBase)
	str("ROXY_API_TOKEN", &c.RoxyAPIToken)
	str("ROXY_WORKSPACE_ID", &c.RoxyWorkspace)
	str("ROXY_PROJECT_ID", &c.RoxyProject)
	str("ROXY_WORKSPACE_LIST_PATH", &c.RoxyWorkspaceListPath)
	str("ROXY_WORKSPACE_LIST_METHOD", &c.RoxyWorkspaceListMethod)
	if strings.TrimSpace(c.RoxyWorkspaceListPath) == "" {
		c.RoxyWorkspaceListPath = "/browser/workspace"
	}
	if strings.TrimSpace(c.RoxyWorkspaceListMethod) == "" {
		c.RoxyWorkspaceListMethod = "GET"
	}
	c.RoxyWorkspaceListMethod = strings.ToUpper(strings.TrimSpace(c.RoxyWorkspaceListMethod))
	boolean("ROXY_OPEN_HEADLESS", &c.RoxyHeadless)
	boolean("ROXY_DELETE_PROFILE_AFTER_RUN", &c.RoxyDeleteProfileAfterRun)

	boolean("CLOAK_HEADLESS", &c.CloakHeadless)
	boolean("CLOAK_HUMANIZE", &c.CloakHumanize)
	boolean("CLOAK_GEOIP", &c.CloakGeoIP)
	str("CLOAK_LOCALE", &c.CloakLocale)
	str("CLOAK_TIMEZONE", &c.CloakTimezone)
	str("CLOAK_FINGERPRINT_SEED", &c.CloakFingerprintSeed)

	boolean("BROWSER_DATA_SAVER_MODE", &c.DataSaverMode)
	list("BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", &c.DataSaverBlockedTypes)
	list("BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", &c.DataSaverBlockedURLs)
	boolean("BROWSER_TRAFFIC_DETAIL_LOG", &c.TrafficDetailLog)
	boolean("BROWSER_JS_COVERAGE_LOG", &c.JSCoverageLog)
	integer("BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", &c.TrafficDetailMaxEntries)
	integer("BROWSER_JS_COVERAGE_MAX_ENTRIES", &c.JSCoverageMaxEntries)

	str("SENTINEL_SOLVER", &c.SentinelSolver)
	str("NODE_BIN", &c.NodeBin)
	str("SENTINEL_RUNNER_PATH", &c.SentinelRunnerPath)

	str("WEBUI_AUTH_CODE", &c.WebUIAuthCode)
	if c.WebUIAuthCode == "" {
		str("AUTH_CODE", &c.WebUIAuthCode)
	}
	str("WEBUI_SESSION_SECRET", &c.WebUISessionSecret)
	str("HOST", &c.BindHost)
	integer("PORT", &c.BindPort)

	str("PROMO_CHECK_DRIVER", &c.PromoCheckDriver)
	boolean("ENABLE_MAILTM", &c.EnableMailTM)
	boolean("ENABLE_TEMPMAILIO", &c.EnableTempMailIO)

	c.RegistrationDriver = strings.ToLower(strings.TrimSpace(c.RegistrationDriver))
	c.CodexOAuthDriver = strings.ToLower(strings.TrimSpace(c.CodexOAuthDriver))
	c.SentinelSolver = strings.ToLower(strings.TrimSpace(c.SentinelSolver))
	c.PromoCheckDriver = strings.ToLower(strings.TrimSpace(c.PromoCheckDriver))
	c.ProtocolTLSProfile = strings.ToLower(strings.TrimSpace(c.ProtocolTLSProfile))
	c.ExtractLinkAPIBase = strings.TrimRight(strings.TrimSpace(c.ExtractLinkAPIBase), "/")
	c.ExtractLinkType = strings.ToLower(strings.TrimSpace(c.ExtractLinkType))
	if c.ExtractLinkType == "" {
		c.ExtractLinkType = "pix"
	}
	c.ExtractLinkWorkers = clampInt(c.ExtractLinkWorkers, 1, 16, 3)
	c.ExtractLinkQueueLimit = clampInt(c.ExtractLinkQueueLimit, c.ExtractLinkWorkers, 5000, 500)
	c.ExtractLinkRequestTimeout = clampInt(c.ExtractLinkRequestTimeout, 5, 300, 30)
	c.ExtractLinkEventTimeout = clampInt(c.ExtractLinkEventTimeout, 30, 900, 180)
	c.MailCodeRequestTimeout = clampInt(c.MailCodeRequestTimeout, 1, 120, 20)
	c.MailCodeChannelWaitSeconds = clampInt(c.MailCodeChannelWaitSeconds, 1, 600, 60)
	c.TrafficDetailMaxEntries = clampInt(c.TrafficDetailMaxEntries, 1, 100000, 2000)
	c.JSCoverageMaxEntries = clampInt(c.JSCoverageMaxEntries, 1, 100000, 1000)
}

func clampInt(value, lower, upper, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value < lower {
		return lower
	}
	if value > upper {
		return upper
	}
	return value
}

// parseMultilineList 用于 .env 里按换行/分号/逗号分隔的多值字段（例如 CLOUDMAIL_DOMAINS）。
// 优先按 JSON 数组解析；失败后按换行、分号、逗号切分。
func parseMultilineList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, s := range arr {
			s = strings.Trim(strings.TrimSpace(s), `"\'	
 `)
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `"\'	
 []`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseList 同时接受 JSON 数组与逗号分隔两种写法，兼容 Python 版的 .env 习惯。
func parseList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		var out []string
		for _, s := range arr {
			s = strings.Trim(strings.TrimSpace(s), `\"'`+"` \t\r\n")
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if strings.HasPrefix(raw, "[") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	if !strings.Contains(raw, ",") {
		if v := strings.Trim(strings.TrimSpace(raw), `\"'`+"` \t\r\n"); v != "" {
			return []string{v}
		}
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `\"'`+"` \t\r\n")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EmailSources 把逗号分隔的来源拆成有序切片，供 Provider 注册表按序兜底。
func (c *Config) EmailSources() []string {
	if strings.TrimSpace(c.EmailSource) == "" {
		return nil
	}
	parts := strings.Split(c.EmailSource, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
