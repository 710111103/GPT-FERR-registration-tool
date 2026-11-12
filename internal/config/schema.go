package config

import (
	"encoding/json"
	"strings"
)

// FieldDef 对应 Python 版 EDITABLE_FIELDS 中的每一个字段元数据。
// 前端 index.html 的 renderConfigLayoutV2 严格依赖这个结构来生成卡片、分组与控件。
type FieldDef struct {
	Key           string   `json:"key"`
	File          string   `json:"file"`
	Type          string   `json:"type"` // bool / int / float / str / list_str_multiline
	Group         string   `json:"group"`
	Label         string   `json:"label"`
	Help          string   `json:"help"`
	Storage       string   `json:"storage,omitempty"` // env
	Secret        bool     `json:"secret,omitempty"`
	Value         any      `json:"value"`
	ExternalURL   string   `json:"external_url,omitempty"`
	ExternalLabel string   `json:"external_label,omitempty"`
	Options       []string `json:"options,omitempty"`
}

// EditableFieldDefs 是完整的配置项字典，与 Python 版 webui/config_editor.py 保持 100% 一致。
var EditableFieldDefs = []FieldDef{
	// ---- WebUI 授权 ----
	{Key: "WEBUI_AUTH_CODE", File: "codex.py", Type: "str", Group: "WebUI 授权", Label: "WebUI 授权码", Help: "保存在 .env（WEBUI_AUTH_CODE），避免出现在命令行中", Storage: "env", Secret: true},
	{Key: "WEBUI_SESSION_SECRET", File: "codex.py", Type: "str", Group: "WebUI 授权", Label: "Session 签名密钥", Help: "可选，保存在 .env；不填则从授权码派生", Storage: "env", Secret: true},

	// ---- 功能开关 ----
	{Key: "ENABLE_CODEX_AUTO", File: "codex.py", Type: "bool", Group: "功能开关", Label: "启用 Codex OAuth", Help: "注册成功后自动跑 Codex 授权"},
	{Key: "REGISTRATION_DRIVER", File: "roxybrowser.py", Type: "str", Group: "注册方式", Label: "默认注册驱动", Help: "protocol=纯协议极速，ant=Ant指纹浏览器，roxy=RoxyBrowser，cloak=CloakBrowser"},
	{Key: "AUTO_PLAN_CHECK_AFTER_REGISTER", File: "register.py", Type: "bool", Group: "注册方式", Label: "注册后自动查套餐", Help: "注册成功后自动入队查询套餐/Plus 资格"},
	{Key: "ENABLE_2FA", File: "twofa.py", Type: "bool", Group: "功能开关", Label: "启用 2FA(TOTP)", Help: "注册完成后自动设置动态口令"},
	{Key: "TWOFA_INLINE_WITH_REGISTRATION", File: "twofa.py", Type: "bool", Group: "功能开关", Label: "注册原地绑定 2FA", Help: "注册成功后在当前会话直接绑定 2FA"},
	{Key: "TWOFA_WORKERS", File: "twofa.py", Type: "int", Group: "功能开关", Label: "2FA并发数", Help: "同时执行的2FA设置任务数，默认4"},
	{Key: "TWOFA_QUEUE_LIMIT", File: "twofa.py", Type: "int", Group: "功能开关", Label: "2FA队列容量", Help: "允许排队等待的2FA任务总数，默认200"},
	{Key: "ENABLE_FLOW_TRIGGER", File: "flow_trigger.py", Type: "bool", Group: "功能开关", Label: "启用 Flow 触发", Help: "注册成功后自动调用内部 Flow 接口"},

	// ---- Ant Browser ----
	{Key: "ANT_API_BASE", File: "antbrowser.py", Type: "str", Group: "Ant Browser", Label: "Ant API 地址", Help: "Ant Browser 本地自动化 API，例如 http://127.0.0.1:19876"},
	{Key: "ANT_PROFILE_ID", File: "antbrowser.py", Type: "str", Group: "Ant Browser", Label: "Ant 实例 ID", Help: "填写 Ant Browser 的 profileId；留空使用默认"},
	{Key: "ANT_LAUNCH_CODE", File: "antbrowser.py", Type: "str", Group: "Ant Browser", Label: "Ant 启动码", Help: "可选，填写实例列表中的 launchCode"},
	{Key: "ANT_HEADLESS", File: "antbrowser.py", Type: "bool", Group: "Ant Browser", Label: "Ant 无头模式", Help: "True=后台运行；False=显示 Ant 浏览器窗口"},
	{Key: "ANT_AUTO_CREATE", File: "antbrowser.py", Type: "bool", Group: "Ant Browser", Label: "自动创建实例", Help: "注册时自动创建临时实例"},
	{Key: "ANT_DELETE_AFTER_RUN", File: "antbrowser.py", Type: "bool", Group: "Ant Browser", Label: "完成后删除实例", Help: "注册结束后停止并删除自动创建的实例"},
	{Key: "ANT_KEEP_BROWSER_OPEN", File: "antbrowser.py", Type: "bool", Group: "Ant Browser", Label: "保持浏览器打开", Help: "调试时保持浏览器窗口打开"},

	// ---- CloakBrowser ----
	{Key: "CLOAK_HEADLESS", File: "cloakbrowser.py", Type: "bool", Group: "CloakBrowser", Label: "无头改用Ant（Cloak任务）", Help: "True=注册和Codex OAuth任务使用隔离Ant无头实例"},
	{Key: "CLOAK_HUMANIZE", File: "cloakbrowser.py", Type: "bool", Group: "CloakBrowser", Label: "Cloak人工行为", Help: "启用 CloakBrowser humanize 鼠标/键盘/滚动行为"},
	{Key: "CLOAK_GEOIP", File: "cloakbrowser.py", Type: "bool", Group: "CloakBrowser", Label: "Cloak按出口定位", Help: "按当前出口 IP 自动匹配时区/语言/WebRTC IP"},
	{Key: "CLOAK_LOCALE", File: "cloakbrowser.py", Type: "str", Group: "CloakBrowser", Label: "Cloak语言", Help: "留空自动；日本可填 ja-JP，美国 en-US"},
	{Key: "CLOAK_TIMEZONE", File: "cloakbrowser.py", Type: "str", Group: "CloakBrowser", Label: "Cloak时区", Help: "留空自动；例如 Asia/Tokyo"},
	{Key: "CLOAK_USE_PROXY", File: "cloakbrowser.py", Type: "bool", Group: "CloakBrowser", Label: "Cloak使用代理池", Help: "把代理传递给 CloakBrowser"},
	{Key: "CLOAK_LICENSE_KEY", File: "cloakbrowser.py", Type: "str", Group: "CloakBrowser", Label: "Cloak License Key", Help: "留空使用免费 binary；填 Pro key 使用最新版"},
	{Key: "CLOAK_FINGERPRINT_SEED", File: "cloakbrowser.py", Type: "str", Group: "CloakBrowser", Label: "Cloak指纹种子", Help: "留空每次随机；固定值=固定指纹"},
	{Key: "CLOAK_USER_DATA_DIR", File: "cloakbrowser.py", Type: "str", Group: "CloakBrowser", Label: "Cloak用户目录", Help: "留空临时环境；填路径可持久化 profile"},
	{Key: "CLOAK_SELENIUM_TIMEOUT", File: "cloakbrowser.py", Type: "int", Group: "CloakBrowser", Label: "Cloak超时(秒)", Help: "默认 90 秒"},
	{Key: "CLOAK_KEEP_BROWSER_OPEN", File: "cloakbrowser.py", Type: "bool", Group: "CloakBrowser", Label: "保留Cloak浏览器", Help: "调试时保持浏览器打开"},

	// ---- RoxyBrowser ----
	{Key: "ROXY_API_BASE", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "Roxy API 地址", Help: "默认 http://127.0.0.1:50100"},
	{Key: "ROXY_API_TOKEN", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "Roxy API Key", Help: "保存在 .env（ROXY_API_TOKEN）", Storage: "env", Secret: true},
	{Key: "ROXY_PROFILE_ID", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "Roxy 环境ID", Help: "指定打开的 Roxy 环境ID；留空则创建临时环境"},
	{Key: "ROXY_WORKSPACE_ID", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "Roxy 工作区ID", Help: "创建一号一环境时必填"},
	{Key: "ROXY_PROJECT_ID", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "Roxy 项目ID", Help: "创建 Profile 时的 projectId"},
	{Key: "ROXY_WORKSPACE_LIST_PATH", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "获取团队接口", Help: "默认 /browser/workspace"},
	{Key: "ROXY_OPEN_PATH", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "打开接口路径", Help: "默认 /browser/open"},
	{Key: "ROXY_OPEN_HEADLESS", File: "roxybrowser.py", Type: "bool", Group: "RoxyBrowser", Label: "无头改用Ant（Roxy任务）", Help: "True=后台运行"},
	{Key: "ROXY_CLOSE_PATH", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "关闭接口路径", Help: "默认 /browser/close"},
	{Key: "ROXY_KEEP_BROWSER_OPEN", File: "roxybrowser.py", Type: "bool", Group: "RoxyBrowser", Label: "保留浏览器", Help: "任务结束后不自动关闭 Roxy 环境"},
	{Key: "ROXY_ONE_PROFILE_PER_ACCOUNT", File: "roxybrowser.py", Type: "bool", Group: "RoxyBrowser", Label: "一号一环境", Help: "每个账号强制创建新 Profile，用完即删"},
	{Key: "ROXY_DELETE_PROFILE_AFTER_RUN", File: "roxybrowser.py", Type: "bool", Group: "RoxyBrowser", Label: "结束后删除环境", Help: "任务结束后删除该环境"},
	{Key: "ROXY_CREATE_USE_PROXY_POOL", File: "roxybrowser.py", Type: "bool", Group: "RoxyBrowser", Label: "创建环境使用代理池", Help: "从代理池随机取一个写入环境"},

	{Key: "ROXY_WORKSPACE_LIST_PATH", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "工作区列表接口路径", Help: "默认 /browser/workspace；留空自动探测多个候选路径"},
	{Key: "ROXY_WORKSPACE_LIST_METHOD", File: "roxybrowser.py", Type: "str", Group: "RoxyBrowser", Label: "工作区列表请求方法", Help: "GET 或 POST；留空默认 GET"},

	// ---- Browser Use ----
	{Key: "BROWSER_USE_API_KEY", File: "browser_use.py", Type: "str", Group: "Browser Use", Label: "Browser Use API Key", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "BROWSER_USE_PROXY_COUNTRY_CODE", File: "browser_use.py", Type: "str", Group: "Browser Use", Label: "代理国家代码", Help: "可选 jp / us / sg / de 等"},
	{Key: "BROWSER_USE_USE_PROXY", File: "browser_use.py", Type: "bool", Group: "Browser Use", Label: "启用云端代理", Help: "是否使用 Browser Use 官方住宅代理"},
	{Key: "BROWSER_USE_FAST_MODE", File: "browser_use.py", Type: "bool", Group: "Browser Use", Label: "极速模式", Help: "减少额外的人工节奏等待，加快注册速度"},
	{Key: "BROWSER_USE_LOG_TIMING", File: "browser_use.py", Type: "bool", Group: "Browser Use", Label: "打印阶段耗时", Help: "在日志中输出每一步的耗时统计"},
	{Key: "BROWSER_USE_SESSION_TIMEOUT", File: "browser_use.py", Type: "int", Group: "Browser Use", Label: "云端会话保活(分)", Help: "默认 240 分钟"},

	// ---- Skyvern ----
	{Key: "SKYVERN_API_KEY", File: "skyvern.py", Type: "str", Group: "Skyvern", Label: "Skyvern API Key", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "SKYVERN_API_BASE", File: "skyvern.py", Type: "str", Group: "Skyvern", Label: "Skyvern API 地址", Help: "默认 https://api.skyvern.com"},

	// ---- 邮箱 / OTP ----
	{Key: "USE_EMAIL_SERVICE", File: "email.py", Type: "bool", Group: "邮箱 / OTP", Label: "自动取邮箱+收码", Help: "True=从邮箱池自动领邮箱并自动收 OTP；False=手动模式"},
	{Key: "REGISTER_EMAIL", File: "register.py", Type: "str", Group: "邮箱 / OTP", Label: "手动注册邮箱", Help: "手动模式时必填"},
	{Key: "REGISTER_NAME", File: "register.py", Type: "str", Group: "邮箱 / OTP", Label: "显示名称", Help: "留空则自动生成英文名"},
	{Key: "REGISTER_PASSWORD", File: "register.py", Type: "str", Group: "邮箱 / OTP", Label: "固定注册密码", Help: "遇到设置密码页时使用；留空则自动随机生成 14 位强密码"},
	{Key: "OTP_MAX_WAIT", File: "email.py", Type: "int", Group: "邮箱 / OTP", Label: "OTP 最长等待(秒)", Help: "等待验证码邮件的最长秒数，默认 180"},
	{Key: "OTP_POLL_INTERVAL", File: "email.py", Type: "int", Group: "邮箱 / OTP", Label: "OTP 轮询间隔(秒)", Help: "每隔多少秒查一次新邮件，默认 5"},
	{Key: "EMAIL_SOURCE", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "邮箱来源", Help: "逗号分隔按序兜底：outlook,generic_api,imap,cloudflare,gptmail,mailnest,remail,mailcode,mailtm,tempmailio"},
	{Key: "IMAP_MAILBOX", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "通用 IMAP 收件箱", Help: "默认 INBOX"},
	{Key: "GPTMAIL_API_KEY", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "GPTMail API Key", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "CLOUDFLARE_API_BASE", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Cloudflare API 地址", Help: "Worker 临时邮箱 API 地址，如 https://mail.example.com"},
	{Key: "CLOUDFLARE_API_KEY", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Cloudflare API Key", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "CLOUDFLARE_AUTH_MODE", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Cloudflare 鉴权模式", Help: "none / bearer / x-api-key / x-admin-auth"},
	{Key: "REMAIL_API_BASE", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Remail API 地址", Help: "默认 https://remail.aishop6.com"},
	{Key: "REMAIL_API_KEY", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Remail API Key", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "REMAIL_PROJECT_ID", File: "email.py", Type: "int", Group: "邮箱 / OTP", Label: "Remail 项目 ID", Help: "用于 ChatGPT 验证码的项目 ID"},
	{Key: "REMAIL_EMAIL_SUFFIX", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "Remail 邮箱后缀", Help: "默认 outlook.com"},

	// ---- CloudMail ----
	{Key: "CLOUDMAIL_API_BASE", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "CloudMail API 地址", Help: "Cloud Mail Worker/API 地址，例如 https://mail.example.com"},
	{Key: "CLOUDMAIL_ADMIN_EMAIL", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "CloudMail管理员邮箱", Help: "用于生成 Token；域名被平台隐藏时也会用它登录读取域名"},
	{Key: "CLOUDMAIL_PASSWORD", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "CloudMail 密码", Help: "用于自动获取 Token；保存在 .env", Storage: "env", Secret: true},
	{Key: "CLOUDMAIL_TOKEN_PATH", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "CloudMail Token路径", Help: "固定使用 /api/public/genToken；如部署版本不同可修改"},
	{Key: "CLOUDMAIL_AUTH_TOKEN", File: "email.py", Type: "str", Group: "邮箱 / OTP", Label: "CloudMail Token", Help: "CloudMail/Cloud Mail API Authorization Token；保存在 .env", Storage: "env", Secret: true},
	{Key: "CLOUDMAIL_DOMAINS", File: "email.py", Type: "list_str_multiline", Group: "邮箱 / OTP", Label: "CloudMail 域名列表", Help: "可留空；运行时会自动从平台获取。也可点“获取 CloudMail 域名”缓存到这里"},
	{Key: "CLOUDMAIL_AUTO_ADD_USER", File: "email.py", Type: "bool", Group: "邮箱 / OTP", Label: "CloudMail自动创建用户", Help: "生成随机邮箱后调用 /api/public/addUser 创建用户"},
	{Key: "CLOUDMAIL_RANDOM_LOCAL_LENGTH", File: "email.py", Type: "int", Group: "邮箱 / OTP", Label: "CloudMail随机名前缀长度", Help: "生成邮箱 local-part 的长度，建议 10-16"},

	// ---- MailCode ----
	{Key: "MAILCODE_API_KEY", File: "email.py", Type: "str", Group: "域名邮箱 MailCode", Label: "MailCode API Key", Help: "保存在 .env；只发送给官方固定地址", Storage: "env", Secret: true},
	{Key: "MAILCODE_PRODUCT_ID", File: "email.py", Type: "str", Group: "域名邮箱 MailCode", Label: "MailCode 商品 ID", Help: "默认 product_a3783a0ead074b4091631b9ad04153f9"},
	{Key: "MAILCODE_REQUEST_TIMEOUT", File: "email.py", Type: "int", Group: "域名邮箱 MailCode", Label: "请求超时(秒)", Help: "默认 20 秒"},
	{Key: "MAILCODE_CHANNEL_WAIT_SECONDS", File: "email.py", Type: "int", Group: "域名邮箱 MailCode", Label: "通道初始化超时(秒)", Help: "默认 60 秒；超时保留已购邮箱，下次继续初始化"},

	// ---- 代理池 ----
	{Key: "PROXY_POOL", File: "proxy.py", Type: "list_str_multiline", Group: "代理池", Label: "代理池(每行一个)", Help: "每行一个代理 URL，例如 http://user:pass@host:port"},
	{Key: "PROTOCOL_PROXY", File: "proxy.py", Type: "str", Group: "代理池", Label: "协议注册专用代理", Help: "协议模式专用代理；为空则从代理池取"},
	{Key: "PLAN_CHECK_PROXY", File: "proxy.py", Type: "str", Group: "代理池", Label: "套餐/Agent专用代理", Help: "查套餐专用代理；保存在 .env", Storage: "env", Secret: true},
	{Key: "PLAN_CHECK_WORKERS", File: "proxy.py", Type: "int", Group: "代理池", Label: "套餐查询并发数", Help: "默认 2"},
	{Key: "COUNTRY_PROXIES", File: "proxy.py", Type: "list_str_multiline", Group: "代理池", Label: "多地区代理(国家=代理)", Help: "每行一个国家代理；可写 US=http://... 显式指定国家，或直接填含地区标识的代理(如 _IN_ / -region-DE-)，系统会自动识别"},
	{Key: "PLAN_CHECK_COUPON_AUTHORITATIVE", File: "proxy.py", Type: "bool", Group: "代理池", Label: "以官方券判定资格", Help: "官方 check_coupon 返回非 eligible 时压掉 accounts/check 的乐观资格判定"},

	// ---- 人工节奏 ----
	{Key: "ENABLE_HUMANIZE_DELAY", File: "humanize.py", Type: "bool", Group: "人工节奏", Label: "启用随机停顿", Help: "各步骤间加入随机等待"},
	{Key: "HUMANIZE_DELAY_FACTOR", File: "humanize.py", Type: "float", Group: "人工节奏", Label: "停顿倍率", Help: "默认 1.0"},

	// ---- 浏览器画像 ----
	{Key: "PROTOCOL_TLS_PROFILE", File: "config.go", Type: "str", Group: "浏览器画像", Label: "协议 TLS 指纹", Help: "与 PROTOCOL_LOCALE / TIMEZONE 配套使用；默认 chrome_152", Options: []string{"chrome_152", "chrome_150", "chrome_146", "chrome_144", "chrome_131", "chrome_124"}},
	{Key: "PROTOCOL_LOCALE", File: "config.go", Type: "str", Group: "浏览器画像", Label: "协议语言", Help: "留空时按代理地区推断；例如 de-DE、en-US"},
	{Key: "PROTOCOL_TIMEZONE", File: "config.go", Type: "str", Group: "浏览器画像", Label: "协议时区", Help: "留空时按代理地区推断；例如 Europe/Berlin"},
	{Key: "BROWSER_LOCALE_PROFILE", File: "browser.py", Type: "str", Group: "浏览器画像", Label: "地区画像", Help: "浏览器驱动专用；协议模式请用 PROTOCOL_LOCALE / PROTOCOL_TIMEZONE"},
	{Key: "AUTO_BROWSER_LOCALE_FROM_IP", File: "browser.py", Type: "bool", Group: "浏览器画像", Label: "按出口IP自动画像", Help: "浏览器驱动专用；协议模式优先使用显式画像，其次读取代理地区标识"},
	{Key: "BROWSER_DATA_SAVER_MODE", File: "browser.py", Type: "bool", Group: "浏览器画像", Label: "本地浏览器省流量模式", Help: "拦截图片媒体减少流量消耗"},
	{Key: "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", File: "browser.py", Type: "list_str_multiline", Group: "浏览器画像", Label: "省流量拦截类型", Help: "默认 image, media"},
	{Key: "BROWSER_TRAFFIC_DETAIL_LOG", File: "browser.py", Type: "bool", Group: "浏览器画像", Label: "流量明细日志", Help: "输出每个网络请求的字节统计"},
	{Key: "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", File: "browser.py", Type: "int", Group: "浏览器画像", Label: "流量明细上限", Help: "单任务最多保留的请求明细数，默认 2000"},
	{Key: "BROWSER_JS_COVERAGE_LOG", File: "browser.py", Type: "bool", Group: "浏览器画像", Label: "JS 覆盖率日志", Help: "输出浏览器 JS 覆盖率统计"},
	{Key: "BROWSER_JS_COVERAGE_MAX_ENTRIES", File: "browser.py", Type: "int", Group: "浏览器画像", Label: "JS 覆盖率上限", Help: "单任务最多保留的覆盖率条目数，默认 1000"},

	// ---- Plus 试用提链 ----
	{Key: "EXTRACT_LINK_API_BASE", File: "extract_link.py", Type: "str", Group: "Plus 试用提链", Label: "提链 API 地址", Help: "提链服务根地址，例如 https://example.com"},
	{Key: "EXTRACT_LINK_CDK", File: "extract_link.py", Type: "str", Group: "Plus 试用提链", Label: "默认 CDK", Help: "保存在 .env；单次请求也可覆盖", Storage: "env", Secret: true},
	{Key: "EXTRACT_LINK_TYPE", File: "extract_link.py", Type: "str", Group: "Plus 试用提链", Label: "提链类型", Help: "pix / upi / kakao_pay / ideal"},
	{Key: "EXTRACT_LINK_WORKERS", File: "extract_link.py", Type: "int", Group: "Plus 试用提链", Label: "并发数", Help: "1-16，默认 3"},
	{Key: "EXTRACT_LINK_QUEUE_LIMIT", File: "extract_link.py", Type: "int", Group: "Plus 试用提链", Label: "队列容量", Help: "默认 500，范围 1-5000"},
	{Key: "EXTRACT_LINK_REQUEST_TIMEOUT", File: "extract_link.py", Type: "int", Group: "Plus 试用提链", Label: "请求超时(秒)", Help: "默认 30 秒"},
	{Key: "EXTRACT_LINK_EVENT_TIMEOUT", File: "extract_link.py", Type: "int", Group: "Plus 试用提链", Label: "事件流超时(秒)", Help: "默认 180 秒"},

	// ---- Codex ----
	{Key: "CODEX_OAUTH_DRIVER", File: "codex.py", Type: "str", Group: "Codex", Label: "Codex授权驱动", Help: "protocol / roxy / cloak / browser_use / same_as_registration"},
	{Key: "CODEX_AUTH_URL_SOURCE", File: "codex.py", Type: "str", Group: "Codex", Label: "授权地址来源", Help: "cpa=CPA生成并上传；sub2=sub2生成；local=本地PKCE"},
	{Key: "CPA_MANAGEMENT_URL", File: "codex.py", Type: "str", Group: "Codex", Label: "CPA 管理地址", Help: "例如 http://localhost:8317/admin/oauth"},
	{Key: "CPA_MANAGEMENT_KEY", File: "codex.py", Type: "str", Group: "Codex", Label: "CPA 管理密钥", Help: "保存在 .env", Storage: "env", Secret: true},

	// ---- 接码平台 ----
	{Key: "SMS_PROVIDER", File: "codex.py", Type: "str", Group: "接码平台", Label: "接码通道", Help: "5sim / grizzly / l / h"},
	{Key: "SMS_COUNTRY", File: "codex.py", Type: "str", Group: "接码平台", Label: "国家代码", Help: "接码平台 country 代码"},
	{Key: "SMS_SERVICE", File: "codex.py", Type: "str", Group: "接码平台", Label: "服务/项目代码", Help: "通常为 openai"},
	{Key: "SMS_API_KEY", File: "codex.py", Type: "str", Group: "接码平台", Label: "GrizzlySMS API密钥", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "FIVESIM_API_KEY", File: "codex.py", Type: "str", Group: "接码平台", Label: "5sim API Token", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "L_API_BASE", File: "codex.py", Type: "str", Group: "接码平台", Label: "L API 地址", Help: "L 取号服务地址"},
	{Key: "L_ADMIN_AUTH_CODE", File: "codex.py", Type: "str", Group: "接码平台", Label: "L 授权码", Help: "保存在 .env", Storage: "env", Secret: true},
	{Key: "H_API_BASE", File: "codex.py", Type: "str", Group: "接码平台", Label: "H API 地址", Help: "H 取号服务地址"},
	{Key: "H_ADMIN_AUTH_CODE", File: "codex.py", Type: "str", Group: "接码平台", Label: "H 授权码", Help: "保存在 .env", Storage: "env", Secret: true},

	// ---- 可选扩展能力 (absorb from turb-oss) ----
	{Key: "SENTINEL_SOLVER", File: "config.go", Type: "str", Group: "高级选项", Label: "Sentinel 求解器", Help: "synthetic=纯Go合成(零依赖)；sdk_js=Node执行真sdk.js"},
	{Key: "PROMO_CHECK_DRIVER", File: "config.go", Type: "str", Group: "高级选项", Label: "优惠检测模式", Help: "off=关闭；protocol=纯协议急速结账探测"},
	{Key: "ENABLE_MAILTM", File: "config.go", Type: "bool", Group: "高级选项", Label: "启用 mail.tm 临时邮箱", Help: "无需 Key 的公开临时邮箱"},
	{Key: "ENABLE_TEMPMAILIO", File: "config.go", Type: "bool", Group: "高级选项", Label: "启用 temp-mail.io 临时邮箱", Help: "无需 Key 的公开临时邮箱"},
}

// GetConfigValues 返回填充好当前值的配置字段列表，前端通过遍历此列表渲染完整表单。
func GetConfigValues(root string) []FieldDef {
	env, _ := readDotEnv(root + "/.env")
	c := Current()
	out := make([]FieldDef, len(EditableFieldDefs))

	for i, f := range EditableFieldDefs {
		item := f
		valStr, hasEnv := env[item.Key]

		// 根据类型给出初始值
		switch item.Type {
		case "bool":
			if hasEnv {
				item.Value = strings.EqualFold(strings.TrimSpace(valStr), "true")
			} else {
				item.Value = getBoolField(c, item.Key)
			}
		case "int":
			if hasEnv {
				var n int
				_ = json.Unmarshal([]byte(valStr), &n)
				item.Value = n
			} else {
				item.Value = getIntField(c, item.Key)
			}
		case "float":
			item.Value = 1.0
		case "list_str_multiline":
			if hasEnv {
				item.Value = parseList(valStr)
			} else {
				item.Value = getListField(c, item.Key)
			}
		default: // str
			if hasEnv {
				item.Value = valStr
			} else {
				item.Value = getStringField(c, item.Key)
			}
		}
		out[i] = item
	}
	return out
}

func getBoolField(c *Config, key string) bool {
	switch key {
	case "ENABLE_CODEX_AUTO":
		return c.EnableCodexAuto
	case "ENABLE_2FA":
		return c.Enable2FA
	case "USE_EMAIL_SERVICE":
		return c.UseEmailService
	case "ROXY_OPEN_HEADLESS":
		return c.RoxyHeadless
	case "ROXY_DELETE_PROFILE_AFTER_RUN":
		return c.RoxyDeleteProfileAfterRun
	case "CLOAK_HEADLESS":
		return c.CloakHeadless
	case "CLOAK_HUMANIZE":
		return c.CloakHumanize
	case "CLOAK_GEOIP":
		return c.CloakGeoIP
	case "BROWSER_DATA_SAVER_MODE":
		return c.DataSaverMode
	case "BROWSER_TRAFFIC_DETAIL_LOG":
		return c.TrafficDetailLog
	case "BROWSER_JS_COVERAGE_LOG":
		return c.JSCoverageLog
	case "ENABLE_MAILTM":
		return c.EnableMailTM
	case "ENABLE_TEMPMAILIO":
		return c.EnableTempMailIO
	case "CLOUDMAIL_AUTO_ADD_USER":
		return c.CloudMailAutoAddUser
	default:
		return false
	}
}

func getIntField(c *Config, key string) int {
	switch key {
	case "OTP_MAX_WAIT":
		return c.OTPMaxWaitSec
	case "OTP_POLL_INTERVAL":
		return c.OTPPollSec
	case "PLAN_CHECK_WORKERS":
		return 2
	case "TWOFA_WORKERS":
		return 4
	case "TWOFA_QUEUE_LIMIT":
		return 200
	case "CLOUDMAIL_RANDOM_LOCAL_LENGTH":
		return c.CloudMailRandomLocalLen
	case "MAILCODE_REQUEST_TIMEOUT":
		return c.MailCodeRequestTimeout
	case "MAILCODE_CHANNEL_WAIT_SECONDS":
		return c.MailCodeChannelWaitSeconds
	case "EXTRACT_LINK_WORKERS":
		return c.ExtractLinkWorkers
	case "EXTRACT_LINK_QUEUE_LIMIT":
		return c.ExtractLinkQueueLimit
	case "EXTRACT_LINK_REQUEST_TIMEOUT":
		return c.ExtractLinkRequestTimeout
	case "EXTRACT_LINK_EVENT_TIMEOUT":
		return c.ExtractLinkEventTimeout
	case "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES":
		return c.TrafficDetailMaxEntries
	case "BROWSER_JS_COVERAGE_MAX_ENTRIES":
		return c.JSCoverageMaxEntries
	default:
		return 0
	}
}

func getStringField(c *Config, key string) string {
	switch key {
	case "REGISTRATION_DRIVER":
		return c.RegistrationDriver
	case "CODEX_OAUTH_DRIVER":
		return c.CodexOAuthDriver
	case "REGISTER_EMAIL":
		return c.RegisterEmail
	case "REGISTER_NAME":
		return ""
	case "REGISTER_PASSWORD":
		return c.RegisterPassword
	case "EMAIL_SOURCE":
		return c.EmailSource
	case "MAILCODE_API_KEY":
		return c.MailCodeAPIKey
	case "MAILCODE_PRODUCT_ID":
		return c.MailCodeProductID
	case "EXTRACT_LINK_API_BASE":
		return c.ExtractLinkAPIBase
	case "EXTRACT_LINK_CDK":
		return c.ExtractLinkCDK
	case "EXTRACT_LINK_TYPE":
		return c.ExtractLinkType
	case "ROXY_API_BASE":
		return c.RoxyAPIBase
	case "ROXY_WORKSPACE_ID":
		return c.RoxyWorkspace
	case "ROXY_PROJECT_ID":
		return c.RoxyProject
	case "SENTINEL_SOLVER":
		return c.SentinelSolver
	case "PROMO_CHECK_DRIVER":
		return c.PromoCheckDriver
	case "WEBUI_AUTH_CODE":
		return c.WebUIAuthCode
	case "CLOUDMAIL_API_BASE":
		return c.CloudMailAPIBase
	case "CLOUDMAIL_ADMIN_EMAIL":
		return c.CloudMailAdminEmail
	case "CLOUDMAIL_PASSWORD":
		return c.CloudMailPassword
	case "CLOUDMAIL_TOKEN_PATH":
		return c.CloudMailTokenPath
	case "CLOUDMAIL_AUTH_TOKEN":
		return c.CloudMailAuthToken
	case "CPA_MANAGEMENT_URL":
		return c.CPAManagementURL
	case "CPA_MANAGEMENT_KEY":
		return c.CPAManagementKey
	case "ROXY_WORKSPACE_LIST_PATH":
		return c.RoxyWorkspaceListPath
	case "ROXY_WORKSPACE_LIST_METHOD":
		return c.RoxyWorkspaceListMethod
	default:
		return ""
	}
}

func getListField(c *Config, key string) []string {
	switch key {
	case "PROXY_POOL":
		return c.ProxyPool
	case "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES":
		return c.DataSaverBlockedTypes
	case "CLOUDMAIL_DOMAINS":
		return c.CloudMailDomains
	default:
		return []string{}
	}
}
