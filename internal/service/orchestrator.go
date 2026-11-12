// Package service 把 mail、register、store、sentinel 组装成可被调度层调用的一体。
//
// Python 版这里是 main.run_registration（一个 550 行的巨型函数）：
// 它同时负责取邮箱、选驱动、跑注册、设 2FA、跑 Codex、落库、触发 Flow。
// Go 版把它拆成 Orchestrator 上的几个方法，每个方法做一件事。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/codex"
	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/job"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/mail/genericapi"
	"github.com/turb/gpt-register/internal/manualotp"
	"github.com/turb/gpt-register/internal/register"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/sms"
	"github.com/turb/gpt-register/internal/store"
	_ "github.com/turb/gpt-register/internal/twofa"
)

// Orchestrator 是注册流程的总调度。
type Orchestrator struct {
	Store   *store.Store
	Mails   *mail.Registry
	Drivers *register.Registry
	Solver  sentinel.Solver
	SMS     sms.Provider
	Names   NameGenerator
}

// NameGenerator 生成显示名与生日。抽成接口便于测试固定值。
type NameGenerator interface {
	DisplayName() string
	Birthday() time.Time
}

// DefaultNames 是最简实现：从内置词表随机。
type DefaultNames struct{}

// DisplayName 返回一个符合 OpenAI 限制的英文名。
func (DefaultNames) DisplayName() string {
	first := []string{"Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery"}
	last := []string{"Smith", "Johnson", "Brown", "Davis", "Miller", "Wilson", "Moore", "Clark"}
	return first[randMod(len(first))] + " " + last[randMod(len(last))]
}

// Birthday 返回 20~40 岁之间的随机生日。
func (DefaultNames) Birthday() time.Time {
	y := time.Now().Year() - 20 - randMod(20)
	m := 1 + randMod(12)
	d := 1 + randMod(28)
	return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
}

// Run 是 job.Runner 的实现：一次完整的注册任务。
func (o *Orchestrator) Run(ctx context.Context, j *domain.Job, lg *job.Logger) (job.Result, error) {
	cfg := config.Current()

	// 驱动选择：任务指定驱动 > 配置默认驱动
	driverMode := cfg.RegistrationDriver
	if d, ok := j.Payload["driver"].(string); ok && strings.TrimSpace(d) != "" {
		driverMode = strings.TrimSpace(d)
	}
	driver, effective, err := o.Drivers.Resolve(driverMode, cfg.RoxyHeadless, cfg.CloakHeadless)
	if err != nil {
		return job.Result{}, err
	}
	if effective != driverMode {
		lg.Infof("无头路由：%s -> %s", driverMode, effective)
	}

	// 代理选择：任务指定代理 > 代理池 > 直连
	proxy := o.pickProxy(cfg, lg)
	if p, ok := j.Payload["proxy"].(string); ok && strings.TrimSpace(p) != "" {
		proxy = config.NormalizeProxyURL(p)
	}

	// 断点续跑：payload 带 resume_account_id 时跳过取邮箱与建号阶段，
	// 直接用账号已确认的注册密码续跑后半程（拿 AT / session / 2FA）。
	if rid, ok := payloadInt64(j.Payload["resume_account_id"]); ok && rid > 0 {
		return o.runResume(ctx, j, cfg, driver, effective, rid, proxy, lg)
	}
	if pd, ok := driver.(*protocol.Driver); ok {
		logBrowserProfile(lg, pd.BrowserProfile(proxy))
	}

	lg.Infof("任务 #%d 开始：驱动=%s 邮箱来源=%s", j.ID, effective, j.EmailSource)

	// 2. 取邮箱
	box, provider, err := o.acquireMailbox(ctx, j, cfg, lg)
	if err != nil {
		return job.Result{}, err
	}
	// 立即把领取的邮箱写回数据库，让前端看板能立即看到分配的邮箱
	_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
		Email: &box.Email,
	})
	var succeeded bool
	releaseReason := "failed"
	defer func() {
		if provider != nil {
			reason := releaseReason
			if succeeded {
				reason = "success"
			} else if ctx.Err() != nil {
				reason = "cancelled"
			}
			_ = provider.Release(context.Background(), box, reason)
		}
	}()
	lg.Infof("已领取邮箱：%s（来源 %s）", box.Email, box.Source)

	// 3. 组织注册请求，注入 OTP 回调
	req := register.Request{
		Email:    box.Email,
		Name:     o.Names.DisplayName(),
		Birthday: o.Names.Birthday(),
		Proxy:    proxy,
		OTP: func(ctx context.Context, email string) (string, error) {
			lg.Infof("等待邮箱验证码：%s", email)
			// 同步 OTPSent 阶段入库，看板即时展示
			otpSentStage := domain.Stage{Flow: "registration", OTPSent: true}
			_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
				Email: &box.Email,
				Stage: &otpSentStage,
			})
			start := time.Now()
			maxWait := time.Duration(cfg.OTPMaxWaitSec) * time.Second
			poll := time.Duration(cfg.OTPPollSec) * time.Second
			if provider != nil {
				res, err := mail.WaitCodeWithRetry(ctx, provider, box, start, maxWait, poll,
					func(elapsed, maxWait time.Duration, lastErr error) {
						if lastErr != nil {
							lg.Infof("正在等待验证码 (已等 %s/%s，取信返回: %v)...", elapsed.Round(time.Second), maxWait, lastErr)
						} else {
							lg.Infof("正在等待验证码 (已等 %s/%s，等待新邮件送达)...", elapsed.Round(time.Second), maxWait)
						}
					})
				if err == nil && strings.TrimSpace(res.Code) != "" {
					lg.Infof("已取到验证码（来源 %s，耗时 %s）", res.Source, time.Since(start).Round(time.Second))
					return res.Code, nil
				}
				// auth:error 是取码源当前返回的断路标记，可能是偶发（该 id 暂时失效），
				// 不是"这一轮还没收到码"。终止本任务换新邮箱，但把该邮箱放回池内供后续重试。
				var mailAuthErr *genericapi.AuthError
				if errors.As(err, &mailAuthErr) {
					if provider != nil {
						_ = provider.Release(context.Background(), box, "failed")
					}
					msg := fmt.Sprintf("邮箱 %s 收信链路断路（取码源返回 auth:error，status=%s），已终止本任务并换新邮箱重开（该邮箱已放回池内可重试）", box.Email, mailAuthErr.Status)
					lg.Errorf("%s", msg)
					failedStage := domain.Stage{Flow: "registration", OTPSent: true}
					_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
						Email: &box.Email,
						Stage: &failedStage,
						Payload: map[string]any{
							"mail_auth_error":     true,
							"mail_auth_error_at":  time.Now().Format("2006-01-02 15:04:05"),
							"manual_otp_required": false,
						},
					})
					succeeded = true // 防止 defer 再按 failed 重复释放
					return "", fmt.Errorf("%s", msg)
				}
				lg.Warnf("自动取码失败（%v），切换为 WebUI 手动验证码输入", err)
			} else {
				lg.Infof("来源 %s 未注册 provider，走 WebUI 手动验证码输入", box.Source)
			}
			// 手动通道：置 manual_otp_required，前端任务行会出现验证码输入框。
			_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
				Email: &box.Email,
				Payload: map[string]any{
					"manual_otp_required": true,
					"manual_otp_email":    box.Email,
					"manual_otp_since":    time.Now().Format(time.RFC3339),
				},
			})
			lg.Infof("请打开邮箱 %s，在 WebUI 任务行提交 4-8 位验证码（最多等 %s）", box.Email, maxWait)
			code, werr := manualotp.Wait(ctx, box.Email, j.ID, maxWait)
			_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
				Payload: map[string]any{"manual_otp_required": false},
			})
			if werr != nil {
				return "", werr
			}
			lg.Infof("已收到手动验证码（耗时 %s）", time.Since(start).Round(time.Second))
			return code, nil
		},
	}

	// 4. 执行驱动
	started := time.Now()
	res, err := driver.Register(ctx, req)
	elapsed := time.Since(started).Round(time.Second)
	if err != nil {
		if isOTPRejected(err) {
			releaseReason = "otp_rejected"
			lg.Errorf("验证码被 OpenAI 拒绝，本邮箱停止重试且不会保存账号：%s", res.Email)
		} else if registrationCanBePersisted(res, err) {
			// 仅当验证码确已核验且账号在 OpenAI 建立成功、仅是提取会话 token 出现波动时：
			// 自动尝试使用已保存的密码与 TOTP 执行一次静默登录刷新获取 AT。
			lg.Infof("注册已在 OpenAI 完成，会话提取异常，正在尝试重新登录获取 AT: %s", res.Email)
			if protoDriver, ok := driver.(*protocol.Driver); ok {
				image := browserProfileFromAccount(res.Extra, protoDriver, proxy)
				at, st, lerr := protoDriver.LoginWithPasswordUsingProfileLogged(ctx, res.Email, res.Password, res.TOTPSecret, extraDeviceID(res.Extra), proxy, image, nil)
				if lerr == nil && at != "" {
					res.AccessToken = at
					res.SessionToken = st
					res.Stage.CredentialAcquired = true
					err = nil
					lg.Infof("密码重新登录成功并已取得新 AT: %s", res.Email)
				} else {
					lg.Warnf("密码重新登录取 AT 失败: %v（账号与密码仍将安全入库，可随时在列表点击刷新 AT）", lerr)
				}
			}
		}
	}

	var savedAccountID int64

	// 关键保护：只有验证码确实核验通过、账号在 OpenAI 建立成功的账号，才入库保全；
	// 若验证码未收到或建号失败，绝不把空壳伪造账号写入库中！
	if registrationCanBePersisted(res, err) {
		accountStatus := "registered"
		if res.AccessToken == "" {
			accountStatus = "interrupted"
		}
		acc := domain.Account{
			Email:  res.Email,
			Status: accountStatus,
			Payload: map[string]any{
				"status":                        accountStatus,
				"access_token":                  res.AccessToken,
				"session_token":                 res.SessionToken,
				"totp_secret":                   res.TOTPSecret,
				"display_name":                  res.Name,
				"proxy_used":                    res.ProxyUsed,
				"driver":                        effective,
				"stage":                         res.Stage,
				"registered_at":                 time.Now().Format(time.RFC3339),
				"registration_password":         res.Password,
				"password":                      res.Password,
				"password_setup_login_verified": true,
			},
		}
		if res.AccessToken == "" {
			acc.Payload["token_expired"] = true
			acc.Payload["token_need_refresh"] = true
			if errors.Is(err, protocol.ErrNoSessionEstablished) {
				acc.Payload["password_setup_message"] = "注册中断：服务端未建立登录会话 (返回 {})"
			}
		} else {
			// 注册成功且拿到有效 AT：直接标活，消除 live_check_status=NULL
			acc.Payload["live_check_status"] = "live"
			acc.Payload["live_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
			acc.Payload["token_expired"] = false
		}
		// 确保 device_id 100% 具备并落库
		did := res.DeviceID
		if did == "" {
			did = extraDeviceID(res.Extra)
		}
		if did == "" {
			did = sentinel.DeviceIDFromSeed(sentinel.FingerprintSeed(res.Email))
		}
		acc.Payload["device_id"] = did
		for k, v := range res.Extra {
			acc.Payload[k] = v
		}
		var insErr error
		savedAccountID, insErr = o.Store.InsertAccount(ctx, acc)
		if insErr == nil {
			succeeded = true
			atStatus := "已成功获取"
			if res.AccessToken == "" {
				atStatus = "待刷新（可点击刷新AT）"
			}
			lg.Infof("账号已安全入库：#%d %s（密码: %s, AT: %s）", savedAccountID, res.Email, maskSecret(res.Password), atStatus)
			if err != nil && res.AccessToken == "" {
				// 保存部分注册结果供人工核查，但不能把缺少会话凭证的任务记作成功。
				return job.Result{
					Email:     res.Email,
					AccountID: savedAccountID,
					Stage:     res.Stage,
					Traffic:   res.Traffic,
				}, err
			}
		}
	}

	if err != nil {
		lg.Errorf("驱动 %s 失败（耗时 %s）：%v", effective, elapsed, err)
		return job.Result{Email: box.Email, Stage: res.Stage, Traffic: res.Traffic}, err
	}
	lg.Infof("驱动 %s 成功（耗时 %s）", effective, elapsed)

	// 5. 可选自动执行 Codex OAuth 授权
	if cfg.EnableCodexAuto && res.Email != "" {
		lg.Infof("[Codex] 开始自动执行 Codex 授权: %s", res.Email)
		cres, cerr := codex.RunCodexOAuth(ctx, o.Store, res.Email, req.Proxy, o.SMS, req.OTP)
		if cerr != nil {
			lg.Warnf("[Codex] 授权失败: %v", cerr)
		} else {
			lg.Infof("[Codex] 授权状态: %s (%s)", cres.Status, cres.Message)
		}
	}

	// 6. 正常成功落库（若前面未入库）
	if !succeeded {
		acc := domain.Account{
			Email:  res.Email,
			Status: "registered",
			Payload: map[string]any{
				"access_token":                  res.AccessToken,
				"session_token":                 res.SessionToken,
				"totp_secret":                   res.TOTPSecret,
				"display_name":                  res.Name,
				"proxy_used":                    res.ProxyUsed,
				"driver":                        effective,
				"stage":                         res.Stage,
				"registered_at":                 time.Now().Format(time.RFC3339),
				"registration_password":         res.Password,
				"password":                      res.Password,
				"password_setup_login_verified": true,
			},
		}
		for k, v := range res.Extra {
			acc.Payload[k] = v
		}
		var insErr error
		savedAccountID, insErr = o.Store.InsertAccount(ctx, acc)
		if insErr != nil {
			return job.Result{Email: res.Email, Stage: res.Stage, Traffic: res.Traffic},
				fmt.Errorf("保存账号失败: %w", insErr)
		}
		succeeded = true
		lg.Infof("账号已入库：#%d %s", savedAccountID, res.Email)
		return job.Result{
			Email:     res.Email,
			AccountID: savedAccountID,
			Stage:     res.Stage,
			Traffic:   res.Traffic,
		}, nil
	}

	return job.Result{
		Email:     res.Email,
		AccountID: savedAccountID,
		Stage:     res.Stage,
		Traffic:   res.Traffic,
	}, nil
}

func isOTPRejected(err error) bool {
	if err == nil {
		return false
	}
	var rejected *protocol.OTPRejectedError
	return errors.As(err, &rejected) || errors.Is(err, protocol.ErrOTPRejected)
}

// registrationCanBePersisted 是所有“密码保全/断点续跑”入口的统一闸门。
// 即使驱动层未来误把阶段标记为成功，明确的验证码拒绝也必须优先判为不可保存。
func registrationCanBePersisted(res register.Result, err error) bool {
	if isOTPRejected(err) {
		return false
	}
	return res.Password != "" && res.Stage.OTPVerified && (res.Stage.AccountCreated || res.Stage.PasswordSet)
}

// acquireMailbox 按任务覆盖与来源链领取可用邮箱。
func (o *Orchestrator) acquireMailbox(ctx context.Context, j *domain.Job, cfg *config.Config, lg *job.Logger) (domain.Mailbox, mail.Provider, error) {
	// 1. 如果任务指定了特定邮箱（例如手动单条输入或断点续跑）
	if strings.TrimSpace(j.Email) != "" {
		src := j.EmailSource
		if src == "" {
			src = cfg.EmailSource
		}
		p, _ := o.Mails.Get(src)
		return domain.Mailbox{
			Email:      strings.TrimSpace(j.Email),
			Source:     domain.EmailSource(src),
			AcquiredAt: time.Now(),
		}, p, nil
	}

	// 2. 确定候选来源列表：任务传入的来源优先
	var sources []string
	if strings.TrimSpace(j.EmailSource) != "" {
		sources = append(sources, strings.ToLower(strings.TrimSpace(j.EmailSource)))
	}
	for _, s := range cfg.EmailSources() {
		if !contains(sources, s) {
			sources = append(sources, s)
		}
	}
	// 默认兜底列表，按最常用到临时来源排序
	for _, fallback := range []string{"generic_api", "outlook", "imap", "cloudflare", "tempmailio", "mailtm"} {
		if !contains(sources, fallback) {
			sources = append(sources, fallback)
		}
	}

	// 3. 尝试从来源中领取可用邮箱
	box, provider, err := o.Mails.Acquire(ctx, sources)
	if err == nil {
		return box, provider, nil
	}

	// 4. 如果邮箱池都空了，但配置了手动 REGISTER_EMAIL
	if cfg.RegisterEmail != "" {
		return domain.Mailbox{Email: cfg.RegisterEmail, Source: "manual"}, nil, nil
	}

	return domain.Mailbox{}, nil, fmt.Errorf("未能从邮箱来源 %v 领取到可用邮箱: %w（请先在「邮箱池」导入对应素材，或确认邮箱状态为可用）", sources, err)
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// pickProxy 从代理池随机取一个；池空则用 PROTOCOL_PROXY。
func (o *Orchestrator) pickProxy(cfg *config.Config, lg *job.Logger) string {
	if cfg.NoProxy {
		return ""
	}
	if len(cfg.ProxyPool) == 0 {
		if cfg.ProtocolProxy != "" {
			return config.NormalizeProxyURL(cfg.ProtocolProxy)
		}
		lg.Warnf("代理池为空，将直连（成功率会显著下降）")
		return ""
	}
	return config.NormalizeProxyURL(cfg.ProxyPool[randMod(len(cfg.ProxyPool))])
}

// Validate 在启动时校验配置与依赖是否自洽，提前暴露常见问题。
func Validate(cfg *config.Config, drivers *register.Registry, mails *mail.Registry) []string {
	var problems []string

	if _, ok := drivers.Lookup(cfg.RegistrationDriver); !ok {
		problems = append(problems, fmt.Sprintf(
			"REGISTRATION_DRIVER=%q 未注册，可选：%v", cfg.RegistrationDriver, drivers.Names()))
	}
	if cfg.UseEmailService {
		for _, s := range cfg.EmailSources() {
			if _, ok := mails.Get(s); !ok {
				problems = append(problems, fmt.Sprintf(
					"EMAIL_SOURCE 中的 %q 未注册，可选：%v", s, mails.Names()))
			}
		}
	}
	if cfg.RegistrationDriver == "protocol" && !cfg.NoProxy && len(cfg.ProxyPool) == 0 && cfg.ProtocolProxy == "" {
		problems = append(problems, "协议驱动建议配置 PROXY_POOL 或 PROTOCOL_PROXY，否则会直连")
	}
	if cfg.SentinelSolver == "sdk_js" {
		if err := sentinel.NewNode(cfg.NodeBin, cfg.SentinelRunnerPath).Available(); err != nil {
			problems = append(problems, fmt.Sprintf("SENTINEL_SOLVER=sdk_js 但 %v", err))
		}
	}
	return problems
}

func randMod(n int) int {
	if n <= 0 {
		return 0
	}
	return int(time.Now().UnixNano() / 1000 % int64(n))
}

var _ = strings.TrimSpace
var _ = slog.Info

// extraDeviceID 从驱动回传的 Extra 里取出注册时使用的 oai-did。
func extraDeviceID(extra map[string]any) string {
	if extra == nil {
		return ""
	}
	if s, ok := extra["device_id"].(string); ok {
		return s
	}
	return ""
}

// maskSecret 只露出首尾两个字符，避免明文密码进日志。
func maskSecret(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// payloadInt64 从 payload 里安全取整数（JSON 解码后可能是 float64）。
func payloadInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case string:
		if s := strings.TrimSpace(n); s != "" {
			var out int64
			if _, err := fmt.Sscanf(s, "%d", &out); err == nil {
				return out, true
			}
		}
	}
	return 0, false
}

// payloadStr 从 payload 里安全取字符串。
func payloadStr(p map[string]any, key string) string {
	if p == nil {
		return ""
	}
	if s, ok := p[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// browserProfileFromAccount 恢复账号注册时的浏览器画像。
// 旧账号缺少部分字段时，才用当前配置与代理地区补全；已有字段绝不覆盖。
func browserProfileFromAccount(payload map[string]any, pd *protocol.Driver, proxy string) protocol.BrowserProfile {
	image := protocol.BrowserProfile{
		TLSProfile:  payloadStr(payload, "browser_tls_profile"),
		ChromeMajor: payloadStr(payload, "browser_chrome_major"),
		UserAgent:   payloadStr(payload, "browser_user_agent"),
		Language:    payloadStr(payload, "browser_language"),
		Timezone:    payloadStr(payload, "browser_timezone"),
		Screen:      payloadStr(payload, "browser_screen"),
	}
	if image == (protocol.BrowserProfile{}) && pd != nil {
		return pd.BrowserProfile(proxy)
	}
	return image.Complete(proxy)
}

func storeBrowserProfile(payload map[string]any, image protocol.BrowserProfile) {
	if payload == nil {
		return
	}
	payload["browser_tls_profile"] = image.TLSProfile
	payload["browser_chrome_major"] = image.ChromeMajor
	payload["browser_user_agent"] = image.UserAgent
	payload["browser_language"] = image.Language
	payload["browser_timezone"] = image.Timezone
	payload["browser_screen"] = image.Screen
}

func logBrowserProfile(lg *job.Logger, image protocol.BrowserProfile) {
	if lg == nil {
		return
	}
	lg.Infof("环境画像：TLS=%s UA=Chrome/%s 语言=%s 时区=%s 屏幕=%s", image.TLSProfile, image.ChromeMajor, image.Language, image.Timezone, image.Screen)
}

// runResume 断点续跑：跳过取邮箱与建号阶段，用账号已确认的注册密码续跑后半程。
//
// 对应上游 core/registration_service.py 的 resume_from=password_checkpoint_saved：
// 密码已经写入 OpenAI 且本地已确认，这里只需要用密码（+ 已有 TOTP）登录拿回
// access_token / session_token，把账号补齐到可导出状态。
func (o *Orchestrator) runResume(ctx context.Context, j *domain.Job, cfg *config.Config, driver register.Driver, effective string, accountID int64, proxy string, lg *job.Logger) (job.Result, error) {
	acc, err := o.Store.GetAccount(ctx, accountID)
	if err != nil {
		return job.Result{}, fmt.Errorf("读取续跑账号失败: %w", err)
	}
	if acc == nil {
		_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Payload: map[string]any{
			"resume_error":    "断点续跑账号不存在",
			"resume_error_at": time.Now().Format("2006-01-02 15:04:05"),
		}})
		return job.Result{}, fmt.Errorf("断点续跑账号不存在: %d", accountID)
	}

	email := strings.TrimSpace(acc.Email)
	if email == "" {
		_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Payload: map[string]any{"resume_error": "账号邮箱为空"}})
		return job.Result{}, fmt.Errorf("账号 #%d 邮箱为空", accountID)
	}

	password := payloadStr(acc.Payload, "registration_password")
	if password == "" {
		password = payloadStr(acc.Payload, "password")
	}
	if password == "" {
		_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Email: &email, Payload: map[string]any{
			"resume_error": "没有已确认的注册密码",
		}})
		return job.Result{}, fmt.Errorf("账号 #%d 没有已确认的注册密码，不能断点续跑", accountID)
	}

	resumeFrom := payloadStr(j.Payload, "resume_from")
	if resumeFrom == "" {
		resumeFrom = "password_checkpoint_saved"
	}
	lg.Infof("[Job %d] 断点续跑账号 #%d（%s），阶段=%s，驱动=%s", j.ID, accountID, email, resumeFrom, effective)

	// 任务行补上邮箱与账号归属，前端看板立即对得上
	_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{
		Email:     &email,
		AccountID: &accountID,
		Payload: map[string]any{
			"resume_from":       resumeFrom,
			"resume_started_at": time.Now().Format("2006-01-02 15:04:05"),
			"resume_error":      "",
		},
	})
	_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Stage: &domain.Stage{Flow: "registration", PasswordSet: true}})

	protoDriver, ok := driver.(*protocol.Driver)
	if !ok {
		msg := "该驱动不支持断点续跑，请把驱动切到 protocol"
		_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Payload: map[string]any{"resume_error": msg}})
		return job.Result{Email: email, AccountID: accountID}, fmt.Errorf("%s", msg)
	}

	deviceID := payloadStr(acc.Payload, "device_id")
	totpSecret := payloadStr(acc.Payload, "totp_secret")
	image := browserProfileFromAccount(acc.Payload, protoDriver, proxy)
	logBrowserProfile(lg, image)

	started := time.Now()
	lg.Infof("续跑步骤 1/2：使用已确认密码登录并取回会话（oai-did=%s，2FA=%t）", deviceID, totpSecret != "")
	at, st, lerr := protoDriver.LoginWithPasswordUsingProfileLogged(ctx, email, password, totpSecret, deviceID, proxy, image, func(msg string) {
		lg.Infof("%s", msg)
	})
	if lerr != nil {
		elapsed := time.Since(started).Round(time.Second)
		msg := "续跑登录失败: " + lerr.Error()
		lg.Errorf("%s（耗时 %s）", msg, elapsed)
		if acc.Payload == nil {
			acc.Payload = map[string]any{}
		}
		acc.Payload["password_setup_status"] = "verification_failed"
		acc.Payload["password_setup_message"] = "登录验收失败，查看账号密码状态"
		acc.Payload["password_setup_error"] = lerr.Error()
		acc.Payload["password_setup_at"] = time.Now().Format("2006-01-02 15:04:05")
		if strings.TrimSpace(deviceID) != "" {
			acc.Payload["device_id"] = deviceID
		}
		storeBrowserProfile(acc.Payload, image)
		acc.Status = "interrupted"
		_, _ = o.Store.InsertAccount(ctx, *acc)
		_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Payload: map[string]any{
			"resume_error":    lerr.Error(),
			"resume_error_at": time.Now().Format("2006-01-02 15:04:05"),
		}})
		return job.Result{Email: email, AccountID: accountID}, fmt.Errorf("%s", msg)
	}

	lg.Infof("续跑步骤 2/2：会话已取回，写回账号（AT 长度=%d）", len(at))
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	if at != "" {
		acc.Payload["access_token"] = at
		acc.Payload["token_expired"] = false
		acc.Payload["token_need_refresh"] = false
	}
	if st != "" {
		acc.Payload["session_token"] = st
	}
	if strings.TrimSpace(deviceID) != "" {
		acc.Payload["device_id"] = deviceID
	}
	storeBrowserProfile(acc.Payload, image)
	acc.Payload["password"] = password
	acc.Payload["registration_password"] = password
	acc.Payload["password_setup_login_verified"] = true
	acc.Payload["password_setup_status"] = "success"
	acc.Payload["password_setup_message"] = "断点续跑登录验收通过"
	acc.Payload["password_setup_error"] = ""
	acc.Payload["password_setup_at"] = time.Now().Format("2006-01-02 15:04:05")
	acc.Payload["registration_password_verified"] = true
	acc.Payload["resume_completed_at"] = time.Now().Format("2006-01-02 15:04:05")
	acc.Payload["resume_from"] = resumeFrom
	acc.Payload["driver"] = effective
	if strings.TrimSpace(proxy) != "" {
		acc.Payload["proxy_used"] = proxy
	}
	acc.Status = "registered"
	acc.Archived = false

	if _, insErr := o.Store.InsertAccount(ctx, *acc); insErr != nil {
		return job.Result{Email: email, AccountID: accountID}, fmt.Errorf("续跑成功但写回账号失败: %w", insErr)
	}

	// 续跑成功后按常规路径补跑 Codex 授权
	if cfg.EnableCodexAuto {
		lg.Infof("[Codex] 开始自动执行 Codex 授权: %s", email)
		if cres, cerr := codex.RunCodexOAuth(ctx, o.Store, email, proxy, o.SMS, nil); cerr != nil {
			lg.Warnf("[Codex] 授权失败: %v", cerr)
		} else {
			lg.Infof("[Codex] 授权状态: %s (%s)", cres.Status, cres.Message)
		}
	}

	stage := domain.Stage{
		Flow:               "registration",
		AccountCreated:     true,
		PasswordSet:        true,
		OTPVerified:        true,
		CredentialAcquired: at != "",
	}
	_ = o.Store.UpdateJob(ctx, j.ID, store.JobUpdate{Stage: &stage, Payload: map[string]any{
		"resume_done": true,
	}})
	lg.Infof("断点续跑完成：%s（账号 #%d）", email, accountID)
	return job.Result{Email: email, AccountID: accountID, Stage: stage}, nil
}
