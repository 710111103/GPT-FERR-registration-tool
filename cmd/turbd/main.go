// Command turbd 是 Go 版 WebUI 与控制台入口（对应 Python 的 web.py）。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/turb/gpt-register/internal/api"
	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/job"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/register"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/service"
	"github.com/turb/gpt-register/internal/sms"
	"github.com/turb/gpt-register/internal/store"
	"github.com/turb/gpt-register/internal/web"
)

// version 由构建时注入：go build -ldflags "-X main.version=1.0.0"
var version = "dev"

func main() {
	var (
		port        = flag.Int("port", 0, "监听端口，默认取配置或 5000")
		host        = flag.String("host", "", "监听地址，默认 127.0.0.1")
		authCode    = flag.String("auth-code", "", "授权码，覆盖 .env 中的 WEBUI_AUTH_CODE")
		root        = flag.String("root", "", "项目根目录，默认为可执行文件所在目录")
		openBrowser = flag.Bool("open-browser", false, "启动后自动打开系统默认浏览器")
		verbose     = flag.Bool("verbose", false, "输出调试日志")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := run(*root, *host, *port, *authCode, *openBrowser); err != nil {
		slog.Error("启动失败", "err", err)
		os.Exit(1)
	}
}

func run(root, host string, port int, authCode string, autoOpenBrowser bool) error {
	if root == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		root = filepath.Dir(exe)
	}
	if err := config.Init(root); err != nil {
		return err
	}
	cfg := config.Current()

	// 命令行参数优先级高于 .env
	if host != "" {
		cfg.BindHost = host
	}
	if port > 0 {
		cfg.BindPort = port
	}
	if authCode != "" {
		cfg.WebUIAuthCode = authCode
	}

	slog.Info("Turb GPT Register 启动中", "root", cfg.Root, "version", version)

	// ---- 存储 ----
	st, err := store.Open(filepath.Join(cfg.Root, "turb.sqlite3"))
	if err != nil {
		return fmt.Errorf("初始化数据库: %w", err)
	}
	defer st.Close()

	// 崩溃恢复：把上次残留的 running 任务复位
	if n, err := st.RecoverInterruptedJobs(context.Background()); err == nil && n > 0 {
		slog.Warn("已恢复中断任务", "count", n)
	}
	// 提链任务没有可恢复的上游句柄，启动时明确关闭残留 queued/running 状态。
	if n, err := st.RecoverInterruptedExtractLinks(context.Background()); err == nil && n > 0 {
		slog.Warn("已恢复中断的提链任务", "count", n)
	}
	// 邮箱回收：把被失败/中断任务锁定为 used 但未实际注册的邮箱自动释放回池
	if n, err := st.RecoverUnconsumedEmails(context.Background()); err == nil && n > 0 {
		slog.Info("已自动回收未消费邮箱", "count", n)
	}

	// ---- 邮箱来源 ----
	// 本地邮箱池按来源各注册一个 Provider；邮件内容走 payload 里的取码地址。
	mails := mail.NewRegistry()
	poolSources := []string{
		"outlook", "generic_api", "mailalias", "imap", "cloudflare", "cloudflare_domain",
		"gptmail", "mailnest", "cloudmail", "remail", "xigua",
	}
	for _, src := range poolSources {
		mails.Register(mail.NewPool(st, src))
	}
	mails.Register(mail.NewMailCode(filepath.Join(cfg.Root, "cache", "mailcode")))
	if cfg.EnableMailTM {
		mails.Register(mail.NewMailTM(filepath.Join(cfg.Root, cfg.MailTMPersistPath)))
	}
	if cfg.EnableTempMailIO {
		mails.Register(mail.NewTempMailIO(filepath.Join(cfg.Root, cfg.TempMailIOPersistPath)))
	}

	// ---- 注册驱动 ----
	drivers := register.NewRegistry()

	solver, solverNote := sentinel.New(cfg.SentinelSolver, cfg.NodeBin,
		filepath.Join(cfg.Root, cfg.SentinelRunnerPath))
	slog.Info("Sentinel 求解器就绪", "solver", solver.Name(), "note", solverNote)

	drivers.Register(&protocol.Driver{
		Solver:   solver,
		Password: cfg.RegisterPassword,
	}, "api", "http")

	for _, name := range []string{"oss_protocol", "roxy", "ant", "cloak", "browser_use", "skyvern"} {
		drivers.Register(&register.Unimplemented{DriverName: name})
	}
	drivers.Register(&register.Unimplemented{DriverName: "roxy"},
		"roxybrowser", "fingerprint", "browser")
	drivers.Register(&register.Unimplemented{DriverName: "cloak"}, "cloakbrowser")
	drivers.Register(&register.Unimplemented{DriverName: "browser_use"},
		"browseruse", "browser_use", "bu")

	// ---- 接码服务 ----
	var smsProv sms.Provider
	switch strings.ToLower(cfg.SMSProvider) {
	case "5sim", "fivesim":
		smsProv = sms.NewFiveSim(cfg.SMSAPIKey)
	case "l":
		smsProv = sms.NewLocalL(cfg.Root, cfg.WebUIAuthCode)
	case "h":
		smsProv = sms.NewLocalH(cfg.Root, cfg.WebUIAuthCode)
	default:
		smsProv = sms.NewGrizzly(cfg.SMSAPIKey)
	}

	// ---- 编排器 ----
	orch := &service.Orchestrator{
		Store:   st,
		Mails:   mails,
		Drivers: drivers,
		Solver:  solver,
		SMS:     smsProv,
		Names:   service.DefaultNames{},
	}

	// 启动前配置校验：只警告不阻止，便于在 WebUI 里改
	for _, p := range service.Validate(cfg, drivers, mails) {
		slog.Warn("配置提示", "issue", p)
	}

	// ---- 任务池 ----
	logDir := filepath.Join(cfg.Root, "logs", "jobs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("创建日志目录: %w", err)
	}
	pool := job.NewPool(st, orch.Run, logDir, 2)
	defer pool.Shutdown()

	// ---- HTTP ----
	restartCh := make(chan struct{}, 1)
	srv := api.New(api.Options{
		Store:   st,
		Pool:    pool,
		Mails:   mails,
		Drivers: drivers,
		Static:  web.Static,
		Version: version,
		SMS:     smsProv,
		Solver:  solver,
		OnRestart: func() {
			select {
			case restartCh <- struct{}{}:
			default:
			}
		},
	})
	// 注册任务进入 success 后异步探测该账号的套餐与优惠；探测并发由
	// PLAN_CHECK_WORKERS 控制，不会阻塞注册任务池。
	pool.SetSuccessHook(srv.QueuePromoCheck)
	if srv.AuthGenerated() {
		slog.Warn("未配置 WEBUI_AUTH_CODE，已生成本次临时授权码",
			"auth_code", srv.AuthCode())
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.BindHost, cfg.BindPort),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 优雅关闭
	errCh := make(chan error, 1)
	targetURL := "http://" + httpServer.Addr
	if cfg.BindHost == "0.0.0.0" || cfg.BindHost == "" {
		targetURL = fmt.Sprintf("http://127.0.0.1:%d", cfg.BindPort)
	}
	go func() {
		slog.Info("WebUI 已启动", "url", targetURL)
		if autoOpenBrowser {
			go func() {
				time.Sleep(350 * time.Millisecond)
				openBrowserURL(targetURL)
			}()
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("HTTP 服务异常: %w", err)
	case sig := <-sigCh:
		slog.Info("收到退出信号，正在关闭", "signal", sig.String())
	case <-restartCh:
		slog.Info("收到热重启信号，正在平滑释放资源并触发自动重载...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpServer.Shutdown(ctx)
		cancel()
		os.Exit(42) // 退出码 42 通知批处理脚本执行热更新重编与重启
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Warn("HTTP 关闭超时", "err", err)
	}
	slog.Info("已退出")
	return nil
}

func openBrowserURL(targetURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	_ = cmd.Start()
}
