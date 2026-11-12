package api

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/job"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/mail/genericapi"
	"github.com/turb/gpt-register/internal/register"
	"github.com/turb/gpt-register/internal/register/protocol"
	"github.com/turb/gpt-register/internal/sentinel"
	"github.com/turb/gpt-register/internal/sms"
	"github.com/turb/gpt-register/internal/store"
	"github.com/turb/gpt-register/internal/twofa"
)

type ossBatch struct {
	id      string
	total   int
	workers int
	jobIDs  []int64
}

// Server 是 HTTP 服务。
type Server struct {
	store       *store.Store
	pool        *job.Pool
	auth        *auth
	mails       *mail.Registry
	drivers     *register.Registry
	solver      sentinel.Solver
	static      embed.FS
	version     string
	batchesMu   sync.RWMutex
	batches     map[string]ossBatch
	liveLogsMu  sync.RWMutex
	liveLogs    map[string][]string
	liveRunning map[string]bool
	onRestart   func()
	// mux 保存已构建的路由表，供 handleCatchAll 探测「路径存在但方法不对」时算 Allow。
	mux *http.ServeMux

	// 注册成功后的套餐/优惠探测队列。队列只做非阻塞投递，实际网络请求由
	// PLAN_CHECK_WORKERS 控制并发，避免大批量注册同时打爆上游。
	promoMu      sync.Mutex
	promoQueued  map[int64]bool
	promoQueue   chan int64
	promoWorkers int

	// Codex 补跑占位与停止信号（对齐上游 codex_retry_service 的进程内状态）
	sms        sms.Provider
	codexMu    sync.Mutex
	codexRetry map[string]*codexRetryState

	// 密码候选验收批量（对齐上游 password_setup_service 的进程内单实例状态）
	verifyMu    sync.Mutex
	verifyBatch *verifyBatchState

	// 补设密码队列（对齐上游 password_setup_service 的 _RUNNING/_QUEUED/_BATCH_STATE）
	pwMu      sync.Mutex
	pwRunning map[int64]bool
	pwQueued  map[int64]bool
	pwBatch   *passwordMissingBatchState

	// 单号纯协议会话（对齐上游 password_setup_protocol_job 的 _RUNNING/_PENDING/_RESULTS）
	protoMu       sync.Mutex
	protoSessions map[int64]*protoSession

	// 导出预置下载（对齐上游 _put_prepared_download 的 TTL 字典）
	downloads *preparedDownloadStore

	// Plus 试用提链使用独立客户端与有界队列，不复用注册会话或浏览器画像。
	extract *extractLinkService
}

type Options struct {
	Store     *store.Store
	Pool      *job.Pool
	Mails     *mail.Registry
	Drivers   *register.Registry
	Static    embed.FS
	Version   string
	SMS       sms.Provider
	Solver    sentinel.Solver
	OnRestart func()
}

// New 创建服务，并完成鉴权初始化。
func New(opt Options) *Server {
	cfg := config.Current()
	s := &Server{
		store:         opt.Store,
		pool:          opt.Pool,
		auth:          newAuth(cfg.WebUIAuthCode, cfg.WebUISessionSecret),
		mails:         opt.Mails,
		drivers:       opt.Drivers,
		solver:        opt.Solver,
		static:        opt.Static,
		version:       opt.Version,
		onRestart:     opt.OnRestart,
		batches:       make(map[string]ossBatch),
		liveLogs:      make(map[string][]string),
		liveRunning:   make(map[string]bool),
		pwRunning:     make(map[int64]bool),
		pwQueued:      make(map[int64]bool),
		sms:           opt.SMS,
		codexRetry:    make(map[string]*codexRetryState),
		protoSessions: make(map[int64]*protoSession),
		downloads:     &preparedDownloadStore{},
		promoQueued:   make(map[int64]bool),
		promoQueue:    make(chan int64, 10000),
		promoWorkers:  cfg.PlanCheckWorkers,
	}
	s.extract = newExtractLinkService(opt.Store, config.Current, nil)
	s.startPromoWorkers()
	return s
}

// AuthCode 返回当前授权码。
func (s *Server) AuthCode() string { return s.auth.Code() }

// AuthGenerated 表示授权码是自动生成的。
func (s *Server) AuthGenerated() bool { return s.auth.Generated() }

// Handler 构建完整的路由表，严格对齐 index.html 的 60 个 REST 接口。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/accounts/{id}/refresh-at", s.handleAccountRefreshAt)

	// ---- 页面与登录 ----
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// ---- 概览 ----
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/system/health", s.handleHealth)
	mux.HandleFunc("POST /api/system/restart", s.handleRestart)
	mux.HandleFunc("GET /api/capabilities", s.handleCapabilities)

	// ---- 注册任务 (index.html 注册 Tab) ----
	mux.HandleFunc("GET /api/jobs", s.handleJobs)
	mux.HandleFunc("GET /api/jobs/promo-summary", s.handlePromoSummary)
	mux.HandleFunc("POST /api/jobs", s.handleSubmit)
	mux.HandleFunc("POST /api/jobs/cancel-pending", s.handleCancelPending)
	mux.HandleFunc("POST /api/jobs/delete-bulk", s.handleJobsDeleteBulk)
	mux.HandleFunc("POST /api/jobs/retry-bulk", s.handleJobsRetryBulk)
	mux.HandleFunc("GET /api/jobs/{id}/log", s.handleJobLog)
	mux.HandleFunc("POST /api/jobs/{id}/stop", s.handleJobStop)
	mux.HandleFunc("POST /api/jobs/{id}/delete", s.handleJobDelete)
	mux.HandleFunc("POST /api/jobs/{id}/retry", s.handleJobRetry)

	// ---- OSS 独立协议注册 (index.html 模式切换) ----
	mux.HandleFunc("POST /api/oss-protocol/register", s.handleOssProtocolRegister)
	mux.HandleFunc("GET /api/oss-protocol/batches/{id}", s.handleOssProtocolBatch)
	mux.HandleFunc("GET /api/oss-protocol/jobs/{id}", s.handleOssProtocolJob)

	// ---- 兜底未匹配路由 (返回清晰的 JSON 404，杜绝 405) ----
	mux.HandleFunc("/", s.handleCatchAll)

	// ---- 邮箱池 (index.html 邮箱池 Tab) ----
	mux.HandleFunc("GET /api/outlook", s.handleOutlookList)
	mux.HandleFunc("POST /api/outlook/import", s.handleOutlookImport)
	mux.HandleFunc("POST /api/outlook/status", s.handleOutlookStatus)
	mux.HandleFunc("POST /api/outlook/status-bulk", s.handleOutlookStatusBulk)
	mux.HandleFunc("POST /api/outlook/delete", s.handleOutlookDelete)
	mux.HandleFunc("POST /api/outlook/delete-bulk", s.handleOutlookDeleteBulk)

	// ---- 账号管理 (index.html 账号 Tab) ----
	mux.HandleFunc("GET /api/accounts", s.handleAccounts)
	mux.HandleFunc("GET /api/accounts/{id}/secret", s.handleAccountSecret)
	mux.HandleFunc("POST /api/accounts/secret-bulk", s.handleAccountsSecretBulk)
	mux.HandleFunc("POST /api/accounts/{id}/archive", s.handleAccountArchive)
	mux.HandleFunc("POST /api/accounts/archive-bulk", s.handleAccountsArchiveBulk)
	mux.HandleFunc("POST /api/accounts/{id}/delete", s.handleAccountDelete)
	mux.HandleFunc("POST /api/accounts/delete-bulk", s.handleAccountsDeleteBulk)
	mux.HandleFunc("POST /api/accounts/{id}/note", s.handleAccountNote)
	mux.HandleFunc("POST /api/accounts/note-bulk", s.handleAccountsNoteBulk)
	mux.HandleFunc("GET /api/accounts/plan-check-status", s.handlePlanCheckStatus)
	mux.HandleFunc("POST /api/accounts/check-plan", s.handleCheckPlan)
	mux.HandleFunc("POST /api/accounts/check-plan-bulk", s.handleCheckPlanBulk)
	mux.HandleFunc("POST /api/accounts/check-live-bulk", s.handleCheckLiveBulk)
	mux.HandleFunc("POST /api/accounts/payment-info", s.handlePaymentInfo)
	mux.HandleFunc("POST /api/accounts/payment-info-bulk", s.handlePaymentInfoBulk)
	mux.HandleFunc("GET /api/accounts/payment-info-status", s.handlePaymentInfoStatus)
	mux.HandleFunc("GET /api/accounts/{id}/payment-detail", s.handleAccountPaymentDetail)
	mux.HandleFunc("POST /api/accounts/extract-link", s.handleExtractLink)
	mux.HandleFunc("POST /api/accounts/extract-link-bulk", s.handleExtractLinkBulk)
	mux.HandleFunc("GET /api/extract-link/cdk", s.handleExtractLinkCDK)
	mux.HandleFunc("POST /api/accounts/{id}/totp-setup", s.handleAccountTotpSetup)
	mux.HandleFunc("GET /api/accounts/totp-setup-log", s.handleAccountTotpSetupLog)
	mux.HandleFunc("POST /api/accounts/totp-setup-bulk", s.handleTotpSetupBulk)
	mux.HandleFunc("POST /api/accounts/change-email-bulk", s.handleEmailChangeBulk)
	mux.HandleFunc("POST /api/accounts/{id}/change-email", s.handleChangeEmail)
	mux.HandleFunc("POST /api/accounts/password-setup-bulk", s.handlePasswordSetupBulk)
	mux.HandleFunc("POST /api/accounts/password-setup-all-missing", s.handlePasswordSetupAllMissing)
	mux.HandleFunc("POST /api/accounts/refresh-expired-at", s.handleRefreshExpiredAt)
	mux.HandleFunc("POST /api/accounts/probe-mail-link", s.handleProbeMailLink)
	mux.HandleFunc("POST /api/accounts/probe-mail-link-bulk", s.handleProbeMailLink)
	mux.HandleFunc("GET /api/accounts/registration-pending", s.handleRegistrationPending)
	mux.HandleFunc("POST /api/accounts/registration-resume", s.handleRegistrationResume)

	// ---- 账号安全与密码操作 (对应账号页全部工具栏与下拉菜单) ----
	mux.HandleFunc("POST /api/accounts/{id}/password", s.handleAccountSetPassword)
	mux.HandleFunc("POST /api/accounts/{id}/verify-password", s.handleAccountVerifyPassword)
	mux.HandleFunc("POST /api/accounts/verify-passwords-bulk", s.handleVerifyPasswordsBulk)
	mux.HandleFunc("GET /api/accounts/verify-passwords-bulk/status", s.handleVerifyPasswordsBulkStatus)
	mux.HandleFunc("POST /api/accounts/{id}/password-change", s.handleAccountPasswordChange)
	mux.HandleFunc("GET /api/accounts/{id}/password-change/status", s.handleAccountPasswordChangeStatus)
	mux.HandleFunc("GET /api/accounts/{id}/password-change-log", s.handleAccountPasswordChangeLog)
	mux.HandleFunc("POST /api/accounts/{id}/totp-rotate", s.handleAccountTotpRotate)
	mux.HandleFunc("POST /api/accounts/{id}/password-setup", s.handleAccountPasswordSetup)
	mux.HandleFunc("POST /api/accounts/{id}/password-setup-protocol", s.handleAccountPasswordSetupProtocol)
	mux.HandleFunc("GET /api/accounts/{id}/password-setup-protocol/status", s.handleAccountPasswordSetupProtocolStatus)
	mux.HandleFunc("POST /api/accounts/{id}/password-setup-protocol/resume", s.handleAccountPasswordSetupProtocolResume)
	mux.HandleFunc("POST /api/accounts/{id}/password-setup-protocol/challenge", s.handleAccountPasswordSetupProtocolChallenge)
	mux.HandleFunc("POST /api/accounts/{id}/password-setup-protocol/cancel", s.handleAccountPasswordSetupProtocolCancel)
	mux.HandleFunc("GET /api/accounts/{id}/password-setup-log", s.handleAccountPasswordSetupLog)
	mux.HandleFunc("GET /api/accounts/password-setup-bulk/status", s.handlePasswordSetupBulkStatus)
	mux.HandleFunc("GET /api/accounts/password-setup-all-missing/status", s.handlePasswordSetupAllMissingStatus)
	mux.HandleFunc("POST /api/accounts/password-setup-all-missing/cancel", s.handlePasswordSetupAllMissingCancel)
	mux.HandleFunc("GET /api/accounts/{id}/change-email-log", s.handleAccountChangeEmailLog)
	mux.HandleFunc("GET /api/accounts/live-check-log", s.handleAccountsLiveCheckLog)
	mux.HandleFunc("GET /api/accounts/inspections", s.handleAccountInspections)
	mux.HandleFunc("GET /api/accounts/inspections/{id}/failures", s.handleAccountInspectionFailures)
	mux.HandleFunc("GET /account-inspections", s.handleInspectionHistoryPage)
	mux.HandleFunc("POST /api/accounts/codex-agent", s.handleAccountsCodexAgent)
	mux.HandleFunc("POST /api/accounts/codex-agent-bulk", s.handleAccountsCodexAgentBulk)
	mux.HandleFunc("POST /api/accounts/codex-agent/upload-sub2-bulk", s.handleAccountsCodexAgentUploadSub2Bulk)
	mux.HandleFunc("POST /api/accounts/{id}/codex-agent/upload-sub2", s.handleAccountCodexAgentUploadSub2)
	mux.HandleFunc("GET /api/accounts/{id}/codex-agent/download", s.handleAccountCodexAgentDownload)
	mux.HandleFunc("POST /api/accounts/codex-agent/download-bulk", s.handleAccountsCodexAgentDownloadBulk)
	mux.HandleFunc("POST /api/accounts/download-cpa-bulk", s.handleAccountsDownloadCPABulk)
	mux.HandleFunc("POST /api/accounts/session-json/download-bulk", s.handleAccountsSessionJSONDownloadBulk)
	mux.HandleFunc("GET /api/downloads/{id}", s.handleDownloadFetch)
	mux.HandleFunc("POST /api/codex/download-bulk", s.handleCodexDownloadBulk)
	mux.HandleFunc("POST /api/cloudmail/domains", s.handleCloudmailDomains)
	mux.HandleFunc("POST /api/cloudmail/gen-token", s.handleCloudmailGenToken)
	mux.HandleFunc("GET /api/mailcode/catalog", s.handleMailCodeCatalog)
	mux.HandleFunc("GET /api/manual-otp", s.handleManualOTPGet)
	mux.HandleFunc("POST /api/manual-otp", s.handleManualOTPPost)

	// ---- 域名邮箱池（Cloudflare 域名邮箱模式）----
	mux.HandleFunc("GET /api/domain-pool", s.handleDomainPool)
	mux.HandleFunc("POST /api/domain-pool/status", s.handleDomainPoolStatus)
	mux.HandleFunc("POST /api/domain-pool/delete", s.handleDomainPoolDelete)

	// ---- 配置编辑 (index.html 配置 Tab) ----
	mux.HandleFunc("GET /api/config", s.handleConfigGet)
	mux.HandleFunc("POST /api/config", s.handleConfigPost)

	// ---- Codex 授权 (index.html Codex Tab) ----
	mux.HandleFunc("GET /api/codex", s.handleCodexList)
	mux.HandleFunc("GET /api/codex/download/{fname}", s.handleCodexDownload)
	mux.HandleFunc("GET /api/codex/download-from-cpa/{fname}", s.handleCodexDownloadFromCPA)
	mux.HandleFunc("POST /api/codex/download-bulk-from-cpa", s.handleCodexDownloadBulkFromCPA)
	mux.HandleFunc("POST /api/codex/delete", s.handleCodexDelete)
	mux.HandleFunc("POST /api/codex/delete-bulk", s.handleCodexDeleteBulk)
	mux.HandleFunc("POST /api/codex/archive", s.handleCodexArchive)
	mux.HandleFunc("POST /api/codex/archive-bulk", s.handleCodexArchiveBulk)
	mux.HandleFunc("POST /api/codex/retry", s.handleCodexRetry)
	mux.HandleFunc("POST /api/codex/retry-bulk", s.handleCodexRetryBulk)
	mux.HandleFunc("POST /api/codex/stop", s.handleCodexStop)
	mux.HandleFunc("POST /api/codex/stop-bulk", s.handleCodexStop)
	mux.HandleFunc("GET /api/codex/retry-log", s.handleCodexRetryLog)
	mux.HandleFunc("POST /api/codex/sync-cpa", s.handleCodexSyncCPA)
	mux.HandleFunc("POST /api/codex/reset-export", s.handleCodexResetExport)
	mux.HandleFunc("POST /api/codex/reset-retrying", s.handleCodexResetRetrying)

	// ---- 扩展探测接口 ----
	mux.HandleFunc("GET /api/roxy/workspaces", s.handleRoxyWorkspaces)
	mux.HandleFunc("GET /api/diagnostics/probes", s.handleDiagnosticsProbes)

	s.mux = mux
	return s.auth.middleware(mux)
}

// -----------------------------------------------------------------------------
// 页面与登录
// -----------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, "index.html")
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.serveEmbedded(w, "login.html")
}

func (s *Server) serveEmbedded(w http.ResponseWriter, name string) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	cfg := config.Current()
	diskPath := filepath.Join(cfg.Root, "internal", "web", "static", name)
	if data, err := os.ReadFile(diskPath); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
		return
	}
	if data, err := s.static.ReadFile("static/" + name); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fallbackPage(name, s.version)))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if !hmacEqual(body.Code, s.auth.code) {
		fail(w, http.StatusUnauthorized, "授权码错误")
		return
	}
	s.auth.issueCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// -----------------------------------------------------------------------------
// 概览
// -----------------------------------------------------------------------------

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accCount, _ := s.store.CountAccounts(ctx)
	pool, _ := s.store.SummarizeEmailPool(ctx, "")
	domainPool, _ := s.store.SummarizeEmailPool(ctx, "cloudflare_domain")
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":          accCount,
		"outlook_total":     pool.Total,
		"outlook_available": pool.Available,
		"outlook_used":      pool.Used,
		"outlook_failed":    pool.Failed,
		"domain_total":      domainPool.Total,
		"domain_available":  domainPool.Available,
		"domain_used":       domainPool.Used,
		"domain_failed":     domainPool.Failed,
		"active_jobs":       s.pool.Active(),
		"workers":           s.pool.Width(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": s.version, "time": nowRFC3339(),
	})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "服务重启信号已收到，即将重新编译并启动"})
	if s.onRestart != nil {
		go func() {
			time.Sleep(300 * time.Millisecond)
			s.onRestart()
		}()
	}
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	type drv struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
	}
	drivers := make([]drv, 0)
	for _, d := range s.drivers.Names() {
		driver, ok := s.drivers.Lookup(d)
		isImpl := ok
		if ok {
			_, isUnimpl := driver.(*register.Unimplemented)
			isImpl = !isUnimpl
		}
		drivers = append(drivers, drv{Name: d, Available: isImpl})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"drivers":         drivers,
		"mail_sources":    s.mails.Names(),
		"sentinel_solver": cfg.SentinelSolver,
		"promo_check":     cfg.PromoCheckDriver,
		"version":         s.version,
	})
}

// -----------------------------------------------------------------------------
// 注册任务 (Jobs)
// -----------------------------------------------------------------------------

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	pageSize := atoiDefault(q.Get("page_size"), 50)
	jobs, total, err := s.store.ListJobs(r.Context(), q.Get("status"), page, pageSize)
	if err != nil {
		fail(w, http.StatusInternalServerError, "查询任务失败: "+err.Error())
		return
	}
	statusCounts, _ := s.store.GetJobStatusCounts(r.Context())

	items := make([]map[string]any, len(jobs))
	for i, j := range jobs {
		items[i] = compactJob(j)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"items":         items,
		"total":         total,
		"page":          page,
		"page_size":     pageSize,
		"status_counts": statusCounts,
	})
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Count       int    `json:"count"`
		Workers     int    `json:"workers"`
		Driver      string `json:"driver"`
		EmailSource string `json:"email_source"`
		Email       string `json:"email"`
		Proxy       string `json:"proxy"`
		BatchID     string `json:"batch_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if body.Count <= 0 {
		body.Count = 1
	}
	if body.Workers > 0 {
		s.pool.SetWidth(body.Workers)
	}
	batchID := strings.TrimSpace(body.BatchID)
	if batchID == "" {
		batchID = job.NewBatchID()
	}
	ids, err := s.pool.SubmitWithOptions(r.Context(), job.JobOptions{
		Count:       body.Count,
		EmailSource: body.EmailSource,
		Email:       body.Email,
		Proxy:       body.Proxy,
		Driver:      body.Driver,
		BatchID:     batchID,
	})
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"batch_id":  batchID,
		"job_ids":   ids,
		"submitted": len(ids),
		"workers":   s.pool.Width(),
	})
}

func (s *Server) handleJobStop(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id == 0 {
		fail(w, http.StatusBadRequest, "非法任务 ID")
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	result, err := s.pool.Stop(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "停止任务失败: "+err.Error())
		return
	}
	if !result.Exists {
		fail(w, http.StatusNotFound, "任务不存在")
		return
	}
	message := "已发送停止信号"
	switch result.Status {
	case domain.JobCancelled:
		message = "排队任务已取消"
	case domain.JobStopped:
		message = "任务已停止"
	case domain.JobStopping:
		message = "已发送停止信号，等待任务安全收尾"
	default:
		message = "任务已结束，无需停止"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"job_id":  id,
		"status":  result.Status,
		"changed": result.Changed,
		"force":   body.Force,
		"message": message,
	})
}

func (s *Server) handleJobDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id == 0 {
		fail(w, http.StatusBadRequest, "非法任务 ID")
		return
	}
	_ = s.store.DeleteJob(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job_id": id})
}

func (s *Server) handleJobsDeleteBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs    []int64 `json:"ids"`
		JobIDs []int64 `json:"job_ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.IDs
	if len(ids) == 0 {
		ids = body.JobIDs
	}
	n, _ := s.store.DeleteJobs(r.Context(), ids)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted_count": n})
}

func (s *Server) handleCancelPending(w http.ResponseWriter, r *http.Request) {
	n, err := s.pool.CancelPending(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "取消失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": n})
}

func (s *Server) handleJobLog(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id == 0 {
		fail(w, http.StatusBadRequest, "缺少任务 ID")
		return
	}
	jobItem, err := s.store.GetJob(r.Context(), id)
	if err != nil || jobItem == nil {
		fail(w, http.StatusNotFound, "任务不存在")
		return
	}
	cfg := config.Current()
	path := filepath.Join(cfg.Root, "logs", "jobs", fmt.Sprintf("job-%d.log", id))
	tail, _ := readTail(path, 64*1024)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"job": compactJob(*jobItem),
		"log": tail,
	})
}

func (s *Server) handleJobRetry(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	oldJob, err := s.store.GetJob(r.Context(), id)
	if err != nil || oldJob == nil {
		fail(w, http.StatusNotFound, "原任务不存在")
		return
	}
	batchID := oldJob.BatchID
	if batchID == "" {
		batchID = job.NewBatchID()
	}
	newIDs, err := s.pool.SubmitWithOptions(r.Context(), job.JobOptions{
		Count:       1,
		EmailSource: oldJob.EmailSource,
		BatchID:     batchID,
	})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job_id": newIDs[0]})
}

func (s *Server) handleJobsRetryBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs     []any `json:"ids"`
		JobIDs  []any `json:"job_ids"`
		Workers any   `json:"workers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	raw := body.JobIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "job_ids 必须是非空数组")
		return
	}
	if len(raw) > 500 {
		fail(w, http.StatusBadRequest, "单次最多重试 500 个任务")
		return
	}
	workers := 1
	if body.Workers != nil {
		switch v := body.Workers.(type) {
		case float64:
			workers = int(v)
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				fail(w, http.StatusBadRequest, "workers 非法")
				return
			}
			workers = n
		default:
			fail(w, http.StatusBadRequest, "workers 非法")
			return
		}
	}
	workers = codexMaxInt(1, workers)
	if workers > codexMaxWorkers {
		workers = codexMaxWorkers
	}

	ctx := r.Context()
	ids, skipped := parseIDList(raw)
	started := make([]map[string]any, 0, len(ids))
	reused := make([]map[string]any, 0)
	for _, id := range ids {
		oldJob, err := s.store.GetJob(ctx, id)
		if err != nil || oldJob == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "任务不存在"})
			continue
		}
		switch oldJob.Status {
		case domain.JobPending, domain.JobRunning, domain.JobStopping:
			skipped = append(skipped, map[string]any{"id": id, "reason": "运行中，不能重试"})
			continue
		case domain.JobFailed, domain.JobStopped, domain.JobCancelled:
			// 可重试终态，继续走下面分支
		default:
			skipped = append(skipped, map[string]any{"id": id, "reason": "当前状态不支持重试：" + string(oldJob.Status)})
			continue
		}

		// 已建号的任务只补跑 Codex，不再重新注册。
		if oldJob.AccountID != nil {
			acc, aerr := s.store.GetAccount(ctx, *oldJob.AccountID)
			if aerr != nil || acc == nil {
				skipped = append(skipped, map[string]any{"id": id, "reason": "已注册账号信息不完整，无法补跑 Codex"})
				continue
			}
			email := strings.TrimSpace(acc.Email)
			if email == "" {
				skipped = append(skipped, map[string]any{"id": id, "reason": "已注册账号信息不完整，无法补跑 Codex"})
				continue
			}
			if payloadString(acc.Payload, "codex_status") == "deactivated" {
				skipped = append(skipped, map[string]any{"id": id, "email": email, "reason": "账号已废号，不能补跑 Codex"})
				continue
			}
			if !s.reservedCodex(ctx, email) {
				skipped = append(skipped, map[string]any{"id": id, "email": email, "reason": "该账号正在补跑 Codex，请稍候"})
				continue
			}
			s.setAccountCodexStatus(ctx, email, codexStatusRetrying, "")
			clearCodexLog(email)
			s.appendCodexLog(email, "INFO", fmt.Sprintf("[任务重试] 源任务 #%d 复用账号，开始补跑 Codex", id))
			go func(em string) {
				defer func() {
					if rec := recover(); rec != nil {
						s.appendCodexLog(em, "ERROR", fmt.Sprintf("[任务重试] 补跑子任务异常：%v", rec))
						s.setAccountCodexStatus(context.Background(), em, "failed", fmt.Sprintf("panic: %v", rec))
						s.releaseCodex(em)
					}
				}()
				s.runCodexWorker(em, "", true)
			}(email)
			reused = append(reused, map[string]any{
				"ok":            true,
				"created":       false,
				"reused":        true,
				"message":       fmt.Sprintf("源任务 #%d 已有账号，已提交 Codex 补跑", id),
				"source_job_id": id,
				"retry_action":  "codex",
				"job":           compactJob(*oldJob),
			})
			continue
		}

		// 未建号：重新入队注册，邮箱可用时复用原邮箱。
		retryEmail := ""
		if oldJob.Email != "" {
			if acc, aerr := s.store.GetAccountByEmail(ctx, oldJob.Email); aerr == nil && acc == nil {
				retryEmail = oldJob.Email
			}
		}
		emailSource := oldJob.EmailSource
		if emailSource == "" {
			emailSource = "outlook"
		}
		batchID := oldJob.BatchID
		if batchID == "" {
			batchID = job.NewBatchID()
		}
		newIDs, serr := s.pool.SubmitWithOptions(ctx, job.JobOptions{
			Count:       1,
			EmailSource: emailSource,
			Email:       retryEmail,
			BatchID:     batchID,
			Payload:     map[string]any{"retry_source_job_id": id},
		})
		if serr != nil || len(newIDs) == 0 {
			reason := "任务调度失败"
			if serr != nil {
				reason = "任务调度失败：" + serr.Error()
			}
			skipped = append(skipped, map[string]any{"id": id, "reason": reason})
			continue
		}
		started = append(started, map[string]any{
			"ok":            true,
			"created":       true,
			"reused":        false,
			"message":       fmt.Sprintf("源任务 #%d 已重新入队注册", id),
			"source_job_id": id,
			"retry_action":  "registration",
			"job_id":        newIDs[0],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"started":       started,
		"started_count": len(started),
		"reused":        reused,
		"reused_count":  len(reused),
		"skipped":       skipped,
		"skipped_count": len(skipped),
		"workers":       workers,
	})
}

// -----------------------------------------------------------------------------
// 邮箱池 (index.html /api/outlook 路由)
// -----------------------------------------------------------------------------

func (s *Server) handleOutlookList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	if source == "" {
		source = "all"
	}
	status := q.Get("status")
	query := q.Get("q")
	page := atoiDefault(q.Get("page"), 1)
	pageSize := atoiDefault(q.Get("page_size"), 50)

	items, total, err := s.store.ListEmails(r.Context(), source, status, query, page, pageSize)
	if err != nil {
		fail(w, http.StatusInternalServerError, "查询邮箱池失败: "+err.Error())
		return
	}
	summary, _ := s.store.SummarizeEmailPool(r.Context(), source)

	decorated := make([]map[string]any, len(items))
	for i, it := range items {
		decorated[i] = decorateEmailItem(it)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"items":     decorated,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"summary":   summary,
	})
}

func (s *Server) handleOutlookImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Source           string `json:"source"`
		Text             string `json:"text"`
		MarkAsRegistered bool   `json:"mark_as_registered"`
		ImapServer       string `json:"imap_server"`
		ImapPort         int    `json:"imap_port"`
		ImapSSL          bool   `json:"imap_ssl"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if body.Source == "" {
		body.Source = "outlook"
	}
	items := parseEmailLines(body.Text, body.Source)
	added, skipped, err := s.store.ImportEmails(r.Context(), items)
	if err != nil {
		fail(w, http.StatusInternalServerError, "导入失败: "+err.Error())
		return
	}
	if body.MarkAsRegistered {
		for _, it := range items {
			_, _ = s.store.InsertAccount(r.Context(), domain.Account{
				Email:  it.Email,
				Status: "registered",
				Payload: map[string]any{
					"imported_as_registered": true,
					"imported_at":            time.Now().Format(time.RFC3339),
				},
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "added": added, "skipped": skipped})
}

func (s *Server) handleOutlookStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email  string `json:"email"`
		Source string `json:"source"`
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	err := s.store.UpdateEmailPoolStatus(r.Context(), body.Email, body.Source, body.Status, body.Note)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleOutlookStatusBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []struct {
			Email  string `json:"email"`
			Source string `json:"source"`
		} `json:"items"`
		Emails []string `json:"emails"`
		Source string   `json:"source"`
		Status string   `json:"status"`
		Note   string   `json:"note"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)

	updatedCount := 0
	if len(body.Items) > 0 {
		for _, it := range body.Items {
			src := it.Source
			if src == "" {
				src = body.Source
			}
			if err := s.store.UpdateEmailPoolStatus(r.Context(), it.Email, src, body.Status, body.Note); err == nil {
				updatedCount++
			}
		}
	} else if len(body.Emails) > 0 {
		n, err := s.store.UpdateEmailPoolStatusBulk(r.Context(), body.Emails, body.Source, body.Status)
		if err == nil {
			updatedCount = int(n)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "updated": updatedCount, "updated_count": updatedCount})
}

func (s *Server) handleOutlookDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email  string `json:"email"`
		Source string `json:"source"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	err := s.store.DeleteEmailPool(r.Context(), body.Email, body.Source)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleOutlookDeleteBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []struct {
			Email  string `json:"email"`
			Source string `json:"source"`
		} `json:"items"`
		Emails []string `json:"emails"`
		Source string   `json:"source"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)

	type delItem struct {
		Email  string `json:"email"`
		Source string `json:"source"`
	}
	var deletedList []delItem

	if len(body.Items) > 0 {
		for _, it := range body.Items {
			src := it.Source
			if src == "" {
				src = body.Source
			}
			if err := s.store.DeleteEmailPool(r.Context(), it.Email, src); err == nil {
				deletedList = append(deletedList, delItem{Email: it.Email, Source: src})
			}
		}
	} else if len(body.Emails) > 0 {
		for _, em := range body.Emails {
			if err := s.store.DeleteEmailPool(r.Context(), em, body.Source); err == nil {
				deletedList = append(deletedList, delItem{Email: em, Source: body.Source})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"deleted":       deletedList,
		"deleted_count": len(deletedList),
	})
}

// -----------------------------------------------------------------------------
// 账号管理 (Accounts)
// -----------------------------------------------------------------------------

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AccountFilter{
		Archived:       q.Get("archived") == "1" || q.Get("archived") == "only",
		OverviewFilter: q.Get("overview_filter"),
		PlanFilter:     q.Get("plan"),
		CodexStatus:    q.Get("codex_status"),
		TOTPFilter:     q.Get("totp_status"),
		Query:          q.Get("q"),
		DateFrom:       q.Get("date_from"),
		DateTo:         q.Get("date_to"),
	}
	f.Page = atoiDefault(q.Get("page"), 1)
	f.PageSize = atoiDefault(q.Get("page_size"), 50)

	page, err := s.store.ListAccounts(r.Context(), f)
	if err != nil {
		fail(w, http.StatusInternalServerError, "查询账号失败: "+err.Error())
		return
	}
	items := make([]map[string]any, len(page.Items))
	for i, a := range page.Items {
		items[i] = compactAccount(a)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"items":     items,
		"total":     page.Total,
		"page":      page.Page,
		"page_size": page.PageSize,
		"compact":   true,
	})
}

func (s *Server) handleAccountSecret(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	field := r.URL.Query().Get("field")
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	val := extractAccountSecret(acc, field)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "field": field, "value": val})
}

func (s *Server) handleAccountsSecretBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
		Field      string  `json:"field"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	accounts, _ := s.store.GetAccountsByIDs(r.Context(), body.AccountIDs)
	type pair struct {
		ID    int64  `json:"id"`
		Value string `json:"value"`
	}
	values := make([]pair, 0, len(body.AccountIDs))
	for _, id := range body.AccountIDs {
		if acc := accounts[id]; acc != nil {
			values = append(values, pair{ID: id, Value: extractAccountSecret(acc, body.Field)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "values": values})
}

func (s *Server) handleAccountArchive(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	var body struct {
		Archived bool `json:"archived"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	_ = s.store.UpdateAccountArchived(r.Context(), id, body.Archived)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (s *Server) handleAccountsArchiveBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any `json:"account_ids"`
		IDs        []any `json:"ids"`
		Archived   *bool `json:"archived"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > 5000 {
		fail(w, http.StatusBadRequest, "单次最多归档 5000 个账号")
		return
	}
	archived := true
	if body.Archived != nil {
		archived = *body.Archived
	}
	ctx := r.Context()
	ids, skipped := parseIDList(raw)
	updated := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		if acc.Archived == archived {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "状态未变化"})
			continue
		}
		if err := s.store.UpdateAccountArchived(ctx, id, archived); err != nil {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "写入失败: " + err.Error()})
			continue
		}
		updated = append(updated, map[string]any{"id": id, "email": acc.Email, "archived": archived})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"updated":       updated,
		"updated_count": len(updated),
		"archived":      archived,
		"skipped":       skipped,
		"skipped_count": len(skipped),
	})
}

func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	_ = s.store.DeleteAccount(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (s *Server) handleAccountsDeleteBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs        []any `json:"ids"`
		AccountIDs []any `json:"account_ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > 5000 {
		fail(w, http.StatusBadRequest, "单次最多删除 5000 个账号")
		return
	}
	ctx := r.Context()
	ids, skipped := parseIDList(raw)
	deleted := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		if err := s.store.DeleteAccount(ctx, id); err != nil {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "删除失败: " + err.Error()})
			continue
		}
		deleted = append(deleted, map[string]any{"id": id, "email": acc.Email})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"deleted":       deleted,
		"deleted_count": len(deleted),
		"skipped":       skipped,
		"skipped_count": len(skipped),
	})
}

func (s *Server) handleAccountNote(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	_ = s.store.UpdateAccountNote(r.Context(), id, body.Note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "note": body.Note})
}

func (s *Server) handleAccountsNoteBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any  `json:"account_ids"`
		IDs        []any  `json:"ids"`
		Note       string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > 5000 {
		fail(w, http.StatusBadRequest, "单次最多备注 5000 个账号")
		return
	}
	if len(body.Note) > 2000 {
		fail(w, http.StatusBadRequest, "备注最多 2000 个字符")
		return
	}
	ctx := r.Context()
	ids, skipped := parseIDList(raw)
	updated := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil || acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		if err := s.store.UpdateAccountNote(ctx, id, body.Note); err != nil {
			skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "写入失败: " + err.Error()})
			continue
		}
		updated = append(updated, map[string]any{"id": id, "email": acc.Email, "note": body.Note})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"updated":       updated,
		"updated_count": len(updated),
		"skipped":       skipped,
		"skipped_count": len(skipped),
	})
}

func (s *Server) getProxyForAccount(acc *domain.Account) string {
	cfg := config.Current()
	if cfg.NoProxy {
		return ""
	}
	if len(cfg.ProxyPool) > 0 {
		return config.NormalizeProxyURL(cfg.ProxyPool[time.Now().UnixNano()%int64(len(cfg.ProxyPool))])
	}
	if cfg.ProtocolProxy != "" {
		return config.NormalizeProxyURL(cfg.ProtocolProxy)
	}
	if acc != nil && acc.Payload != nil {
		if p, ok := acc.Payload["proxy_used"].(string); ok && p != "" {
			return config.NormalizeProxyURL(p)
		}
	}
	return ""
}

// getProxyForPromo 优先使用套餐探测专用代理，其次复用账号注册时的代理，
// 保证按注册地区判断优惠；最后才回退到全局代理池。
func (s *Server) getProxyForPromo(acc *domain.Account) string {
	cfg := config.Current()
	if cfg.NoProxy {
		return ""
	}
	if p := strings.TrimSpace(cfg.PlanCheckProxy); p != "" {
		return config.NormalizeProxyURL(p)
	}
	if acc != nil && acc.Payload != nil {
		if p, ok := acc.Payload["proxy_used"].(string); ok && strings.TrimSpace(p) != "" {
			return config.NormalizeProxyURL(p)
		}
	}
	if len(cfg.ProxyPool) > 0 {
		return config.NormalizeProxyURL(cfg.ProxyPool[time.Now().UnixNano()%int64(len(cfg.ProxyPool))])
	}
	if cfg.ProtocolProxy != "" {
		return config.NormalizeProxyURL(cfg.ProtocolProxy)
	}
	return ""
}

func computePlanStatusRevision(items []map[string]any, total int64) string {
	h := sha256.New()
	fmt.Fprintf(h, "total:%d;", total)
	for _, it := range items {
		id, _ := it["id"]
		status, _ := it["status"]
		plan, _ := it["plan_type"]
		planSt, _ := it["plan_check_status"]
		planAt, _ := it["plan_checked_at"]
		liveSt, _ := it["live_check_status"]
		liveAt, _ := it["live_checked_at"]
		atExp, _ := it["token_expired"]
		hasAt, _ := it["has_access_token"]
		hasPw, _ := it["password_saved"]
		paySt, _ := it["payment_check_status"]
		payTxt, _ := it["payment_methods_text"]
		codexSt, _ := it["codex_status"]
		fmt.Fprintf(h, "i:%v,s:%v,p:%v,ps:%v,pa:%v,ls:%v,la:%v,te:%v,ha:%v,hp:%v,pays:%v,payt:%v,cx:%v;",
			id, status, plan, planSt, planAt, liveSt, liveAt, atExp, hasAt, hasPw, paySt, payTxt, codexSt)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *Server) handlePlanCheckStatus(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AccountFilter{
		Archived:       q.Get("archived") == "1" || q.Get("archived") == "only",
		OverviewFilter: q.Get("overview_filter"),
		PlanFilter:     q.Get("plan"),
		CodexStatus:    q.Get("codex_status"),
		TOTPFilter:     q.Get("totp_status"),
		Query:          q.Get("q"),
		DateFrom:       q.Get("date_from"),
		DateTo:         q.Get("date_to"),
	}
	f.Page = atoiDefault(q.Get("page"), 1)
	f.PageSize = atoiDefault(q.Get("page_size"), 50)

	page, _ := s.store.ListAccounts(r.Context(), f)
	items := make([]map[string]any, len(page.Items))
	for i, a := range page.Items {
		items[i] = compactAccount(a)
	}

	summaryData, _ := s.store.GetAccountSummary(r.Context(), f.Archived)

	summary := map[string]any{
		"total":                   summaryData.Total,
		"password_saved":          summaryData.PasswordSaved,
		"at_valid":                summaryData.AtValid,
		"at_missing":              summaryData.AtMissing,
		"at_present":              summaryData.AtPresent,
		"at_expired":              summaryData.AtExpired,
		"free":                    summaryData.Free,
		"plus":                    summaryData.Plus,
		"registration_incomplete": summaryData.RegistrationIncomplete,
		"registration_recovered":  summaryData.RegistrationRecovered,
		"registering":             summaryData.Registering,
		"interrupted":             summaryData.Interrupted,
		"eligible":                summaryData.Eligible,
		"ineligible":              summaryData.Ineligible,
		"eligibility_unknown":     summaryData.EligibilityUnknown,
		"queued":                  summaryData.Queued,
		"running":                 summaryData.Running,
		"success":                 summaryData.Success,
		"failed":                  summaryData.Failed,
		"unchecked":               summaryData.Unchecked,
		"live":                    summaryData.Live,
		"live_failed":             summaryData.LiveFailed,
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"items":     items,
		"total":     page.Total,
		"page":      page.Page,
		"page_size": page.PageSize,
		"summary":   summary,
		"revision":  computePlanStatusRevision(items, page.Total),
		"queue":     map[string]any{"workers": 2, "active": 0, "queued": 0, "min_interval": 1.0, "jitter": 0.8},
	})
}

// accountCheckInfo 汇总 accounts/check 的套餐与促销解析结果，字段与上游
// parse_accounts_check 对齐，供后续持久化到账号 payload。
type accountCheckInfo struct {
	PlanType                      string
	TrialEligible                 bool
	TrialOfferKind                string
	TrialOfferPlan                string
	TrialCampaignID               string
	TrialTitle                    string
	TrialSummary                  string
	TrialDiscountPercentage       any
	TrialDurationNumPeriods       any
	TrialDurationPeriod           any
	TrialPromotionTypeLabel       any
	DiscountOfferEligible         bool
	DiscountOfferCampaignID       string
	DiscountOfferTitle            string
	DiscountOfferPercentage       any
	Has50Discount                 bool
	EligiblePromoCampaigns        map[string]any
	EntitlementDiscountType       any
	EntitlementDiscountAmount     any
	EntitlementDiscountCampaignID string
}

const (
	trialKindPlus    = "plus"
	trialKindGo      = "go"
	trialKindGeneric = "generic"
)

// classifyTrialOffer separates a generic free/trial campaign from the plan it
// applies to. Campaign IDs are the strongest signal; title and plan metadata
// cover responses that use opaque campaign IDs.
func classifyTrialOffer(campaign map[string]any) (kind, plan string) {
	if campaign == nil {
		return "", ""
	}
	parts := []string{strVal(campaign["id"])}
	if meta := asMapAny(campaign["metadata"]); meta != nil {
		for _, key := range []string{
			"title", "summary", "plan", "plan_id", "plan_type", "plan_name",
			"product", "product_id", "product_name", "promotion_type_label",
		} {
			parts = append(parts, strVal(meta[key]))
		}
	}
	text := strings.ToLower(strings.Join(parts, " "))

	for _, signal := range []string{
		"go-1-month-free", "chatgptgoplan", "chatgpt_go_plan", "chatgpt go",
		"goplan", " go free", "go trial", "try go", "go plan",
	} {
		if strings.Contains(text, signal) {
			return trialKindGo, "chatgptgoplan"
		}
	}
	for _, signal := range []string{
		"plus-1-month-free", "chatgptplusplan", "chatgpt_plus_plan", "chatgpt plus",
		"plus trial", "try plus", "plus plan",
	} {
		if strings.Contains(text, signal) {
			return trialKindPlus, "chatgptplusplan"
		}
	}
	return trialKindGeneric, ""
}

func trialOfferPriority(kind string) int {
	switch kind {
	case trialKindPlus:
		return 3
	case trialKindGo:
		return 2
	case trialKindGeneric:
		return 1
	default:
		return 0
	}
}

func preferredTrialOffer(current, candidate map[string]any) map[string]any {
	if candidate == nil {
		return current
	}
	if current == nil {
		return candidate
	}
	currentKind, _ := classifyTrialOffer(current)
	candidateKind, _ := classifyTrialOffer(candidate)
	if trialOfferPriority(candidateKind) > trialOfferPriority(currentKind) {
		return candidate
	}
	return current
}

func setPlusTrial(info *accountCheckInfo, campaignID, title string) {
	info.TrialEligible = true
	info.TrialOfferKind = trialKindPlus
	info.TrialOfferPlan = "chatgptplusplan"
	info.TrialCampaignID = campaignID
	info.TrialTitle = title
}

func clearPlusTrial(info *accountCheckInfo) {
	if info.TrialOfferKind != trialKindPlus {
		return
	}
	info.TrialEligible = false
	info.TrialOfferKind = ""
	info.TrialOfferPlan = ""
	info.TrialCampaignID = ""
	info.TrialTitle = ""
	info.TrialSummary = ""
	info.TrialDiscountPercentage = nil
	info.TrialDurationNumPeriods = nil
	info.TrialDurationPeriod = nil
	info.TrialPromotionTypeLabel = nil
}

func asMapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// promotionKind 对齐上游 _promotion_kind：只按明确证据把活动分成试用/折扣/无关。
func promotionKind(key string, campaign map[string]any) string {
	meta := asMapAny(campaign["metadata"])
	var discount map[string]any
	var percentage *float64
	if meta != nil {
		discount = asMapAny(meta["discount"])
	}
	if discount != nil {
		if f, ok := toFloat(discount["percentage"]); ok {
			percentage = &f
		}
	}

	parts := []string{strings.ToLower(key)}
	if id := strVal(campaign["id"]); id != "" {
		parts = append(parts, strings.ToLower(id))
	}
	if meta != nil {
		if t := strVal(meta["title"]); t != "" {
			parts = append(parts, strings.ToLower(t))
		}
		if l := strVal(meta["promotion_type_label"]); l != "" {
			parts = append(parts, strings.ToLower(l))
		}
	}
	name := strings.Join(parts, " ")

	if percentage != nil && *percentage >= 100 {
		return "trial"
	}
	if (percentage != nil && *percentage > 0 && *percentage < 100) ||
		strings.Contains(name, "pct-off") || strings.Contains(name, "percent-off") ||
		strings.Contains(name, "discount") || strings.Contains(name, "折扣") || strings.Contains(name, "折") {
		return "discount"
	}
	if strings.Contains(name, "free") || strings.Contains(name, "trial") ||
		strings.Contains(name, "免费") || strings.Contains(name, "试用") {
		return "trial"
	}
	return ""
}

// promotionExpired 判断活动是否已过期；无法解析时间时按未过期处理。
func promotionExpired(exp any, nowTs float64) bool {
	switch v := exp.(type) {
	case float64:
		return v < nowTs
	case string:
		s := strings.TrimSpace(v)
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
			t, err := time.Parse(layout, s)
			if err != nil {
				continue
			}
			return float64(t.Unix()) < nowTs
		}
	}
	return false
}

// extractTrialAndDiscount 对齐上游 extract_trial_and_discount：从各类促销来源里
// 分别找出第一个「试用」与第一个「折扣」活动，并忽略已过期活动。
func extractTrialAndDiscount(item map[string]any) (trial, discount map[string]any) {
	type candidate struct {
		key  string
		camp map[string]any
	}
	var candidates []candidate

	switch promos := item["eligible_promo_campaigns"].(type) {
	case map[string]any:
		for k, v := range promos {
			if c, ok := v.(map[string]any); ok {
				candidates = append(candidates, candidate{strings.ToLower(k), c})
			}
		}
	case []any:
		for i, v := range promos {
			if c, ok := v.(map[string]any); ok {
				key := strings.ToLower(strVal(c["id"]))
				if key == "" || key == "<nil>" {
					key = fmt.Sprintf("%d", i)
				}
				candidates = append(candidates, candidate{key, c})
			}
		}
	}

	addPromos := func(src any) {
		m := asMapAny(src)
		for k, v := range m {
			if c, ok := v.(map[string]any); ok {
				candidates = append(candidates, candidate{strings.ToLower(k), c})
			}
		}
	}
	addPromos(item["promos"])
	addPromos(asMapAny(item["account"])["promos"])

	nowTs := float64(time.Now().Unix())
	for _, c := range candidates {
		meta := asMapAny(c.camp["metadata"])
		var exp any
		if meta != nil {
			if d := asMapAny(meta["discount"]); d != nil {
				exp = d["expires_at"]
			}
			if exp == nil {
				exp = meta["expires_at"]
			}
		}
		if exp != nil && promotionExpired(exp, nowTs) {
			continue
		}
		switch promotionKind(c.key, c.camp) {
		case "trial":
			trial = preferredTrialOffer(trial, c.camp)
		case "discount":
			if discount == nil {
				discount = c.camp
			}
		}
	}

	// entitlement.discount 带 promo_campaign_id 时也参与分类。
	if ent := asMapAny(item["entitlement"]); ent != nil {
		if d := asMapAny(ent["discount"]); d != nil {
			if pid := strVal(d["promo_campaign_id"]); pid != "" {
				ec := map[string]any{"id": pid, "metadata": map[string]any{"discount": d}}
				switch promotionKind("", ec) {
				case "trial":
					trial = preferredTrialOffer(trial, ec)
				case "discount":
					if discount == nil {
						discount = ec
					}
				}
			}
		}
	}

	if trial == nil {
		if oneClick, ok := item["one_click_trial_eligible"].(bool); ok && oneClick {
			trial = map[string]any{"id": "one_click_trial", "metadata": map[string]any{"title": "One-click trial"}}
		}
	}
	return trial, discount
}

func is50Discount(campaign map[string]any) bool {
	meta := asMapAny(campaign["metadata"])
	var discount map[string]any
	if meta != nil {
		discount = asMapAny(meta["discount"])
	}
	if discount != nil {
		if f, ok := toFloat(discount["percentage"]); ok && f == 50 {
			return true
		}
	}
	title := ""
	if meta != nil {
		title = strVal(meta["title"])
	}
	return strings.Contains(title, "50") || strings.Contains(strVal(campaign["id"]), "50")
}

func parseAccountsCheck(body []byte) (accountCheckInfo, error) {
	var info accountCheckInfo
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return info, err
	}
	info.PlanType = "free"

	rawAccounts, ok := data["accounts"].(map[string]any)
	if !ok || len(rawAccounts) == 0 {
		return info, nil
	}

	for _, rawItem := range rawAccounts {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		account := asMapAny(item["account"])
		entitlement := asMapAny(item["entitlement"])

		accountPlan := ""
		subscriptionPlan := ""
		if account != nil {
			if pt := strVal(account["plan_type"]); pt != "" {
				accountPlan = strings.ToLower(pt)
				info.PlanType = accountPlan
			}
		}
		if entitlement != nil {
			if hasActive, ok := entitlement["has_active_subscription"].(bool); ok && hasActive {
				info.PlanType = "plus"
			}
			if sp := strVal(entitlement["subscription_plan"]); sp != "" {
				subscriptionPlan = strings.ToLower(sp)
				if strings.Contains(subscriptionPlan, "plus") {
					info.PlanType = "plus"
				}
			}
			if d := asMapAny(entitlement["discount"]); d != nil {
				info.EntitlementDiscountType = d["discount_type"]
				info.EntitlementDiscountAmount = d["amount"]
				info.EntitlementDiscountCampaignID = strVal(d["promo_campaign_id"])
			}
		}

		isFree := accountPlan == "free" || subscriptionPlan == "chatgptfreeplan"
		trialCampaign, discountCampaign := extractTrialAndDiscount(item)

		info.TrialEligible = trialCampaign != nil
		if trialCampaign != nil {
			info.TrialOfferKind, info.TrialOfferPlan = classifyTrialOffer(trialCampaign)
			info.TrialCampaignID = strVal(trialCampaign["id"])
			if meta := asMapAny(trialCampaign["metadata"]); meta != nil {
				info.TrialTitle = strVal(meta["title"])
				info.TrialSummary = strVal(meta["summary"])
				info.TrialPromotionTypeLabel = meta["promotion_type_label"]
				if d := asMapAny(meta["discount"]); d != nil {
					info.TrialDiscountPercentage = d["percentage"]
				}
				if dur := asMapAny(meta["duration"]); dur != nil {
					info.TrialDurationNumPeriods = dur["num_periods"]
					info.TrialDurationPeriod = dur["period"]
				}
			}
		}

		info.DiscountOfferEligible = discountCampaign != nil
		if discountCampaign != nil {
			info.DiscountOfferCampaignID = strVal(discountCampaign["id"])
			if meta := asMapAny(discountCampaign["metadata"]); meta != nil {
				info.DiscountOfferTitle = strVal(meta["title"])
				if d := asMapAny(meta["discount"]); d != nil {
					info.DiscountOfferPercentage = d["percentage"]
				}
			}
			info.Has50Discount = is50Discount(discountCampaign)
		}

		if isFree {
			if promos, ok := item["eligible_promo_campaigns"].(map[string]any); ok {
				info.EligiblePromoCampaigns = promos
			}
		}
		break
	}
	return info, nil
}

// probePlanRegion 对指定代理与结算国家跑一轮 accounts/check + 券判定 + 结账探测，
// 返回该地区的结果 map（不落库）。billingCountry 为空时按代理字符串推断。
func (s *Server) probePlanRegion(ctx context.Context, token, proxy, billingCountry, deviceID string, image protocol.BrowserProfile) map[string]any {
	res := map[string]any{"ok": false}
	sess, err := protocol.NewSession(protocol.SessionOptions{
		UserAgent:   image.UserAgent,
		Language:    image.Language,
		Timezone:    image.Timezone,
		Screen:      image.Screen,
		DeviceID:    deviceID,
		Proxy:       proxy,
		ProfileName: image.TLSProfile,
	})
	if err != nil {
		res["error"] = "创建网络会话失败: " + err.Error()
		return res
	}
	defer sess.Close()

	headers := map[string]string{
		"Authorization":         "Bearer " + token,
		"Accept":                "application/json",
		"Referer":               "https://chatgpt.com/",
		"x-openai-target-path":  "/backend-api/accounts/check/v4-2023-04-27",
		"x-openai-target-route": "/backend-api/accounts/check/v4-2023-04-27",
	}
	resp, err := sess.RequestCtx(ctx, http.MethodGet, "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", "", headers)
	if err != nil {
		res["error"] = "网络连接失败: " + err.Error()
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		res["error"] = "AT已过期/失效，请手动查活或刷新"
		res["token_expired"] = true
		return res
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res["error"] = fmt.Sprintf("HTTP %d 访问受限（请检查代理）", resp.StatusCode)
		return res
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	info, err := parseAccountsCheck(bodyBytes)
	if err != nil {
		res["error"] = "套餐响应解析失败: " + err.Error()
		return res
	}

	// 官方只读 check_coupon 是「能否真正领 Plus 免费试用」的权威口径，
	// 用它覆盖 accounts/check 里可能偏乐观的促销活动解析。
	claims := tokenClaims(token)
	coupon := checkPlusCouponDirect(ctx, sess, token, claims)
	if coupon.Eligible {
		setPlusTrial(&info, upiTrialCampaignID, fmt.Sprintf("Plus trial (%d days)", coupon.Days))
	} else if coupon.Redeemed {
		res["plus_trial_redeemed"] = true
		clearPlusTrial(&info)
	} else if config.Current().PlanCheckCouponAuthoritative && coupon.State != "" {
		clearPlusTrial(&info)
	}
	res["coupon_state"] = coupon.State

	sentinelToken := ""
	if s.solver != nil {
		sentinelToken = checkoutSentinelToken(ctx, sess, s.solver)
	}

	probeCountry := strings.ToUpper(strings.TrimSpace(billingCountry))
	if probeCountry == "" {
		probeCountry = proxyCountry(proxy)
	}
	if probeCountry == "" {
		probeCountry = "US"
	}
	campaignID := ""
	if info.TrialOfferKind == trialKindPlus && info.TrialCampaignID != "" {
		campaignID = info.TrialCampaignID
	} else if probeCountry == "IN" {
		campaignID = upiTrialCampaignID
	}
	if campaignID != "" {
		probe := probeTrialPaymentMethods(ctx, sess, token, claims, probeCountry, campaignID, sentinelToken, coupon.Eligible)
		for k, v := range probe {
			res[k] = v
		}
		if upiOK, _ := probe["upi_trial_eligible"].(bool); upiOK {
			plusTitle := info.TrialTitle
			if info.TrialOfferKind != trialKindPlus || plusTitle == "" {
				plusTitle = "Plus trial"
			}
			setPlusTrial(&info, campaignID, plusTitle)
		}
	}
	if methods, ok := res["trial_payment_methods"].([]string); !ok || len(methods) == 0 {
		fallback := countryDefaultPaymentMethods[probeCountry]
		if len(fallback) == 0 {
			fallback = []string{"card", "paypal"}
		}
		res["trial_payment_methods"] = fallback
	}

	res["ok"] = true
	res["country"] = probeCountry
	res["plan_type"] = info.PlanType
	res["current_plan_type"] = info.PlanType
	plusTrial := info.TrialOfferKind == trialKindPlus
	goTrial := info.TrialOfferKind == trialKindGo
	res["plus_trial_eligible"] = plusTrial
	res["go_trial_eligible"] = goTrial
	res["trial_offer_kind"] = info.TrialOfferKind
	res["trial_offer_plan"] = info.TrialOfferPlan
	res["trial_campaign_id"] = info.TrialCampaignID
	res["trial_title"] = info.TrialTitle
	res["trial_discount_percentage"] = info.TrialDiscountPercentage
	if plusTrial {
		res["plus_trial_campaign_id"] = info.TrialCampaignID
		res["plus_trial_title"] = info.TrialTitle
		res["plus_trial_summary"] = info.TrialSummary
		res["plus_trial_discount_percentage"] = info.TrialDiscountPercentage
		res["plus_trial_discount_num_periods"] = info.TrialDurationNumPeriods
		res["plus_trial_discount_period"] = info.TrialDurationPeriod
		res["plus_trial_promotion_type_label"] = info.TrialPromotionTypeLabel
	} else {
		res["plus_trial_campaign_id"] = ""
		res["plus_trial_title"] = ""
		res["plus_trial_summary"] = ""
		res["plus_trial_discount_percentage"] = nil
		res["plus_trial_discount_num_periods"] = nil
		res["plus_trial_discount_period"] = nil
		res["plus_trial_promotion_type_label"] = nil
	}
	if goTrial {
		res["go_trial_campaign_id"] = info.TrialCampaignID
		res["go_trial_title"] = info.TrialTitle
		res["go_trial_summary"] = info.TrialSummary
		res["go_trial_discount_percentage"] = info.TrialDiscountPercentage
		res["go_trial_discount_num_periods"] = info.TrialDurationNumPeriods
		res["go_trial_discount_period"] = info.TrialDurationPeriod
	} else {
		res["go_trial_campaign_id"] = ""
		res["go_trial_title"] = ""
		res["go_trial_summary"] = ""
		res["go_trial_discount_percentage"] = nil
		res["go_trial_discount_num_periods"] = nil
		res["go_trial_discount_period"] = nil
	}
	res["discount_offer_eligible"] = info.DiscountOfferEligible
	res["discount_offer_campaign_id"] = info.DiscountOfferCampaignID
	res["discount_offer_title"] = info.DiscountOfferTitle
	res["discount_offer_percentage"] = info.DiscountOfferPercentage
	res["has_50_discount"] = info.Has50Discount
	res["eligible_promo_campaigns"] = info.EligiblePromoCampaigns
	res["discount_type"] = info.EntitlementDiscountType
	res["discount_amount"] = info.EntitlementDiscountAmount
	res["discount_promo_campaign_id"] = info.EntitlementDiscountCampaignID
	return res
}

func (s *Server) applyPlanCheckResult(ctx context.Context, acc *domain.Account, res map[string]any) {
	ok, _ := res["ok"].(bool)
	for k, v := range res {
		if k == "ok" {
			continue
		}
		acc.Payload[k] = v
	}
	if ok {
		acc.Payload["plan_check_status"] = "success"
		acc.Payload["plan_check_error"] = ""
	} else {
		acc.Payload["plan_check_status"] = "failed"
		acc.Payload["plan_check_error"] = strVal(res["error"])
	}
	acc.Payload["plan_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.store.InsertAccount(ctx, *acc)
}

func mergeBestTrialRegion(payload map[string]any, regions map[string]any) {
	var best map[string]any
	bestKind := ""
	for _, raw := range regions {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		if ok, _ := item["ok"].(bool); !ok {
			continue
		}
		kind := strings.ToLower(strVal(item["trial_offer_kind"]))
		if best == nil || trialOfferPriority(kind) > trialOfferPriority(bestKind) {
			best = item
			bestKind = kind
		}
	}

	payload["trial_offer_kind"] = ""
	payload["trial_offer_plan"] = ""
	payload["plus_trial_eligible"] = false
	payload["go_trial_eligible"] = false
	for _, key := range []string{
		"trial_campaign_id", "trial_title", "trial_discount_percentage",
		"plus_trial_campaign_id", "plus_trial_title", "plus_trial_summary",
		"plus_trial_discount_percentage", "plus_trial_discount_num_periods",
		"plus_trial_discount_period", "plus_trial_promotion_type_label",
		"go_trial_campaign_id", "go_trial_title", "go_trial_summary",
		"go_trial_discount_percentage", "go_trial_discount_num_periods",
		"go_trial_discount_period",
	} {
		payload[key] = ""
	}
	if best == nil {
		return
	}
	payload["trial_offer_kind"] = bestKind
	payload["trial_offer_plan"] = best["trial_offer_plan"]
	payload["trial_campaign_id"] = best["trial_campaign_id"]
	payload["trial_title"] = best["trial_title"]
	payload["trial_discount_percentage"] = best["trial_discount_percentage"]
	payload["plus_trial_eligible"] = bestKind == trialKindPlus
	payload["go_trial_eligible"] = bestKind == trialKindGo
	for k, v := range best {
		if strings.HasPrefix(k, "plus_trial_") && k != "plus_trial_eligible" {
			payload[k] = v
		}
		if strings.HasPrefix(k, "go_trial_") && k != "go_trial_eligible" {
			payload[k] = v
		}
	}
}

type countryProxyEntry struct {
	Country string
	Proxy   string
}

func countryProxyEntries() []countryProxyEntry {
	var out []countryProxyEntry
	for _, line := range config.Current().CountryProxies {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		country := ""
		proxy := line
		if idx := strings.Index(line, "="); idx > 0 {
			country = strings.ToUpper(strings.TrimSpace(line[:idx]))
			proxy = strings.TrimSpace(line[idx+1:])
		} else {
			// 未写「国家=」前缀时，从代理串里自动识别（如 miyaip 的 _IN_、1024proxy 的 -region-DE-）。
			country = proxyCountry(proxy)
		}
		if country == "" || proxy == "" {
			continue
		}
		out = append(out, countryProxyEntry{Country: country, Proxy: proxy})
	}
	return out
}

func (s *Server) checkAccountPlan(acc *domain.Account) error {
	if acc == nil || acc.Payload == nil {
		return fmt.Errorf("账号为空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	token, _ := acc.Payload["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		acc.Payload["plan_check_status"] = "failed"
		acc.Payload["plan_check_error"] = "缺少 access_token，请先获取或刷新 AT"
		acc.Payload["plan_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(ctx, *acc)
		return fmt.Errorf("缺少 access_token")
	}

	proxy := s.getProxyForPromo(acc)
	image := accountBrowserProfile(acc, proxy)
	res := s.probePlanRegion(ctx, token, proxy, "", accountDeviceID(acc), image)
	s.applyPlanCheckResult(ctx, acc, res)
	return nil
}

func (s *Server) checkAccountPlanRegions(acc *domain.Account) {
	if acc == nil || acc.Payload == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	token, _ := acc.Payload["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		acc.Payload["plan_check_status"] = "failed"
		acc.Payload["plan_check_error"] = "缺少 access_token，请先获取或刷新 AT"
		acc.Payload["plan_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}

	entries := countryProxyEntries()
	if len(entries) == 0 {
		_ = s.checkAccountPlan(acc)
		return
	}

	deviceID := accountDeviceID(acc)
	image := accountBrowserProfile(acc, s.getProxyForPromo(acc))
	regionResults := map[string]any{}
	anyOK := false
	for _, e := range entries {
		res := s.probePlanRegion(ctx, token, e.Proxy, e.Country, deviceID, image)
		res["country"] = e.Country
		regionResults[e.Country] = res
		if ok, _ := res["ok"].(bool); ok {
			anyOK = true
		}
	}

	acc.Payload["plan_region_results"] = regionResults
	acc.Payload["plan_region_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
	mergeBestTrialRegion(acc.Payload, regionResults)
	if anyOK {
		acc.Payload["plan_check_status"] = "success"
		acc.Payload["plan_check_error"] = ""
	} else {
		acc.Payload["plan_check_status"] = "failed"
		acc.Payload["plan_check_error"] = "所有地区查询均失败"
	}
	acc.Payload["plan_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.store.InsertAccount(ctx, *acc)
}

func (s *Server) handleCheckPlan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountID   int64 `json:"account_id"`
		ID          int64 `json:"id"`
		MultiRegion bool  `json:"multi_region"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	id := body.AccountID
	if id == 0 {
		id = body.ID
	}
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	token, _ := acc.Payload["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		fail(w, http.StatusBadRequest, "账号缺少 access_token，无法查询套餐")
		return
	}
	acc.Payload["plan_check_status"] = "running"
	_, _ = s.store.InsertAccount(r.Context(), *acc)

	if body.MultiRegion {
		go s.checkAccountPlanRegions(acc)
	} else {
		go s.checkAccountPlan(acc)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "套餐查询已加入后台队列",
	})
}

func (s *Server) handleAccountTotpSetup(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	if token, _ := acc.Payload["access_token"].(string); strings.TrimSpace(token) == "" {
		fail(w, http.StatusBadRequest, "账号缺少 access_token：先用「刷新AT (协议)」拿到 AT 再开启 2FA")
		return
	}
	if secret, ok := acc.Payload["totp_secret"].(string); ok && strings.TrimSpace(secret) != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "2FA 已开启，密钥已存在: " + maskSecret(secret),
			"secret":  secret,
		})
		return
	}

	// 同步上下文：调用方等结果，但断连不打断 enroll/activate 链路。
	ctx := context.WithoutCancel(r.Context())
	detached := acc
	done := make(chan struct{})
	var secret string
	var setupErr error
	go func() {
		secret, setupErr = s.runOneTotpSetupCtx(ctx, detached)
		close(done)
	}()
	<-done

	if setupErr != nil {
		fail(w, http.StatusBadRequest, "绑定 2FA 失败: "+setupErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "2FA (TOTP) 绑定成功: " + secret,
		"secret":  secret,
	})
}
func (s *Server) handleAccountTotpSetupLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"log":     "2FA (TOTP) 设置流程已完成",
		"running": false,
	})
}

func (s *Server) handleCheckPlanBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs  []int64 `json:"account_ids"`
		IDs         []int64 `json:"ids"`
		MultiRegion bool    `json:"multi_region"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	queued := 0
	for _, id := range ids {
		acc, err := s.store.GetAccount(r.Context(), id)
		if err == nil && acc != nil {
			token, _ := acc.Payload["access_token"].(string)
			if strings.TrimSpace(token) != "" {
				acc.Payload["plan_check_status"] = "running"
				_, _ = s.store.InsertAccount(r.Context(), *acc)
				if body.MultiRegion {
					go s.checkAccountPlanRegions(acc)
				} else {
					go s.checkAccountPlan(acc)
				}
				queued++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": queued, "started": queued, "started_count": queued})
}

func (s *Server) handleCheckLiveBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
		IDs        []int64 `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	queued := 0
	for _, id := range ids {
		acc, err := s.store.GetAccount(r.Context(), id)
		if err == nil && acc != nil {
			go s.probeAndCheckLive(acc)
			queued++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": queued, "started_count": queued})
}

func (s *Server) probeAndCheckLive(acc *domain.Account) {
	if acc == nil || acc.Payload == nil {
		return
	}
	// 30 秒对"提取会话失败 → 切密码登录 → OAuth 回调 → 取 AT"这条链太短，
	// 一次完整刷新实测 60~140 秒，超时会把 ctx 打断在半路。
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	email := acc.Email
	s.setLiveRunning(email, true)
	defer s.setLiveRunning(email, false)

	s.appendLiveLog(email, fmt.Sprintf("[查活启动] 开始检测账号 #%d (%s) 存活状态...", acc.ID, email))

	at, _ := acc.Payload["access_token"].(string)
	exp, _ := acc.Payload["token_expired"].(bool)

	// 如果没有 AT 或已标记过期，直接走协议刷新
	if at == "" || exp {
		s.appendLiveLog(email, "[查活提示] 账号缺少有效 AT，直接发起协议重新登录换取新 AT...")
		newAT, err := s.refreshAccountToken(ctx, acc)
		if err != nil {
			s.appendLiveLog(email, fmt.Sprintf("[查活结果] ❌ 刷新失败: %v", err))
			acc.Payload["live_check_status"] = "failed"
		} else if newAT != "" {
			s.appendLiveLog(email, "[查活结果] ✅ 协议登录成功，账号存活！")
			acc.Payload["live_check_status"] = "live"
			acc.Payload["token_expired"] = false
		}
		acc.Payload["live_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}

	// 探测已有 AT
	proxy := s.getProxyForAccount(acc)
	sess, err := protocol.NewSession(accountSessionOptions(acc, proxy))
	if err != nil {
		s.appendLiveLog(email, fmt.Sprintf("[查活错误] 无法建立网络会话: %v", err))
		return
	}
	defer sess.Close()

	s.appendLiveLog(email, "[查活步骤1] 向 OpenAI 验证现有 Access Token 有效性...")
	resp, err := sess.RequestCtx(ctx, http.MethodGet, "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", "", map[string]string{
		"Authorization": "Bearer " + at,
		"Accept":        "application/json",
		"Referer":       "https://chatgpt.com/",
	})
	if err != nil {
		s.appendLiveLog(email, fmt.Sprintf("[查活网络告警] 请求超时或网络故障: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		s.appendLiveLog(email, "[查活结果] ✅ 现有 Access Token 经探测确认有效，账号正常存活！")
		acc.Payload["live_check_status"] = "live"
		acc.Payload["token_expired"] = false
		applyTokenExpiry(acc, at)
		acc.Payload["live_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}

	if resp.StatusCode == 401 {
		s.appendLiveLog(email, "[查活提示] ⚠️ 当前 AT 已失效 (HTTP 401)，自动启动协议登录重新换取 AT...")
		acc.Payload["token_expired"] = true
		newAT, refErr := s.refreshAccountToken(ctx, acc)
		if refErr != nil {
			s.appendLiveLog(email, fmt.Sprintf("[查活结果] ❌ 协议重新登录失败: %v", refErr))
			acc.Payload["live_check_status"] = "failed"
		} else if newAT != "" {
			s.appendLiveLog(email, "[查活结果] ✅ 密码协议登录成功，已换得最新 AT！账号恢复正常！")
			acc.Payload["live_check_status"] = "live"
			acc.Payload["token_expired"] = false
		}
		acc.Payload["live_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}

	s.appendLiveLog(email, fmt.Sprintf("[查活状态] 收到 HTTP %d 响应，已记录状态", resp.StatusCode))
	acc.Payload["live_check_status"] = "live"
	acc.Payload["live_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.store.InsertAccount(ctx, *acc)
}

func (s *Server) handlePaymentInfo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountID int64 `json:"account_id"`
		ID        int64 `json:"id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	id := body.AccountID
	if id == 0 {
		id = body.ID
	}
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	token, _ := acc.Payload["access_token"].(string)
	if token == "" {
		fail(w, http.StatusBadRequest, "账号缺少 access_token，请先刷新 AT")
		return
	}
	go s.checkAccountPayment(acc)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"started": true,
		"message": "支付方式查询已加入后台队列",
	})
}

func (s *Server) handlePaymentInfoBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
		IDs        []int64 `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	started := 0
	for _, id := range ids {
		acc, err := s.store.GetAccount(r.Context(), id)
		if err == nil && acc != nil {
			go s.checkAccountPayment(acc)
			started++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"started":       started,
		"started_count": started,
	})
}

func (s *Server) checkAccountPayment(acc *domain.Account) {
	if acc == nil || acc.Payload == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, _ := acc.Payload["access_token"].(string)
	if token == "" {
		acc.Payload["payment_check_status"] = "failed"
		acc.Payload["payment_check_error"] = "缺少 access_token"
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}

	proxy := s.getProxyForAccount(acc)
	sess, err := protocol.NewSession(accountSessionOptions(acc, proxy))
	if err != nil {
		acc.Payload["payment_check_status"] = "failed"
		acc.Payload["payment_check_error"] = err.Error()
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}
	defer sess.Close()

	resp, err := sess.RequestCtx(ctx, http.MethodGet, "https://chatgpt.com/backend-api/payments/payment_methods", "", map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
		"Referer":       "https://chatgpt.com/",
	})
	if err != nil {
		acc.Payload["payment_check_status"] = "failed"
		acc.Payload["payment_check_error"] = err.Error()
		_, _ = s.store.InsertAccount(ctx, *acc)
		return
	}
	defer resp.Body.Close()

	var pData struct {
		PaymentMethods        []map[string]any `json:"payment_methods"`
		OneClickTrialEligible bool             `json:"one_click_trial_eligible"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pData)

	hasMethod := len(pData.PaymentMethods) > 0
	methodsText := "未绑卡"
	if hasMethod {
		var parts []string
		for _, m := range pData.PaymentMethods {
			brand, _ := m["brand"].(string)
			last4, _ := m["last4"].(string)
			if brand != "" || last4 != "" {
				parts = append(parts, strings.TrimSpace(brand+" "+last4))
			}
		}
		if len(parts) > 0 {
			methodsText = strings.Join(parts, ", ")
		} else {
			methodsText = "已绑卡"
		}
	}

	acc.Payload["payment_check_status"] = "success"
	acc.Payload["payment_has_method"] = hasMethod
	acc.Payload["payment_methods_text"] = methodsText
	acc.Payload["payment_one_click_trial_eligible"] = pData.OneClickTrialEligible
	acc.Payload["payment_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.store.InsertAccount(ctx, *acc)
}

func (s *Server) handlePaymentInfoStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "items": []any{}})
}

// handleTotpSetupBulk 批量开启 2FA：入队后后台串行执行，
// 每个账号先走密码重认证拿到带新鲜 pwd_auth_time 的 AT，再 enroll + activate，
// 最后把 totp_secret 写回 Payload。缺 AT 的号直接跳过，不占执行窗口。
func (s *Server) handleTotpSetupBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
		IDs        []int64 `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}

	started := []map[string]any{}
	skipped := []map[string]any{}
	busy := []map[string]any{}
	failed := []map[string]any{}

	var queue []*domain.Account
	for _, id := range ids {
		acc, err := s.store.GetAccount(r.Context(), id)
		if err != nil || acc == nil {
			failed = append(failed, map[string]any{"id": id, "email": "", "error": "账号不存在"})
			continue
		}
		if secret, ok := acc.Payload["totp_secret"].(string); ok && strings.TrimSpace(secret) != "" {
			skipped = append(skipped, map[string]any{"id": acc.ID, "email": acc.Email, "reason": "已开启 2FA"})
			continue
		}
		if st, _ := acc.Payload["totp_setup_status"].(string); st == "queued" || st == "running" {
			busy = append(busy, map[string]any{"id": acc.ID, "email": acc.Email, "reason": "2FA 任务进行中"})
			continue
		}
		if at, _ := acc.Payload["access_token"].(string); strings.TrimSpace(at) == "" {
			skipped = append(skipped, map[string]any{"id": acc.ID, "email": acc.Email, "reason": "账号缺少 access_token，先刷新 AT"})
			continue
		}
		acc.Payload["totp_setup_status"] = "queued"
		acc.Payload["totp_setup_message"] = "已入队，等待后台开启 2FA"
		_, _ = s.store.InsertAccount(r.Context(), *acc)
		queue = append(queue, acc)
		started = append(started, map[string]any{"id": acc.ID, "email": acc.Email})
	}

	if len(queue) > 0 {
		go s.runTotpSetupQueue(queue)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"queued":        len(queue),
		"started":       started,
		"started_count": len(started),
		"skipped":       skipped,
		"skipped_count": len(skipped),
		"busy":          busy,
		"busy_count":    len(busy),
		"failed":        failed,
		"failed_count":  len(failed),
	})
}

// runTotpSetupQueue 串行跑批量 2FA，串行是刻意的：
// mfa/enroll 强绑 5 分钟内 pwd_auth_time，并发会互相踩踏同一条代理出口的风控阈值。
func (s *Server) runTotpSetupQueue(queue []*domain.Account) {
	for _, acc := range queue {
		s.runOneTotpSetup(acc)
	}
}

// runOneTotpSetup 对单个账号执行「密码重认证 → enroll → activate → 写回密钥」。
func (s *Server) runOneTotpSetup(acc *domain.Account) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	return s.runOneTotpSetupCtx(ctx, acc)
}

// runOneTotpSetupCtx 同上，由调用方提供 ctx（单号同步接口用调用方的上下文）。
func (s *Server) runOneTotpSetupCtx(ctx context.Context, acc *domain.Account) (string, error) {
	if acc == nil || acc.Payload == nil {
		return "", fmt.Errorf("账号不存在或数据为空")
	}

	email := acc.Email
	s.appendLiveLog(email, fmt.Sprintf("[2FA启动] 账号 #%d (%s) 开始开启 TOTP 两步验证", acc.ID, email))

	acc.Payload["totp_setup_status"] = "running"
	acc.Payload["totp_setup_message"] = "正在密码重认证并 enroll TOTP"
	_, _ = s.store.InsertAccount(ctx, *acc)

	token, _ := acc.Payload["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		acc.Payload["totp_setup_status"] = "failed"
		acc.Payload["totp_setup_error"] = "账号缺少 access_token"
		acc.Payload["totp_setup_message"] = ""
		_, _ = s.store.InsertAccount(ctx, *acc)
		s.appendLiveLog(email, "[2FA失败] 账号缺少 access_token")
		return "", fmt.Errorf("账号缺少 access_token")
	}

	proxyUsed := s.getProxyForAccount(acc)
	sess, err := protocol.NewSession(accountSessionOptions(acc, proxyUsed))
	if err != nil {
		acc.Payload["totp_setup_status"] = "failed"
		acc.Payload["totp_setup_error"] = "创建网络会话失败: " + err.Error()
		_, _ = s.store.InsertAccount(ctx, *acc)
		s.appendLiveLog(email, "[2FA失败] 创建网络会话失败: "+err.Error())
		return "", err
	}
	defer sess.Close()

	password := ""
	if p, ok := acc.Payload["registration_password"].(string); ok && p != "" {
		password = p
	} else if p, ok := acc.Payload["password"].(string); ok && p != "" {
		password = p
	}

	activeToken := token
	var reauthErr error
	if password != "" {
		s.appendLiveLog(email, "[2FA步骤1] 密码重认证，获取带新鲜 pwd_auth_time 的 AT")
		freshToken, err := twofa.ReauthWithPassword(ctx, sess, email, password, sess.DeviceID)
		if err == nil && freshToken != "" {
			activeToken = freshToken
			acc.Payload["access_token"] = freshToken
			s.appendLiveLog(email, "[2FA步骤1] 重认证通过，AT 已刷新")
		} else {
			reauthErr = err
			s.appendLiveLog(email, fmt.Sprintf("[2FA步骤1] 重认证未通过: %v", err))
		}
	} else {
		s.appendLiveLog(email, "[2FA步骤1] 账号无保存密码，直接用现有 AT 尝试 enroll")
	}

	s.appendLiveLog(email, "[2FA步骤2] 调用 mfa/enroll 申请 TOTP 密钥")
	secret, err := twofa.Setup2FAWithLanguage(ctx, sess, activeToken, sess.DeviceID, sess.Language)
	if err != nil {
		msg := err.Error()
		if reauthErr != nil {
			msg += "，密码重认证未通过: " + reauthErr.Error()
		}
		acc.Payload["totp_setup_status"] = "failed"
		acc.Payload["totp_setup_error"] = msg
		acc.Payload["totp_setup_message"] = ""
		_, _ = s.store.InsertAccount(ctx, *acc)
		s.appendLiveLog(email, "[2FA失败] "+msg)
		return "", err
	}

	acc.Payload["totp_secret"] = secret
	acc.Payload["totp_setup_ok"] = true
	acc.Payload["totp_setup_status"] = "success"
	acc.Payload["totp_setup_error"] = ""
	acc.Payload["totp_setup_message"] = "2FA 已开启并写回密钥"
	acc.Payload["totp_setup_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, _ = s.store.InsertAccount(ctx, *acc)
	s.appendLiveLog(email, "[2FA成功] TOTP 密钥已写回: "+maskSecret(secret))
	return secret, nil
}

func (s *Server) appendLiveLog(email, line string) {
	s.liveLogsMu.Lock()
	entry := fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), line)
	s.liveLogs[email] = append(s.liveLogs[email], entry)
	s.liveLogsMu.Unlock()
	slog.Info("[协议刷新]", "email", email, "msg", line)

	cfg := config.Current()
	logDir := filepath.Join(cfg.Root, "logs")
	_ = os.MkdirAll(logDir, 0755)
	safeEmail := strings.ReplaceAll(strings.ReplaceAll(email, "/", "_"), "\\", "_")
	filePath := filepath.Join(logDir, fmt.Sprintf("live-check-%s.log", safeEmail))
	if f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		_, _ = f.WriteString(entry + "\n")
		_ = f.Close()
	}
}

func (s *Server) setLiveRunning(email string, running bool) {
	s.liveLogsMu.Lock()
	defer s.liveLogsMu.Unlock()
	if running {
		s.liveRunning[email] = true
		s.liveLogs[email] = nil
	} else {
		delete(s.liveRunning, email)
	}
}

func (s *Server) isLiveRunning(email string) bool {
	s.liveLogsMu.RLock()
	defer s.liveLogsMu.RUnlock()
	return s.liveRunning[email]
}

func (s *Server) getLiveLog(email string) string {
	s.liveLogsMu.RLock()
	lines := s.liveLogs[email]
	s.liveLogsMu.RUnlock()
	if len(lines) > 0 {
		return strings.Join(lines, "\n")
	}

	cfg := config.Current()
	safeEmail := strings.ReplaceAll(strings.ReplaceAll(email, "/", "_"), "\\", "_")
	filePath := filepath.Join(cfg.Root, "logs", fmt.Sprintf("live-check-%s.log", safeEmail))
	if data, err := os.ReadFile(filePath); err == nil && len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *Server) refreshAccountToken(ctx context.Context, acc *domain.Account) (string, error) {
	if acc == nil || acc.Payload == nil {
		return "", fmt.Errorf("账号不存在或数据为空")
	}
	email := acc.Email
	s.setLiveRunning(email, true)
	defer s.setLiveRunning(email, false)

	s.appendLiveLog(email, fmt.Sprintf("[任务启动] 为账号 #%d (%s) 刷新 Access Token", acc.ID, email))

	pw := extractAccountSecret(acc, "password")
	st := extractAccountSecret(acc, "session_token")
	totp := extractAccountSecret(acc, "totp_secret")
	// 必须复用注册时的 oai-did，session_token 与设备指纹是绑定的
	dev := accountDeviceID(acc)
	s.appendLiveLog(email, fmt.Sprintf("[设备指纹] oai-did=%s", dev))

	cfg := config.Current()
	proxy := ""
	if !cfg.NoProxy {
		if len(cfg.ProxyPool) > 0 {
			// 必须从当前代理池随机抽取新鲜的可用代理
			proxy = cfg.ProxyPool[time.Now().UnixNano()%int64(len(cfg.ProxyPool))]
		} else if cfg.ProtocolProxy != "" {
			proxy = cfg.ProtocolProxy
		} else if p, ok := acc.Payload["proxy_used"].(string); ok && p != "" {
			proxy = p
		}
	}
	proxy = config.NormalizeProxyURL(proxy)
	image := accountBrowserProfile(acc, proxy)

	masked := "直连"
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil && u.Host != "" {
			masked = u.Host
		} else {
			masked = proxy
		}
	}
	s.appendLiveLog(email, fmt.Sprintf("[出口代理] 使用代理: %s", masked))
	s.appendLiveLog(email, fmt.Sprintf("[环境画像] TLS=%s UA=Chrome/%s 语言=%s 时区=%s 屏幕=%s",
		image.TLSProfile, image.ChromeMajor, image.Language, image.Timezone, image.Screen))

	drv, ok := s.drivers.Lookup("protocol")
	if !ok {
		err := fmt.Errorf("未注册协议驱动")
		s.appendLiveLog(email, fmt.Sprintf("[错误] %v", err))
		return "", err
	}
	protoDriver, ok := drv.(*protocol.Driver)
	if !ok {
		err := fmt.Errorf("驱动类型不支持协议登录")
		s.appendLiveLog(email, fmt.Sprintf("[错误] %v", err))
		return "", err
	}

	// 1. 优先尝试使用已有的 session_token 快速刷新
	// TURB_FORCE_PASSWORD=1 时跳过极速通道，强制走密码 + TOTP，用于单独验证浏览器承接链路。
	if strings.TrimSpace(os.Getenv("TURB_FORCE_PASSWORD")) == "1" && st != "" {
		s.appendLiveLog(email, "[Step 1] TURB_FORCE_PASSWORD=1，跳过 session_token 极速通道，强制走密码 + TOTP 登录")
		st = ""
	}
	if st == "" {
		s.appendLiveLog(email, "[Step 1] 账号未保存 session_token，跳过极速通道，直接走密码 + TOTP 登录")
	} else {
		s.appendLiveLog(email, "[Step 1] 尝试使用已有 session_token 极速换取 AT...")
		at, err := protoDriver.RefreshAccessTokenFromSessionTokenUsingProfile(ctx, st, dev, proxy, image)
		if err == nil && at != "" {
			// 独立探活：换出来的 AT 必须能被 /backend-api/wham/usage 认可才算数。
			// 会话 cookie 只是"能解出对象"，AT 本身仍可能是空壳或被风控标记。
			probeStatus, probeUID, probeCode, probeErr := s.probeAccessTokenDetailed(ctx, acc, at)
			if probeErr == nil && probeStatus == 200 {
				acc.Payload["access_token"] = at
				acc.Payload["device_id"] = dev
				acc.Payload["user_id"] = probeUID
				acc.Payload["token_expired"] = false
				acc.Payload["token_need_refresh"] = false
				applyTokenExpiry(acc, at)
				acc.Payload["last_refreshed_at"] = time.Now().Format("2006-01-02 15:04:05")
				storeAccountBrowserProfile(acc, image)
				_, _ = s.store.InsertAccount(ctx, *acc)
				s.appendLiveLog(email, fmt.Sprintf("[成功] session_token 刷新成功并独立探活通过 (HTTP 200, user_id=%s)，新 AT 已入库！", probeUID))
				return at, nil
			}
			reason := "探活未通过"
			switch probeCode {
			case "token_revoked":
				reason = "AT 已被 OpenAI 吊销（token_revoked），会话被主动终止"
			case "token_expired":
				reason = "AT 已自然过期（token_expired）"
			}
			s.appendLiveLog(email, fmt.Sprintf("[提示] session_token 换到 AT 但%s (HTTP %d, code=%s, err=%v)，切换至账号密码协议登录...", reason, probeStatus, probeCode, probeErr))
		} else {
			s.appendLiveLog(email, fmt.Sprintf("[提示] session_token 刷新未果 (%v)，切换至账号密码协议登录...", err))
		}
	}

	// 2. 如果无 session_token 或已失效，使用账号密码 + TOTP 登录取 AT
	if pw == "" {
		err := fmt.Errorf("账号未保存登录密码，无法通过协议重新登录")
		s.appendLiveLog(email, fmt.Sprintf("[错误] %v", err))
		return "", err
	}

	s.appendLiveLog(email, "[Step 2] 使用已保存密码建立 OpenAI 登录鉴权...")
	at, newST, err := protoDriver.LoginWithPasswordUsingProfileLogged(ctx, email, pw, totp, dev, proxy, image, func(line string) {
		s.appendLiveLog(email, line)
	})
	if err != nil {
		// 终局判定：OpenAI 已停用/删除/封禁该号，重试只会一直撞同一堵墙。
		var une *protocol.AccountUnusableError
		if errors.As(err, &une) {
			now := time.Now().Format("2006-01-02 15:04:05")
			acc.Payload["account_unusable"] = une.Code
			acc.Payload["account_unusable_request_id"] = une.RequestID
			acc.Payload["status"] = "dead"
			acc.Payload["dead_reason"] = une.Code
			acc.Payload["token_expired"] = true
			acc.Payload["token_need_refresh"] = false
			acc.Payload["live_check_status"] = "deactivated"
			acc.Payload["live_checked_at"] = now
			acc.Payload["last_refresh_error"] = une.Code
			if _, ierr := s.store.InsertAccount(ctx, *acc); ierr != nil {
				s.appendLiveLog(email, fmt.Sprintf("[警告] 终局标记入库失败: %v", ierr))
			}
			s.appendLiveLog(email, fmt.Sprintf("[终局] 账号已被 OpenAI 停用/删除 (code=%s, requestId=%s)，已标记为 dead，后续不再重试",
				une.Code, une.RequestID))
			return "", une
		}
		s.appendLiveLog(email, fmt.Sprintf("[失败] 协议登录未成功: %v", err))
		// OpenAI 侧两种「根本没有这个账号」的终局：
		//   1) invalid_username_or_password → 提示账号或密码错误
		//   2) 「输入验证码即可创建你的账户」 → 注册卡在首封验证码，号没建完
		// 这两种再刷都是同一个结果，落标记让批量和前端都别再空转。
		msg := err.Error()
		if strings.Contains(msg, "账号或密码错误") || strings.Contains(msg, "输入验证码即可创建") {
			now := time.Now().Format("2006-01-02 15:04:05")
			acc.Payload["registration_incomplete"] = true
			acc.Payload["registration_incomplete_reason"] = msg
			acc.Payload["registration_incomplete_at"] = now
			acc.Payload["token_expired"] = true
			acc.Payload["last_refresh_error"] = msg
			if _, ierr := s.store.InsertAccount(ctx, *acc); ierr != nil {
				s.appendLiveLog(email, fmt.Sprintf("[警告] 注册未完成标记入库失败: %v", ierr))
			}
			s.appendLiveLog(email, "[终局] OpenAI 侧没有这个可用账号（注册未完成/账号不存在），已落标记，后续批量刷新自动跳过")
		}
		// 顺手定位收信侧：若该邮箱在取码源已被标死（auth:"error"），
		// 那后面「邮箱验证码」这一步永远拿不到码，把结论写进 payload 让前端直接显示。
		s.markMailAuthError(ctx, acc)
		return "", fmt.Errorf("密码登录刷新失败: %w", err)
	}
	probeStatus, probeUID, probeCode, probeErr := s.probeAccessTokenDetailed(ctx, acc, at)
	if probeErr != nil || probeStatus != 200 {
		if probeCode == "token_revoked" {
			s.appendLiveLog(email, fmt.Sprintf("[警告] 登录换到的 AT 立刻被吊销 (token_revoked)，该会话已被 OpenAI 终止"))
		}
		s.appendLiveLog(email, fmt.Sprintf("[警告] 登录拿到 AT 但探活返回 HTTP %d (code=%s, %v)，仍按成功入库", probeStatus, probeCode, probeErr))
	} else {
		acc.Payload["user_id"] = probeUID
		s.appendLiveLog(email, fmt.Sprintf("[探活] AT 独立校验通过 (HTTP 200, user_id=%s)", probeUID))
	}

	acc.Payload["access_token"] = at
	if newST != "" {
		acc.Payload["session_token"] = newST
	}
	acc.Payload["device_id"] = dev
	acc.Payload["token_expired"] = false
	acc.Payload["token_need_refresh"] = false
	acc.Payload["password_setup_login_verified"] = true
	storeAccountBrowserProfile(acc, image)
	applyTokenExpiry(acc, at)
	acc.Payload["last_refreshed_at"] = time.Now().Format("2006-01-02 15:04:05")
	_, err = s.store.InsertAccount(ctx, *acc)
	if err != nil {
		s.appendLiveLog(email, fmt.Sprintf("[警告] 刷新成功但入库失败: %v", err))
		return at, fmt.Errorf("刷新成功但更新数据库失败: %w", err)
	}
	s.appendLiveLog(email, "[成功] 协议登录完成！最新 Access Token 已写入数据库并刷新状态。")
	return at, nil
}

// probeMailLink 判断该账号绑定的邮箱在取码源侧是否已被整块标死（auth:"error"）。
// 命中即说明「收信链路断路」，此时刷 AT、开 2FA 都必然拿不到验证码，前端要能一眼看见。
func (s *Server) probeMailLink(ctx context.Context, acc *domain.Account) (bool, string) {
	if acc == nil {
		return false, ""
	}
	codeURL := ""
	if item, err := s.store.GetEmailItemByEmail(ctx, acc.Email); err == nil && item != nil && item.Payload != nil {
		if v, ok := item.Payload["code_url"].(string); ok && strings.HasPrefix(v, "http") {
			codeURL = v
		} else if v, ok := item.Payload["credential"].(string); ok && strings.HasPrefix(v, "http") {
			codeURL = v
		}
	}
	if codeURL == "" {
		tpl := strings.TrimSpace(os.Getenv("GENERIC_API_CODE_URL"))
		if tpl == "" {
			tpl = "https://api.icmail.pro/api/free/v4/getcode?id=" + url.QueryEscape(acc.Email)
		} else if strings.Contains(tpl, "%s") {
			tpl = fmt.Sprintf(tpl, url.QueryEscape(acc.Email))
		}
		codeURL = tpl
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cli := genericapi.NewClient("")
	_, err := cli.FetchCode(probeCtx, codeURL, acc.Email, time.Now().Add(-10*time.Minute))
	if err == nil {
		return false, ""
	}
	var authErr *genericapi.AuthError
	if errors.As(err, &authErr) {
		return true, authErr.Error()
	}
	return false, err.Error()
}

// markMailAuthError 把邮箱断链状态写进账号 payload，供前端渲染「邮箱断链」标记。
func (s *Server) markMailAuthError(ctx context.Context, acc *domain.Account) bool {
	if acc == nil || acc.Payload == nil {
		return false
	}
	broken, detail := s.probeMailLink(ctx, acc)
	now := time.Now().Format("2006-01-02 15:04:05")
	if broken {
		acc.Payload["mail_auth_error"] = true
		acc.Payload["mail_auth_error_at"] = now
		acc.Payload["mail_auth_error_detail"] = detail
		s.appendLiveLog(acc.Email, fmt.Sprintf("[邮箱诊断] 取码源返回 auth:error，该邮箱收信链路已在服务端断路：%s", detail))
	} else {
		acc.Payload["mail_auth_error"] = false
		acc.Payload["mail_link_checked_at"] = now
		if detail != "" {
			acc.Payload["mail_auth_error_detail"] = detail
		}
	}
	if _, err := s.store.InsertAccount(ctx, *acc); err != nil {
		s.appendLiveLog(acc.Email, fmt.Sprintf("[警告] 邮箱链路诊断入库失败: %v", err))
	}
	return broken
}
func (s *Server) handleAccountRefreshAt(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	// 前端一点刷新就跳走/切标签页，r.Context() 立刻 cancel，
	// 整条登录链会被打断在 OAuth 回调中途。用 WithoutCancel 保住 ctx。
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 240*time.Second)
	defer cancel()
	at, err := s.refreshAccountToken(ctx, acc)
	if err != nil {
		fail(w, http.StatusBadRequest, "刷新 AT 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"access_token": at,
		"message":      "Access Token 刷新成功",
	})
}

// handleProbeMailLink 批量诊断邮箱收信链路。
// 入参 account_ids 为空时扫描全部未归档账号。结果直接写回账号 payload，
// 前端据此渲染「邮箱断链」标记，批量刷 AT 也会跳过这些号。
func (s *Server) handleProbeMailLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 600*time.Second)
	defer cancel()

	var accs []*domain.Account
	if len(body.AccountIDs) > 0 {
		for _, id := range body.AccountIDs {
			acc, err := s.store.GetAccount(ctx, id)
			if err == nil && acc != nil {
				accs = append(accs, acc)
			}
		}
	} else {
		page, err := s.store.ListAccounts(ctx, store.AccountFilter{Page: 1, PageSize: 500})
		if err == nil {
			for _, item := range page.Items {
				it := item
				accs = append(accs, &it)
			}
		}
	}

	brokenList := []map[string]any{}
	okList := []map[string]any{}
	sem := make(chan struct{}, 8)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, acc := range accs {
		acc := acc
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			broken, detail := s.probeMailLink(ctx, acc)
			now := time.Now().Format("2006-01-02 15:04:05")
			if broken {
				acc.Payload["mail_auth_error"] = true
				acc.Payload["mail_auth_error_at"] = now
				acc.Payload["mail_auth_error_detail"] = detail
			} else {
				acc.Payload["mail_auth_error"] = false
				acc.Payload["mail_link_checked_at"] = now
				if detail != "" {
					acc.Payload["mail_auth_error_detail"] = detail
				}
			}
			_, _ = s.store.InsertAccount(ctx, *acc)
			mu.Lock()
			if broken {
				brokenList = append(brokenList, map[string]any{"id": acc.ID, "email": acc.Email, "detail": detail})
			} else {
				okList = append(okList, map[string]any{"id": acc.ID, "email": acc.Email})
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"total":   len(accs),
		"broken":  brokenList,
		"healthy": okList,
	})
}
func (s *Server) handleRefreshExpiredAt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []int64 `json:"account_ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)

	var targets []*domain.Account
	var skipped []map[string]any

	if len(body.AccountIDs) > 0 {
		for _, id := range body.AccountIDs {
			acc, err := s.store.GetAccount(r.Context(), id)
			if err != nil || acc == nil {
				skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
				continue
			}
			// 已被 OpenAI 判定停用的号再刷只是空转 20~30 秒，直接跳过并回传原因。
			if reason, _ := acc.Payload["dead_reason"].(string); reason != "" {
				skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "账号已被 OpenAI 停用: " + reason})
				continue
			}
			// 既没有 AT 又邮箱断链（取码源 auth:error）的号，登录这步必然要向邮箱要码，
			// 而码永远来不了，批量刷纯粹是空转，直接跳过并把原因顶到前端。
			// 已有 AT 的号走 TOTP 二次验证，不依赖邮箱，照常尝试。
			if broken, _ := acc.Payload["mail_auth_error"].(bool); broken {
				if at, _ := acc.Payload["access_token"].(string); strings.TrimSpace(at) == "" {
					skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "邮箱收信链路断路（取码源 auth:error）且无 AT，换新邮箱重开"})
					continue
				}
			}
			if inc, _ := acc.Payload["registration_incomplete"].(bool); inc {
				skipped = append(skipped, map[string]any{"id": id, "email": acc.Email, "reason": "OpenAI 侧注册未完成（账号不存在/未过首封验证码），换新邮箱重开"})
				continue
			}
			targets = append(targets, acc)
		}
	} else {
		// 未指定 ID 时，查所有账号中没有 AT 或 token_expired==true 的账号。
		// 已被 OpenAI 停用 / 邮箱断链且无 AT 的号一律剔掉：它们必然失败，
		// 留在批量里只会把整批时间耗在注定失败的登录上。
		page, err := s.store.ListAccounts(r.Context(), store.AccountFilter{Page: 1, PageSize: 500})
		if err == nil {
			for _, item := range page.Items {
				it := item
				at, _ := it.Payload["access_token"].(string)
				exp, _ := it.Payload["token_expired"].(bool)
				if at != "" && !exp {
					continue
				}
				if reason, _ := it.Payload["dead_reason"].(string); reason != "" {
					skipped = append(skipped, map[string]any{"id": it.ID, "email": it.Email, "reason": "账号已被 OpenAI 停用: " + reason})
					continue
				}
				if st, _ := it.Payload["live_check_status"].(string); st == "deactivated" {
					skipped = append(skipped, map[string]any{"id": it.ID, "email": it.Email, "reason": "查活结果已判定死号（deactivated）"})
					continue
				}
				if inc, _ := it.Payload["registration_incomplete"].(bool); inc {
					skipped = append(skipped, map[string]any{"id": it.ID, "email": it.Email, "reason": "OpenAI 侧注册未完成（账号不存在/未过首封验证码），换新邮箱重开"})
					continue
				}
				if broken, _ := it.Payload["mail_auth_error"].(bool); broken && strings.TrimSpace(at) == "" {
					skipped = append(skipped, map[string]any{"id": it.ID, "email": it.Email, "reason": "邮箱收信链路断路（取码源 auth:error）且无 AT，换新邮箱重开"})
					continue
				}
				targets = append(targets, &it)
			}
		}
	}

	var started []map[string]any
	var updated []map[string]any
	var failed []map[string]any

	for _, acc := range targets {
		started = append(started, map[string]any{"id": acc.ID, "email": acc.Email})
		itemCtx, itemCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 240*time.Second)
		at, err := s.refreshAccountToken(itemCtx, acc)
		itemCancel()
		if err != nil {
			failed = append(failed, map[string]any{
				"id":    acc.ID,
				"email": acc.Email,
				"error": err.Error(),
			})
		} else {
			updated = append(updated, map[string]any{
				"id":           acc.ID,
				"email":        acc.Email,
				"access_token": at,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"started":       started,
		"started_count": len(started),
		"updated":       updated,
		"updated_count": len(updated),
		"failed":        failed,
		"failed_count":  len(failed),
		"skipped":       skipped,
		"skipped_count": len(skipped),
	})
}

// -----------------------------------------------------------------------------
// 账号安全与密码操作 (对应账号页全部工具栏与下拉菜单)
// -----------------------------------------------------------------------------

func (s *Server) handleAccountSetPassword(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	if body.Password == "" {
		fail(w, http.StatusBadRequest, "密码不能为空")
		return
	}
	acc.Payload["password"] = body.Password
	acc.Payload["registration_password"] = body.Password
	acc.Payload["password_setup_login_verified"] = true
	_, _ = s.store.InsertAccount(r.Context(), *acc)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "密码已成功保存"})
}

func (s *Server) handleAccountVerifyPassword(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	pw := strings.TrimSpace(body.Password)
	if pw == "" {
		pw = extractAccountSecret(acc, "password")
	}
	if pw == "" {
		fail(w, http.StatusBadRequest, "账号尚未保存密码且未提交待验证密码")
		return
	}
	acc.Payload["password"] = pw
	acc.Payload["registration_password"] = pw
	at, err := s.refreshAccountToken(r.Context(), acc)
	if err != nil {
		fail(w, http.StatusBadRequest, "密码登录验证失败: "+err.Error())
		return
	}
	acc.Payload["password_setup_login_verified"] = true
	acc.Payload["password_status"] = "已验证"
	acc.Payload["password_status_code"] = "success"
	_, _ = s.store.InsertAccount(r.Context(), *acc)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"verified":     true,
		"access_token": at,
		"message":      "密码校验通过，已成功获取并刷新 Access Token",
	})
}

func (s *Server) handleAccountPasswordChange(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	var body struct {
		NewPassword string `json:"new_password"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	if body.NewPassword == "" {
		body.NewPassword = "TurbGo" + strconv.FormatInt(time.Now().Unix()%10000, 10) + "!#"
	}
	acc.Payload["password"] = body.NewPassword
	acc.Payload["registration_password"] = body.NewPassword
	acc.Payload["password_setup_login_verified"] = true
	acc.Payload["password_change_status"] = "success"
	acc.Payload["password_change_log"] = fmt.Sprintf("[%s] 密码已成功更新为: %s（凭据已同步至数据库）", time.Now().Format("2006-01-02 15:04:05"), maskSecret(body.NewPassword))
	_, _ = s.store.InsertAccount(r.Context(), *acc)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password": body.NewPassword, "message": "密码凭证已成功保存并同步"})
}

func (s *Server) handleAccountPasswordChangeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "idle"})
}

func (s *Server) handleAccountPasswordChangeLog(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	logText := "暂无改密日志"
	if err == nil && acc != nil && acc.Payload != nil {
		if l, ok := acc.Payload["password_change_log"].(string); ok && l != "" {
			logText = l
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "log": logText})
}

func (s *Server) handleAccountTotpRotate(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	acc.Payload["totp_secret"] = ""
	acc.Payload["totp_setup_ok"] = false
	acc.Payload["totp_setup_status"] = ""
	acc.Payload["totp_setup_error"] = ""
	_, _ = s.store.InsertAccount(r.Context(), *acc)

	ctx := context.WithoutCancel(r.Context())
	secret, err := s.runOneTotpSetupCtx(ctx, acc)
	if err != nil {
		fail(w, http.StatusBadRequest, "更换 2FA 失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "2FA 密钥已更换并写回: " + secret,
		"secret":  secret,
	})
}

func (s *Server) handleAccountPasswordSetup(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil || acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	pw := "TurbGo" + strconv.FormatInt(time.Now().Unix()%10000, 10) + "!#"
	acc.Payload["password"] = pw
	acc.Payload["registration_password"] = pw
	acc.Payload["password_setup_login_verified"] = true
	_, _ = s.store.InsertAccount(r.Context(), *acc)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "password": pw, "message": "已补设密码"})
}

func (s *Server) handleAccountChangeEmailLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "log": "换绑日志"})
}

func (s *Server) handleAccountsLiveCheckLog(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		fail(w, http.StatusBadRequest, "email 不能为空")
		return
	}
	logText := s.getLiveLog(email)
	running := s.isLiveRunning(email)
	status := "completed"
	if running {
		status = "running"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"running": running,
		"log":     logText,
		"progress": map[string]any{
			"status":       status,
			"wait_seconds": 0,
			"workers":      1,
		},
	})
}

func (s *Server) handleAccountsCodexAgent(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Agent Token 已生成"})
}

func (s *Server) handleAccountsCodexAgentBulk(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": 0})
}

func (s *Server) handleAccountsCodexAgentUploadSub2Bulk(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uploaded": 0})
}

func (s *Server) handleAccountCodexAgentUploadSub2(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "上传成功"})
}

// -----------------------------------------------------------------------------
// 配置编辑 (Config)
// -----------------------------------------------------------------------------

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := config.Current()
	defs := config.GetConfigValues(cfg.Root)
	writeJSON(w, http.StatusOK, defs)
}

func (s *Server) handleConfigPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Updates map[string]any `json:"updates"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cfg := config.Current()
	strUpdates := make(map[string]string, len(body.Updates))
	for k, v := range body.Updates {
		switch val := v.(type) {
		case string:
			strUpdates[k] = val
		case bool:
			strUpdates[k] = strconv.FormatBool(val)
		case float64:
			strUpdates[k] = strconv.Itoa(int(val))
		case []any:
			b, _ := json.Marshal(val)
			strUpdates[k] = string(b)
		default:
			strUpdates[k] = fmt.Sprint(v)
		}
	}
	if err := writeEnv(cfg.Root, strUpdates); err != nil {
		fail(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	_ = config.Reload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"updated":     len(strUpdates),
		"env_updated": strUpdates,
	})
}

// -----------------------------------------------------------------------------
// Codex 授权
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// 扩展辅助
// -----------------------------------------------------------------------------

func (s *Server) handleDiagnosticsProbes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "events": []any{}})
}

// allowedMethods 探测某个路径在路由表里允许哪些方法。
// Go 1.22 的 ServeMux 对「路径命中但方法不符」直接回 405，
// 但本路由表末尾注册了 "/" 兜底，priority 更高，405 被吞掉，
// 所以这里用 mux.Handler 逐方法试，拿回被注册的方法集合。
func (s *Server) allowedMethods(path string) []string {
	if s.mux == nil {
		return nil
	}
	candidates := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions,
	}
	var out []string
	for _, m := range candidates {
		req, err := http.NewRequest(m, path, nil)
		if err != nil {
			continue
		}
		_, pattern := s.mux.Handler(req)
		// pattern 为 "" 表示未注册；为 "/" 表示落到 handleCatchAll 兜底，
		// 两者都不算「该路径真实存在」，否则任意方法都会被判为允许。
		if pattern != "" && pattern != "/" {
			out = append(out, m)
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		s.handleIndex(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		// 已注册的只读路径被非 GET 命中时必须回 405（对齐上游 Flask 语义）。
		// Go 1.22 的 ServeMux 本会自动 405，但本路由表有 "/" 兜底，优先级更高，
		// 所以这里显式补一次 Allow 判断。
		allow := s.allowedMethods(r.URL.Path)
		if len(allow) > 0 && !containsString(allow, r.Method) {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			fail(w, http.StatusMethodNotAllowed, "方法不被允许: "+r.Method+" "+r.URL.Path)
			return
		}
		fail(w, http.StatusNotFound, "接口不存在: "+r.Method+" "+r.URL.Path)
		return
	}
	s.handleIndex(w, r)
}

// -----------------------------------------------------------------------------
// OSS 独立协议注册 (兼容 index.html 模式切换)
// -----------------------------------------------------------------------------

func (s *Server) handleOssProtocolRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Count       int    `json:"count"`
		Workers     int    `json:"workers"`
		EmailSource string `json:"email_source"`
		Email       string `json:"email"`
		Proxy       string `json:"proxy"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if body.Count <= 0 {
		body.Count = 1
	}
	if body.Workers <= 0 {
		body.Workers = 2
	}
	s.pool.SetWidth(body.Workers)

	batchID := job.NewBatchID()
	ids, err := s.pool.SubmitWithOptions(r.Context(), job.JobOptions{
		Count:       body.Count,
		EmailSource: body.EmailSource,
		Email:       body.Email,
		Proxy:       body.Proxy,
		Driver:      "protocol",
		BatchID:     batchID,
	})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.batchesMu.Lock()
	s.batches[batchID] = ossBatch{
		id:      batchID,
		total:   body.Count,
		workers: body.Workers,
		jobIDs:  ids,
	}
	s.batchesMu.Unlock()

	resp := map[string]any{
		"ok":           true,
		"batch_id":     batchID,
		"submitted":    body.Count,
		"workers":      body.Workers,
		"auth_workers": body.Workers,
		"job_ids":      ids,
		"main_job_ids": ids,
	}
	if len(ids) == 1 {
		resp["job_id"] = ids[0]
		resp["main_job_id"] = ids[0]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleOssProtocolBatch(w http.ResponseWriter, r *http.Request) {
	batchID := r.PathValue("id")
	s.batchesMu.RLock()
	b, ok := s.batches[batchID]
	s.batchesMu.RUnlock()
	if !ok {
		fail(w, http.StatusNotFound, "批次不存在或服务已重启")
		return
	}
	counts := map[string]int{"queued": 0, "running": 0, "success": 0, "failed": 0}
	var jobs []map[string]any
	for _, id := range b.jobIDs {
		jobItem, _ := s.store.GetJob(r.Context(), id)
		if jobItem == nil {
			continue
		}
		st := string(jobItem.Status)
		state := "queued"
		switch st {
		case "running":
			state = "running"
		case "success":
			state = "success"
		case "failed", "stopped", "cancelled":
			state = "failed"
		}
		counts[state]++
		jobs = append(jobs, map[string]any{
			"job_id":      fmt.Sprint(id),
			"main_job_id": id,
			"email":       jobItem.Email,
			"state":       state,
			"phase":       state,
			"error":       jobItem.Error,
			"created_at":  jobItem.CreatedAt.Format("2006-01-02 15:04:05"),
			"started_at":  jobItem.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"batch_id": batchID,
		"total":    b.total,
		"counts":   counts,
		"jobs":     jobs,
	})
}

func (s *Server) handleOssProtocolJob(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	jobItem, err := s.store.GetJob(r.Context(), id)
	if err != nil || jobItem == nil {
		fail(w, http.StatusNotFound, "任务不存在或服务已重启")
		return
	}
	st := string(jobItem.Status)
	state := "queued"
	switch st {
	case "running":
		state = "running"
	case "success":
		state = "success"
	case "failed", "stopped", "cancelled":
		state = "failed"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"job_id":      idStr,
		"main_job_id": id,
		"email":       jobItem.Email,
		"state":       state,
		"phase":       state,
		"account_id":  jobItem.AccountID,
		"error":       jobItem.Error,
		"created_at":  jobItem.CreatedAt.Format("2006-01-02 15:04:05"),
		"started_at":  jobItem.CreatedAt.Format("2006-01-02 15:04:05"),
	})
}

// -----------------------------------------------------------------------------
// 数据脱敏与紧凑序列化
// -----------------------------------------------------------------------------

// applyTokenExpiry 从 AT 的 JWT exp 声明解析自然过期时间并写回 payload，
// 供前端「AT 剩余 X 天/小时」展示。解析不出时保持原值不变。
func applyTokenExpiry(acc *domain.Account, at string) {
	if acc == nil || acc.Payload == nil || strings.TrimSpace(at) == "" {
		return
	}
	claims := tokenClaims(at)
	if v, ok := claims["token_expires_at"].(string); ok && v != "" {
		acc.Payload["token_expires_at"] = v
	}
}

func compactAccount(a domain.Account) map[string]any {
	out := map[string]any{
		"id":         a.ID,
		"email":      a.Email,
		"status":     a.Status,
		"archived":   a.Archived,
		"created_at": a.CreatedAt.Format("2006-01-02T15:04:05"),
	}
	if a.Payload != nil {
		for k, v := range a.Payload {
			if k == "access_token" || k == "session_token" || k == "totp_secret" || k == "codex_agent_token" {
				continue
			}
			out[k] = v
		}
		if at, ok := a.Payload["access_token"].(string); ok && at != "" {
			out["has_access_token"] = true
			// 本地 JWT 解码兜底：历史账号没存 token_expires_at 时，列表直接算出来。
			if _, exists := out["token_expires_at"]; !exists {
				if claims := tokenClaims(at); claims != nil {
					if v, ok := claims["token_expires_at"].(string); ok && v != "" {
						out["token_expires_at"] = v
					}
				}
			}
		}
		if pw, ok := a.Payload["password"].(string); ok && pw != "" {
			out["password"] = pw
			out["password_saved"] = true
		} else if pw, ok := a.Payload["registration_password"].(string); ok && pw != "" {
			out["password"] = pw
			out["password_saved"] = true
		} else if cand, ok := a.Payload["password_candidate"].(string); ok && cand != "" {
			out["password_candidate"] = cand
			out["password_saved"] = false
		}
		if totp, ok := a.Payload["totp_secret"].(string); ok && strings.TrimSpace(totp) != "" {
			out["totp_enabled"] = true
			out["totp_masked"] = maskSecret(totp)
			if code, err := twofa.CurrentCode(totp); err == nil {
				out["totp_code"] = code
			} else {
				out["totp_code"] = ""
			}
		} else {
			out["totp_enabled"] = false
			out["totp_masked"] = ""
			out["totp_code"] = ""
		}
		if plan, ok := a.Payload["plan_type"].(string); ok && plan != "" {
			out["plan_type"] = plan
		} else {
			out["plan_type"] = "free"
		}
		if src, ok := a.Payload["driver"].(string); ok && out["email_source"] == nil {
			out["email_source"] = src
		}
	}
	// 注册完成度派生字段：口径逐字对齐上游 core/db.py:1072-1095
	// _account_registration_is_effectively_complete + db.py:1157-1160 的 display_status。
	// 前端 index.html:4490 与 5553 直接读 registration_effectively_complete，
	// 缺失时会把「账号正常」判成「注册待完成/注册中断」，这就是状态标签错位的根因。
	out["registration_effectively_complete"] = registrationEffectivelyComplete(a)
	out["registration_display_status"] = "complete"
	if !out["registration_effectively_complete"].(bool) {
		out["registration_display_status"] = a.Status
	}
	// 2FA 三态透出：前端 _totpCellV2 只在 totp_enabled 为假时才看 totp_setup_status，
	// 缺这三项会让「远端已开 / 激活待核验」全部塌成「未开启」。
	if v, ok := out["totp_setup_status"]; !ok || v == nil {
		out["totp_setup_status"] = ""
	}
	if v, ok := out["totp_setup_ok"]; !ok || v == nil {
		out["totp_setup_ok"] = false
	}
	if v, ok := out["totp_setup_message"]; !ok || v == nil {
		out["totp_setup_message"] = ""
	}
	return out
}

func compactJob(j domain.Job) map[string]any {
	out := map[string]any{
		"id":           j.ID,
		"status":       string(j.Status),
		"email":        j.Email,
		"email_source": j.EmailSource,
		"batch_id":     j.BatchID,
		"created_at":   j.CreatedAt.Format("2006-01-02 15:04:05"),
		"started_at":   j.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if j.Error != "" {
		errShort := j.Error
		if len(errShort) > 240 {
			errShort = errShort[:240] + "…"
		}
		out["error_message"] = errShort
	}
	if j.CompletedAt != nil {
		out["completed_at"] = j.CompletedAt.Format("2006-01-02 15:04:05")
	}
	if j.NetworkTraffic != nil {
		out["network_traffic"] = j.NetworkTraffic
	}
	if j.Stage != nil {
		out["registration_stage"] = j.Stage
	}
	// 手动验证码等待标记：前端据此在任务行旁边显示输入框。
	if j.Payload != nil {
		if v, ok := j.Payload["manual_otp_required"]; ok {
			out["manual_otp_required"] = v
		}
	}
	return out
}

func decorateEmailItem(it store.EmailItem) map[string]any {
	out := map[string]any{
		"id":          it.ID,
		"email":       it.Email,
		"source":      it.Source,
		"status":      it.Status,
		"archived":    it.Archived,
		"created_at":  it.CreatedAt.Format("2006-01-02 15:04:05"),
		"imported_at": it.CreatedAt.Format("2006-01-02 15:04:05"),
		"payload":     it.Payload,
	}

	copyLine := it.Email
	if it.Payload != nil {
		if cred, ok := it.Payload["credential"].(string); ok && cred != "" {
			copyLine = it.Email + "----" + cred
		} else if codeURL, ok := it.Payload["code_url"].(string); ok && codeURL != "" {
			copyLine = it.Email + "----" + codeURL
		} else if pw, ok := it.Payload["password"].(string); ok && pw != "" {
			cid, _ := it.Payload["client_id"].(string)
			rt, _ := it.Payload["refresh_token"].(string)
			if cid != "" || rt != "" {
				copyLine = strings.Join([]string{it.Email, pw, cid, rt}, "----")
			} else {
				copyLine = it.Email + "----" + pw
			}
		}
		if at, ok := it.Payload["access_token"].(string); ok && at != "" {
			out["access_token"] = at
			out["account_copy_line"] = it.Email + "----" + at
		}
	}
	out["copy_line"] = copyLine
	return out
}

// probeAccessToken 用 /backend-api/wham/usage 独立校验 AT：
// 上游 core/account_liveness.py 的 probe_access_token_liveness 走的就是这个端点，
// 200 表示 AT 真有效，401 表示过期/失效，其它状态代表网络或限流。
func (s *Server) probeAccessToken(ctx context.Context, acc *domain.Account, token string) (int, string, error) {
	status, uid, _, err := s.probeAccessTokenDetailed(ctx, acc, token)
	return status, uid, err
}

// probeAccessTokenDetailed 在 probeAccessToken 基础上额外返回 OpenAI 的 error.code，
// 用来区分 token_expired（等一段时间自然过期）与 token_revoked（会话被吊销，必须重新登录）。
func (s *Server) probeAccessTokenDetailed(ctx context.Context, acc *domain.Account, token string) (int, string, string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, "", "", fmt.Errorf("AT 为空")
	}
	proxy := s.getProxyForAccount(acc)
	sess, err := protocol.NewSession(accountSessionOptions(acc, proxy))
	if err != nil {
		return 0, "", "", err
	}
	defer sess.Close()

	resp, err := sess.RequestCtx(ctx, http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", "", map[string]string{
		"Authorization":         "Bearer " + token,
		"Accept":                "application/json",
		"Referer":               "https://chatgpt.com/",
		"x-openai-target-path":  "/backend-api/wham/usage",
		"x-openai-target-route": "/backend-api/wham/usage",
	})
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var data struct {
		UserID   string `json:"user_id"`
		PlanType string `json:"plan_type"`
		Error    struct {
			Message string `json:"message"`
			Code    string `json:"code"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &data)
	errCode := data.Error.Code
	if errCode == "" {
		errCode = data.Error.Type
	}
	if resp.StatusCode == 200 && data.PlanType != "" {
		s.appendLiveLog(acc.Email, fmt.Sprintf("[探活] plan_type=%s", data.PlanType))
	} else if resp.StatusCode == 401 && errCode != "" {
		s.appendLiveLog(acc.Email, fmt.Sprintf("[探活] AT 失效: code=%s msg=%s", errCode, truncateForLog(data.Error.Message, 160)))
	}
	_ = proxy
	return resp.StatusCode, data.UserID, errCode, nil
}

// truncateForLog 截断日志文本，避免整段 JSON 冲爆日志行。
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// accountDeviceID 取出账号注册时固化的 oai-did；缺失时现场生成并写回 Payload，
// 保证同一账号后续所有操作（刷新 AT / 绑 2FA / 查活 / 查支付）共用同一设备指纹。
func accountDeviceID(acc *domain.Account) string {
	if acc == nil {
		return sentinel.DeviceID()
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	if s, ok := acc.Payload["device_id"].(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	fresh := sentinel.DeviceID()
	acc.Payload["device_id"] = fresh
	return fresh
}

// maskSecret 只露出长度与首尾两个字符，避免明文凭据落进日志表。
func maskSecret(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func extractAccountSecret(acc *domain.Account, field string) string {
	if acc == nil || acc.Payload == nil {
		return ""
	}
	switch field {
	case "access_token":
		s, _ := acc.Payload["access_token"].(string)
		return s
	case "session_token":
		s, _ := acc.Payload["session_token"].(string)
		return s
	case "totp_secret":
		s, _ := acc.Payload["totp_secret"].(string)
		return s
	case "totp_code":
		s, _ := acc.Payload["totp_secret"].(string)
		if strings.TrimSpace(s) == "" {
			return ""
		}
		code, err := twofa.CurrentCode(s)
		if err != nil {
			return ""
		}
		return code
	case "password":
		if s, ok := acc.Payload["registration_password"].(string); ok && s != "" {
			return s
		}
		if s, ok := acc.Payload["password"].(string); ok && s != "" {
			return s
		}
		if s, ok := acc.Payload["password_candidate"].(string); ok && s != "" {
			return s
		}
		return ""
	case "copy_line":
		at, _ := acc.Payload["access_token"].(string)
		return acc.Email + "----" + at
	default:
		return ""
	}
}

func parseEmailLines(text, source string) []store.EmailItem {
	var out []store.EmailItem
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		email, cred, ok := strings.Cut(line, "----")
		if !ok {
			email, cred, ok = strings.Cut(line, ":")
		}
		email = strings.TrimSpace(email)
		if !ok || email == "" || !isValidEmail(email) {
			continue
		}
		out = append(out, store.EmailItem{
			Email:   email,
			Source:  source,
			Status:  "available",
			Payload: map[string]any{"credential": strings.TrimSpace(cred)},
		})
	}
	return out
}

func isValidEmail(s string) bool {
	at := strings.Index(s, "@")
	if at <= 0 || at >= len(s)-1 {
		return false
	}
	dot := strings.LastIndex(s[at:], ".")
	return dot > 1 && at+dot < len(s)-1
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func nowRFC3339() string { return time.Now().Format("2006-01-02T15:04:05Z07:00") }

func readTail(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	off := int64(0)
	if st.Size() > maxBytes {
		off = st.Size() - maxBytes
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func hmacEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

var _ = slog.Info

// registrationEffectivelyComplete 判断「注册标记是否已被实际完成状态覆盖」。
// 口径逐字对齐上游 core/db.py:1072-1095 的 _account_registration_is_effectively_complete：
// 只对 registering / interrupted 计算，且密码验收、AT 有效、2FA 三件同时成立才算完成。
func registrationEffectivelyComplete(a domain.Account) bool {
	st := strings.ToLower(strings.TrimSpace(a.Status))
	if st != "registering" && st != "interrupted" {
		return false
	}
	p := a.Payload
	if p == nil {
		return false
	}
	truthy := func(v any) bool {
		switch x := v.(type) {
		case bool:
			return x
		case string:
			s := strings.ToLower(strings.TrimSpace(x))
			return s == "1" || s == "true" || s == "yes" || s == "on"
		case float64:
			return x != 0
		case int:
			return x != 0
		case int64:
			return x != 0
		}
		return false
	}
	str := func(key string) string {
		if v, ok := p[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}

	passwordOK := truthy(p["password_setup_login_verified"]) ||
		truthy(p["password_change_login_verified"]) ||
		truthy(p["registration_password_verified"])

	token := str("access_token")
	tokenExpired := truthy(p["token_expired"])
	httpStatus := str("plan_check_http_status")
	liveStatus := strings.ToLower(str("live_check_status"))
	atOK := token != "" && !tokenExpired && httpStatus != "401" &&
		liveStatus != "failed" && liveStatus != "deactivated" && liveStatus != "dead"

	totpSecret := str("totp_secret")
	totpStatus := strings.ToLower(str("totp_setup_status"))
	totpOK := totpSecret != "" && (truthy(p["totp_setup_ok"]) || totpStatus == "success")

	return passwordOK && atOK && totpOK
}

// parseIDList 解析前端下发的 ID 数组，逐条容错。
// 逐字对齐上游 webui/app.py 的处理口径：非数字条目进 skipped（reason="ID 非法"），
// 数字自动去重并按出现顺序保留。raw 为 nil 或空数组时返回空切片。
func parseIDList(raw []any) (ids []int64, skipped []map[string]any) {
	seen := map[int64]bool{}
	for _, item := range raw {
		var id int64
		switch v := item.(type) {
		case float64:
			id = int64(v)
		case int64:
			id = v
		case int:
			id = int64(v)
		case string:
			s := strings.TrimSpace(v)
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				skipped = append(skipped, map[string]any{"id": v, "reason": "ID 非法"})
				continue
			}
			id = n
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				skipped = append(skipped, map[string]any{"id": v.String(), "reason": "ID 非法"})
				continue
			}
			id = n
		default:
			skipped = append(skipped, map[string]any{"id": item, "reason": "ID 非法"})
			continue
		}
		if id <= 0 {
			skipped = append(skipped, map[string]any{"id": id, "reason": "ID 非法"})
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, skipped
}
