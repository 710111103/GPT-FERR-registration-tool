// Package job 是注册任务的调度层。
//
// 与 Python 版 core/registration_service.py 的对比：
//
//	Python: ThreadPoolExecutor + _THREAD_CTX(ThreadLocal) + _STOP_EVENTS 字典
//	        + _ACTIVE_JOBS 集合 + _JOB_DRIVERS 字典 + StopRequested 异常
//	Go:     有界 semaphore + context.WithCancel + 一个 jobs map
//
// 取消、超时、级联关闭全部由 context 承担，不再需要任何线程局部状态。
package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/store"
)

// ErrStopped 表示任务被用户手动停止。
var ErrStopped = errors.New("任务已被用户手动停止")

// Runner 是任务真正要做的事。由 register 包实现并注入，避免 job 依赖具体驱动。
type Runner func(ctx context.Context, j *domain.Job, log *Logger) (Result, error)

// Result 是 Runner 的产出。
type Result struct {
	Email     string
	AccountID int64
	Stage     domain.Stage
	Traffic   *domain.Traffic
}

// SuccessHook 在任务成功终态持久化后调用。它必须快速返回；耗时工作应由
// 调用方自行排队，避免占用注册任务 goroutine。
type SuccessHook func(accountID int64)

// Pool 管理并发注册任务。
type Pool struct {
	store  *store.Store
	runner Runner
	logDir string

	// width 是当前并发上限。调整时会新建一个 semaphore，旧任务跑完为止，
	// 语义与 Python 版"改线程数即新建线程池"一致。
	mu    sync.RWMutex
	sem   chan struct{}
	width int

	jobsMu sync.RWMutex
	jobs   map[int64]*handle

	hookMu      sync.RWMutex
	successHook SuccessHook

	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type handle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// NewPool 创建任务池。width 为并发数。
func NewPool(st *store.Store, runner Runner, logDir string, width int) *Pool {
	if width < 1 {
		width = 1
	}
	if width > 64 {
		width = 64
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		store:   st,
		runner:  runner,
		logDir:  logDir,
		sem:     make(chan struct{}, width),
		width:   width,
		jobs:    make(map[int64]*handle),
		baseCtx: ctx,
		cancel:  cancel,
	}
}

// SetWidth 调整并发上限。已在跑的任务不受影响。
func (p *Pool) SetWidth(n int) {
	if n < 1 {
		n = 1
	}
	if n > 64 {
		n = 64
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n == p.width {
		return
	}
	p.width = n
	p.sem = make(chan struct{}, n)
}

// Width 返回当前并发上限。
func (p *Pool) Width() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.width
}

// SetSuccessHook 注册成功任务回调，用于衔接注册后的套餐/优惠探测等旁路任务。
func (p *Pool) SetSuccessHook(hook SuccessHook) {
	p.hookMu.Lock()
	p.successHook = hook
	p.hookMu.Unlock()
}

// JobOptions 是一批任务的提交参数。
type JobOptions struct {
	Count       int
	EmailSource string
	Email       string
	Proxy       string
	Driver      string
	BatchID     string
	// Payload 在任务启动前写入 payload 字段，供 runner 读取（如 resume_account_id）。
	Payload map[string]any
}

// NewBatchID 生成一次注册提交的持久化批次 ID。
func NewBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}

// SubmitWithOptions 创建带特定参数的任务。
func (p *Pool) SubmitWithOptions(ctx context.Context, opt JobOptions) ([]int64, error) {
	if opt.Count < 1 {
		opt.Count = 1
	}
	if opt.Count > 10000 {
		return nil, fmt.Errorf("单次最多提交 10000 个任务")
	}
	if opt.BatchID == "" {
		opt.BatchID = NewBatchID()
	}
	ids := make([]int64, 0, opt.Count)
	for i := 0; i < opt.Count; i++ {
		email := ""
		if opt.Count == 1 && opt.Email != "" {
			email = opt.Email
		}
		id, err := p.store.CreateJobWithBatch(ctx, email, opt.EmailSource, "", opt.BatchID)
		if err != nil {
			return ids, fmt.Errorf("创建任务失败: %w", err)
		}
		upd := store.JobUpdate{Driver: opt.Driver, Proxy: opt.Proxy}
		for k, v := range opt.Payload {
			if upd.Payload == nil {
				upd.Payload = map[string]any{}
			}
			upd.Payload[k] = v
		}
		if upd.Driver != "" || upd.Proxy != "" || len(upd.Payload) > 0 {
			_ = p.store.UpdateJob(ctx, id, upd)
		}
		logPath := filepath.Join(p.logDir, fmt.Sprintf("job-%d.log", id))
		ids = append(ids, id)
		p.launch(id, opt.EmailSource, logPath)
	}
	return ids, nil
}

// Submit 创建 count 条任务并异步执行，立即返回任务 ID 列表。
func (p *Pool) Submit(ctx context.Context, count int, emailSource string) ([]int64, error) {
	return p.SubmitWithOptions(ctx, JobOptions{Count: count, EmailSource: emailSource})
}

// launch 在 goroutine 中等待信号量后执行任务。
func (p *Pool) launch(id int64, emailSource, logPath string) {
	p.mu.RLock()
	sem := p.sem
	p.mu.RUnlock()

	ctx, cancel := context.WithCancel(p.baseCtx)
	h := &handle{cancel: cancel, done: make(chan struct{})}
	p.jobsMu.Lock()
	p.jobs[id] = h
	p.jobsMu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(h.done)
		defer func() {
			p.jobsMu.Lock()
			delete(p.jobs, id)
			p.jobsMu.Unlock()
			cancel()
		}()

		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			p.finish(context.Background(), id, domain.JobCancelled, "排队期间被取消", Result{})
			return
		}

		// 用户可能在排队期间点了取消
		if ctx.Err() != nil {
			p.finish(context.Background(), id, domain.JobCancelled, "排队期间被取消", Result{})
			return
		}

		// 抢占任务，防止重复执行
		ok, err := p.store.ClaimJob(ctx, id)
		if err != nil {
			p.finish(context.Background(), id, domain.JobFailed, "抢占任务失败: "+err.Error(), Result{})
			return
		}
		if !ok {
			return // 已被取消或删除
		}

		lg, err := NewLogger(logPath)
		if err != nil {
			lg = NewDiscardLogger()
		}
		defer lg.Close()

		lg.Infof("[Job %d] 开始注册任务（并发上限 %d）", id, p.Width())
		j, err := p.store.GetJob(context.Background(), id)
		if err != nil || j == nil {
			p.finish(context.Background(), id, domain.JobFailed, "任务记录不存在", Result{})
			return
		}

		res, runErr := p.safeRun(ctx, j, lg)
		switch {
		case errors.Is(runErr, ErrStopped) || errors.Is(ctx.Err(), context.Canceled):
			lg.Warnf("[Job %d] 已按用户请求停止", id)
			p.finish(context.Background(), id, domain.JobStopped, "用户手动停止", res)
		case runErr != nil:
			lg.Errorf("[Job %d] 注册失败: %v", id, runErr)
			res.Stage.Fail("unknown", classifyError(runErr))
			p.finish(context.Background(), id, domain.JobFailed, runErr.Error(), res)
		default:
			lg.Infof("[Job %d] 注册成功: %s", id, res.Email)
			p.finish(context.Background(), id, domain.JobSuccess, "", res)
			p.notifySuccess(res.AccountID)
		}
	}()
}

func (p *Pool) notifySuccess(accountID int64) {
	if accountID == 0 {
		return
	}
	p.hookMu.RLock()
	hook := p.successHook
	p.hookMu.RUnlock()
	if hook != nil {
		hook(accountID)
	}
}

// safeRun 隔离 panic，保证一个任务崩溃不会带崩整个进程。
func (p *Pool) safeRun(ctx context.Context, j *domain.Job, lg *Logger) (res Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			lg.Errorf("[Job %d] 任务 panic: %v", j.ID, r)
			err = fmt.Errorf("任务内部错误: %v", r)
		}
	}()
	return p.runner(ctx, j, lg)
}

// finish 写回任务终态。
func (p *Pool) finish(ctx context.Context, id int64, status domain.JobStatus, errMsg string, res Result) {
	u := store.JobUpdate{
		Status:    &status,
		Completed: true,
	}
	if errMsg != "" {
		u.Error = &errMsg
	}
	if res.Email != "" {
		u.Email = &res.Email
	}
	if res.AccountID != 0 {
		u.AccountID = &res.AccountID
	}
	if res.Stage.Flow != "" {
		u.Stage = &res.Stage
	}
	if res.Traffic != nil {
		u.Traffic = res.Traffic
	}
	if err := p.store.UpdateJob(ctx, id, u); err != nil {
		slog.Error("写回任务状态失败", "job", id, "err", err)
	}
}

// Stop records the stop request first, then cancels the live handle. A running
// job without a live handle is finalized immediately so the database can
// never remain stuck in running/stopping after the process has lost the task.
func (p *Pool) Stop(id int64) (store.JobStopResult, error) {
	result, err := p.store.RequestJobStop(context.Background(), id)
	if err != nil || !result.Exists {
		return result, err
	}

	p.jobsMu.RLock()
	h := p.jobs[id]
	p.jobsMu.RUnlock()
	if h != nil {
		h.cancel()
		return result, nil
	}
	if result.Status == domain.JobRunning || result.Status == domain.JobStopping {
		return p.store.FinalizeStoppedJob(context.Background(), id)
	}
	return result, nil
}

// CancelHandles cancels in-memory handles by ID. It is used after the store has
// atomically moved pending jobs to cancelled.
func (p *Pool) CancelHandles(ids []int64) int {
	cancelled := 0
	p.jobsMu.RLock()
	handles := make([]*handle, 0, len(ids))
	for _, id := range ids {
		if h := p.jobs[id]; h != nil {
			handles = append(handles, h)
		}
	}
	p.jobsMu.RUnlock()
	for _, h := range handles {
		h.cancel()
		cancelled++
	}
	return cancelled
}

// CancelPending cancels queue entries both in SQLite and in this process. This
// is important because changing only the database leaves goroutines blocked on
// the semaphore until unrelated running tasks finish.
func (p *Pool) CancelPending(ctx context.Context) (int64, error) {
	ids, err := p.store.CancelPendingJobs(ctx)
	if err != nil {
		return 0, err
	}
	p.CancelHandles(ids)
	return int64(len(ids)), nil
}

// StopAll 取消所有在跑任务并等待收尾。
func (p *Pool) StopAll(timeout time.Duration) {
	p.jobsMu.RLock()
	handles := make([]*handle, 0, len(p.jobs))
	for _, h := range p.jobs {
		handles = append(handles, h)
	}
	p.jobsMu.RUnlock()

	for _, h := range handles {
		h.cancel()
	}
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("等待任务收尾超时", "timeout", timeout)
	}
}

// Shutdown 关闭整个池。
func (p *Pool) Shutdown() {
	p.StopAll(30 * time.Second)
	p.cancel()
}

// Active 返回当前在跑任务数。
func (p *Pool) Active() int {
	p.jobsMu.RLock()
	defer p.jobsMu.RUnlock()
	return len(p.jobs)
}

// classifyError 把错误归类成与 Python 版一致的 error_code，便于看板统计。
func classifyError(err error) string {
	msg := err.Error()
	switch {
	case contains(msg, "otp") || contains(msg, "验证码"):
		return "otp"
	case contains(msg, "password") || contains(msg, "密码"):
		return "password"
	case contains(msg, "token") || contains(msg, "session") || contains(msg, "oauth"):
		return "credential"
	case contains(msg, "403") || contains(msg, "cloudflare") || contains(msg, "challenge"):
		return "blocked"
	default:
		return "unknown"
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	ls, lsub := lower(s), lower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
