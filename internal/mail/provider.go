// Package mail 统一了 Python 版里十几个各自为政的取码客户端。
//
// Python 现状（core/ 下）：outlook_client、generic_api_mail_client、imap_mail_client、
// qqmail_client、cf_temp_mail_client、cloudmail_client、gptmail_client、mailnest_client、
// remail_client、mailcode_client、xigua_client、mailtm_client、tempmailio_client ——
// 每个都导出 pick_account / fetch_latest_otp / release_account 三个同名函数，
// 靠 core/email_provider.py 里的 if-else 链分发。
//
// Go 版把这三件事收敛成一个接口，Provider 自己决定语义。
package mail

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail/genericapi"
)

// ErrNoMailbox 表示该来源当前没有可用邮箱。
var ErrNoMailbox = errors.New("该来源暂无可用邮箱")

// ErrOTPTimeout 表示在等待窗口内没有收到验证码。
var ErrOTPTimeout = errors.New("等待验证码超时")

// Provider 是一个邮箱来源。
type Provider interface {
	// Name 返回来源标识，需与配置里的 EMAIL_SOURCE 取值一致。
	Name() string
	// Acquire 领取一个邮箱。返回的 Mailbox 会传给 WaitCode 与 Release。
	Acquire(ctx context.Context) (domain.Mailbox, error)
	// WaitCode 在 after 之后收到的邮件里找验证码。
	WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error)
	// Release 归还邮箱。reason 为 "success" 表示已成功消费，其余为失败回收。
	Release(ctx context.Context, box domain.Mailbox, reason string) error
}

// Registry 持有全部已注册的 Provider。
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}}
}

// Register 注册一个 Provider。同名重复注册会覆盖，便于测试替换。
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get 按名称取 Provider。第二个返回值表示是否存在。
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Names 返回已注册来源名，用于启动日志与配置校验。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Acquire 按配置顺序依次尝试各来源，首个成功者胜出。
// 语义与 Python 版 EMAIL_SOURCE="outlook,generic_api,imap" 的兜底链一致。
func (r *Registry) Acquire(ctx context.Context, sources []string) (domain.Mailbox, Provider, error) {
	if len(sources) == 0 {
		return domain.Mailbox{}, nil, fmt.Errorf("未配置邮箱来源")
	}
	var errs []error
	for _, name := range sources {
		p, ok := r.Get(name)
		if !ok {
			errs = append(errs, fmt.Errorf("未知邮箱来源 %q", name))
			continue
		}
		box, err := p.Acquire(ctx)
		if err == nil {
			return box, p, nil
		}
		if errors.Is(err, ErrNoMailbox) {
			continue // 这个来源空了，试下一个
		}
		if ctx.Err() != nil {
			return domain.Mailbox{}, nil, ctx.Err()
		}
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}
	if len(errs) == 0 {
		return domain.Mailbox{}, nil, ErrNoMailbox
	}
	return domain.Mailbox{}, nil, errors.Join(errs...)
}

// WaitCodeWithRetry 在超时窗口内轮询取码。
// 可选接收 onProgress 回调，定期上报等待进度与最近一次错误，防止用户界面无日志反馈。
func WaitCodeWithRetry(
	ctx context.Context,
	p Provider,
	box domain.Mailbox,
	after time.Time,
	maxWait, poll time.Duration,
	onProgress ...func(elapsed, maxWait time.Duration, lastErr error),
) (domain.OTPResult, error) {
	if poll <= 0 {
		poll = 5 * time.Second
	}
	if maxWait <= 0 {
		maxWait = 180 * time.Second
	}
	started := time.Now()
	deadline := started.Add(maxWait)
	var lastErr error
	lastReport := time.Now()
	for {
		if ctx.Err() != nil {
			return domain.OTPResult{}, ctx.Err()
		}
		res, err := p.WaitCode(ctx, box, after)
		if err == nil && res.Code != "" {
			return res, nil
		}
		// auth:error 是上游对该邮箱的静态断路标记，继续轮询只会空转到 maxWait，
		// 立刻返回让编排层换邮箱/换来源，别把整个任务窗口耗死。
		var authErr *genericapi.AuthError
		if errors.As(err, &authErr) {
			return domain.OTPResult{}, err
		}
		lastErr = err
		if time.Now().After(deadline) {
			if lastErr != nil {
				return domain.OTPResult{}, fmt.Errorf("%w: %v", ErrOTPTimeout, lastErr)
			}
			return domain.OTPResult{}, ErrOTPTimeout
		}
		if len(onProgress) > 0 && onProgress[0] != nil && time.Since(lastReport) >= 8*time.Second {
			onProgress[0](time.Since(started), maxWait, lastErr)
			lastReport = time.Now()
		}
		select {
		case <-time.After(poll):
		case <-ctx.Done():
			return domain.OTPResult{}, ctx.Err()
		}
	}
}
