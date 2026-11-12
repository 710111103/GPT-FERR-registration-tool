package mail

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail/genericapi"
	"github.com/turb/gpt-register/internal/store"
)

// PoolProvider 包装本地 SQLite 邮箱池，作为来源使用。
//
// Python 版对应 core/email_provider.py 里对 db 的直接调用：
// 从 email_pool 表原子领取一个 status=available 的行。
// 这里把它也做成 Provider，于是"池"和"外部 API"在注册表里是同一种东西。
type PoolProvider struct {
	store  *store.Store
	source string
	// fetchURL 可选：若该来源的行 payload 里带取码地址，则直接请求它。
	fetchURL func(payload map[string]any) string
}

// NewPool 创建池来源。source 需与导入时的来源标识一致。
func NewPool(st *store.Store, source string) *PoolProvider {
	return &PoolProvider{
		store:  st,
		source: source,
		fetchURL: func(p map[string]any) string {
			u, _ := p["code_url"].(string)
			return u
		},
	}
}

func (p *PoolProvider) Name() string { return p.source }

// Acquire 从池里原子领取一条可用邮箱。
func (p *PoolProvider) Acquire(ctx context.Context) (domain.Mailbox, error) {
	item, err := p.store.ClaimEmail(ctx, p.source)
	if err != nil {
		return domain.Mailbox{}, err
	}
	if item == nil {
		return domain.Mailbox{}, ErrNoMailbox
	}
	cred := map[string]string{}
	for k, v := range item.Payload {
		if s, ok := v.(string); ok {
			cred[k] = s
		}
	}
	return domain.Mailbox{
		Email:      item.Email,
		Source:     domain.EmailSource(item.Source),
		Credential: cred,
		AcquiredAt: time.Now(),
	}, nil
}

// WaitCode 按 payload 里的取码地址拉验证码。
// 通用 API 邮箱的来源格式就是 "email----code_url"。
func (p *PoolProvider) WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error) {
	codeURL := box.Credential["code_url"]
	if codeURL == "" {
		codeURL = box.Credential["credential"]
	}
	// credential 可能是 "email----code_url" 里的第二段，若不像 URL 就忽略
	if codeURL != "" && !strings.HasPrefix(codeURL, "http") {
		codeURL = ""
	}
	if codeURL == "" {
		return domain.OTPResult{}, fmt.Errorf(
			"邮箱 %s 没有取码地址，且来源 %q 未实现 IMAP/Graph 取信", box.Email, p.source)
	}

	cli := genericapi.NewClient("")
	res, err := cli.FetchCode(ctx, codeURL, box.Email, after)
	if err != nil {
		return domain.OTPResult{}, err
	}
	if res.Source == "" {
		res.Source = p.source
	}
	return res, nil
}

// Release 按注册结果回写池状态。
func (p *PoolProvider) Release(ctx context.Context, box domain.Mailbox, reason string) error {
	switch reason {
	case "success":
		return nil // ClaimEmail 已置为 used
	case "cancelled":
		// 用户停止时释放浏览器/邮箱资源，但不要让同批的下一个任务在几毫秒后
		// 再次领取同一地址。冷却期内在 ClaimEmail 层不可见，到期后自动恢复。
		return p.store.ReleaseEmailWithCooldown(ctx, box.Email, 10*time.Minute)
	case "otp_rejected":
		// 验证码被 OpenAI 明确拒绝时，该邮箱可能已被上一轮注册占用或存在旧验证码，
		// 不再自动回到 available，避免几秒后被同一任务链反复领取。
		_, err := p.store.RecordEmailFailure(ctx, box.Email, string(box.Source), reason, 1)
		return err
	default:
		// 单次失败可能是偶发（网络抖动 / 取码源瞬时断路），先放回 available 重试；
		// 连续失败达到 2 次才真正标 failed，避免坏号无限空转。
		_, err := p.store.RecordEmailFailure(ctx, box.Email, string(box.Source), reason, 2)
		return err
	}
}

// flattenJSON 把任意 JSON 结构压成一段文本，便于统一正则取码。
func flattenJSON(v any) string {
	var sb strings.Builder
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			sb.WriteString(t)
			sb.WriteString(" ")
		case float64, bool, nil:
			fmt.Fprintf(&sb, "%v ", t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return sb.String()
}
