package mail

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// tempmailIOBase 是 temp-mail.io 的公开 API，无需 Key。
const tempmailIOBase = "https://api.internal.temp-mail.io/api/v3"

// 与 mail.tm 的区别：域名不固定，每次创建时由服务端轮换，
// 供应商域名轮换比固定域名更不易被一次性封禁。
type tempmailIOAccount struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type TempMailIOProvider struct {
	persist *persistStore

	mu       sync.Mutex
	accounts []tempmailIOAccount
	loaded   bool
}

// NewTempMailIO 创建 temp-mail.io 来源。
func NewTempMailIO(persistPath string) *TempMailIOProvider {
	return &TempMailIOProvider{persist: &persistStore{path: persistPath}}
}

func (p *TempMailIOProvider) Name() string { return string(domain.SourceTempMailIO) }

func (p *TempMailIOProvider) ensureLoaded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	var accs []tempmailIOAccount
	if err := p.persist.load(&accs); err == nil {
		p.accounts = accs
	}
}

func (p *TempMailIOProvider) Acquire(ctx context.Context) (domain.Mailbox, error) {
	p.ensureLoaded()

	p.mu.Lock()
	if len(p.accounts) > 0 {
		acc := p.accounts[0]
		p.accounts = p.accounts[1:]
		p.mu.Unlock()
		_ = p.save()
		return domain.Mailbox{
			Email:      acc.Email,
			Source:     domain.SourceTempMailIO,
			AcquiredAt: time.Now(),
			Credential: map[string]string{"token": acc.Token},
		}, nil
	}
	p.mu.Unlock()

	var out struct {
		Email string `json:"email"`
		Token string `json:"token"`
	}
	if err := jsonPost(ctx, tempmailIOBase+"/email/new", nil, map[string]any{}, &out); err != nil {
		return domain.Mailbox{}, fmt.Errorf("temp-mail.io 创建邮箱失败: %w", err)
	}
	if out.Email == "" || out.Token == "" {
		return domain.Mailbox{}, fmt.Errorf("temp-mail.io 返回内容不完整")
	}
	return domain.Mailbox{
		Email:      out.Email,
		Source:     domain.SourceTempMailIO,
		AcquiredAt: time.Now(),
		Credential: map[string]string{"token": out.Token},
	}, nil
}

func (p *TempMailIOProvider) WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error) {
	tok := box.Credential["token"]
	url := fmt.Sprintf("%s/email/%s/messages?token=%s", tempmailIOBase, box.Email, tok)

	var list []struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		Subject   string `json:"subject"`
		BodyText  string `json:"body_text"`
		BodyHTML  string `json:"body_html"`
	}
	if err := jsonGet(ctx, url, nil, &list); err != nil {
		return domain.OTPResult{}, err
	}
	for _, m := range list {
		ts, _ := time.Parse(time.RFC3339, m.CreatedAt)
		if !after.IsZero() && ts.Before(after.Add(-30*time.Second)) {
			continue
		}
		if code := ExtractOTP(m.Subject + " " + m.BodyText + " " + stripTags(m.BodyHTML)); code != "" {
			return domain.OTPResult{Code: code, Received: ts, Source: "tempmailio"}, nil
		}
	}
	return domain.OTPResult{}, nil
}

func (p *TempMailIOProvider) Release(ctx context.Context, box domain.Mailbox, reason string) error {
	if reason == "success" {
		return nil
	}
	p.mu.Lock()
	p.accounts = append(p.accounts, tempmailIOAccount{
		Email: box.Email,
		Token: box.Credential["token"],
	})
	p.mu.Unlock()
	return p.save()
}

func (p *TempMailIOProvider) save() error {
	p.mu.Lock()
	accs := append([]tempmailIOAccount(nil), p.accounts...)
	p.mu.Unlock()
	return p.persist.save(accs)
}

// stripTags 粗暴去掉 HTML 标签，只保留文本用于正则取码。
func stripTags(s string) string {
	var sb strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
