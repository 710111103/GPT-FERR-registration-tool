package mail

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// mailtmProvider 实现 mail.tm 免费临时邮箱（无需 API Key）。
//
// API：https://api.mail.tm
//
//	POST /domains            列出可用域名
//	POST /accounts           创建邮箱（address + password）
//	POST /token              换取 JWT（1 小时有效）
//	GET  /messages?page=1    Bearer JWT 列出邮件
//	GET  /messages/{id}      取单封正文
//
// 凭据会落盘，因为"查活"要用同一邮箱重走一遍 OTP，进程重启后必须能恢复。
const mailtmBase = "https://api.mail.tm"

type mailtmAccount struct {
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type MailTMProvider struct {
	persist *persistStore

	mu       sync.Mutex
	accounts []mailtmAccount
	loaded   bool
}

// NewMailTM 创建 mail.tm 来源。persistPath 为凭据落盘路径。
func NewMailTM(persistPath string) *MailTMProvider {
	return &MailTMProvider{persist: &persistStore{path: persistPath}}
}

func (p *MailTMProvider) Name() string { return string(domain.SourceMailTM) }

func (p *MailTMProvider) ensureLoaded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	var accs []mailtmAccount
	if err := p.persist.load(&accs); err == nil {
		for _, a := range accs {
			if a.ExpiresAt.IsZero() || a.ExpiresAt.After(time.Now()) {
				p.accounts = append(p.accounts, a)
			}
		}
	}
}

// Acquire 优先复用池中已有邮箱，池空则新建一个。
func (p *MailTMProvider) Acquire(ctx context.Context) (domain.Mailbox, error) {
	p.ensureLoaded()

	p.mu.Lock()
	if len(p.accounts) > 0 {
		acc := p.accounts[0]
		p.accounts = p.accounts[1:]
		p.mu.Unlock()
		tok, err := p.token(ctx, acc)
		if err != nil {
			return domain.Mailbox{}, err
		}
		p.save()
		return domain.Mailbox{
			Email:      acc.Email,
			Source:     domain.SourceMailTM,
			AcquiredAt: time.Now(),
			Credential: map[string]string{"password": acc.Password, "token": tok},
		}, nil
	}
	p.mu.Unlock()

	acc, err := p.create(ctx)
	if err != nil {
		return domain.Mailbox{}, err
	}
	tok, err := p.token(ctx, acc)
	if err != nil {
		return domain.Mailbox{}, err
	}
	return domain.Mailbox{
		Email:      acc.Email,
		Source:     domain.SourceMailTM,
		AcquiredAt: time.Now(),
		Credential: map[string]string{"password": acc.Password, "token": tok},
	}, nil
}

func (p *MailTMProvider) create(ctx context.Context) (mailtmAccount, error) {
	var domains struct {
		Members []struct {
			Domain string `json:"domain"`
			Active bool   `json:"isActive"`
		} `json:"hydra:member"`
	}
	if err := jsonGet(ctx, mailtmBase+"/domains?page=1", nil, &domains); err != nil {
		return mailtmAccount{}, fmt.Errorf("mail.tm 获取域名失败: %w", err)
	}
	domainName := ""
	for _, d := range domains.Members {
		if d.Active && d.Domain != "" {
			domainName = d.Domain
			break
		}
	}
	if domainName == "" {
		return mailtmAccount{}, fmt.Errorf("mail.tm 没有可用域名")
	}

	local := randomString(12)
	addr := local + "@" + domainName
	password := randomString(16)
	body := map[string]string{"address": addr, "password": password}
	if err := jsonPost(ctx, mailtmBase+"/accounts", nil, body, nil); err != nil {
		return mailtmAccount{}, fmt.Errorf("mail.tm 创建邮箱失败: %w", err)
	}
	return mailtmAccount{Email: addr, Password: password}, nil
}

// token 换取（或刷新）JWT。
func (p *MailTMProvider) token(ctx context.Context, acc mailtmAccount) (string, error) {
	if acc.Token != "" && time.Now().Before(acc.ExpiresAt.Add(-2*time.Minute)) {
		return acc.Token, nil
	}
	var out struct {
		Token string `json:"token"`
	}
	body := map[string]string{"address": acc.Email, "password": acc.Password}
	if err := jsonPost(ctx, mailtmBase+"/token", nil, body, &out); err != nil {
		return "", fmt.Errorf("mail.tm 换 token 失败: %w", err)
	}
	p.mu.Lock()
	for i := range p.accounts {
		if p.accounts[i].Email == acc.Email {
			p.accounts[i].Token = out.Token
			p.accounts[i].ExpiresAt = time.Now().Add(50 * time.Minute)
		}
	}
	p.mu.Unlock()
	return out.Token, nil
}

// WaitCode 拉取收件箱并提取第一个六位验证码。
func (p *MailTMProvider) WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error) {
	tok := box.Credential["token"]
	headers := map[string]string{"Authorization": "Bearer " + tok}

	var list struct {
		Members []struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
			Subject   string `json:"subject"`
			Intro     string `json:"intro"`
		} `json:"hydra:member"`
	}
	if err := jsonGet(ctx, mailtmBase+"/messages?page=1", headers, &list); err != nil {
		return domain.OTPResult{}, err
	}
	for _, m := range list.Members {
		ts, _ := time.Parse(time.RFC3339, m.CreatedAt)
		if !after.IsZero() && ts.Before(after.Add(-30*time.Second)) {
			continue
		}
		if code := ExtractOTP(m.Subject + " " + m.Intro); code != "" {
			return domain.OTPResult{Code: code, Received: ts, Source: "mailtm"}, nil
		}
		var msg struct {
			Text string   `json:"text"`
			HTML []string `json:"html"`
		}
		if err := jsonGet(ctx, mailtmBase+"/messages/"+m.ID, headers, &msg); err == nil {
			text := msg.Text + " " + strings.Join(msg.HTML, " ")
			if code := ExtractOTP(text); code != "" {
				return domain.OTPResult{Code: code, Received: ts, Source: "mailtm"}, nil
			}
		}
	}
	return domain.OTPResult{}, nil
}

// Release reason=success 时邮箱已被消费，直接丢弃；否则放回池中复用。
func (p *MailTMProvider) Release(ctx context.Context, box domain.Mailbox, reason string) error {
	if reason == "success" {
		return nil
	}
	p.mu.Lock()
	p.accounts = append(p.accounts, mailtmAccount{
		Email:    box.Email,
		Password: box.Credential["password"],
		Token:    box.Credential["token"],
	})
	p.mu.Unlock()
	return p.save()
}

func (p *MailTMProvider) save() error {
	p.mu.Lock()
	accs := append([]mailtmAccount(nil), p.accounts...)
	p.mu.Unlock()
	return p.persist.save(accs)
}

// randomString 生成 [a-z0-9] 的随机串。
func randomString(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
