package mail

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

func TestExtractOTP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"引号包裹", `Your verification code is "482913"`, "482913"},
		{"正文裸数字", `Enter the code 730251 to continue`, "730251"},
		{"中文正文", `您的验证码是 559023，请勿泄露`, "559023"},
		{"无验证码", `Welcome to OpenAI`, ""},
		{"年份不算", `Copyright 2024 OpenAI`, ""},
		{"空串", ``, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExtractOTP(c.in); got != c.want {
				t.Errorf("ExtractOTP(%q) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

// fakeProvider 用于测试注册表的兜底链。
type fakeProvider struct {
	name  string
	boxes []domain.Mailbox
	codes []string
	err   error
	mu    sync.Mutex
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Acquire(ctx context.Context) (domain.Mailbox, error) {
	if f.err != nil {
		return domain.Mailbox{}, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.boxes) == 0 {
		return domain.Mailbox{}, ErrNoMailbox
	}
	b := f.boxes[0]
	f.boxes = f.boxes[1:]
	return b, nil
}

func (f *fakeProvider) WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		return domain.OTPResult{}, nil
	}
	c := f.codes[0]
	f.codes = f.codes[1:]
	return domain.OTPResult{Code: c, Received: time.Now(), Source: f.name}, nil
}

func (f *fakeProvider) Release(ctx context.Context, box domain.Mailbox, reason string) error {
	return nil
}

func TestRegistryFallsBackToNextSource(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeProvider{name: "empty", err: ErrNoMailbox})
	r.Register(&fakeProvider{
		name:  "outlook",
		boxes: []domain.Mailbox{{Email: "a@example.com", Source: "outlook"}},
	})

	box, p, err := r.Acquire(context.Background(), []string{"empty", "outlook"})
	if err != nil {
		t.Fatalf("领取失败: %v", err)
	}
	if box.Email != "a@example.com" {
		t.Errorf("领到 %q", box.Email)
	}
	if p.Name() != "outlook" {
		t.Errorf("来源 = %q", p.Name())
	}
}

func TestRegistryAllSourcesExhausted(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeProvider{name: "a", err: ErrNoMailbox})
	r.Register(&fakeProvider{name: "b", err: ErrNoMailbox})

	_, _, err := r.Acquire(context.Background(), []string{"a", "b"})
	if !errors.Is(err, ErrNoMailbox) {
		t.Errorf("期望 ErrNoMailbox，得到 %v", err)
	}
}

func TestWaitCodeWithRetrySucceeds(t *testing.T) {
	r := NewRegistry()
	p := &fakeProvider{
		name:  "test",
		boxes: []domain.Mailbox{{Email: "x@example.com"}},
		codes: []string{"", "123456"}, // 第一次没码，第二次有
	}
	r.Register(p)

	res, err := WaitCodeWithRetry(context.Background(), p, domain.Mailbox{Email: "x@example.com"},
		time.Now(), 5*time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("取码失败: %v", err)
	}
	if res.Code != "123456" {
		t.Errorf("验证码 = %q", res.Code)
	}
}

func TestWaitCodeWithRetryTimesOut(t *testing.T) {
	p := &fakeProvider{name: "never"}
	_, err := WaitCodeWithRetry(context.Background(), p, domain.Mailbox{},
		time.Now(), 120*time.Millisecond, 20*time.Millisecond)
	if !errors.Is(err, ErrOTPTimeout) {
		t.Errorf("期望超时，得到 %v", err)
	}
}

func TestRegistryNamesSorted(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeProvider{name: "zeta"})
	r.Register(&fakeProvider{name: "alpha"})
	names := r.Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "zeta" {
		t.Errorf("Names() = %v，期望 [alpha zeta]", names)
	}
}
