// Package register 定义注册驱动接口与注册表。
//
// Python 版的问题：七套驱动的契约是隐式的——都叫 run_xxx_registration，
// 参数顺序靠约定，返回值靠 dict 字段默契，新增驱动必须改 main.run_registration 的分发链。
//
// Go 版把它变成显式接口：新增驱动只需实现 Driver 并在注册表登记，调度层零改动。
package register

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

// ErrCheckpointUnsupported 表示该驱动不支持断点续跑。
var ErrCheckpointUnsupported = errors.New("该驱动不支持断点续跑")

// Request 是一次注册请求。字段与 Python 版 run_registration 签名一一对应。
type Request struct {
	Email    string
	Name     string
	Birthday time.Time
	Proxy    string

	// OTP 是取码回调。驱动在需要验证码时调用，由调度层注入，
	// 取代 Python 的 on_email_acquired 回调与全局邮箱状态。
	OTP func(ctx context.Context, email string) (string, error)

	// Checkpoint 非 nil 表示这是断点续跑。
	Checkpoint *Checkpoint
}

// Checkpoint 断点续跑信息。只保存阶段事实，不保存敏感值。
type Checkpoint struct {
	AccountID int64
	From      string // 例如 password_checkpoint_saved
	Password  string
}

// Result 注册产出。
type Result struct {
	Email        string
	Name         string
	Password     string
	AccessToken  string
	SessionToken string
	TOTPSecret   string
	DeviceID     string
	Stage        domain.Stage
	Traffic      *domain.Traffic
	ProxyUsed    string
	Extra        map[string]any
}

// Driver 是注册驱动。
type Driver interface {
	Name() string
	Register(ctx context.Context, req Request) (Result, error)
}

// Registry 驱动注册表。
type Registry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{drivers: map[string]Driver{}}
}

// Register 登记驱动。同时登记一组别名，兼容 Python 版的多种拼写
// （如 roxy / roxybrowser / fingerprint / browser）。
func (r *Registry) Register(d Driver, aliases ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drivers[d.Name()] = d
	for _, a := range aliases {
		r.drivers[a] = d
	}
}

// Lookup 按名称（含别名）查驱动。
func (r *Registry) Lookup(name string) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[name]
	return d, ok
}

// Names 返回去重后的驱动名，用于错误提示与启动校验。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for k, d := range r.drivers {
		if k == d.Name() {
			out = append(out, k)
			seen[k] = true
		}
	}
	for k := range r.drivers {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Resolve 解析驱动名，并应用无头路由规则。
//
// Python 版的 core/headless_routing.py 做了一件事：配了 roxy 但开了无头，
// 实际走 ant 驱动（Playwright），有头才走 Roxy/Selenium。这里保持同样语义。
func (r *Registry) Resolve(name string, headlessRoxy, headlessCloak bool) (Driver, string, error) {
	name = normalize(name)
	if (isRoxy(name) && headlessRoxy) || (isCloak(name) && headlessCloak) {
		if d, ok := r.drivers["ant"]; ok {
			return d, "ant", nil
		}
	}
	d, ok := r.drivers[name]
	if !ok {
		return nil, "", fmt.Errorf("不支持的注册驱动 %q，可选：%v", name, r.Names())
	}
	return d, d.Name(), nil
}

func normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == ' ' || c == '-' {
			c = '_'
		}
		out = append(out, c)
	}
	return string(out)
}

func isRoxy(n string) bool {
	return n == "roxy" || n == "roxybrowser" || n == "fingerprint" || n == "browser"
}

func isCloak(n string) bool {
	return n == "cloak" || n == "cloakbrowser"
}

// SameAsRegistration 解析 CODEX_OAUTH_DRIVER=same_as_registration 的语义。
func SameAsRegistration(codexDriver, regDriver string) string {
	if normalize(codexDriver) == "same_as_registration" {
		return normalize(regDriver)
	}
	return normalize(codexDriver)
}
