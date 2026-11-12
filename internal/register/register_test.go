package register

import (
	"context"
	"strings"
	"testing"

	"github.com/turb/gpt-register/internal/domain"
)

type stubDriver struct{ name string }

func (s *stubDriver) Name() string { return s.name }
func (s *stubDriver) Register(ctx context.Context, req Request) (Result, error) {
	return Result{Email: req.Email, Stage: domain.NewStage()}, nil
}

func TestResolveExactName(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubDriver{name: "protocol"})

	d, effective, err := r.Resolve("protocol", false, false)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if effective != "protocol" || d.Name() != "protocol" {
		t.Errorf("得到 %q", effective)
	}
}

func TestResolveAliases(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubDriver{name: "roxy"}, "roxybrowser", "fingerprint", "browser")

	for _, alias := range []string{"roxy", "roxybrowser", "fingerprint", "browser"} {
		d, _, err := r.Resolve(alias, false, false)
		if err != nil || d.Name() != "roxy" {
			t.Errorf("别名 %q 解析失败: %v", alias, err)
		}
	}
}

// TestHeadlessRouting 验证与 Python core/headless_routing.py 一致的语义：
// 配了 roxy 但开启无头时，实际走 ant 驱动。
func TestHeadlessRouting(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubDriver{name: "roxy"})
	r.Register(&stubDriver{name: "ant"})

	_, effective, err := r.Resolve("roxy", true, false)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if effective != "ant" {
		t.Errorf("无头路由应走 ant，得到 %q", effective)
	}

	// 有头时应保持 roxy
	_, effective, _ = r.Resolve("roxy", false, false)
	if effective != "roxy" {
		t.Errorf("有头应保持 roxy，得到 %q", effective)
	}
}

func TestResolveUnknownDriver(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubDriver{name: "protocol"})

	_, _, err := r.Resolve("nonexistent", false, false)
	if err == nil {
		t.Fatal("未知驱动应报错")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Errorf("错误信息应列出可用驱动: %v", err)
	}
}

func TestSameAsRegistration(t *testing.T) {
	if got := SameAsRegistration("same_as_registration", "cloak"); got != "cloak" {
		t.Errorf("= %q，期望 cloak", got)
	}
	if got := SameAsRegistration("browser_use", "cloak"); got != "browser_use" {
		t.Errorf("= %q，期望 browser_use", got)
	}
}

func TestUnimplementedReportsClearly(t *testing.T) {
	u := &Unimplemented{DriverName: "skyvern"}
	_, err := u.Register(context.Background(), Request{Email: "a@b.c"})
	if err == nil {
		t.Fatal("未实现驱动应报错")
	}
	if !strings.Contains(err.Error(), "尚未移植") {
		t.Errorf("错误信息不明确: %v", err)
	}
}
