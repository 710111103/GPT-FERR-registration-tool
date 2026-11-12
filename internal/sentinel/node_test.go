package sentinel

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLanguagesFor(t *testing.T) {
	got := strings.Join(LanguagesFor("de-DE"), ",")
	if want := "de-DE,de,en-US,en"; got != want {
		t.Fatalf("LanguagesFor(de-DE) = %q, want %q", got, want)
	}
	if got := strings.Join(LanguagesFor("en-US"), ","); got != "en-US,en" {
		t.Fatalf("LanguagesFor(en-US) = %q, want en-US,en", got)
	}
	if got := strings.Join(LanguagesFor(""), ","); got != "en-US,en" {
		t.Fatalf("LanguagesFor(empty) = %q, want en-US,en", got)
	}
}

// TestNodeSolverRequirementsProtocol 防止 runner 改回裸 token 输出后，Go 端仍然
// 按 JSON 信封解析而出现难以定位的失败。requirements 阶段不访问网络，适合做常规回归。
func TestNodeSolverRequirementsProtocol(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node 不可用")
	}
	runner, err := filepath.Abs(filepath.Join("..", "..", "sentinel", "sentinel-runner.js"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	solver := NewNode(nodeBin, runner)
	p, err := solver.Requirements(ctx, Request{
		Flow:      "checkout_session_approval",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
		Language:  "ja-JP",
		Timezone:  "Asia/Tokyo",
		Screen:    "1920x1080",
		DeviceID:  "8a5ad769-e9e7-4461-ae3a-6755d7f46b0b",
		BuildID:   "test-build",
	})
	if err != nil {
		t.Fatalf("requirements 失败: %v", err)
	}
	if !strings.HasPrefix(p, "gAAAAAC") || !strings.HasSuffix(p, "~S") {
		t.Fatalf("requirements 返回格式异常: len=%d prefix=%q suffix=%q", len(p), p[:min(12, len(p))], p[max(0, len(p)-3):])
	}
}
