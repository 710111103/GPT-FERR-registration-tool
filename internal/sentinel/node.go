package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NodeSolver 通过 Node 子进程运行真实 sdk.js 产出 token。
//
// 这条路线的价值（来自 turb-oss 快照的 sentinel_protocol.py 注释）：
// synthetic 路线合成的 p 字段在时区/locale 细节上对不齐——页面 locale 是 vi-VN，
// token 里却是英文的 "(Indochina Time)"，实测会降低通过率。
// 真 sdk.js 在 V8 沙箱里执行，指纹天然一致。
type NodeSolver struct {
	nodeBin  string
	runnerJS string
	timeout  time.Duration
}

// NewNode 创建 Node 求解器。runnerJS 是 sentinel-runner.js 的路径。
func NewNode(nodeBin, runnerJS string) *NodeSolver {
	if nodeBin == "" {
		nodeBin = "node"
	}
	return &NodeSolver{
		nodeBin:  nodeBin,
		runnerJS: runnerJS,
		timeout:  90 * time.Second,
	}
}

func (s *NodeSolver) Name() string { return "sdk_js" }

// Available 检查 Node 与 runner 脚本是否就绪。配置校验时调用。
func (s *NodeSolver) Available() error {
	if _, err := exec.LookPath(s.nodeBin); err != nil {
		return fmt.Errorf("找不到 Node 可执行文件 %q: %w", s.nodeBin, err)
	}
	if s.runnerJS != "" {
		if _, err := os.Stat(s.runnerJS); err != nil {
			return fmt.Errorf("找不到 sentinel runner 脚本 %q: %w", s.runnerJS, err)
		}
	}
	return nil
}

// nodeReq 是传给 runner 的 JSON 结构。
type nodeReq struct {
	Action    string   `json:"action"` // requirements | solve
	Flow      string   `json:"flow"`
	UserAgent string   `json:"user_agent"`
	Language  string   `json:"language"`
	Languages []string `json:"languages,omitempty"`
	Timezone  string   `json:"timezone"`
	Screen    string   `json:"screen"`
	DeviceID  string   `json:"device_id"`
	BuildID   string   `json:"build_id"`
	Challenge any      `json:"challenge,omitempty"`
	P         string   `json:"p,omitempty"`
}

type nodeResp struct {
	OK    bool   `json:"ok"`
	Value string `json:"value"`
	Error string `json:"error"`
}

func (s *NodeSolver) run(ctx context.Context, req nodeReq) (string, error) {
	if err := s.Available(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.nodeBin, s.runnerJS, "--stdin")
	cmd.Dir = filepath.Dir(s.runnerJS)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("sentinel runner 执行失败: %s", msg)
	}
	var resp nodeResp
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return "", fmt.Errorf("解析 runner 输出失败: %w (原始输出: %s)", err, truncate(stdout.String(), 200))
	}
	if !resp.OK {
		return "", fmt.Errorf("runner 返回错误: %s", resp.Error)
	}
	return resp.Value, nil
}

func (s *NodeSolver) Requirements(ctx context.Context, req Request) (string, error) {
	return s.run(ctx, nodeReq{
		Action:    "requirements",
		Flow:      req.Flow,
		UserAgent: req.UserAgent,
		Language:  req.Language,
		Languages: req.Languages,
		Timezone:  req.Timezone,
		Screen:    req.Screen,
		DeviceID:  req.DeviceID,
		BuildID:   req.BuildID,
	})
}

func (s *NodeSolver) Solve(ctx context.Context, req Request, ch Challenge, p string) (string, error) {
	return s.run(ctx, nodeReq{
		Action:    "solve",
		Flow:      req.Flow,
		UserAgent: req.UserAgent,
		Language:  req.Language,
		Languages: req.Languages,
		Timezone:  req.Timezone,
		Screen:    req.Screen,
		DeviceID:  req.DeviceID,
		BuildID:   req.BuildID,
		Challenge: ch,
		P:         p,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// New 按配置选择求解器。配置无效时回退到 synthetic 并返回原因。
func New(mode, nodeBin, runnerJS string) (Solver, string) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sdk_js", "node", "protocol":
		n := NewNode(nodeBin, runnerJS)
		if err := n.Available(); err != nil {
			return NewSynthetic(), fmt.Sprintf("Node 求解器不可用，已回退 synthetic: %v", err)
		}
		return n, "使用 Node 执行真 sdk.js"
	case "quickjs":
		// QuickJS 路线需要额外的 quickjs runner 脚本，尚未移植时回退。
		return NewSynthetic(), "quickjs 求解器尚未移植，已回退 synthetic"
	default:
		return NewSynthetic(), "使用纯 Go 合成指纹"
	}
}
