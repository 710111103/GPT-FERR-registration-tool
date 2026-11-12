// Package sentinel 封装 OpenAI Sentinel token 的生成。
package sentinel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Challenge 是 /backend-api/sentinel/req 返回的挑战。
type Challenge struct {
	Token       string          `json:"token"`
	Turnstile   json.RawMessage `json:"turnstile,omitempty"`
	ProofOfWork *ProofOfWork    `json:"proofofwork,omitempty"`
	So          json.RawMessage `json:"so,omitempty"`
}

// ProofOfWork 是工作量证明参数。
type ProofOfWork struct {
	Required   bool   `json:"required"`
	Seed       string `json:"seed"`
	Difficulty string `json:"difficulty"`
}

// Request 是生成 token 所需的上下文。
type Request struct {
	UserAgent string
	Language  string
	Languages []string
	Timezone  string
	Screen    string // 形如 1920x1080
	DeviceID  string
	Flow      string // 例如 "authorize_continue"
	BuildID   string
}

// LanguagesFor 返回与主语言一致的 navigator.languages 列表。
// Sentinel SDK 会同时读取 language 与 languages；只传前者会导致 JS 指纹
// 沿用脚本里的日本默认值，与德国等代理地区发生冲突。
func LanguagesFor(language string) []string {
	primary := strings.TrimSpace(language)
	if primary == "" {
		primary = "en-US"
	}
	base := primary
	if i := strings.IndexByte(base, '-'); i > 0 {
		base = base[:i]
	}
	out := []string{primary}
	if !strings.EqualFold(base, primary) {
		out = append(out, base)
	}
	if !strings.EqualFold(base, "en") {
		out = append(out, "en-US", "en")
	}
	return out
}

// Solver 生成 Sentinel token。
type Solver interface {
	Name() string
	Requirements(ctx context.Context, req Request) (string, error)
	Solve(ctx context.Context, req Request, ch Challenge, p string) (string, error)
}

// ---- synthetic：纯 Go 高精合成，不依赖 Node ----

type SyntheticSolver struct{}

func NewSynthetic() *SyntheticSolver { return &SyntheticSolver{} }

func (s *SyntheticSolver) Name() string { return "synthetic" }

// buildConfigArray 生成符合 sdk.js getConfig() 的 25 维浏览器指纹数组。
func buildConfigArray(req Request, now time.Time, attempt any, elapsedMs any) []any {
	loc, err := time.LoadLocation(req.Timezone)
	if err != nil {
		loc = time.UTC
	}
	dateStr := formatJSDate(now, loc, req.Timezone)

	nowMs := float64(now.UnixNano()) / 1e6
	perfNow := 26000.0 + randFloat()*6000.0
	timeOrigin := nowMs - perfNow

	langPrimary := req.Language
	if langPrimary == "" {
		langPrimary = "en-US"
	}
	languages := req.Languages
	if len(languages) == 0 {
		languages = LanguagesFor(langPrimary)
	}

	ua := req.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	}

	return []any{
		screenSum(req.Screen), // [0] screen.width + screen.height
		dateStr,               // [1] Date.toString() 字符串
		4294967296,            // [2] performance.memory.jsHeapSizeLimit (4GiB)
		attempt,               // [3] PoW 尝试次数（requirements 阶段为随机小数）
		ua,                    // [4] navigator.userAgent
		"https://sentinel.openai.com/sentinel/20260810913b/sdk.js", // [5] script src
		req.BuildID,                  // [6] data-build
		langPrimary,                  // [7] navigator.language
		strings.Join(languages, ","), // [8] navigator.languages
		elapsedMs,                    // [9] PoW 耗时毫秒数（requirements 阶段为随机小数）
		"doNotTrack",                 // [10] navigator 原型采样
		"location",                   // [11] document 键名采样
		"releaseEvents",              // [12] window 键名采样
		perfNow,                      // [13] performance.now()
		req.DeviceID,                 // [14] sid (oai-did)
		"",                           // [15] URL search params
		8,                            // [16] navigator.hardwareConcurrency (8核)
		timeOrigin,                   // [17] performance.timeOrigin
		0,                            // [18] Number("ai" in window)
		0,                            // [19] Number("createPRNG" in window)
		0,                            // [20] Number("cache" in window)
		0,                            // [21] Number("data" in window)
		0,                            // [22] Number("solana" in window)
		0,                            // [23] Number("dump" in window，Firefox 特有为 0)
		1,                            // [24] Number("requestIdleCallback" in window，Chrome 为 1)
	}
}

// formatJSDate 生成完全符合 Chrome 原生 Date.toString() 的字符串：
// 如 "Wed Nov 11 2026 18:20:30 GMT+0100 (Central European Standard Time)"
func formatJSDate(t time.Time, loc *time.Location, tzName string) string {
	if loc != nil {
		t = t.In(loc)
	}
	weekday := t.Format("Mon")
	month := t.Format("Jan")
	day := t.Format("02")
	year := t.Format("2006")
	timeStr := t.Format("15:04:05")

	_, offsetSec := t.Zone()
	offsetMin := offsetSec / 60
	sign := "+"
	if offsetMin < 0 {
		sign = "-"
		offsetMin = -offsetMin
	}
	gmt := fmt.Sprintf("GMT%s%02d%02d", sign, offsetMin/60, offsetMin%60)
	if tzName == "" {
		tzName = t.Format("MST")
	}
	return fmt.Sprintf("%s %s %s %s %s %s (%s)", weekday, month, day, year, timeStr, gmt, tzName)
}

// Requirements 生成第一趟获取题目所需的 p 字段（带 gAAAAAC 前缀及 ~S 结尾）。
func (s *SyntheticSolver) Requirements(ctx context.Context, req Request) (string, error) {
	now := time.Now()
	arr := buildConfigArray(req, now, randFloat(), randFloat())
	raw, err := json.Marshal(arr)
	if err != nil {
		return "", err
	}
	return "gAAAAAC" + base64.StdEncoding.EncodeToString(raw) + "~S", nil
}

// Solve 计算 PoW 并拼出最终放入 openai-sentinel-token 头的完整 JSON。
func (s *SyntheticSolver) Solve(ctx context.Context, req Request, ch Challenge, p string) (string, error) {
	out := map[string]any{
		"p":    p,
		"t":    "",
		"c":    ch.Token,
		"id":   req.DeviceID,
		"flow": req.Flow,
	}
	if ch.Turnstile != nil {
		out["t"] = string(ch.Turnstile)
	}
	if ch.ProofOfWork != nil && ch.ProofOfWork.Required {
		t, err := solvePOW(ctx, ch.ProofOfWork.Seed, ch.ProofOfWork.Difficulty, req)
		if err != nil {
			return "", err
		}
		out["p"] = t
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// solvePOW 做 OpenAI 原版 32 位 FNV-1a 前缀碰撞：找到使 hash(seed + base64(config)) 满足难度的解答。
func solvePOW(ctx context.Context, seed, difficulty string, req Request) (string, error) {
	diffLen := len(difficulty)
	startTime := time.Now()
	arr := buildConfigArray(req, startTime, 0, 0)
	deadline := startTime.Add(60 * time.Second)

	for nonce := 0; nonce < 500000; nonce++ {
		if nonce%2048 == 0 {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf("PoW 计算超时")
			}
		}
		arr[3] = nonce
		arr[9] = float64(time.Since(startTime).Milliseconds())

		raw, err := json.Marshal(arr)
		if err != nil {
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(raw)
		h := fnv1aSDK(seed + encoded)
		if diffLen <= len(h) && h[:diffLen] <= difficulty {
			return "gAAAAAB" + encoded + "~S", nil
		}
	}
	return "", fmt.Errorf("PoW 未找到满足难度的解答")
}

// fnv1aSDK 复刻 OpenAI sdk.js 中的 32 位 Math.imul 混淆哈希算法。
func fnv1aSDK(s string) string {
	var e uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		e ^= uint32(s[i])
		e = uint32(uint64(e) * 16777619)
	}
	e ^= e >> 16
	e = uint32(uint64(e) * 2246822507)
	e ^= e >> 13
	e = uint32(uint64(e) * 3266489909)
	e ^= e >> 16
	return fmt.Sprintf("%08x", e)
}

func screenSum(s string) string {
	if s == "" {
		return "3000"
	}
	parts := strings.SplitN(s, "x", 2)
	if len(parts) != 2 {
		return s
	}
	var w, h int
	fmt.Sscanf(parts[0], "%d", &w)
	fmt.Sscanf(parts[1], "%d", &h)
	return fmt.Sprint(w + h)
}

func randFloat() float64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0.5
	}
	return float64(n.Int64()) / float64(int64(1)<<53)
}

// DeviceID 生成一个稳定的 sid（UUID v4 风格）。
func DeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// DeviceIDFromSeed 由邮箱或种子稳定派生出唯一的 UUID v4，保证同一邮箱多次执行指纹绝对一致且可复现。
func DeviceIDFromSeed(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return DeviceID()
	}
	sum := sha256.Sum256([]byte("openai:device:" + seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// FingerprintSeed 把邮箱映射成稳定的指纹种子，保证同一账号多次尝试指纹一致。
func FingerprintSeed(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:8])
}
