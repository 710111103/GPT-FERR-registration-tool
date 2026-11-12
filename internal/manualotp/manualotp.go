// Package manualotp 是进程内的手动邮箱验证码通道。
//
// 对齐上游 core/manual_otp.py：注册任务 / Codex 补跑在拿不到自动验证码时，
// 调用 Wait 阻塞等待；用户在 WebUI 提交 4-8 位验证码，Submit 入队并唤醒等待侧。
package manualotp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.Mutex
	codes   = map[string][]string{}       // email(lower) -> 待消费的验证码队列
	events  = map[string]chan struct{}{}  // email(lower) -> 唤醒信号
	waiting = map[string]map[string]any{} // email(lower) -> 等待中的元信息
)

// norm 统一邮箱键。
func norm(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// eventFor 取（或建）该邮箱的唤醒通道。
func eventFor(key string) chan struct{} {
	ch := events[key]
	if ch == nil {
		ch = make(chan struct{}, 1)
		events[key] = ch
	}
	return ch
}

// Mark 登记"该邮箱正在等手动验证码"。
func Mark(email string, jobID any) {
	key := norm(email)
	if key == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	waiting[key] = map[string]any{
		"email":  email,
		"job_id": jobID,
		"since":  float64(time.Now().UnixNano()) / 1e9,
	}
	ch := eventFor(key)
	select {
	case <-ch:
	default:
	}
}

// Clear 摘掉等待登记。
func Clear(email string) {
	key := norm(email)
	if key == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	delete(waiting, key)
}

// List 列出全部等待中的条目。
func List() []map[string]any {
	mu.Lock()
	defer mu.Unlock()
	out := make([]map[string]any, 0, len(waiting))
	for _, v := range waiting {
		cp := make(map[string]any, len(v))
		for k, vv := range v {
			cp[k] = vv
		}
		out = append(out, cp)
	}
	return out
}

// Submit 校验并投递一个验证码；返回落库用的规范化值。
func Submit(email, code string) error {
	key := norm(email)
	if key == "" {
		return fmt.Errorf("email 为空")
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if code == "" {
		return fmt.Errorf("验证码为空")
	}
	digits := true
	for _, r := range code {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	if !digits || len(code) < 4 || len(code) > 8 {
		return fmt.Errorf("验证码格式看起来不对: %q", code)
	}
	mu.Lock()
	codes[key] = append(codes[key], code)
	ch := eventFor(key)
	mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
	return nil
}

// Pop 取走最早的一个验证码；没有则返回空串。
func Pop(email string) string {
	key := norm(email)
	if key == "" {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	q := codes[key]
	if len(q) == 0 {
		return ""
	}
	code := q[0]
	q = q[1:]
	if len(q) == 0 {
		delete(codes, key)
	} else {
		codes[key] = q
	}
	return code
}

// Wait 阻塞等待手动验证码。先吃掉已投递的码，否则登记等待并轮询到超时。
func Wait(ctx context.Context, email string, jobID any, timeout time.Duration) (string, error) {
	key := norm(email)
	if key == "" {
		return "", fmt.Errorf("手动 OTP：email 为空")
	}
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	if code := Pop(email); code != "" {
		Clear(email)
		return code, nil
	}

	Mark(email, jobID)
	defer Clear(email)

	mu.Lock()
	ch := eventFor(key)
	mu.Unlock()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if code := Pop(email); code != "" {
			return code, nil
		}
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("用户手动停止")
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("等待手动验证码超时（%s）：%s", timeout, email)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("用户手动停止")
		case <-ticker.C:
		case <-ch:
		}
	}
}
