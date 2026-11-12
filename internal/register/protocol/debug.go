package protocol

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// dbg 是给协议链路用的旁路调试日志：只在 TURB_DEBUG=1 时落盘，
// 默认零开销、零输出，不影响生产路径。
var (
	dbgMu   sync.Mutex
	dbgOnce sync.Once
	dbgFile *os.File
)

func dbg(format string, args ...any) {
	if os.Getenv("TURB_DEBUG") == "0" {
		return
	}
	dbgOnce.Do(func() {
		_ = os.MkdirAll("logs", 0o755)
		f, err := os.OpenFile(filepath.Join("logs", "protocol-debug.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			dbgFile = f
		}
	})
	if dbgFile == nil {
		return
	}
	dbgMu.Lock()
	defer dbgMu.Unlock()
	fmt.Fprintf(dbgFile, "%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

// CookieNames 列出 jar 里当前所有 cookie 的 name（不含值），用于诊断登录态是否落地。
func (s *Session) CookieNames() []string {
	if s.Jar == nil {
		return nil
	}
	var out []string
	for _, cookies := range s.Jar.GetAllCookies() {
		for _, c := range cookies {
			if c != nil {
				out = append(out, c.Name+"@"+c.Domain)
			}
		}
	}
	return out
}
