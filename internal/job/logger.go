package job

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Logger 是单个任务的结构化日志写入器。
// 与 Python 版每个 job 一个日志文件、WebUI 轮询 tail 的做法保持一致。
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewLogger 打开（或创建）任务的日志文件。
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("日志路径为空")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, path: path}, nil
}

// NewDiscardLogger 用于日志文件不可写的降级场景。
func NewDiscardLogger() *Logger { return &Logger{} }

// Path 返回日志文件路径。
func (l *Logger) Path() string { return l.path }

func (l *Logger) write(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("15:04:05"), level, msg)
	if os.Getenv("TURB_LOG_STDERR") != "" {
		_, _ = io.WriteString(os.Stderr, line)
	}
	if l.f == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.WriteString(line)
}

// Infof 记录普通信息。
func (l *Logger) Infof(format string, args ...any) { l.write("INFO", format, args...) }

// Warnf 记录警告。
func (l *Logger) Warnf(format string, args ...any) { l.write("WARNING", format, args...) }

// Errorf 记录错误。
func (l *Logger) Errorf(format string, args ...any) { l.write("ERROR", format, args...) }

// Close 关闭日志文件。
func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	l.f = nil
	return err
}

var _ = slog.Info
