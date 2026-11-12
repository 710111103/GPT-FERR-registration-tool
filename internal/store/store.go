// Package store 是 SQLite 持久化层。
//
// 与 Python 版 db.py（227 KB、单文件数百函数）相比，这里按聚合拆成多个文件：
//
//	schema.go  —— 建表、索引、迁移
//	account.go —— 账号读写
//	emailpool.go —— 邮箱池
//	job.go     —— 任务记录
//
// 并发模型：SQLite 的写锁是全局的，所以这里用单个写协程（writer goroutine）
// 串行化所有写操作，读操作各自开连接。这比 Python 版的"每个调用开短连接 + WAL"
// 更彻底地避免 SQLITE_BUSY。
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 持有数据库句柄与写串行化通道。
type Store struct {
	db        *sql.DB
	writeCh   chan writeReq
	closed    chan struct{}
	closeOnce sync.Once

	// 读连接池上限。SQLite 读可并发，但太多连接会放大 WAL 检查点压力。
	maxReadConns int
}

type writeReq struct {
	ctx  context.Context
	fn   func(*sql.Tx) error
	resp chan error
}

// Open 打开（必要时创建）数据库并启动写协程。
func Open(path string) (*Store, error) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	// _txlock=immediate 让事务一开始就拿写锁，避免升级死锁。
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(0)

	s := &Store{
		db:      db,
		writeCh: make(chan writeReq, 256),
		closed:  make(chan struct{}),
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	go s.writeLoop()
	return s, nil
}

// Close 停止写协程并关闭数据库。
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.writeCh)
		<-s.closed
		err = s.db.Close()
	})
	return err
}

func (s *Store) writeLoop() {
	defer close(s.closed)
	for req := range s.writeCh {
		req.resp <- s.execWrite(req.ctx, req.fn)
	}
}

func (s *Store) execWrite(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Write 把一次写操作投递给写协程并等待结果。
func (s *Store) Write(ctx context.Context, fn func(*sql.Tx) error) error {
	select {
	case <-s.closed:
		return fmt.Errorf("数据库已关闭")
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	resp := make(chan error, 1)
	select {
	case s.writeCh <- writeReq{ctx: ctx, fn: fn, resp: resp}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return fmt.Errorf("数据库已关闭")
	}
	select {
	case err := <-resp:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Read 执行只读查询。SQLite 读不阻塞写（WAL 模式）。
func (s *Store) Read(ctx context.Context, fn func(*sql.DB) error) error {
	return fn(s.db)
}

// now 返回项目统一的时间戳格式（秒级 ISO8601，与 Python 版 _now() 一致）。
func now() string {
	return time.Now().Format("2006-01-02T15:04:05")
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func parseJSON(raw string) map[string]any {
	if raw == "" {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return map[string]any{}
	}
	if m == nil {
		return map[string]any{}
	}
	return m
}
