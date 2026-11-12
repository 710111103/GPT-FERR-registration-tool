package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/config"
)

// promoCheckEnabled 只启用已经实现的协议探测。off 保持完全旁路，
// 便于用户在不做任何额外请求的情况下只使用注册功能。
func promoCheckEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(config.Current().PromoCheckDriver)) {
	case "protocol", "on", "auto":
		return true
	default:
		return false
	}
}

func (s *Server) startPromoWorkers() {
	if !promoCheckEnabled() {
		return
	}
	workers := s.promoWorkers
	if workers < 1 {
		workers = 2
	}
	if workers > 16 {
		workers = 16
	}
	s.promoWorkers = workers
	for i := 0; i < workers; i++ {
		go s.promoWorker()
	}
	slog.Info("优惠探测队列已启动", "workers", workers)
}

// QueuePromoCheck 由注册任务成功回调调用。它会立即把账号标成 queued，
// 然后非阻塞投递到后台队列；绝不阻塞注册任务的收尾。
func (s *Server) QueuePromoCheck(accountID int64) {
	if accountID == 0 || s.store == nil || !promoCheckEnabled() {
		return
	}

	s.promoMu.Lock()
	if s.promoQueued[accountID] {
		s.promoMu.Unlock()
		return
	}
	s.promoQueued[accountID] = true
	s.promoMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	acc, err := s.store.GetAccount(ctx, accountID)
	if err != nil || acc == nil {
		s.promoDone(accountID)
		if err != nil {
			slog.Warn("优惠探测读取账号失败", "account", accountID, "err", err)
		}
		return
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	if strings.EqualFold(strVal(acc.Payload["plan_check_status"]), "success") {
		s.promoDone(accountID)
		return
	}
	acc.Payload["plan_check_status"] = "queued"
	acc.Payload["plan_check_error"] = ""
	acc.Payload["plan_check_queued_at"] = time.Now().Format(time.RFC3339)
	if _, err := s.store.InsertAccount(ctx, *acc); err != nil {
		s.promoDone(accountID)
		slog.Warn("标记优惠探测排队失败", "account", accountID, "err", err)
		return
	}

	select {
	case s.promoQueue <- accountID:
	default:
		s.promoDone(accountID)
		acc.Payload["plan_check_status"] = "failed"
		acc.Payload["plan_check_error"] = "优惠探测队列已满，请稍后手动重试"
		acc.Payload["plan_checked_at"] = time.Now().Format("2006-01-02 15:04:05")
		_, _ = s.store.InsertAccount(context.Background(), *acc)
		slog.Warn("优惠探测队列已满", "account", accountID)
	}
}

func (s *Server) promoWorker() {
	for accountID := range s.promoQueue {
		func() {
			defer s.promoDone(accountID)
			defer func() {
				if recovered := recover(); recovered != nil {
					slog.Error("优惠探测 worker panic", "account", accountID, "panic", recovered)
				}
			}()
			s.runPromoCheck(accountID)
		}()
	}
}

func (s *Server) runPromoCheck(accountID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	acc, err := s.store.GetAccount(ctx, accountID)
	cancel()
	if err != nil || acc == nil {
		if err != nil {
			slog.Warn("优惠探测读取账号失败", "account", accountID, "err", err)
		}
		return
	}
	if acc.Payload == nil {
		acc.Payload = map[string]any{}
	}
	acc.Payload["plan_check_status"] = "running"
	acc.Payload["plan_check_error"] = ""
	acc.Payload["plan_check_started_at"] = time.Now().Format(time.RFC3339)
	if _, err := s.store.InsertAccount(context.Background(), *acc); err != nil {
		slog.Warn("标记优惠探测运行中失败", "account", accountID, "err", err)
		return
	}
	if err := s.checkAccountPlan(acc); err != nil {
		slog.Warn("优惠探测失败", "account", accountID, "err", err)
	}
}

func (s *Server) promoDone(accountID int64) {
	s.promoMu.Lock()
	delete(s.promoQueued, accountID)
	s.promoMu.Unlock()
}
