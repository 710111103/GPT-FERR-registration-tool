package job

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/store"
)

func newTestPool(t *testing.T, runner Runner, width int) (*Pool, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	p := NewPool(st, runner, t.TempDir(), width)
	t.Cleanup(func() {
		p.Shutdown()
		_ = st.Close()
	})
	return p, st
}

func waitJobStatus(t *testing.T, st *store.Store, id int64, want domain.JobStatus) *domain.Job {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j, err := st.GetJob(context.Background(), id)
		if err != nil {
			t.Fatalf("读取任务 #%d 失败: %v", id, err)
		}
		if j != nil && j.Status == want {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	j, _ := st.GetJob(context.Background(), id)
	t.Fatalf("任务 #%d 未进入 %s，当前: %+v", id, want, j)
	return nil
}

func TestStopPendingCancelsWithoutRunning(t *testing.T) {
	started := make(chan int64, 4)
	var calls atomic.Int32
	runner := func(ctx context.Context, j *domain.Job, _ *Logger) (Result, error) {
		calls.Add(1)
		started <- j.ID
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	p, st := newTestPool(t, runner, 1)
	ids, err := p.Submit(context.Background(), 2, "outlook")
	if err != nil || len(ids) != 2 {
		t.Fatalf("提交失败: ids=%v err=%v", ids, err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("第一个任务未启动")
	}

	result, err := p.Stop(ids[1])
	if err != nil {
		t.Fatalf("停止排队任务失败: %v", err)
	}
	if !result.Changed || result.Status != domain.JobCancelled {
		t.Fatalf("停止结果错误: %+v", result)
	}
	waitJobStatus(t, st, ids[1], domain.JobCancelled)
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("排队任务仍被执行，runner 调用次数=%d", got)
	}
}

func TestStopRunningReachesStopped(t *testing.T) {
	started := make(chan int64, 1)
	runner := func(ctx context.Context, j *domain.Job, _ *Logger) (Result, error) {
		started <- j.ID
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	p, st := newTestPool(t, runner, 1)
	ids, err := p.Submit(context.Background(), 1, "outlook")
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("任务未启动")
	}

	result, err := p.Stop(ids[0])
	if err != nil {
		t.Fatalf("停止运行任务失败: %v", err)
	}
	if result.Status != domain.JobStopping {
		t.Fatalf("停止后的中间状态错误: %+v", result)
	}
	j := waitJobStatus(t, st, ids[0], domain.JobStopped)
	if j.CompletedAt == nil {
		t.Fatal("停止任务缺少完成时间")
	}
}

func TestStopOrphanRunningJobFinalizesDatabase(t *testing.T) {
	p, st := newTestPool(t, func(context.Context, *domain.Job, *Logger) (Result, error) {
		return Result{}, errors.New("不应执行")
	}, 1)
	id, err := st.CreateJob(context.Background(), "", "outlook", "")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	if ok, err := st.ClaimJob(context.Background(), id); err != nil || !ok {
		t.Fatalf("抢占任务失败: ok=%v err=%v", ok, err)
	}

	result, err := p.Stop(id)
	if err != nil {
		t.Fatalf("停止残留任务失败: %v", err)
	}
	if result.Status != domain.JobStopped || !result.Changed {
		t.Fatalf("残留任务未收尾: %+v", result)
	}
	waitJobStatus(t, st, id, domain.JobStopped)
}

func TestCancelPendingCancelsWaitingHandles(t *testing.T) {
	started := make(chan int64, 1)
	var calls atomic.Int32
	runner := func(ctx context.Context, j *domain.Job, _ *Logger) (Result, error) {
		calls.Add(1)
		started <- j.ID
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	p, st := newTestPool(t, runner, 1)
	ids, err := p.Submit(context.Background(), 3, "outlook")
	if err != nil || len(ids) != 3 {
		t.Fatalf("提交失败: ids=%v err=%v", ids, err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("第一个任务未启动")
	}

	n, err := p.CancelPending(context.Background())
	if err != nil {
		t.Fatalf("取消全部排队失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("取消数量=%d，期望 2", n)
	}
	waitJobStatus(t, st, ids[1], domain.JobCancelled)
	waitJobStatus(t, st, ids[2], domain.JobCancelled)
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("排队任务仍被执行，runner 调用次数=%d", got)
	}
}

func TestStopDoesNotOverwriteSuccess(t *testing.T) {
	p, st := newTestPool(t, func(context.Context, *domain.Job, *Logger) (Result, error) {
		return Result{}, nil
	}, 1)
	id, err := st.CreateJob(context.Background(), "", "outlook", "")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	success := domain.JobSuccess
	if err := st.UpdateJob(context.Background(), id, store.JobUpdate{Status: &success, Completed: true}); err != nil {
		t.Fatalf("写入成功状态失败: %v", err)
	}

	result, err := p.Stop(id)
	if err != nil {
		t.Fatalf("停止终态任务失败: %v", err)
	}
	if result.Changed || result.Status != domain.JobSuccess {
		t.Fatalf("终态被覆盖: %+v", result)
	}
	waitJobStatus(t, st, id, domain.JobSuccess)
}

func TestSuccessHookReceivesAccountID(t *testing.T) {
	p, st := newTestPool(t, func(context.Context, *domain.Job, *Logger) (Result, error) {
		return Result{Email: "probe@example.com", AccountID: 42}, nil
	}, 1)
	got := make(chan int64, 1)
	p.SetSuccessHook(func(accountID int64) {
		got <- accountID
	})
	ids, err := p.Submit(context.Background(), 1, "outlook")
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	waitJobStatus(t, st, ids[0], domain.JobSuccess)
	select {
	case accountID := <-got:
		if accountID != 42 {
			t.Fatalf("回调账号 ID=%d，期望 42", accountID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("成功回调未执行")
	}
}
