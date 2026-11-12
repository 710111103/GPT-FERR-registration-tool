package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/turb/gpt-register/internal/domain"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInsertAndGetAccount(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	id, err := st.InsertAccount(ctx, domain.Account{
		Email:   "a@example.com",
		Status:  "registered",
		Payload: map[string]any{"access_token": "tok", "device_id": "device-test"},
	})
	if err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	if id == 0 {
		t.Fatal("返回的 id 为 0")
	}

	got, err := st.GetAccount(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("读取账号失败: %v", err)
	}
	if got.Email != "a@example.com" {
		t.Errorf("邮箱 = %q，期望 a@example.com", got.Email)
	}
	if got.Payload["access_token"] != "tok" {
		t.Errorf("payload 丢失: %v", got.Payload)
	}
}

func TestInsertAccountUpsertsByEmail(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	id1, err := st.InsertAccount(ctx, domain.Account{
		Email:   "dup@example.com",
		Status:  "registered",
		Payload: map[string]any{"device_id": "device-test-1"},
	})
	if err != nil {
		t.Fatalf("首次插入账号失败: %v", err)
	}
	id2, err := st.InsertAccount(ctx, domain.Account{
		Email:   "DUP@example.com",
		Status:  "updated",
		Payload: map[string]any{"device_id": "device-test-2"},
	})
	if err != nil {
		t.Fatalf("覆盖账号失败: %v", err)
	}

	if id1 != id2 {
		t.Fatalf("同邮箱应覆盖同一行，得到 %d 与 %d", id1, id2)
	}
	got, err := st.GetAccount(ctx, id1)
	if err != nil || got == nil {
		t.Fatalf("读取覆盖后的账号失败: %v", err)
	}
	if got.Status != "updated" {
		t.Errorf("状态未被覆盖: %q", got.Status)
	}

	n, _ := st.CountAccounts(ctx)
	if n != 1 {
		t.Errorf("账号数 = %d，期望 1", n)
	}
}

func TestClaimEmailIsExclusive(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	added, _, err := st.ImportEmails(ctx, []EmailItem{
		{Email: "x@example.com", Source: "outlook"},
	})
	if err != nil || added != 1 {
		t.Fatalf("导入失败: added=%d err=%v", added, err)
	}

	box, err := st.ClaimEmail(ctx, "outlook")
	if err != nil || box == nil {
		t.Fatalf("领取失败: %v", err)
	}
	if box.Email != "x@example.com" {
		t.Errorf("领到 %q", box.Email)
	}

	// 第二次应该领不到
	box2, err := st.ClaimEmail(ctx, "outlook")
	if err != nil {
		t.Fatalf("第二次领取报错: %v", err)
	}
	if box2 != nil {
		t.Errorf("邮箱被重复领取: %v", box2)
	}
}

func TestCancelledEmailHasCooldownBeforeReclaim(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_, _, err := st.ImportEmails(ctx, []EmailItem{{Email: "cool@example.com", Source: "outlook"}})
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	box, err := st.ClaimEmail(ctx, "outlook")
	if err != nil || box == nil {
		t.Fatalf("首次领取失败: box=%v err=%v", box, err)
	}
	if err := st.ReleaseEmailWithCooldown(ctx, box.Email, time.Minute); err != nil {
		t.Fatalf("带冷却释放失败: %v", err)
	}
	again, err := st.ClaimEmail(ctx, "outlook")
	if err != nil {
		t.Fatalf("冷却期间领取报错: %v", err)
	}
	if again != nil {
		t.Fatalf("冷却期间被重复领取: %+v", again)
	}
}

func TestOTPRejectedEmailIsFailedImmediately(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_, _, err := st.ImportEmails(ctx, []EmailItem{{Email: "rejected@example.com", Source: "generic_api"}})
	if err != nil {
		t.Fatalf("导入邮箱失败: %v", err)
	}
	if _, err := st.ClaimEmail(ctx, "generic_api"); err != nil {
		t.Fatalf("领取邮箱失败: %v", err)
	}
	reached, err := st.RecordEmailFailure(ctx, "rejected@example.com", "generic_api", "otp_rejected", 2)
	if err != nil {
		t.Fatalf("记录验证码拒绝失败: %v", err)
	}
	if !reached {
		t.Fatal("验证码拒绝应立即终止该邮箱")
	}
	status := emailPoolStatus(t, st, "rejected@example.com")
	if status != "failed" {
		t.Fatalf("验证码拒绝后的状态 = %q，期望 failed", status)
	}
}

func TestRecordEmailFailureNeverReleasesExistingAccount(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	_, _, err := st.ImportEmails(ctx, []EmailItem{{Email: "existing@example.com", Source: "generic_api"}})
	if err != nil {
		t.Fatalf("导入邮箱失败: %v", err)
	}
	if _, err := st.ClaimEmail(ctx, "generic_api"); err != nil {
		t.Fatalf("领取邮箱失败: %v", err)
	}
	_, err = st.InsertAccount(ctx, domain.Account{
		Email:  "existing@example.com",
		Status: "registered",
		Payload: map[string]any{
			"status":    "registered",
			"device_id": "device-test",
		},
	})
	if err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	if _, err := st.RecordEmailFailure(ctx, "existing@example.com", "generic_api", "registration_failed", 1); err != nil {
		t.Fatalf("记录失败状态失败: %v", err)
	}
	status := emailPoolStatus(t, st, "existing@example.com")
	if status != "used" {
		t.Fatalf("已入库账号对应邮箱状态 = %q，期望 used", status)
	}
}

func emailPoolStatus(t *testing.T, st *Store, email string) string {
	t.Helper()
	var status string
	err := st.Read(context.Background(), func(db *sql.DB) error {
		return db.QueryRow(`SELECT status FROM email_pool WHERE email=? COLLATE NOCASE`, email).Scan(&status)
	})
	if err != nil {
		t.Fatalf("读取邮箱状态失败: %v", err)
	}
	return status
}

func TestJobLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	id, err := st.CreateJob(ctx, "", "outlook", "/tmp/x.log")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}

	ok, err := st.ClaimJob(ctx, id)
	if err != nil || !ok {
		t.Fatalf("抢占失败: ok=%v err=%v", ok, err)
	}
	// 重复抢占必须失败
	ok2, _ := st.ClaimJob(ctx, id)
	if ok2 {
		t.Error("任务被重复抢占")
	}

	status := domain.JobSuccess
	email := "done@example.com"
	if err := st.UpdateJob(ctx, id, JobUpdate{Status: &status, Email: &email, Completed: true}); err != nil {
		t.Fatalf("更新任务失败: %v", err)
	}

	j, err := st.GetJob(ctx, id)
	if err != nil || j == nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if j.Status != domain.JobSuccess || j.Email != "done@example.com" {
		t.Errorf("任务状态错误: %+v", j)
	}
}

func TestRequestJobStopTransitions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	pendingID, err := st.CreateJob(ctx, "", "outlook", "")
	if err != nil {
		t.Fatalf("创建排队任务失败: %v", err)
	}
	result, err := st.RequestJobStop(ctx, pendingID)
	if err != nil {
		t.Fatalf("停止排队任务失败: %v", err)
	}
	if !result.Exists || !result.Changed || result.Status != domain.JobCancelled {
		t.Fatalf("排队停止结果错误: %+v", result)
	}
	j, _ := st.GetJob(ctx, pendingID)
	if j == nil || j.Status != domain.JobCancelled || j.CompletedAt == nil {
		t.Fatalf("排队任务未正确取消: %+v", j)
	}

	runningID, _ := st.CreateJob(ctx, "", "outlook", "")
	if ok, err := st.ClaimJob(ctx, runningID); err != nil || !ok {
		t.Fatalf("抢占运行任务失败: ok=%v err=%v", ok, err)
	}
	result, err = st.RequestJobStop(ctx, runningID)
	if err != nil {
		t.Fatalf("停止运行任务失败: %v", err)
	}
	if result.Status != domain.JobStopping || !result.Changed {
		t.Fatalf("运行停止结果错误: %+v", result)
	}
	result, err = st.FinalizeStoppedJob(ctx, runningID)
	if err != nil {
		t.Fatalf("收尾运行任务失败: %v", err)
	}
	if result.Status != domain.JobStopped || !result.Changed {
		t.Fatalf("运行任务收尾结果错误: %+v", result)
	}
}

func TestRequestJobStopDoesNotOverwriteTerminalState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	id, _ := st.CreateJob(ctx, "", "outlook", "")
	status := domain.JobSuccess
	if err := st.UpdateJob(ctx, id, JobUpdate{Status: &status, Completed: true}); err != nil {
		t.Fatalf("写入成功状态失败: %v", err)
	}
	result, err := st.RequestJobStop(ctx, id)
	if err != nil {
		t.Fatalf("停止终态任务失败: %v", err)
	}
	if !result.Exists || result.Changed || result.Status != domain.JobSuccess {
		t.Fatalf("终态被覆盖: %+v", result)
	}
	result, err = st.FinalizeStoppedJob(ctx, id)
	if err != nil {
		t.Fatalf("收尾终态任务失败: %v", err)
	}
	if result.Changed || result.Status != domain.JobSuccess {
		t.Fatalf("终态收尾被覆盖: %+v", result)
	}
}

func TestCancelPendingJobsReturnsOnlyPendingIDs(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	runningID, _ := st.CreateJob(ctx, "", "outlook", "")
	if ok, err := st.ClaimJob(ctx, runningID); err != nil || !ok {
		t.Fatalf("抢占任务失败: ok=%v err=%v", ok, err)
	}
	pendingA, _ := st.CreateJob(ctx, "", "outlook", "")
	pendingB, _ := st.CreateJob(ctx, "", "outlook", "")

	ids, err := st.CancelPendingJobs(ctx)
	if err != nil {
		t.Fatalf("取消排队失败: %v", err)
	}
	if len(ids) != 2 || ids[0] != pendingA || ids[1] != pendingB {
		t.Fatalf("取消 ID 错误: %v", ids)
	}
	j, _ := st.GetJob(ctx, runningID)
	if j.Status != domain.JobRunning {
		t.Fatalf("运行任务被误取消: %+v", j)
	}
}

func TestRecoverInterruptedJobs(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	id, _ := st.CreateJob(ctx, "", "outlook", "")
	_, _ = st.ClaimJob(ctx, id) // 变成 running，模拟进程崩溃

	n, err := st.RecoverInterruptedJobs(ctx)
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if n != 1 {
		t.Errorf("恢复数量 = %d，期望 1", n)
	}
	j, _ := st.GetJob(ctx, id)
	if j.Status != domain.JobFailed {
		t.Errorf("中断任务状态 = %q，期望 failed", j.Status)
	}
}

func TestPromoBatchQueriesIsolateBatchesAndDedupeAccounts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	accountA, err := st.InsertAccount(ctx, domain.Account{
		Email:   "promo-a@example.com",
		Status:  "registered",
		Payload: map[string]any{"device_id": "promo-device-a", "plan_check_status": "success", "plus_trial_eligible": true},
	})
	if err != nil {
		t.Fatalf("插入账号 A 失败: %v", err)
	}
	accountB, err := st.InsertAccount(ctx, domain.Account{
		Email:   "promo-b@example.com",
		Status:  "registered",
		Payload: map[string]any{"device_id": "promo-device-b", "plan_check_status": "success", "go_trial_eligible": true},
	})
	if err != nil {
		t.Fatalf("插入账号 B 失败: %v", err)
	}

	success := domain.JobSuccess
	createSuccessfulJob := func(batchID string, accountID int64) {
		t.Helper()
		id, err := st.CreateJobWithBatch(ctx, "", "outlook", "", batchID)
		if err != nil {
			t.Fatalf("创建批次 %s 任务失败: %v", batchID, err)
		}
		if err := st.UpdateJob(ctx, id, JobUpdate{Status: &success, AccountID: &accountID, Completed: true}); err != nil {
			t.Fatalf("写入成功任务失败: %v", err)
		}
	}

	createSuccessfulJob("batch_old", accountB)
	createSuccessfulJob("batch_new", accountA)
	createSuccessfulJob("batch_new", accountA) // 同一账号批量重试不应重复计数。

	latest, err := st.LatestJobBatchID(ctx)
	if err != nil || latest != "batch_new" {
		t.Fatalf("最近批次 = %q, err=%v", latest, err)
	}
	payloads, err := st.ListSuccessfulJobAccountPayloads(ctx, "batch_new")
	if err != nil {
		t.Fatalf("读取批次 payload 失败: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("批次 payload 数量 = %d, want 1", len(payloads))
	}
	if payloads[0]["plus_trial_eligible"] != true {
		t.Fatalf("批次隔离或 payload 读取错误: %#v", payloads[0])
	}
}
