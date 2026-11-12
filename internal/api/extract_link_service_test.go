package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/store"
)

func openAPITestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func insertExtractAccount(t *testing.T, st *store.Store, email string) int64 {
	t.Helper()
	id, err := st.InsertAccount(context.Background(), domain.Account{
		Email:  email,
		Status: "registered",
		Payload: map[string]any{
			"device_id":           "device-test",
			"access_token":        "access-token-test",
			"current_plan_type":   "free",
			"plus_trial_eligible": true,
		},
	})
	if err != nil {
		t.Fatalf("插入测试账号失败: %v", err)
	}
	return id
}

func testExtractConfig(base string) *config.Config {
	return &config.Config{
		ExtractLinkAPIBase:        base,
		ExtractLinkCDK:            "default-cdk-SECRET",
		ExtractLinkType:           "pix",
		ExtractLinkWorkers:        1,
		ExtractLinkQueueLimit:     2,
		ExtractLinkRequestTimeout: 5,
		ExtractLinkEventTimeout:   30,
	}
}

func testExtractService(st *store.Store, cfg *config.Config, client *http.Client, queueLimit int) *extractLinkService {
	if client == nil {
		client = http.DefaultClient
	}
	return &extractLinkService{
		store:  st,
		cfg:    func() *config.Config { return cfg },
		client: client,
		queue:  make(chan extractLinkTask, queueLimit),
	}
}

func TestExtractLinkStreamEventsMultilineAndEscapedJobID(t *testing.T) {
	var gotRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		if got := r.URL.Query().Get("cdk"); got != "secret cdk" {
			t.Errorf("cdk = %q", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n"+
			"event: result\n"+
			"data: {\"result\":{\"long_url\":\"https://pay.example.test/link\",\n"+
			"data: \"payment_method\":\"PIX\"}}\n\n")
	}))
	defer upstream.Close()

	cfg := testExtractConfig(upstream.URL)
	svc := testExtractService(nil, cfg, upstream.Client(), 0)
	var result map[string]any
	err := svc.streamEvents(context.Background(), cfg, "job/1 ?", "secret cdk", func(event string, data map[string]any) (bool, error) {
		if event != "result" {
			t.Fatalf("event = %q，期望 result", event)
		}
		result, _ = data["result"].(map[string]any)
		return true, nil
	})
	if err != nil {
		t.Fatalf("读取 SSE 失败: %v", err)
	}
	if result["long_url"] != "https://pay.example.test/link" || result["payment_method"] != "PIX" {
		t.Fatalf("多行 data 未正确合并: %#v", result)
	}
	if !strings.Contains(gotRequestURI, "/api/jobs/job%2F1%20%3F/events?") {
		t.Fatalf("job_id 未正确转义: %q", gotRequestURI)
	}
}

func TestExtractLinkStreamEventsEndsWithoutResult(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr error
	}{
		{name: "done", body: "event: done\ndata: {\"message\":\"finished\"}\n\n", wantErr: errExtractLinkNoResult},
		{name: "eof", body: "event: log\ndata: {\"message\":\"waiting\"}\n\n", wantErr: errExtractLinkNoResult},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, tt.body)
			}))
			defer upstream.Close()

			cfg := testExtractConfig(upstream.URL)
			svc := testExtractService(nil, cfg, upstream.Client(), 0)
			err := svc.streamEvents(context.Background(), cfg, "job-1", "cdk", func(string, map[string]any) (bool, error) {
				return false, nil
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v，期望 %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractLinkRunPersistsOnlyResultAsSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/extract":
			writeJSON(w, http.StatusOK, map[string]any{"job_id": "job-success", "cdk_remaining": 8})
		case r.Method == http.MethodGet && r.URL.Path == "/api/jobs/job-success/events":
			fmt.Fprint(w, "event: log\ndata: {\"message\":\"creating checkout\"}\n\n"+
				"event: result\ndata: {\"result\":{\"long_url\":\"https://pay.example.test/success\",\"payment_method\":\"PIX\",\"expires_at\":\"2026-11-13T00:00:00\"}}\n\n"+
				"event: done\ndata: {}\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	st := openAPITestStore(t)
	id := insertExtractAccount(t, st, "success@example.test")
	cfg := testExtractConfig(upstream.URL)
	svc := testExtractService(st, cfg, upstream.Client(), 0)
	claimed, err := st.ClaimAccountExtract(context.Background(), id, "pix", "manual")
	if err != nil || !claimed {
		t.Fatalf("认领失败: claimed=%v err=%v", claimed, err)
	}
	svc.run(context.Background(), extractLinkTask{
		AccountID: id,
		Email:     "success@example.test",
		Token:     "access-token-test",
		LinkType:  "pix",
		CDK:       "request-cdk",
	})

	acc, err := st.GetAccount(context.Background(), id)
	if err != nil || acc == nil {
		t.Fatalf("读取账号失败: %v", err)
	}
	if acc.Payload["extract_link_status"] != "success" || acc.Payload["extract_link_ok"] != true {
		t.Fatalf("提链未成功: %#v", acc.Payload)
	}
	if acc.Payload["extract_link_long_url"] != "https://pay.example.test/success" {
		t.Fatalf("链接未保存: %#v", acc.Payload)
	}
	if acc.Payload["extract_link_job_id"] != "job-success" {
		t.Fatalf("job_id 未保存: %#v", acc.Payload)
	}
}

func TestExtractLinkRunFailsWhenStreamEndsWithoutResult(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "done", body: "event: done\ndata: {\"message\":\"finished\"}\n\n"},
		{name: "eof", body: "event: log\ndata: {\"message\":\"still waiting\"}\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/extract" {
					writeJSON(w, http.StatusOK, map[string]any{"job_id": "job-no-result"})
					return
				}
				if r.Method == http.MethodGet && r.URL.Path == "/api/jobs/job-no-result/events" {
					fmt.Fprint(w, tt.body)
					return
				}
				http.NotFound(w, r)
			}))
			defer upstream.Close()

			st := openAPITestStore(t)
			id := insertExtractAccount(t, st, tt.name+"@example.test")
			cfg := testExtractConfig(upstream.URL)
			svc := testExtractService(st, cfg, upstream.Client(), 0)
			if claimed, err := st.ClaimAccountExtract(context.Background(), id, "pix", "manual"); err != nil || !claimed {
				t.Fatalf("认领失败: claimed=%v err=%v", claimed, err)
			}
			svc.run(context.Background(), extractLinkTask{
				AccountID: id, Email: tt.name + "@example.test", Token: "access-token-test",
				LinkType: "pix", CDK: "request-cdk",
			})
			acc, err := st.GetAccount(context.Background(), id)
			if err != nil || acc == nil {
				t.Fatalf("读取账号失败: %v", err)
			}
			if acc.Payload["extract_link_status"] != "failed" || acc.Payload["extract_link_ok"] != false {
				t.Fatalf("无 result 的事件流必须失败: %#v", acc.Payload)
			}
			if reason := stringValue(acc.Payload["extract_link_error"]); !strings.Contains(reason, "未返回 result") {
				t.Fatalf("失败原因不明确: %q", reason)
			}
		})
	}
}

func TestExtractLinkRunRedactsTokenAndCDK(t *testing.T) {
	const token = "secret-access-token"
	const cdk = "secret-request-cdk"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/extract" {
			writeJSON(w, http.StatusOK, map[string]any{"job_id": "job-error"})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/jobs/job-error/events" {
			fmt.Fprintf(w, "event: error\ndata: {\"error\":\"upstream rejected %s with %s\"}\n\n", token, cdk)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	st := openAPITestStore(t)
	id := insertExtractAccount(t, st, "redaction@example.test")
	cfg := testExtractConfig(upstream.URL)
	svc := testExtractService(st, cfg, upstream.Client(), 0)
	if claimed, err := st.ClaimAccountExtract(context.Background(), id, "pix", "manual"); err != nil || !claimed {
		t.Fatalf("认领失败: claimed=%v err=%v", claimed, err)
	}
	svc.run(context.Background(), extractLinkTask{
		AccountID: id, Email: "redaction@example.test", Token: token, LinkType: "pix", CDK: cdk,
	})
	acc, err := st.GetAccount(context.Background(), id)
	if err != nil || acc == nil {
		t.Fatalf("读取账号失败: %v", err)
	}
	reason := stringValue(acc.Payload["extract_link_error"])
	if strings.Contains(reason, token) || strings.Contains(reason, cdk) {
		t.Fatalf("错误信息泄露敏感值: %q", reason)
	}
	if !strings.Contains(reason, "[redacted]") {
		t.Fatalf("错误信息未显示脱敏标记: %q", reason)
	}
}

func TestExtractLinkEnqueueClaimAndQueueFull(t *testing.T) {
	st := openAPITestStore(t)
	firstID := insertExtractAccount(t, st, "first@example.test")
	secondID := insertExtractAccount(t, st, "second@example.test")
	cfg := testExtractConfig("https://extract.example.test")
	svc := testExtractService(st, cfg, nil, 1)

	first, err := svc.enqueue(context.Background(), extractLinkTask{
		AccountID: firstID, Email: "first@example.test", Token: "access-token-test",
	})
	if err != nil || !first.Accepted || first.Busy {
		t.Fatalf("首次入队失败: %#v err=%v", first, err)
	}
	duplicate, err := svc.enqueue(context.Background(), extractLinkTask{
		AccountID: firstID, Email: "first@example.test", Token: "access-token-test",
	})
	if err != nil || !duplicate.Busy || duplicate.Accepted {
		t.Fatalf("重复认领必须返回 busy: %#v err=%v", duplicate, err)
	}
	full, err := svc.enqueue(context.Background(), extractLinkTask{
		AccountID: secondID, Email: "second@example.test", Token: "access-token-test",
	})
	if err != nil || full.Accepted || full.Busy || full.Error != "提链队列已满" {
		t.Fatalf("队列入队结果异常: %#v err=%v", full, err)
	}
	second, err := st.GetAccount(context.Background(), secondID)
	if err != nil || second == nil {
		t.Fatalf("读取第二账号失败: %v", err)
	}
	if second.Payload["extract_link_status"] != "failed" {
		t.Fatalf("队列满时认领状态未回滚: %#v", second.Payload)
	}
}

func TestExtractLinkBulkDeduplicatesAndCounts(t *testing.T) {
	st := openAPITestStore(t)
	firstID := insertExtractAccount(t, st, "bulk-first@example.test")
	secondID := insertExtractAccount(t, st, "bulk-second@example.test")
	cfg := testExtractConfig("https://extract.example.test")
	svc := testExtractService(st, cfg, nil, 1)
	srv := &Server{store: st, extract: svc}

	body := fmt.Sprintf(`{"account_ids":[%d,%d,%d,999999,"bad"]}`, firstID, firstID, secondID)
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/extract-link-bulk", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleExtractLinkBulk(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		StartedCount int `json:"started_count"`
		BusyCount    int `json:"busy_count"`
		FailedCount  int `json:"failed_count"`
		SkippedCount int `json:"skipped_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if response.StartedCount != 1 || response.BusyCount != 0 || response.FailedCount != 1 || response.SkippedCount != 2 {
		t.Fatalf("批量计数错误: %#v body=%s", response, rec.Body.String())
	}
}

func TestExtractLinkCDKErrorRedactsDefaultCDK(t *testing.T) {
	const defaultCDK = "default-cdk-SECRET"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("code"); got != defaultCDK {
			t.Errorf("code = %q，期望默认 CDK", got)
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "upstream rejected " + defaultCDK})
	}))
	defer upstream.Close()

	cfg := testExtractConfig(upstream.URL)
	svc := testExtractService(nil, cfg, upstream.Client(), 0)
	srv := &Server{extract: svc}
	req := httptest.NewRequest(http.MethodGet, "/api/extract-link/cdk", nil)
	rec := httptest.NewRecorder()
	srv.handleExtractLinkCDK(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), defaultCDK) {
		t.Fatalf("默认 CDK 泄露: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "[redacted]") {
		t.Fatalf("默认 CDK 未脱敏: %s", rec.Body.String())
	}
}

func TestExtractLinkEligibility(t *testing.T) {
	acc := &domain.Account{Payload: map[string]any{
		"current_plan_type": "free", "plus_trial_eligible": true, "access_token": "token",
	}}
	if eligible, reason := extractLinkEligible(acc); !eligible || reason != "" {
		t.Fatalf("应符合资格: eligible=%v reason=%q", eligible, reason)
	}
	acc.Payload["plus_trial_eligible"] = false
	if eligible, _ := extractLinkEligible(acc); eligible {
		t.Fatal("plus_trial_eligible=false 不应符合资格")
	}
}

func TestExtractLinkEventTimeoutBounds(t *testing.T) {
	cfg := &config.Config{ExtractLinkEventTimeout: 1, ExtractLinkRequestTimeout: 1}
	if got := extractEventTimeout(cfg); got != 30*time.Second {
		t.Fatalf("事件超时下界 = %s", got)
	}
	if got := extractRequestTimeout(cfg); got != 5*time.Second {
		t.Fatalf("请求超时下界 = %s", got)
	}
}
