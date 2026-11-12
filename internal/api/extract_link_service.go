package api

// Plus 试用提链服务。提链上游是独立的后台服务：先创建 job，再通过 SSE
// 接收日志和最终结果。这里使用有界进程内队列，并把所有状态原子合并回账号
// payload，避免旧账号快照覆盖注册流程刚刚写入的 Token 或套餐字段。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/store"
)

const (
	extractLinkDefaultWorkers      = 3
	extractLinkDefaultQueueLimit   = 500
	extractLinkDefaultRequestLimit = 30
	extractLinkDefaultEventLimit   = 180
	extractLinkMaxBatch            = 500
	extractLinkMaxErrorRunes       = 500
)

var (
	errExtractLinkDone     = errors.New("提链事件流已结束")
	errExtractLinkNoResult = errors.New("提链事件流结束但未返回 result")
)

type extractLinkTask struct {
	AccountID int64
	Email     string
	Token     string
	LinkType  string
	CDK       string
	Trigger   string
}

type extractLinkEnqueueResult struct {
	Accepted bool   `json:"accepted"`
	Busy     bool   `json:"busy"`
	Error    string `json:"error"`
	LinkType string `json:"link_type"`
}

type extractLinkService struct {
	store  *store.Store
	cfg    func() *config.Config
	client *http.Client
	queue  chan extractLinkTask

	startOnce sync.Once
	workers   int
}

func newExtractLinkService(st *store.Store, cfgFn func() *config.Config, client *http.Client) *extractLinkService {
	if cfgFn == nil {
		cfgFn = config.Current
	}
	if client == nil {
		client = &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	cfg := cfgFn()
	workers := cfg.ExtractLinkWorkers
	if workers < 1 {
		workers = extractLinkDefaultWorkers
	}
	if workers > 16 {
		workers = 16
	}
	limit := cfg.ExtractLinkQueueLimit
	if limit < 1 {
		limit = extractLinkDefaultQueueLimit
	}
	if limit < workers {
		limit = workers
	}
	if limit > 5000 {
		limit = 5000
	}
	s := &extractLinkService{
		store:   st,
		cfg:     cfgFn,
		client:  client,
		queue:   make(chan extractLinkTask, limit),
		workers: workers,
	}
	s.start()
	return s
}

func (s *extractLinkService) start() {
	if s == nil || s.store == nil || s.queue == nil {
		return
	}
	s.startOnce.Do(func() {
		for i := 0; i < s.workers; i++ {
			go s.worker()
		}
	})
}

func (s *extractLinkService) worker() {
	for task := range s.queue {
		s.run(context.Background(), task)
	}
}

func normalizeExtractLinkType(value string, cfg *config.Config) (string, error) {
	linkType := strings.ToLower(strings.TrimSpace(value))
	if linkType == "" && cfg != nil {
		linkType = strings.ToLower(strings.TrimSpace(cfg.ExtractLinkType))
	}
	if linkType == "" {
		linkType = "pix"
	}
	switch linkType {
	case "pix", "upi", "kakao_pay", "ideal":
		return linkType, nil
	default:
		return "", errors.New("提链类型无效，仅支持 pix / upi / kakao_pay / ideal")
	}
}

func resolveExtractCDK(value string, cfg *config.Config) (string, error) {
	cdk := strings.TrimSpace(value)
	if cdk == "" && cfg != nil {
		cdk = strings.TrimSpace(cfg.ExtractLinkCDK)
	}
	if cdk == "" {
		return "", errors.New("EXTRACT_LINK_CDK/CDK 为空")
	}
	return cdk, nil
}

func resolveExtractBase(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", errors.New("提链配置不可用")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.ExtractLinkAPIBase), "/")
	if base == "" {
		return "", errors.New("EXTRACT_LINK_API_BASE 为空")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("EXTRACT_LINK_API_BASE 不是合法的 HTTP(S) 地址")
	}
	return base, nil
}

func extractRequestTimeout(cfg *config.Config) time.Duration {
	seconds := extractLinkDefaultRequestLimit
	if cfg != nil && cfg.ExtractLinkRequestTimeout > 0 {
		seconds = cfg.ExtractLinkRequestTimeout
	}
	if seconds < 5 {
		seconds = 5
	}
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

func extractEventTimeout(cfg *config.Config) time.Duration {
	seconds := extractLinkDefaultEventLimit
	if cfg != nil && cfg.ExtractLinkEventTimeout > 0 {
		seconds = cfg.ExtractLinkEventTimeout
	}
	if seconds < 30 {
		seconds = 30
	}
	if seconds > 900 {
		seconds = 900
	}
	return time.Duration(seconds) * time.Second
}

func (s *extractLinkService) enqueue(ctx context.Context, task extractLinkTask) (extractLinkEnqueueResult, error) {
	if s == nil || s.store == nil || s.queue == nil {
		return extractLinkEnqueueResult{}, errors.New("提链服务未初始化")
	}
	cfg := s.cfg()
	linkType, err := normalizeExtractLinkType(task.LinkType, cfg)
	if err != nil {
		return extractLinkEnqueueResult{}, err
	}
	cdk, err := resolveExtractCDK(task.CDK, cfg)
	if err != nil {
		return extractLinkEnqueueResult{}, err
	}
	if _, err := resolveExtractBase(cfg); err != nil {
		return extractLinkEnqueueResult{}, err
	}
	task.LinkType = linkType
	task.CDK = cdk
	task.Trigger = strings.TrimSpace(task.Trigger)
	if task.Trigger == "" {
		task.Trigger = "manual"
	}

	claimed, err := s.store.ClaimAccountExtract(ctx, task.AccountID, linkType, task.Trigger)
	if err != nil {
		return extractLinkEnqueueResult{}, fmt.Errorf("认领提链任务失败: %w", err)
	}
	if !claimed {
		return extractLinkEnqueueResult{
			Busy:     true,
			Error:    "该账号正在提链中",
			LinkType: linkType,
		}, nil
	}

	select {
	case s.queue <- task:
		return extractLinkEnqueueResult{Accepted: true, LinkType: linkType}, nil
	default:
		message := "提链队列已满"
		s.failQueued(context.Background(), task.AccountID, message)
		return extractLinkEnqueueResult{Error: message, LinkType: linkType}, nil
	}
}

func (s *extractLinkService) failQueued(ctx context.Context, accountID int64, message string) {
	if s == nil || s.store == nil {
		return
	}
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ts := time.Now().Format("2006-01-02T15:04:05")
	_ = s.store.UpdateAccountExtract(updateCtx, accountID, map[string]any{
		"extract_link_status":       "failed",
		"extract_link_ok":           false,
		"extract_link_completed_at": ts,
		"extract_link_checked_at":   ts,
		"extract_link_error":        message,
		"extract_link_message":      message,
	})
}

func (s *extractLinkService) run(parent context.Context, task extractLinkTask) {
	cfg := s.cfg()
	claimed, err := s.store.MarkAccountExtractRunning(parent, task.AccountID)
	if err != nil || !claimed {
		return
	}

	jobID := ""
	var cdkRemaining any
	lastEvent := ""
	var lastData map[string]any
	logs := make([]string, 0, 8)

	fail := func(reason string) {
		reason = trimExtractText(safeExtractError(reason, task.CDK, task.Token), extractLinkMaxErrorRunes)
		if reason == "" {
			reason = "提链任务失败"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ts := time.Now().Format("2006-01-02T15:04:05")
		_ = s.store.UpdateAccountExtract(ctx, task.AccountID, map[string]any{
			"extract_link_status":       "failed",
			"extract_link_ok":           false,
			"extract_link_completed_at": ts,
			"extract_link_checked_at":   ts,
			"extract_link_error":        reason,
			"extract_link_message":      reason,
		})
	}

	job, err := s.createJob(parent, cfg, task)
	if err != nil {
		fail(err.Error())
		return
	}
	jobID, _ = job["job_id"].(string)
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		fail("提链服务未返回 job_id")
		return
	}
	cdkRemaining = job["cdk_remaining"]
	_ = s.store.UpdateAccountExtract(parent, task.AccountID, map[string]any{
		"extract_link_status":        "running",
		"extract_link_ok":            false,
		"extract_link_job_id":        jobID,
		"extract_link_type":          task.LinkType,
		"extract_link_message":       "提链任务已创建，等待结果",
		"extract_link_cdk_remaining": cdkRemaining,
	})

	streamCtx, cancel := context.WithTimeout(parent, extractEventTimeout(cfg))
	defer cancel()
	err = s.streamEvents(streamCtx, cfg, jobID, task.CDK, func(event string, data map[string]any) (bool, error) {
		lastEvent, lastData = event, data
		switch event {
		case "log":
			message := trimExtractText(stringValue(data["message"]), 300)
			if message == "" {
				return false, nil
			}
			logs = append(logs, message)
			if err := s.store.UpdateAccountExtract(parent, task.AccountID, map[string]any{
				"extract_link_status":  "running",
				"extract_link_ok":      false,
				"extract_link_job_id":  jobID,
				"extract_link_message": message,
			}); err != nil {
				return true, err
			}
			return false, nil
		case "result":
			result, _ := data["result"].(map[string]any)
			if result == nil {
				result = map[string]any{}
			}
			if v, ok := result["cdk_remaining"]; ok {
				cdkRemaining = v
			}
			resultJSON, _ := json.Marshal(result)
			ts := time.Now().Format("2006-01-02T15:04:05")
			values := map[string]any{
				"extract_link_status":            "success",
				"extract_link_ok":                true,
				"extract_link_job_id":            jobID,
				"extract_link_type":              task.LinkType,
				"extract_link_long_url":          stringValue(result["long_url"]),
				"extract_link_copy_paste":        stringValue(result["copy_paste"]),
				"extract_link_image_url_png":     stringValue(result["image_url_png"]),
				"extract_link_image_url_svg":     stringValue(result["image_url_svg"]),
				"extract_link_payment_method":    stringValue(result["payment_method"]),
				"extract_link_payment_link_type": stringValue(result["payment_link_type"]),
				"extract_link_expires_at":        stringValue(result["expires_at"]),
				"extract_link_cdk_remaining":     cdkRemaining,
				"extract_link_result_json":       string(resultJSON),
				"extract_link_message":           "提链成功，已获取链接",
				"extract_link_error":             "",
				"extract_link_checked_at":        ts,
				"extract_link_completed_at":      ts,
			}
			if err := s.store.UpdateAccountExtract(parent, task.AccountID, values); err != nil {
				return true, err
			}
			return true, nil
		case "error":
			message := extractEventError(data)
			if message == "" {
				message = "提链任务失败"
			}
			return true, errors.New(message)
		case "done":
			return true, errExtractLinkDone
		default:
			return false, nil
		}
	})
	if err == nil {
		// result 事件已在回调中持久化成功。
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(streamCtx.Err(), context.DeadlineExceeded) {
		fail(fmt.Sprintf("监听提链事件超时（%s）", extractEventTimeout(cfg)))
		return
	}
	if errors.Is(err, errExtractLinkDone) || errors.Is(err, errExtractLinkNoResult) || errors.Is(err, io.EOF) {
		message := "提链事件流结束但未返回 result"
		if lastEvent != "" {
			message += "；最后事件 " + lastEvent
			if detail := extractEventError(lastData); detail != "" {
				message += ": " + detail
			}
		}
		fail(message)
		return
	}
	reason := err.Error()
	if (reason == "" || strings.Contains(reason, "未返回 result")) && len(logs) > 0 {
		reason = logs[len(logs)-1]
	}
	fail(reason)
}

func (s *extractLinkService) createJob(ctx context.Context, cfg *config.Config, task extractLinkTask) (map[string]any, error) {
	base, err := resolveExtractBase(cfg)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"link_type": task.LinkType,
		"cdk":       task.CDK,
		"token":     task.Token,
	})
	reqCtx, cancel := context.WithTimeout(ctx, extractRequestTimeout(cfg))
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"/api/extract", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("创建提链请求失败")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, requestContextError(reqCtx, err)
	}
	defer resp.Body.Close()
	data, readErr := decodeLimitedJSON(resp.Body, 1<<20)
	if readErr != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, errors.New("提链服务返回了无法解析的响应")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, extractHTTPError("创建提链任务", resp.StatusCode, data)
	}
	if data == nil {
		return nil, errors.New("提链服务未返回 job_id")
	}
	return data, nil
}

func (s *extractLinkService) streamEvents(ctx context.Context, cfg *config.Config, jobID, cdk string, onEvent func(string, map[string]any) (bool, error)) error {
	base, err := resolveExtractBase(cfg)
	if err != nil {
		return err
	}
	endpoint := base + "/api/jobs/" + url.PathEscape(jobID) + "/events?" + url.Values{"cdk": {cdk}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("创建提链事件请求失败")
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		return requestContextError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := decodeLimitedJSON(resp.Body, 1<<16)
		return extractHTTPError("监听提链事件", resp.StatusCode, data)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	event := "message"
	dataLines := make([]string, 0, 4)
	dispatch := func() (bool, error) {
		if len(dataLines) == 0 {
			event = "message"
			return false, nil
		}
		raw := strings.Join(dataLines, "\n")
		data := map[string]any{"raw": raw}
		var decoded any
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			if obj, ok := decoded.(map[string]any); ok {
				data = obj
			}
		}
		currentEvent := event
		event = "message"
		dataLines = dataLines[:0]
		return onEvent(currentEvent, data)
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			stop, dispatchErr := dispatch()
			if dispatchErr != nil || stop {
				return dispatchErr
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			if event == "" {
				event = "message"
			}
		case strings.HasPrefix(line, "data:"):
			value := strings.TrimPrefix(line, "data:")
			value = strings.TrimPrefix(value, " ")
			dataLines = append(dataLines, value)
		}
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("读取提链事件流失败")
	}
	if len(dataLines) > 0 {
		stop, dispatchErr := dispatch()
		if dispatchErr != nil || stop {
			return dispatchErr
		}
	}
	return errExtractLinkNoResult
}

func (s *extractLinkService) queryCDK(ctx context.Context, code string) (map[string]any, error) {
	cfg := s.cfg()
	base, err := resolveExtractBase(cfg)
	if err != nil {
		return nil, err
	}
	cdk, err := resolveExtractCDK(code, cfg)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/api/cdk?" + url.Values{"code": {cdk}}.Encode()
	reqCtx, cancel := context.WithTimeout(ctx, extractRequestTimeout(cfg))
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("创建 CDK 查询请求失败")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, requestContextError(reqCtx, err)
	}
	defer resp.Body.Close()
	data, readErr := decodeLimitedJSON(resp.Body, 1<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, extractHTTPError("查询 CDK", resp.StatusCode, data)
	}
	if readErr != nil {
		return nil, errors.New("CDK 查询返回了无法解析的响应")
	}
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}

func decodeLimitedJSON(r io.Reader, limit int64) (map[string]any, error) {
	decoder := json.NewDecoder(io.LimitReader(r, limit))
	var data map[string]any
	if err := decoder.Decode(&data); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}

func extractHTTPError(action string, status int, data map[string]any) error {
	detail := extractEventError(data)
	if detail != "" {
		return fmt.Errorf("%s失败 HTTP %d: %s", action, status, trimExtractText(detail, 300))
	}
	return fmt.Errorf("%s失败 HTTP %d", action, status)
}

func extractEventError(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	if raw, ok := data["raw"].(string); ok && len(data) == 1 {
		return strings.TrimSpace(raw)
	}
	if value, ok := data["error"]; ok {
		if text := errorValue(value); text != "" {
			return text
		}
	}
	for _, key := range []string{"message", "detail", "reason", "msg", "description", "raw"} {
		if text := stringValue(data[key]); text != "" {
			return strings.TrimSpace(text)
		}
	}
	if raw, err := json.Marshal(data); err == nil {
		return string(raw)
	}
	return ""
}

func errorValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"message", "detail", "reason", "error", "msg", "description"} {
			if text := stringValue(v[key]); text != "" {
				return strings.TrimSpace(text)
			}
		}
		raw, _ := json.Marshal(v)
		return string(raw)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(raw)
	}
}

func requestContextError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("请求提链服务超时")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("请求提链服务已取消")
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	if err == nil {
		return errors.New("请求提链服务失败")
	}
	return fmt.Errorf("请求提链服务失败: %v", err)
}

func safeExtractError(message string, secrets ...string) string {
	message = strings.TrimSpace(message)
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "[redacted]")
		message = strings.ReplaceAll(message, url.QueryEscape(secret), "[redacted]")
		message = strings.ReplaceAll(message, url.PathEscape(secret), "[redacted]")
	}
	return message
}

func trimExtractText(text string, maxRunes int) string {
	text = strings.TrimSpace(text)
	if maxRunes <= 0 || len([]rune(text)) <= maxRunes {
		return text
	}
	runes := []rune(text)
	return string(runes[:maxRunes]) + "…"
}

func extractLinkEligible(acc *domain.Account) (bool, string) {
	if acc == nil {
		return false, "账号不存在"
	}
	plan := strings.ToLower(strings.TrimSpace(stringValue(acc.Payload["current_plan_type"])))
	if plan == "" {
		plan = strings.ToLower(strings.TrimSpace(stringValue(acc.Payload["plan_type"])))
	}
	if plan != "free" || !boolValue(acc.Payload["plus_trial_eligible"]) {
		return false, "仅支持 free(可Plus试用) 账号提链；请先查询套餐确认资格"
	}
	if strings.TrimSpace(stringValue(acc.Payload["access_token"])) == "" {
		return false, "该账号没有 access_token"
	}
	return true, ""
}
