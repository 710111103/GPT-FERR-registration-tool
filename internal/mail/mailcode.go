package mail

// MailCode 域名邮箱 Provider。
//
// 官方地址固定，生产配置只能提供 API Key、商品 ID 和超时；不能通过 .env
// 把 API Key 转发到其它域名。购买幂等键在扣款请求前原子落盘，进程重启后
// 继续使用同一键确认结果。日志与返回错误不包含 API Key、幂等键或完整 URL。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/config"
	"github.com/turb/gpt-register/internal/domain"
)

const (
	mailCodeBase      = "https://mailcode.bzb.qzz.io/api/open/v1"
	mailCodeHTTPLimit = 4 << 20
)

// MailCodeError 保留服务端 HTTP 状态和业务错误码，供购买重试与调用方分支判断。
type MailCodeError struct {
	Message    string
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *MailCodeError) Error() string { return e.Message }

type mailCodeOptions struct {
	base   string
	state  string
	client *http.Client
	config func() *config.Config
	now    func() time.Time
}

// MailCode 是域名邮箱来源。缓存目录由启动入口传入。
type MailCode struct {
	base       string
	stateDir   string
	client     *http.Client
	config     func() *config.Config
	now        func() time.Time
	purchaseMu sync.Mutex
	contextMu  sync.Mutex
	contexts   map[string]*mailCodeAccount
	locks      map[string]*sync.Mutex
}

type mailCodeAccount struct {
	Email        string `json:"email"`
	MailboxID    string `json:"mailbox_id"`
	OrderID      string `json:"order_id,omitempty"`
	NextSequence string `json:"next_sequence"`
}

type mailCodePendingPurchase struct {
	Key     string             `json:"key"`
	OrderID string             `json:"order_id,omitempty"`
	Item    *mailCodeOrderItem `json:"item,omitempty"`
}

type mailCodeOrderItem struct {
	Email     string `json:"email"`
	MailboxID string `json:"mailbox_id"`
	Status    string `json:"status"`
}

type mailCodeOrder struct {
	OrderID string              `json:"order_id"`
	Status  string              `json:"status"`
	Items   []mailCodeOrderItem `json:"items"`
}

type mailCodeCodeRecord struct {
	Code       string          `json:"code"`
	Sequence   json.RawMessage `json:"sequence"`
	ReceivedAt int64           `json:"received_at"`
	ExpiresAt  int64           `json:"expires_at"`
}

type mailCodeCodes struct {
	Records       []mailCodeCodeRecord `json:"records"`
	NextSequence  json.RawMessage      `json:"next_sequence"`
	HasMore       bool                 `json:"has_more"`
	ChannelStatus string               `json:"channel_status"`
}

type MailCodeCatalog struct {
	Products []map[string]any `json:"products"`
	Wallet   any              `json:"wallet"`
}

// NewMailCode 创建官方域名邮箱 Provider。
func NewMailCode(stateDir string) *MailCode {
	return newMailCode(mailCodeOptions{
		base:   mailCodeBase,
		state:  stateDir,
		client: &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }},
		config: config.Current,
		now:    time.Now,
	})
}

func newMailCode(opt mailCodeOptions) *MailCode {
	if opt.base == "" {
		opt.base = mailCodeBase
	}
	opt.base = strings.TrimRight(opt.base, "/")
	if opt.client == nil {
		opt.client = &http.Client{}
	}
	if opt.config == nil {
		opt.config = config.Current
	}
	if opt.now == nil {
		opt.now = time.Now
	}
	return &MailCode{
		base:     opt.base,
		stateDir: opt.state,
		client:   opt.client,
		config:   opt.config,
		now:      opt.now,
		contexts: make(map[string]*mailCodeAccount),
		locks:    make(map[string]*sync.Mutex),
	}
}

func (m *MailCode) Name() string { return string(domain.SourceMailCode) }

// Acquire 购买一个域名邮箱，并在通道进入 READY 后才交付给注册流程。
func (m *MailCode) Acquire(ctx context.Context) (domain.Mailbox, error) {
	cfg := m.config()
	key := strings.TrimSpace(cfg.MailCodeAPIKey)
	product := strings.TrimSpace(cfg.MailCodeProductID)
	if key == "" {
		return domain.Mailbox{}, &MailCodeError{Message: "MailCode API Key 未配置"}
	}
	if product == "" {
		return domain.Mailbox{}, &MailCodeError{Message: "MailCode 商品 ID 未配置"}
	}

	m.purchaseMu.Lock()
	defer m.purchaseMu.Unlock()

	pendingPath := m.purchasePath(key, product)
	pending := mailCodePendingPurchase{}
	if err := loadJSONFile(pendingPath, &pending); err != nil {
		return domain.Mailbox{}, fmt.Errorf("读取 MailCode 待确认购买失败: %w", err)
	}
	if pending.Key == "" {
		pending.Key = "turb-mailcode-" + randomHex(16)
	}
	// 发起可能扣款的请求前必须先持久化幂等键。
	if err := saveJSONFile(pendingPath, pending); err != nil {
		return domain.Mailbox{}, fmt.Errorf("保存 MailCode 幂等购买状态失败: %w", err)
	}

	if pending.Item == nil {
		for attempt := 0; attempt < 3; attempt++ {
			data, err := m.request(ctx, http.MethodPost, "/orders",
				map[string]any{"product_id": product, "count": 1}, nil, pending.Key)
			if err == nil {
				item, orderID, parseErr := decodeMailCodeOrder(data)
				if parseErr != nil {
					return domain.Mailbox{}, parseErr
				}
				pending.Item = &item
				pending.OrderID = orderID
				if saveErr := saveJSONFile(pendingPath, pending); saveErr != nil {
					return domain.Mailbox{}, fmt.Errorf("保存 MailCode 已购邮箱失败: %w", saveErr)
				}
				break
			}
			var mcErr *MailCodeError
			if !errors.As(err, &mcErr) {
				return domain.Mailbox{}, err
			}
			if !mcErr.retryable() {
				if mcErr.Status == http.StatusConflict && mcErr.Code == "IDEMPOTENCY_CONFLICT" {
					return domain.Mailbox{}, mcErr
				}
				if mcErr.Status >= 400 && mcErr.Status < 500 {
					_ = os.Remove(pendingPath)
				}
				return domain.Mailbox{}, mcErr
			}
			if attempt == 2 {
				return domain.Mailbox{}, &MailCodeError{
					Message: mcErr.Message + "；购买结果未确认，已保存幂等键，下次继续原请求",
					Status:  mcErr.Status, Code: mcErr.Code, RetryAfter: mcErr.RetryAfter,
				}
			}
			if err := sleepContext(ctx, retryDelay(mcErr.RetryAfter)); err != nil {
				return domain.Mailbox{}, err
			}
		}
	}
	if pending.Item == nil {
		return domain.Mailbox{}, &MailCodeError{Message: "MailCode 购买结果未确认，已保留幂等键"}
	}

	acc := &mailCodeAccount{
		Email: strings.TrimSpace(pending.Item.Email), MailboxID: pending.Item.MailboxID,
		OrderID: pending.OrderID, NextSequence: "0",
	}
	if err := m.prepare(ctx, acc); err != nil {
		m.remember(acc)
		return domain.Mailbox{}, err
	}
	if err := saveJSONFile(m.contextPath(key, acc.Email), acc); err != nil {
		return domain.Mailbox{}, fmt.Errorf("保存 MailCode 取码上下文失败: %w", err)
	}
	_ = os.Remove(pendingPath)
	m.remember(acc)
	return domain.Mailbox{
		Email: acc.Email, Source: domain.SourceMailCode, AcquiredAt: m.now(),
		Credential: map[string]string{"mailbox_id": acc.MailboxID, "order_id": acc.OrderID},
	}, nil
}

// WaitCode 每次只拉一页；总等待和轮询由 mail.WaitCodeWithRetry 负责。
func (m *MailCode) WaitCode(ctx context.Context, box domain.Mailbox, after time.Time) (domain.OTPResult, error) {
	acc, err := m.accountContext(box)
	if err != nil {
		return domain.OTPResult{}, err
	}
	lock := m.accountLock(acc.Email)
	lock.Lock()
	defer lock.Unlock()

	path := "/mailboxes/" + url.PathEscape(acc.MailboxID) + "/codes"
	params := url.Values{"limit": {"100"}}
	if acc.NextSequence != "" {
		params.Set("after_sequence", acc.NextSequence)
	}
	data, err := m.request(ctx, http.MethodGet, path, nil, params, "")
	if err != nil {
		return domain.OTPResult{}, err
	}
	var page mailCodeCodes
	if err := json.Unmarshal(data, &page); err != nil || page.Records == nil {
		return domain.OTPResult{}, &MailCodeError{Message: "MailCode 取码响应缺少 records 数组"}
	}
	next := rawSequence(page.NextSequence)
	if next == "" {
		next = acc.NextSequence
	}
	if err := validateSequence(next); err != nil {
		return domain.OTPResult{}, err
	}

	var best domain.OTPResult
	bestSeq := int64(-1)
	for _, rec := range page.Records {
		if len(rec.Code) != 6 || !digitsOnly(rec.Code) {
			continue
		}
		received := time.UnixMilli(rec.ReceivedAt)
		if !after.IsZero() && received.Before(after) {
			continue
		}
		if rec.ExpiresAt > 0 && !time.UnixMilli(rec.ExpiresAt).After(m.now()) {
			continue
		}
		seq, _ := strconv.ParseInt(rawSequence(rec.Sequence), 10, 64)
		if best.Code == "" || received.After(best.Received) || (received.Equal(best.Received) && seq > bestSeq) {
			best = domain.OTPResult{Code: rec.Code, Received: received, Source: "mailcode"}
			bestSeq = seq
		}
	}
	acc.NextSequence = next
	if err := saveJSONFile(m.contextPath(strings.TrimSpace(m.config().MailCodeAPIKey), acc.Email), acc); err != nil {
		return domain.OTPResult{}, fmt.Errorf("保存 MailCode 游标失败: %w", err)
	}
	m.remember(acc)
	if page.ChannelStatus == "CLOSED" || page.ChannelStatus == "PAUSED" {
		return domain.OTPResult{}, &MailCodeError{Message: "MailCode 取码通道已关闭或暂停", Status: http.StatusNotFound}
	}
	return best, nil
}

// Release 只释放本地引用。平台没有退款或撤销邮箱 API，已购使用权保持不变。
func (m *MailCode) Release(context.Context, domain.Mailbox, string) error {
	return nil
}

// Catalog 只读取商品与钱包，不会创建订单或购买邮箱。
func (m *MailCode) Catalog(ctx context.Context) (MailCodeCatalog, error) {
	products, err := m.listProducts(ctx)
	if err != nil {
		return MailCodeCatalog{}, err
	}
	wallet, err := m.request(ctx, http.MethodGet, "/wallet", nil, nil, "")
	if err != nil {
		return MailCodeCatalog{}, err
	}
	var out any
	if json.Unmarshal(wallet, &out) != nil {
		out = json.RawMessage(wallet)
	}
	return MailCodeCatalog{Products: products, Wallet: out}, nil
}

func (m *MailCode) prepare(ctx context.Context, acc *mailCodeAccount) error {
	deadline := time.Now().Add(time.Duration(max(1, m.config().MailCodeChannelWaitSeconds)) * time.Second)
	for {
		data, err := m.request(ctx, http.MethodGet,
			"/mailboxes/"+url.PathEscape(acc.MailboxID)+"/codes", nil, url.Values{"limit": {"100"}}, "")
		if err != nil {
			var mcErr *MailCodeError
			if !errors.As(err, &mcErr) || !mcErr.retryable() {
				return err
			}
			if time.Now().After(deadline) {
				return &MailCodeError{Message: "MailCode 取码通道初始化超时；已购邮箱保留，下次领取继续初始化"}
			}
			if err := sleepContext(ctx, retryDelay(mcErr.RetryAfter)); err != nil {
				return err
			}
			continue
		}
		var page mailCodeCodes
		if json.Unmarshal(data, &page) != nil || page.Records == nil {
			return &MailCodeError{Message: "MailCode 初始化响应缺少 records 数组"}
		}
		next := rawSequence(page.NextSequence)
		if next == "" {
			next = acc.NextSequence
		}
		if err := validateSequence(next); err != nil {
			return err
		}
		acc.NextSequence = next
		switch page.ChannelStatus {
		case "READY":
			return nil
		case "PAUSED", "CLOSED":
			return &MailCodeError{Message: "MailCode 通道不可用：" + page.ChannelStatus}
		}
		if time.Now().After(deadline) {
			return &MailCodeError{Message: "MailCode 取码通道初始化超时；已购邮箱保留，下次领取继续初始化"}
		}
		if err := sleepContext(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

func (m *MailCode) listProducts(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	for offset := 0; ; offset += 100 {
		data, err := m.request(ctx, http.MethodGet, "/products", nil,
			url.Values{"offset": {strconv.Itoa(offset)}, "limit": {"100"}}, "")
		if err != nil {
			return nil, err
		}
		var rows []map[string]any
		if err := json.Unmarshal(data, &rows); err != nil {
			return nil, &MailCodeError{Message: "MailCode 商品列表结构无效"}
		}
		out = append(out, rows...)
		if len(rows) < 100 {
			return out, nil
		}
	}
}

func (m *MailCode) request(ctx context.Context, method, path string, body any, params url.Values, idempotencyKey string) (json.RawMessage, error) {
	cfg := m.config()
	key := strings.TrimSpace(cfg.MailCodeAPIKey)
	if key == "" {
		return nil, &MailCodeError{Message: "MailCode API Key 未配置"}
	}
	timeout := time.Duration(max(1, cfg.MailCodeRequestTimeout)) * time.Second
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, &MailCodeError{Message: "MailCode 请求体编码失败"}
		}
		reader = bytes.NewReader(raw)
	}
	u := m.base + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(reqCtx, method, u, reader)
	if err != nil {
		return nil, &MailCodeError{Message: "MailCode 请求构造失败"}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, &MailCodeError{Message: "MailCode 网络请求失败"}
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, mailCodeHTTPLimit))
	if readErr != nil {
		return nil, &MailCodeError{Message: "MailCode 响应读取失败", Status: resp.StatusCode}
	}
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	var envelope struct {
		Data      json.RawMessage `json:"data"`
		Error     any             `json:"error"`
		RequestID string          `json:"request_id"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, &MailCodeError{Message: fmt.Sprintf("MailCode 响应不是 JSON，HTTP %d", resp.StatusCode), Status: resp.StatusCode, RetryAfter: retryAfter}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || envelope.Error != nil {
		code, message := parseMailCodeError(envelope.Error)
		safeMessage := fmt.Sprintf("MailCode HTTP %d", resp.StatusCode)
		if code != "" {
			safeMessage += " " + code
		}
		if message != "" {
			safeMessage += ": " + message
		}
		if envelope.RequestID != "" {
			safeMessage += "; request_id=" + envelope.RequestID
		}
		return nil, &MailCodeError{Message: safeMessage, Status: resp.StatusCode, Code: code, RetryAfter: retryAfter}
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, &MailCodeError{Message: "MailCode 响应缺少 data", Status: resp.StatusCode}
	}
	return envelope.Data, nil
}

func decodeMailCodeOrder(raw json.RawMessage) (mailCodeOrderItem, string, error) {
	var order mailCodeOrder
	if err := json.Unmarshal(raw, &order); err != nil {
		return mailCodeOrderItem{}, "", &MailCodeError{Message: "MailCode 购买响应结构无效；保留原幂等键，勿重新下单"}
	}
	if order.Status != "COMPLETED" || len(order.Items) != 1 {
		return mailCodeOrderItem{}, "", &MailCodeError{Message: "MailCode 购买响应结构无效；保留原幂等键，勿重新下单"}
	}
	item := order.Items[0]
	if strings.TrimSpace(item.MailboxID) == "" || !strings.Contains(item.Email, "@") || item.Status != "ACTIVE" {
		return mailCodeOrderItem{}, "", &MailCodeError{Message: "MailCode 购买响应缺少有效邮箱，保留原幂等键"}
	}
	return item, order.OrderID, nil
}

func (e *MailCodeError) retryable() bool {
	return e.Status == 0 || e.Status == http.StatusTooManyRequests || e.Status >= 500
}

func (m *MailCode) purchasePath(key, product string) string {
	return filepath.Join(m.stateDir, "purchases", mailCodeHash(m.base, key, product)+".json")
}

func (m *MailCode) contextPath(key, email string) string {
	return filepath.Join(m.stateDir, "contexts", mailCodeHash(m.base, key, strings.ToLower(strings.TrimSpace(email)))+".json")
}

func (m *MailCode) accountContext(box domain.Mailbox) (*mailCodeAccount, error) {
	email := strings.ToLower(strings.TrimSpace(box.Email))
	if email == "" {
		return nil, &MailCodeError{Message: "MailCode 邮箱为空"}
	}
	m.contextMu.Lock()
	if acc := m.contexts[email]; acc != nil {
		copy := *acc
		m.contextMu.Unlock()
		return &copy, nil
	}
	m.contextMu.Unlock()

	acc := &mailCodeAccount{Email: strings.TrimSpace(box.Email), MailboxID: box.Credential["mailbox_id"], NextSequence: "0"}
	if err := loadJSONFile(m.contextPath(strings.TrimSpace(m.config().MailCodeAPIKey), email), acc); err != nil {
		return nil, fmt.Errorf("读取 MailCode 取码上下文失败: %w", err)
	}
	if acc.MailboxID == "" {
		return nil, &MailCodeError{Message: "MailCode 取码上下文缺少 mailbox_id"}
	}
	if acc.NextSequence == "" {
		acc.NextSequence = "0"
	}
	m.remember(acc)
	return acc, nil
}

func (m *MailCode) remember(acc *mailCodeAccount) {
	if acc == nil {
		return
	}
	copy := *acc
	m.contextMu.Lock()
	m.contexts[strings.ToLower(strings.TrimSpace(acc.Email))] = &copy
	m.contextMu.Unlock()
}

func (m *MailCode) accountLock(email string) *sync.Mutex {
	email = strings.ToLower(strings.TrimSpace(email))
	m.contextMu.Lock()
	defer m.contextMu.Unlock()
	lock := m.locks[email]
	if lock == nil {
		lock = &sync.Mutex{}
		m.locks[email] = lock
	}
	return lock
}

func mailCodeHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func rawSequence(value json.RawMessage) string {
	s := strings.TrimSpace(string(value))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var out string
		if json.Unmarshal(value, &out) == nil {
			return strings.TrimSpace(out)
		}
	}
	return s
}

func validateSequence(value string) error {
	if value == "" || !digitsOnly(value) {
		return &MailCodeError{Message: "MailCode 返回了无效 next_sequence"}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > 9000000000000000000 {
		return &MailCodeError{Message: "MailCode 返回了无效 next_sequence"}
	}
	return nil
}

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseMailCodeError(v any) (string, string) {
	obj, _ := v.(map[string]any)
	code, _ := obj["code"].(string)
	message, _ := obj["message"].(string)
	return strings.TrimSpace(code), strings.TrimSpace(message)
}

func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

func retryDelay(value time.Duration) time.Duration {
	if value < time.Second {
		return time.Second
	}
	return value
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
