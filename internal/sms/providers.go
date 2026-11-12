package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var smsCodeRegex = regexp.MustCompile(`\b(\d{6})\b`)

// -----------------------------------------------------------------------------
// GrizzlySMS
// -----------------------------------------------------------------------------

type GrizzlyProvider struct {
	APIBase string
	APIKey  string
	Client  *http.Client
}

func NewGrizzly(apiKey string) *GrizzlyProvider {
	return &GrizzlyProvider{
		APIBase: "https://api.grizzlysms.com/stubs/handler_api.php",
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (g *GrizzlyProvider) Name() string { return "grizzly" }

func (g *GrizzlyProvider) req(ctx context.Context, params url.Values) (string, error) {
	params.Set("api_key", g.APIKey)
	reqURL := g.APIBase + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(b))
	switch text {
	case "NO_NUMBERS":
		return "", ErrNoNumbers
	case "NO_BALANCE":
		return "", ErrNoBalance
	case "BAD_KEY":
		return "", fmt.Errorf("Grizzly API Key 无效")
	}
	return text, nil
}

func (g *GrizzlyProvider) AcquireNumber(ctx context.Context, service, country string) (string, string, error) {
	if service == "" {
		service = "openai"
	}
	p := url.Values{}
	p.Set("action", "getNumber")
	p.Set("service", service)
	if country != "" {
		p.Set("country", country)
	}
	text, err := g.req(ctx, p)
	if err != nil {
		return "", "", err
	}
	// 返回格式：ACCESS_NUMBER:$id:$number
	parts := strings.Split(text, ":")
	if len(parts) >= 3 && parts[0] == "ACCESS_NUMBER" {
		return parts[1], strings.TrimPrefix(parts[2], "+"), nil
	}
	return "", "", fmt.Errorf("Grizzly 取号返回异常: %s", text)
}

func (g *GrizzlyProvider) WaitSMSCode(ctx context.Context, activationID string, timeout, pollInterval time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		p := url.Values{}
		p.Set("action", "getStatus")
		p.Set("id", activationID)
		text, err := g.req(ctx, p)
		if err == nil {
			// 返回格式：STATUS_OK:$code
			if strings.HasPrefix(text, "STATUS_OK") {
				parts := strings.Split(text, ":")
				if len(parts) >= 2 {
					return parts[1], nil
				}
			}
			if text == "STATUS_CANCEL" {
				return "", fmt.Errorf("号码已被平台取消")
			}
		}
		if time.Now().After(deadline) {
			return "", ErrTimeout
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (g *GrizzlyProvider) Cancel(ctx context.Context, activationID string) error {
	p := url.Values{}
	p.Set("action", "setStatus")
	p.Set("status", "8") // 8 = 取消
	p.Set("id", activationID)
	_, err := g.req(ctx, p)
	return err
}

func (g *GrizzlyProvider) Complete(ctx context.Context, activationID string) error {
	p := url.Values{}
	p.Set("action", "setStatus")
	p.Set("status", "6") // 6 = 完成
	p.Set("id", activationID)
	_, err := g.req(ctx, p)
	return err
}

// -----------------------------------------------------------------------------
// 5sim.net
// -----------------------------------------------------------------------------

type FiveSimProvider struct {
	APIBase string
	Token   string
	Client  *http.Client
}

func NewFiveSim(token string) *FiveSimProvider {
	return &FiveSimProvider{
		APIBase: "https://5sim.net/v1/user",
		Token:   token,
		Client:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (f *FiveSimProvider) Name() string { return "5sim" }

func (f *FiveSimProvider) req(ctx context.Context, method, path string, dst any) error {
	reqURL := f.APIBase + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(string(b))
		if strings.Contains(msg, "no free phones") {
			return ErrNoNumbers
		}
		if strings.Contains(msg, "not enough user balance") {
			return ErrNoBalance
		}
		return fmt.Errorf("5sim HTTP %d: %s", resp.StatusCode, msg)
	}
	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func (f *FiveSimProvider) AcquireNumber(ctx context.Context, service, country string) (string, string, error) {
	if service == "" {
		service = "openai"
	}
	if country == "" {
		country = "any"
	}
	path := fmt.Sprintf("/buy/activation/%s/any/%s", country, service)
	var order struct {
		ID    int64  `json:"id"`
		Phone string `json:"phone"`
	}
	if err := f.req(ctx, http.MethodGet, path, &order); err != nil {
		return "", "", err
	}
	return fmt.Sprint(order.ID), strings.TrimPrefix(order.Phone, "+"), nil
}

func (f *FiveSimProvider) WaitSMSCode(ctx context.Context, activationID string, timeout, pollInterval time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var order struct {
			Status string `json:"status"`
			SMS    []struct {
				Code string `json:"code"`
				Text string `json:"text"`
			} `json:"sms"`
		}
		if err := f.req(ctx, http.MethodGet, "/check/"+activationID, &order); err == nil {
			if len(order.SMS) > 0 {
				last := order.SMS[len(order.SMS)-1]
				if last.Code != "" {
					return last.Code, nil
				}
				if m := smsCodeRegex.FindStringSubmatch(last.Text); len(m) >= 2 {
					return m[1], nil
				}
			}
			if order.Status == "CANCELED" || order.Status == "TIMEOUT" {
				return "", fmt.Errorf("5sim 订单已失效: %s", order.Status)
			}
		}
		if time.Now().After(deadline) {
			return "", ErrTimeout
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (f *FiveSimProvider) Cancel(ctx context.Context, activationID string) error {
	return f.req(ctx, http.MethodGet, "/cancel/"+activationID, nil)
}

func (f *FiveSimProvider) Complete(ctx context.Context, activationID string) error {
	return f.req(ctx, http.MethodGet, "/finish/"+activationID, nil)
}

// -----------------------------------------------------------------------------
// 本地 L / H 取号接口
// -----------------------------------------------------------------------------

type LocalAdminProvider struct {
	name       string
	apiBase    string
	authCode   string
	pathPrefix string
	client     *http.Client
}

func NewLocalL(apiBase, authCode string) *LocalAdminProvider {
	return &LocalAdminProvider{
		name:       "l",
		apiBase:    strings.TrimRight(apiBase, "/"),
		authCode:   authCode,
		pathPrefix: "/api/admin/l",
		client:     &http.Client{Timeout: 20 * time.Second},
	}
}

func NewLocalH(apiBase, authCode string) *LocalAdminProvider {
	return &LocalAdminProvider{
		name:       "h",
		apiBase:    strings.TrimRight(apiBase, "/"),
		authCode:   authCode,
		pathPrefix: "/api/admin/h",
		client:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (l *LocalAdminProvider) Name() string { return l.name }

func (l *LocalAdminProvider) postJSON(ctx context.Context, action string, payload any, dst any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := l.apiBase + l.pathPrefix + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+l.authCode)
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s HTTP %d: %s", l.name, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func (l *LocalAdminProvider) AcquireNumber(ctx context.Context, service, country string) (string, string, error) {
	var resp struct {
		OK    bool   `json:"ok"`
		ID    any    `json:"id"`
		Phone string `json:"phone"`
		Error string `json:"error"`
	}
	body := map[string]string{"service": service, "country": country}
	if err := l.postJSON(ctx, "/acquire", body, &resp); err != nil {
		return "", "", err
	}
	if !resp.OK {
		return "", "", fmt.Errorf("%s 取号失败: %s", l.name, resp.Error)
	}
	return fmt.Sprint(resp.ID), strings.TrimPrefix(resp.Phone, "+"), nil
}

func (l *LocalAdminProvider) WaitSMSCode(ctx context.Context, activationID string, timeout, pollInterval time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var resp struct {
			OK    bool   `json:"ok"`
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		if err := l.postJSON(ctx, "/status", map[string]string{"id": activationID}, &resp); err == nil {
			if resp.OK && resp.Code != "" {
				return resp.Code, nil
			}
		}
		if time.Now().After(deadline) {
			return "", ErrTimeout
		}
		select {
		case <-time.After(pollInterval):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func (l *LocalAdminProvider) Cancel(ctx context.Context, activationID string) error {
	return l.postJSON(ctx, "/release", map[string]string{"id": activationID}, nil)
}

func (l *LocalAdminProvider) Complete(ctx context.Context, activationID string) error {
	return nil // 本地接口自动完成
}
