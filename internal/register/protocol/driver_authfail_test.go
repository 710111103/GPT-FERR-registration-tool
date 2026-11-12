package protocol

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func errURL(payload string) string {
	return "https://auth.openai.com/error?payload=" + base64.StdEncoding.EncodeToString([]byte(payload))
}

func TestDetectAccountUnusable(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantNil bool
		want    string
	}{
		{"deactivated", errURL(`{"errorCode":"account_deactivated","kind":"AccountDeactivated","requestId":"9d7ae95b-1660-4692-9a84-aa36b352515c"}`), false, "account_deactivated"},
		{"deleted", errURL(`{"errorCode":"account_deleted"}`), false, "account_deleted"},
		{"banned", errURL(`{"errorCode":"account_banned"}`), false, "account_banned"},
		{"suspended", errURL(`{"errorCode":"account_suspended"}`), false, "account_suspended"},
		{"email changed", errURL(`{"errorCode":"email_address_changed"}`), false, "email_address_changed"},
		{"kind only", errURL(`{"kind":"account_deactivated"}`), false, "account_deactivated"},
		{"bad password", errURL(`{"errorCode":"invalid_username_or_password"}`), true, ""},
		{"plain url", "https://chatgpt.com/", true, ""},
		{"empty", "", true, ""},
	}
	for _, c := range cases {
		got := detectAccountUnusable(c.raw)
		if c.wantNil {
			if got != nil {
				t.Fatalf("%s: 期望 nil，得到 %v", c.name, got)
			}
			continue
		}
		if got == nil {
			t.Fatalf("%s: 期望 %s，得到 nil", c.name, c.want)
		}
		if got.Code != c.want {
			t.Fatalf("%s: 期望 code=%s，得到 %s", c.name, c.want, got.Code)
		}
		if !errors.Is(got, ErrAccountUnusable) {
			t.Fatalf("%s: errors.Is 未命中 ErrAccountUnusable", c.name)
		}
	}
}

func TestIsAuthErrorURL(t *testing.T) {
	yes := []string{
		"https://auth.openai.com/error?payload=abc",
		"https://auth.openai.com/error",
		"https://auth.openai.com/error/foo",
		"https://x.test/cb?error=access_denied",
	}
	for _, u := range yes {
		if !isAuthErrorURL(u) {
			t.Fatalf("应判为错误页: %s", u)
		}
	}
	no := []string{
		"https://chatgpt.com/",
		"https://auth.openai.com/about-you",
		"https://auth.openai.com/api/accounts/authorize/continue",
		"",
	}
	for _, u := range no {
		if isAuthErrorURL(u) {
			t.Fatalf("不应判为错误页: %s", u)
		}
	}
}

func TestDecodeAuthErrorRequestID(t *testing.T) {
	raw := errURL(`{"errorCode":"account_deactivated","kind":"AccountDeactivated","requestId":"9d7ae95b-1660-4692-9a84-aa36b352515c","message":"Your account has been deactivated."}`)
	info := decodeAuthError(raw)
	if info.Code != "account_deactivated" {
		t.Fatalf("code 解析错: %q", info.Code)
	}
	if info.RequestID != "9d7ae95b-1660-4692-9a84-aa36b352515c" {
		t.Fatalf("requestId 解析错: %q", info.RequestID)
	}
	if info.Kind != "AccountDeactivated" {
		t.Fatalf("kind 解析错: %q", info.Kind)
	}
}

func TestDetectOTPRejected(t *testing.T) {
	raw := errURL(`{"errorCode":"wrong_email_otp_code","kind":"AuthApiFailure","requestId":"otp-request-1"}`)
	got := detectOTPRejected(raw)
	if got == nil {
		t.Fatal("wrong_email_otp_code 应识别为验证码拒绝")
	}
	if got.Code != "wrong_email_otp_code" || got.RequestID != "otp-request-1" {
		t.Fatalf("错误字段解析不正确: %+v", got)
	}
	if !errors.Is(got, ErrOTPRejected) {
		t.Fatal("errors.Is 未命中 ErrOTPRejected")
	}

	other := errURL(`{"errorCode":"invalid_username_or_password"}`)
	if got := detectOTPRejected(other); got != nil {
		t.Fatalf("普通登录错误不应识别为验证码拒绝: %+v", got)
	}
}

func TestFollowOAuthCallbackReturnsOTPRejected(t *testing.T) {
	rejectedURL := errURL(`{"errorCode":"wrong_email_otp_code","kind":"AuthApiFailure","requestId":"otp-request-2"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, rejectedURL, http.StatusFound)
	}))
	defer server.Close()

	sess, err := NewSession(SessionOptions{})
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	driver := &Driver{}
	err = driver.followOAuthCallback(context.Background(), sess, server.URL)
	if !errors.Is(err, ErrOTPRejected) {
		t.Fatalf("OAuth 回调应返回可识别的验证码拒绝，实际: %v", err)
	}
	var rejected *OTPRejectedError
	if !errors.As(err, &rejected) || rejected.Code != "wrong_email_otp_code" {
		t.Fatalf("未返回结构化验证码拒绝: %#v", err)
	}
}
