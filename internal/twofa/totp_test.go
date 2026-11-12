package twofa

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

func TestGenerateCode(t *testing.T) {
	// 验证 RFC 6238 标准测试密钥
	secret := "JBSWY3DPEHPK3PXP"
	tm := time.Unix(1111111111, 0)
	code, err := GenerateCode(secret, tm)
	if err != nil {
		t.Fatalf("GenerateCode 报错: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code 长度应为 6，得到 %q", code)
	}

	// 验证当前时间生成 6 位纯数字
	nowCode, err := GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("当前时间生成报错: %v", err)
	}
	if len(nowCode) != 6 {
		t.Errorf("动态码格式错误: %q", nowCode)
	}
}

type recordingRequester struct {
	calls  int
	extras []map[string]string
}

func (r *recordingRequester) Request(method, rawURL string, body string, extra map[string]string) (*http.Response, error) {
	r.calls++
	r.extras = append(r.extras, extra)
	responseBody := `{"success":true}`
	if r.calls == 1 {
		responseBody = `{"secret":"JBSWY3DPEHPK3PXP","session_id":"sess-1"}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(responseBody)),
	}, nil
}

func TestSetup2FAWithLanguageUsesAccountLanguage(t *testing.T) {
	requester := &recordingRequester{}
	if _, err := Setup2FAWithLanguage(context.Background(), requester, "at-test", "did-test", "ja-JP"); err != nil {
		t.Fatalf("Setup2FAWithLanguage() error = %v", err)
	}
	if requester.calls != 2 {
		t.Fatalf("calls = %d, want 2", requester.calls)
	}
	for i, extra := range requester.extras {
		if got := extra["oai-language"]; got != "ja-JP" {
			t.Fatalf("request %d oai-language = %q, want ja-JP", i+1, got)
		}
		if got := extra["oai-device-id"]; got != "did-test" {
			t.Fatalf("request %d oai-device-id = %q, want did-test", i+1, got)
		}
	}
}
