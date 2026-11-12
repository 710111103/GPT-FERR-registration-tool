package genericapi

import (
	"testing"
	"time"
)

func TestExtractFromHTMLCards(t *testing.T) {
	htmlSample := `
<!DOCTYPE html>
<html><body>
<div class="card">
  <div class="dt">2026-11-07 00:10:00</div>
  <div class="bd">Your ChatGPT verification code is 654321. Do not share this.</div>
</div>
</body></html>`

	after := time.Date(2026, 11, 7, 0, 9, 0, 0, time.Local)
	code, src := ExtractOTPFromText(htmlSample, after)
	if code != "654321" {
		t.Errorf("提取错误，得到 %q (来源: %s)", code, src)
	}
}

func TestExtractNoiseFiltering(t *testing.T) {
	sample := `{"status": 200, "message": "error code 000000", "code": "918273"}`
	code, src := ExtractOTPFromText(sample, time.Time{})
	if code != "918273" {
		t.Errorf("未能过滤 000000，得到 %q (来源: %s)", code, src)
	}
}

func TestExtractRejectsUndatedCodeWhenAfterIsSet(t *testing.T) {
	sample := `{"status": 200, "code": "918273"}`
	code, src := ExtractOTPFromText(sample, time.Now().Add(-time.Minute))
	if code != "" {
		t.Fatalf("after 非零时不应返回无法确认时间的旧验证码，得到 %q (来源: %s)", code, src)
	}
}

func TestExtractDoesNotFallBackToOldJSONCode(t *testing.T) {
	sample := `{
  "messages": [{"date": "2026-11-11 22:00:00", "code": "654321"}],
  "code": "918273"
}`
	after := time.Date(2026, 11, 11, 23, 36, 21, 0, time.Local)
	code, src := ExtractOTPFromText(sample, after)
	if code != "" {
		t.Fatalf("旧日期候选被过滤后不应回退到无日期 code，得到 %q (来源: %s)", code, src)
	}
}

func TestExtractFreshDatedCodeWithNaiveLocalTime(t *testing.T) {
	sample := `{"messages": [{"receivedAt": "2026-11-11 23:36:22", "code": "246810"}]}`
	after := time.Date(2026, 11, 11, 23, 36, 21, 0, time.Local)
	code, src := ExtractOTPFromText(sample, after)
	if code != "246810" {
		t.Fatalf("应提取本次请求后的新验证码，得到 %q (来源: %s)", code, src)
	}
}

func TestParseTimeFlexUsesLocalTimezoneForNaiveTimestamp(t *testing.T) {
	got := parseTimeFlex("2026-11-11 23:36:22")
	if got.IsZero() {
		t.Fatal("无时区时间未解析")
	}
	if got.Location() != time.Local {
		t.Fatalf("无时区时间应按本地时区解析，得到 %s", got.Location())
	}
	if got.Hour() != 23 || got.Minute() != 36 {
		t.Fatalf("时间被时区偏移改写: %s", got.Format(time.RFC3339))
	}
}
