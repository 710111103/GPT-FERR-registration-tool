package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/store"
)

func TestPaymentProfileValueCompatibility(t *testing.T) {
	profile := map[string]any{"name": "Test User", "country": "BR"}
	tests := []struct {
		name  string
		value any
		want  any
	}{
		{name: "JSON string", value: `{"name":"Test User","country":"BR"}`, want: profile},
		{name: "object", value: profile, want: profile},
		{name: "profile wrapper", value: map[string]any{"profile": profile}, want: profile},
		{name: "nested JSON string wrapper", value: `{"profile":{"name":"Test User","country":"BR"}}`, want: profile},
		{name: "empty string", value: "  ", want: nil},
		{name: "invalid string", value: `{"name":`, want: nil},
		{name: "multi-key object", value: map[string]any{"profile": profile, "extra": true}, want: map[string]any{"profile": profile, "extra": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paymentProfileValue(tt.value); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("paymentProfileValue() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDomainPoolHandlersAreSourceIsolated(t *testing.T) {
	st := openAPITestStore(t)
	ctx := context.Background()
	_, _, err := st.ImportEmails(ctx, []store.EmailItem{
		{Email: "pool@example.test", Source: domainPoolSource, Status: "available"},
		{Email: "pool@example.test", Source: "generic_api", Status: "available"},
		{Email: "other@example.test", Source: domainPoolSource, Status: "failed"},
	})
	if err != nil {
		t.Fatalf("导入域名池测试数据失败: %v", err)
	}
	s := &Server{store: st}

	getReq := httptest.NewRequest(http.MethodGet, "/api/domain-pool?status=available", nil)
	getRec := httptest.NewRecorder()
	s.handleDomainPool(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("查询状态码 = %d, body=%s", getRec.Code, getRec.Body.String())
	}
	var items []store.EmailItem
	if err := json.Unmarshal(getRec.Body.Bytes(), &items); err != nil {
		t.Fatalf("解析域名池响应失败: %v", err)
	}
	if len(items) != 1 || items[0].Email != "pool@example.test" || items[0].Source != domainPoolSource {
		t.Fatalf("域名池来源隔离失败: %#v", items)
	}

	statusReq := httptest.NewRequest(http.MethodPost, "/api/domain-pool/status", strings.NewReader(
		`{"email":"pool@example.test","status":"used","note":"manual"}`))
	statusRec := httptest.NewRecorder()
	s.handleDomainPoolStatus(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("更新状态码 = %d, body=%s", statusRec.Code, statusRec.Body.String())
	}
	cfItems, _, err := st.ListEmails(ctx, domainPoolSource, "", "pool@example.test", 1, 10)
	if err != nil || len(cfItems) != 1 || cfItems[0].Status != "used" {
		t.Fatalf("域名池状态未更新: items=%#v err=%v", cfItems, err)
	}
	genericItems, _, err := st.ListEmails(ctx, "generic_api", "", "pool@example.test", 1, 10)
	if err != nil || len(genericItems) != 1 || genericItems[0].Status != "available" {
		t.Fatalf("更新域名池时污染了其他来源: items=%#v err=%v", genericItems, err)
	}

	invalidReq := httptest.NewRequest(http.MethodPost, "/api/domain-pool/status", strings.NewReader(
		`{"email":"pool@example.test","status":"disabled"}`))
	invalidRec := httptest.NewRecorder()
	s.handleDomainPoolStatus(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("非法状态码 = %d, body=%s", invalidRec.Code, invalidRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/api/domain-pool/delete", strings.NewReader(
		`{"email":"pool@example.test"}`))
	deleteRec := httptest.NewRecorder()
	s.handleDomainPoolDelete(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("删除状态码 = %d, body=%s", deleteRec.Code, deleteRec.Body.String())
	}
	cfItems, _, err = st.ListEmails(ctx, domainPoolSource, "", "pool@example.test", 1, 10)
	if err != nil || len(cfItems) != 0 {
		t.Fatalf("域名池记录未删除: items=%#v err=%v", cfItems, err)
	}
	genericItems, _, err = st.ListEmails(ctx, "generic_api", "", "pool@example.test", 1, 10)
	if err != nil || len(genericItems) != 1 {
		t.Fatalf("删除域名池记录时误删其他来源: items=%#v err=%v", genericItems, err)
	}
}

type catalogTestProvider struct {
	catalog mail.MailCodeCatalog
	err     error
}

func (p *catalogTestProvider) Name() string { return string(domain.SourceMailCode) }

func (p *catalogTestProvider) Acquire(context.Context) (domain.Mailbox, error) {
	return domain.Mailbox{}, mail.ErrNoMailbox
}

func (p *catalogTestProvider) WaitCode(context.Context, domain.Mailbox, time.Time) (domain.OTPResult, error) {
	return domain.OTPResult{}, mail.ErrOTPTimeout
}

func (p *catalogTestProvider) Release(context.Context, domain.Mailbox, string) error { return nil }

func (p *catalogTestProvider) Catalog(context.Context) (mail.MailCodeCatalog, error) {
	return p.catalog, p.err
}

func TestMailCodeCatalogHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := mail.NewRegistry()
		registry.Register(&catalogTestProvider{catalog: mail.MailCodeCatalog{
			Products: []map[string]any{{"id": "product-1", "name": "Mailbox"}},
			Wallet:   map[string]any{"balance": float64(12)},
		}})
		s := &Server{mails: registry}
		req := httptest.NewRequest(http.MethodGet, "/api/mailcode/catalog", nil)
		rec := httptest.NewRecorder()
		s.handleMailCodeCatalog(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("状态码 = %d, body=%s", rec.Code, rec.Body.String())
		}
		var body struct {
			OK       bool             `json:"ok"`
			Products []map[string]any `json:"products"`
			Wallet   map[string]any   `json:"wallet"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}
		if !body.OK || len(body.Products) != 1 || body.Products[0]["id"] != "product-1" || body.Wallet["balance"] != float64(12) {
			t.Fatalf("目录响应不完整: %#v", body)
		}
	})

	t.Run("provider error", func(t *testing.T) {
		registry := mail.NewRegistry()
		registry.Register(&catalogTestProvider{err: errors.New("catalog unavailable")})
		s := &Server{mails: registry}
		req := httptest.NewRequest(http.MethodGet, "/api/mailcode/catalog", nil)
		rec := httptest.NewRecorder()
		s.handleMailCodeCatalog(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "catalog unavailable") {
			t.Fatalf("错误响应 = %s", rec.Body.String())
		}
	})
}
