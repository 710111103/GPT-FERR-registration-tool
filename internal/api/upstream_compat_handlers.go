package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/turb/gpt-register/internal/domain"
	"github.com/turb/gpt-register/internal/mail"
	"github.com/turb/gpt-register/internal/store"
)

const domainPoolSource = "cloudflare_domain"

// handleAccountPaymentDetail returns the most recent detailed payment probe.
// The list endpoint intentionally remains lightweight; this endpoint is loaded
// only when the operator expands one account.
func (s *Server) handleAccountPaymentDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取账号失败")
		return
	}
	if acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}

	payload := acc.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	endpointStatus := payload["payment_endpoint_status"]
	if endpointStatus == nil {
		endpointStatus = map[string]any{}
	}
	endpointUnavailable := payload["payment_endpoint_unavailable"]
	if endpointUnavailable == nil {
		endpointUnavailable = []any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                           true,
		"id":                           acc.ID,
		"email":                        acc.Email,
		"payment_check_status":         stringValue(payload["payment_check_status"]),
		"payment_check_error":          stringValue(payload["payment_check_error"]),
		"payment_checked_at":           stringValue(payload["payment_checked_at"]),
		"payment_methods_text":         stringValue(payload["payment_methods_text"]),
		"payment_endpoint_status":      endpointStatus,
		"payment_endpoint_unavailable": endpointUnavailable,
		"has_customer_object":          boolValue(payload["has_customer_object"]),
		"processor_entity":             payload["processor_entity"],
		"has_transaction_history":      boolValue(payload["has_transaction_history"]),
		"payment_portal_url":           stringValue(payload["payment_portal_url"]),
		"profile":                      paymentProfileValue(payload["payment_profile_json"]),
	})
}

// paymentProfileValue accepts both the legacy JSON string and the newer object
// representation. A one-key {"profile": ...} wrapper is unwrapped for clients.
func paymentProfileValue(value any) any {
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil
		}
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			return paymentProfileValue(decoded)
		}
		return nil
	}
	if object, ok := value.(map[string]any); ok && len(object) == 1 {
		if profile, exists := object["profile"]; exists {
			return profile
		}
	}
	return value
}

func (s *Server) handleExtractLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountID int64  `json:"account_id"`
		ID        int64  `json:"id"`
		LinkType  string `json:"link_type"`
		CDK       string `json:"cdk"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	id := body.AccountID
	if id == 0 {
		id = body.ID
	}
	acc, err := s.store.GetAccount(r.Context(), id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取账号失败")
		return
	}
	if acc == nil {
		fail(w, http.StatusNotFound, "账号不存在")
		return
	}
	eligible, reason := extractLinkEligible(acc)
	if !eligible {
		fail(w, http.StatusBadRequest, reason)
		return
	}
	token := strings.TrimSpace(stringValue(acc.Payload["access_token"]))
	result, err := s.extract.enqueue(r.Context(), extractLinkTask{
		AccountID: acc.ID,
		Email:     acc.Email,
		Token:     token,
		LinkType:  body.LinkType,
		CDK:       body.CDK,
		Trigger:   "manual",
	})
	if err != nil {
		fail(w, http.StatusBadRequest, safeExtractError(err.Error(), body.CDK, token))
		return
	}
	if result.Busy {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok": false, "busy": true, "accepted": false,
			"error": result.Error, "link_type": result.LinkType,
		})
		return
	}
	if !result.Accepted {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "busy": false, "accepted": false,
			"error": result.Error, "link_type": result.LinkType,
		})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "started": true, "accepted": true,
		"link_type": result.LinkType,
	})
}

func (s *Server) handleExtractLinkBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any  `json:"account_ids"`
		IDs        []any  `json:"ids"`
		LinkType   string `json:"link_type"`
		CDK        string `json:"cdk"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.AccountIDs
	if len(ids) == 0 {
		ids = body.IDs
	}
	if len(ids) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(ids) > extractLinkMaxBatch {
		fail(w, http.StatusBadRequest, "单次最多提链 500 个账号")
		return
	}

	started := make([]map[string]any, 0)
	busy := make([]map[string]any, 0)
	failed := make([]map[string]any, 0)
	skipped := make([]map[string]any, 0)
	seen := make(map[int64]struct{}, len(ids))
	for _, raw := range ids {
		id, ok := accountIDValue(raw)
		if !ok {
			skipped = append(skipped, map[string]any{"id": raw, "reason": "ID 非法"})
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}

		acc, err := s.store.GetAccount(r.Context(), id)
		if err != nil {
			failed = append(failed, map[string]any{"id": id, "error": "读取账号失败"})
			continue
		}
		if acc == nil {
			skipped = append(skipped, map[string]any{"id": id, "reason": "账号不存在"})
			continue
		}
		eligible, _ := extractLinkEligible(acc)
		if !eligible {
			skipped = append(skipped, map[string]any{
				"id": id, "email": acc.Email, "reason": "不是 free(可Plus试用)",
			})
			continue
		}
		token := strings.TrimSpace(stringValue(acc.Payload["access_token"]))
		if token == "" {
			skipped = append(skipped, map[string]any{
				"id": id, "email": acc.Email, "reason": "缺少 access_token",
			})
			continue
		}
		result, err := s.extract.enqueue(r.Context(), extractLinkTask{
			AccountID: acc.ID,
			Email:     acc.Email,
			Token:     token,
			LinkType:  body.LinkType,
			CDK:       body.CDK,
			Trigger:   "manual_bulk",
		})
		item := map[string]any{
			"id": id, "email": acc.Email, "accepted": result.Accepted,
			"busy": result.Busy, "link_type": result.LinkType,
		}
		if result.Error != "" {
			item["error"] = safeExtractError(result.Error, body.CDK, token)
		}
		switch {
		case err != nil:
			item["error"] = safeExtractError(err.Error(), body.CDK, token)
			failed = append(failed, item)
		case result.Accepted:
			started = append(started, item)
		case result.Busy:
			busy = append(busy, item)
		default:
			failed = append(failed, item)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"started": started, "started_count": len(started),
		"busy": busy, "busy_count": len(busy),
		"failed": failed, "failed_count": len(failed),
		"skipped": skipped, "skipped_count": len(skipped),
	})
}

func accountIDValue(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		id := int64(v)
		return id, id > 0 && float64(id) == v
	case json.Number:
		id, err := v.Int64()
		return id, err == nil && id > 0
	case string:
		id, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return id, err == nil && id > 0
	default:
		return 0, false
	}
}

func (s *Server) handleExtractLinkCDK(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	secrets := []string{code}
	if s.extract != nil {
		if cfg := s.extract.cfg(); cfg != nil {
			if resolved, resolveErr := resolveExtractCDK(code, cfg); resolveErr == nil {
				secrets = append(secrets, resolved)
			}
		}
	}
	data, err := s.extract.queryCDK(r.Context(), code)
	if err != nil {
		fail(w, http.StatusBadRequest, safeExtractError(err.Error(), secrets...))
		return
	}
	response := make(map[string]any, len(data)+1)
	for key, value := range data {
		response[key] = value
	}
	response["ok"] = true
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleMailCodeCatalog(w http.ResponseWriter, r *http.Request) {
	if s.mails == nil {
		fail(w, http.StatusBadRequest, "MailCode 邮箱来源未注册")
		return
	}
	provider, ok := s.mails.Get(string(domain.SourceMailCode))
	if !ok {
		fail(w, http.StatusBadRequest, "MailCode 邮箱来源未注册")
		return
	}
	mailCode, ok := provider.(interface {
		Catalog(context.Context) (mail.MailCodeCatalog, error)
	})
	if !ok {
		fail(w, http.StatusBadRequest, "MailCode 邮箱来源类型不支持商品查询")
		return
	}
	catalog, err := mailCode.Catalog(r.Context())
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "products": catalog.Products, "wallet": catalog.Wallet,
	})
}

func (s *Server) handleDomainPool(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	status := strings.ToLower(strings.TrimSpace(query.Get("status")))
	if status != "" && !validDomainPoolStatus(status) {
		fail(w, http.StatusBadRequest, "status 非法")
		return
	}
	limit := atoiDefault(query.Get("limit"), 500)
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	items, _, err := s.store.ListEmails(r.Context(), domainPoolSource, status, "", 1, limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取域名邮箱池失败")
		return
	}
	if items == nil {
		items = []store.EmailItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleDomainPoolStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email  string `json:"email"`
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	body.Status = strings.ToLower(strings.TrimSpace(body.Status))
	if body.Email == "" || !validDomainPoolStatus(body.Status) {
		fail(w, http.StatusBadRequest, "email 或 status 非法")
		return
	}
	if err := s.store.UpdateEmailPoolStatus(r.Context(), body.Email, domainPoolSource, body.Status, body.Note); err != nil {
		fail(w, http.StatusInternalServerError, "更新域名邮箱状态失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDomainPoolDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求 JSON 无效")
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	if body.Email == "" {
		fail(w, http.StatusBadRequest, "email 为空")
		return
	}
	deleted, err := s.store.DeleteEmailPoolRecord(r.Context(), body.Email, domainPoolSource)
	if err != nil {
		fail(w, http.StatusInternalServerError, "删除域名邮箱失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

func validDomainPoolStatus(status string) bool {
	switch status {
	case "available", "used", "failed":
		return true
	default:
		return false
	}
}
