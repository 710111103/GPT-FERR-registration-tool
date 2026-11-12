package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/turb/gpt-register/internal/codex"
	"github.com/turb/gpt-register/internal/store"
)

// cxStr 安全取 payload 字符串。
func cxStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// cxInt 安全取 payload 整数。
func cxInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

// cxToken 从 payload 顶层或 tokens 子对象里取字段。
func cxToken(payload map[string]any, key string) string {
	if v := cxStr(payload, key); v != "" {
		return v
	}
	if tokens, ok := payload["tokens"].(map[string]any); ok {
		return cxStr(tokens, key)
	}
	return ""
}

var cxPlans = map[string]bool{"free": true, "plus": true, "team": true, "pro": true, "enterprise": true}

// codexRecord 把一条 SQLite 记录转成前端 renderCodex 需要的展示对象。
func codexRecord(acc store.CodexAccount) map[string]any {
	fname := acc.Filename
	payload := acc.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	withoutPrefix := fname
	if strings.HasPrefix(fname, "codex-") && strings.HasSuffix(fname, ".json") {
		withoutPrefix = fname[5 : len(fname)-5]
	}
	email := cxStr(payload, "email")
	if email == "" {
		email = withoutPrefix
	}
	plan := ""
	if idx := strings.LastIndex(withoutPrefix, "-"); idx > 0 {
		suffix := strings.ToLower(withoutPrefix[idx+1:])
		if cxPlans[suffix] {
			plan = suffix
			if cxStr(payload, "email") == "" {
				email = withoutPrefix[:idx]
			}
		}
	}
	accessToken := cxToken(payload, "access_token")
	refreshToken := cxToken(payload, "refresh_token")
	preview := accessToken
	if len(preview) > 32 {
		preview = preview[:32]
	}
	accountID := cxStr(payload, "account_id")
	if accountID == "" {
		accountID = cxStr(payload, "chatgpt_account_id")
	}
	record := map[string]any{
		"id":                   acc.ID,
		"filename":             fname,
		"path":                 "sqlite://codex_accounts/" + fname,
		"email":                email,
		"plan":                 plan,
		"account_id":           accountID,
		"type":                 cxStr(payload, "type"),
		"last_refresh":         cxStr(payload, "last_refresh"),
		"expired":              cxStr(payload, "expired"),
		"access_token_preview": preview,
		"size":                 cxInt(payload, "_size"),
		"mtime":                cxStr(payload, "_mtime"),
		"exported_at":          payload["_exported_at"],
		"exported_count":       cxInt(payload, "_exported_count"),
		"archived":             acc.Archived,
		"archived_at":          payload["_archived_at"],
		"refresh_token":        refreshToken,
		"access_token":         accessToken,
		"has_refresh_token":    refreshToken != "",
	}
	if cxStr(payload, "type") == "" {
		record["type"] = "codex"
	}
	return record
}

// handleCodexList 对应上游 GET /api/codex。
func (s *Server) handleCodexList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	archived := strings.ToLower(strings.TrimSpace(q.Get("archived")))
	if archived == "" {
		archived = "0"
	}
	dateFrom := strings.TrimSpace(q.Get("date_from"))
	dateTo := strings.TrimSpace(q.Get("date_to"))
	query := strings.TrimSpace(q.Get("q"))
	pagedFlag := strings.ToLower(strings.TrimSpace(q.Get("paged")))
	paged := pagedFlag == "1" || pagedFlag == "true" || pagedFlag == "yes"
	hasPage := q.Get("page") != ""
	hasSize := q.Get("page_size") != ""

	summary := func() map[string]any {
		total, exported, pending, err := s.store.CodexSummary(r.Context())
		if err != nil {
			total, exported, pending = 0, 0, 0
		}
		return map[string]any{"total": total, "exported": exported, "pending": pending}
	}

	if paged || hasPage || hasSize {
		page := atoiDefault(q.Get("page"), 1)
		if page < 1 {
			page = 1
		}
		limit := atoiDefault(q.Get("limit"), 500)
		if limit < 1 {
			limit = 500
		}
		pageSize := atoiDefault(q.Get("page_size"), 0)
		if pageSize <= 0 {
			pageSize = limit
		}
		if pageSize < 1 {
			pageSize = 50
		}
		if pageSize > 500 {
			pageSize = 500
		}
		items, total, err := s.store.ListCodexAccountsFiltered(r.Context(), store.CodexFilter{
			Archived: archived,
			DateFrom: dateFrom,
			DateTo:   dateTo,
			Query:    query,
			Page:     page,
			PageSize: pageSize,
		})
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		records := make([]map[string]any, 0, len(items))
		for _, it := range items {
			records = append(records, codexRecord(it))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"accounts":  records,
			"items":     records,
			"total":     total,
			"offset":    (page - 1) * pageSize,
			"limit":     pageSize,
			"page":      page,
			"page_size": pageSize,
			"summary":   summary(),
		})
		return
	}

	limit := atoiDefault(q.Get("limit"), 500)
	if limit < 1 {
		limit = 1
	}
	items, total, err := s.store.ListCodexAccountsFiltered(r.Context(), store.CodexFilter{
		Archived: archived,
		DateFrom: dateFrom,
		DateTo:   dateTo,
		Query:    query,
		Page:     1,
		PageSize: limit,
	})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	records := make([]map[string]any, 0, len(items))
	for _, it := range items {
		records = append(records, codexRecord(it))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"summary":  summary(),
		"accounts": records,
		"items":    records,
		"total":    total,
	})
}

// codexBodyFilenames 解析 {filenames:[...]}。
func codexBodyFilenames(w http.ResponseWriter, r *http.Request, limitMsg string) ([]string, bool) {
	var body struct {
		Filenames []any `json:"filenames"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return nil, false
	}
	if len(body.Filenames) == 0 {
		fail(w, http.StatusBadRequest, "filenames 必须是非空数组")
		return nil, false
	}
	if len(body.Filenames) > 1000 {
		fail(w, http.StatusBadRequest, limitMsg)
		return nil, false
	}
	out := make([]string, 0, len(body.Filenames))
	for _, item := range body.Filenames {
		if s, ok := item.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(item))
		}
	}
	return out, true
}

// codexAttachment 写附件响应头。
func codexAttachment(w http.ResponseWriter, name, mime string, payload []byte) {
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// handleCodexDownload GET /api/codex/download/{fname}
func (s *Server) handleCodexDownload(w http.ResponseWriter, r *http.Request) {
	fname := r.PathValue("fname")
	content, err := s.store.ReadCodexCredential(r.Context(), fname)
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	if _, _, err := s.store.MarkCodexExported(r.Context(), fname); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	codexAttachment(w, fname, "application/json; charset=utf-8", []byte(content))
}

// handleCodexDownloadFromCPA GET /api/codex/download-from-cpa/{fname}
func (s *Server) handleCodexDownloadFromCPA(w http.ResponseWriter, r *http.Request) {
	fname := r.PathValue("fname")
	content, err := s.store.ReadCodexCredential(r.Context(), fname)
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	var local map[string]any
	if json.Unmarshal([]byte(content), &local) != nil {
		local = map[string]any{}
	}
	email := strings.TrimSpace(cxStr(local, "email"))
	text, cpaName, _, err := codex.DownloadCodexAuthText(r.Context(), "", email, fname)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	if _, _, err := s.store.MarkCodexExported(r.Context(), fname); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	codexAttachment(w, cpaName, "application/json; charset=utf-8", []byte(text))
}

// handleCodexDownloadBulkFromCPA POST /api/codex/download-bulk-from-cpa
func (s *Server) handleCodexDownloadBulkFromCPA(w http.ResponseWriter, r *http.Request) {
	filenames, ok := codexBodyFilenames(w, r, "单次最多 1000 个")
	if !ok {
		return
	}
	type addedItem struct {
		LocalFilename string `json:"local_filename"`
		CpaFilename   string `json:"cpa_filename"`
	}
	type errorItem struct {
		Filename string `json:"filename"`
		Error    string `json:"error"`
	}
	added := make([]addedItem, 0, len(filenames))
	errorsList := make([]errorItem, 0)
	usedNames := map[string]bool{}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, fname := range filenames {
		content, err := s.store.ReadCodexCredential(r.Context(), fname)
		if err != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: err.Error()})
			continue
		}
		var local map[string]any
		if json.Unmarshal([]byte(content), &local) != nil {
			local = map[string]any{}
		}
		email := strings.TrimSpace(cxStr(local, "email"))
		text, cpaName, _, derr := codex.DownloadCodexAuthText(r.Context(), "", email, fname)
		if derr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: derr.Error()})
			continue
		}
		arcname := cpaName
		if usedNames[arcname] {
			stem, rest, found := strings.Cut(arcname, ".")
			if found {
				arcname = fmt.Sprintf("%s-%d.%s", stem, len(usedNames)+1, rest)
			} else {
				arcname = fmt.Sprintf("%s-%d", arcname, len(usedNames)+1)
			}
		}
		usedNames[arcname] = true
		fw, werr := zw.Create(arcname)
		if werr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: werr.Error()})
			continue
		}
		if _, werr := fw.Write([]byte(text)); werr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: werr.Error()})
			continue
		}
		added = append(added, addedItem{LocalFilename: fname, CpaFilename: cpaName})
		if _, _, merr := s.store.MarkCodexExported(r.Context(), fname); merr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: merr.Error()})
		}
	}

	manifest := map[string]any{
		"exported_at": time.Now().Format("2006-01-02T15:04:05"),
		"source":      "cpa",
		"count":       len(added),
		"files":       added,
		"errors":      errorsList,
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if fw, werr := zw.Create("manifest.json"); werr == nil {
		_, _ = fw.Write(append(manifestJSON, '\n'))
	}
	_ = zw.Close()

	if len(added) == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"error":  "没有成功从 CPA 下载任何凭证",
			"errors": errorsList,
		})
		return
	}
	dlName := "codex-cpa-bulk-" + time.Now().Format("20060102-150405") + ".zip"
	codexAttachment(w, dlName, "application/zip", buf.Bytes())
}

// handleCodexDownloadBulk POST /api/codex/download-bulk（本地聚合 JSON）
func (s *Server) handleCodexDownloadBulk(w http.ResponseWriter, r *http.Request) {
	filenames, ok := codexBodyFilenames(w, r, "单次最多 1000 个")
	if !ok {
		return
	}
	type bundleItem struct {
		Filename string         `json:"filename"`
		Data     map[string]any `json:"data"`
	}
	type errorItem struct {
		Filename string `json:"filename"`
		Error    string `json:"error"`
	}
	bundle := make([]bundleItem, 0, len(filenames))
	errorsList := make([]errorItem, 0)
	for _, fname := range filenames {
		content, err := s.store.ReadCodexCredential(r.Context(), fname)
		if err != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: err.Error()})
			continue
		}
		var parsed map[string]any
		if jerr := json.Unmarshal([]byte(content), &parsed); jerr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: jerr.Error()})
			continue
		}
		bundle = append(bundle, bundleItem{Filename: fname, Data: parsed})
		if _, _, merr := s.store.MarkCodexExported(r.Context(), fname); merr != nil {
			errorsList = append(errorsList, errorItem{Filename: fname, Error: merr.Error()})
		}
	}
	result := map[string]any{
		"exported_at": time.Now().Format("2006-01-02T15:04:05"),
		"count":       len(bundle),
		"credentials": bundle,
	}
	if len(errorsList) > 0 {
		result["errors"] = errorsList
	}
	out, _ := json.MarshalIndent(result, "", "  ")
	dlName := "codex-bulk-" + time.Now().Format("20060102-150405") + ".json"
	codexAttachment(w, dlName, "application/json; charset=utf-8", out)
}

// handleCodexDelete POST /api/codex/delete
func (s *Server) handleCodexDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	fname := strings.TrimSpace(body.Filename)
	if fname == "" {
		fail(w, http.StatusBadRequest, "filename 为空")
		return
	}
	deleted, err := s.store.DeleteCodex(r.Context(), fname)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !deleted {
		fail(w, http.StatusNotFound, "凭证文件不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": fname})
}

// handleCodexDeleteBulk POST /api/codex/delete-bulk
func (s *Server) handleCodexDeleteBulk(w http.ResponseWriter, r *http.Request) {
	filenames, ok := codexBodyFilenames(w, r, "单次最多删除 1000 个")
	if !ok {
		return
	}
	type skippedItem struct {
		Filename string `json:"filename"`
		Reason   string `json:"reason"`
	}
	deleted := make([]string, 0, len(filenames))
	skipped := make([]skippedItem, 0)
	seen := map[string]bool{}
	for _, raw := range filenames {
		fname := strings.TrimSpace(raw)
		if fname == "" || seen[fname] {
			continue
		}
		seen[fname] = true
		okDel, err := s.store.DeleteCodex(r.Context(), fname)
		if err != nil {
			skipped = append(skipped, skippedItem{Filename: fname, Reason: err.Error()})
			continue
		}
		if okDel {
			deleted = append(deleted, fname)
		} else {
			skipped = append(skipped, skippedItem{Filename: fname, Reason: "文件不存在"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"deleted":       deleted,
		"deleted_count": len(deleted),
		"skipped":       skipped,
	})
}

// handleCodexArchive POST /api/codex/archive
func (s *Server) handleCodexArchive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filename string `json:"filename"`
		Archived *bool  `json:"archived"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	fname := strings.TrimSpace(body.Filename)
	if fname == "" {
		fail(w, http.StatusBadRequest, "filename 必填")
		return
	}
	archived := true
	if body.Archived != nil {
		archived = *body.Archived
	}
	gotArchived, at, err := s.store.ArchiveCodex(r.Context(), fname, archived)
	if err != nil {
		acc, gerr := s.store.GetCodexAccount(r.Context(), fname)
		if gerr == nil && acc == nil {
			fail(w, http.StatusNotFound, "凭证不存在: "+fname)
			return
		}
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"filename": fname,
		"archived": gotArchived,
		"record": map[string]any{
			"archived":       gotArchived,
			"archived_at":    at,
			"exported_at":    nil,
			"exported_count": 0,
		},
	})
}

// handleCodexArchiveBulk POST /api/codex/archive-bulk
func (s *Server) handleCodexArchiveBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filenames []any `json:"filenames"`
		Archived  *bool `json:"archived"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if len(body.Filenames) == 0 {
		fail(w, http.StatusBadRequest, "filenames 必须是非空数组")
		return
	}
	if len(body.Filenames) > 1000 {
		fail(w, http.StatusBadRequest, "单次最多 1000 个")
		return
	}
	archived := true
	if body.Archived != nil {
		archived = *body.Archived
	}
	type updatedItem struct {
		Filename string `json:"filename"`
		Archived bool   `json:"archived"`
	}
	type skippedItem struct {
		Filename string `json:"filename"`
		Reason   string `json:"reason"`
	}
	updated := make([]updatedItem, 0, len(body.Filenames))
	skipped := make([]skippedItem, 0)
	seen := map[string]bool{}
	for _, raw := range body.Filenames {
		fname, _ := raw.(string)
		if fname == "" {
			skipped = append(skipped, skippedItem{Filename: fmt.Sprint(raw), Reason: "非法文件名"})
			continue
		}
		if seen[fname] {
			continue
		}
		seen[fname] = true
		acc, gerr := s.store.GetCodexAccount(r.Context(), fname)
		if gerr != nil {
			skipped = append(skipped, skippedItem{Filename: fname, Reason: gerr.Error()})
			continue
		}
		if acc == nil {
			skipped = append(skipped, skippedItem{Filename: fname, Reason: "凭证不存在"})
			continue
		}
		if _, _, aerr := s.store.ArchiveCodex(r.Context(), fname, archived); aerr != nil {
			skipped = append(skipped, skippedItem{Filename: fname, Reason: aerr.Error()})
			continue
		}
		updated = append(updated, updatedItem{Filename: fname, Archived: archived})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"updated":       updated,
		"updated_count": len(updated),
		"archived":      archived,
		"skipped":       skipped,
		"failed":        skipped,
	})
}

// handleCodexResetExport POST /api/codex/reset-export
func (s *Server) handleCodexResetExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	fname := strings.TrimSpace(body.Filename)
	if fname == "" {
		fail(w, http.StatusBadRequest, "filename 为空")
		return
	}
	if err := s.store.ResetCodexExported(r.Context(), fname); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAccountCodexAgentDownload GET /api/accounts/{id}/codex-agent/download
func (s *Server) handleAccountCodexAgentDownload(w http.ResponseWriter, r *http.Request) {
	id := atoiDefault(r.PathValue("id"), 0)
	if id <= 0 {
		fail(w, http.StatusBadRequest, "account_id 无效")
		return
	}
	content, filename, err := s.store.CodexAgentCredential(r.Context(), int64(id))
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	codexAttachment(w, filename, "application/json; charset=utf-8", []byte(content))
}

// handleAccountsCodexAgentDownloadBulk POST /api/accounts/codex-agent/download-bulk
func (s *Server) handleAccountsCodexAgentDownloadBulk(w http.ResponseWriter, r *http.Request) {
	var ids []any
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var body struct {
			AccountIDs []any `json:"account_ids"`
			IDs        []any `json:"ids"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err == nil {
			ids = body.AccountIDs
			if len(ids) == 0 {
				ids = body.IDs
			}
		}
	}
	if len(ids) == 0 {
		if err := r.ParseForm(); err != nil {
			fail(w, http.StatusBadRequest, "表单解析失败: "+err.Error())
			return
		}
		raw := strings.TrimSpace(r.FormValue("account_ids"))
		if raw == "" {
			raw = strings.TrimSpace(r.FormValue("ids"))
		}
		if raw != "" {
			var parsed []any
			if json.Unmarshal([]byte(raw), &parsed) == nil {
				ids = parsed
			} else {
				for _, part := range strings.Split(raw, ",") {
					if p := strings.TrimSpace(part); p != "" {
						ids = append(ids, p)
					}
				}
			}
		}
	}
	if len(ids) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(ids) > 1000 {
		fail(w, http.StatusBadRequest, "单次最多下载 1000 个账号")
		return
	}

	type addedItem struct {
		ID       int64  `json:"id"`
		Email    string `json:"email"`
		Filename string `json:"filename"`
	}
	type errorItem struct {
		ID    any    `json:"id"`
		Email string `json:"email,omitempty"`
		Error string `json:"error"`
	}
	added := make([]addedItem, 0, len(ids))
	errorsList := make([]errorItem, 0)
	usedNames := map[string]bool{}
	seen := map[int64]bool{}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, raw := range ids {
		var accID int64
		switch v := raw.(type) {
		case float64:
			accID = int64(v)
		case string:
			if n := atoiDefault(strings.TrimSpace(v), 0); n > 0 {
				accID = int64(n)
			}
		}
		if accID <= 0 {
			errorsList = append(errorsList, errorItem{ID: raw, Error: "ID 非法"})
			continue
		}
		if seen[accID] {
			continue
		}
		seen[accID] = true
		acc, gerr := s.store.GetAccount(r.Context(), accID)
		if gerr != nil || acc == nil {
			errorsList = append(errorsList, errorItem{ID: accID, Error: "账号不存在"})
			continue
		}
		content, filename, cerr := s.store.CodexAgentCredential(r.Context(), accID)
		if cerr != nil {
			errorsList = append(errorsList, errorItem{ID: accID, Email: acc.Email, Error: cerr.Error()})
			continue
		}
		arcname := filename
		if usedNames[arcname] {
			stem, rest, found := strings.Cut(arcname, ".")
			if found {
				arcname = fmt.Sprintf("%s-%d.%s", stem, len(usedNames)+1, rest)
			} else {
				arcname = fmt.Sprintf("%s-%d", arcname, len(usedNames)+1)
			}
		}
		usedNames[arcname] = true
		fw, werr := zw.Create(arcname)
		if werr != nil {
			errorsList = append(errorsList, errorItem{ID: accID, Email: acc.Email, Error: werr.Error()})
			continue
		}
		_, _ = fw.Write([]byte(content))
		added = append(added, addedItem{ID: accID, Email: acc.Email, Filename: arcname})
	}
	manifest := map[string]any{
		"exported_at": time.Now().Format("2006-01-02T15:04:05"),
		"source":      "accounts-codex-agent",
		"count":       len(added),
		"files":       added,
		"errors":      errorsList,
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if fw, werr := zw.Create("manifest.json"); werr == nil {
		_, _ = fw.Write(append(manifestJSON, '\n'))
	}
	_ = zw.Close()

	if len(added) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":     false,
			"error":  "没有可下载的 Codex Agent Token",
			"errors": errorsList,
		})
		return
	}
	dlName := "accounts-codex-agent-" + time.Now().Format("20060102-150405") + ".zip"
	codexAttachment(w, dlName, "application/zip", buf.Bytes())
}
