package api

// 账号导出四件套：对齐上游 webui/app.py:1995-2220 的
// POST /api/accounts/session-json/download-bulk 与 POST /api/accounts/download-cpa-bulk，
// 以及配套的 _put_prepared_download / GET /api/downloads/{id} 预置下载通道。
//
// CPA 侧复用 internal/codex 的 ListCPACodexAuthFiles / FindCPACodexAuthFile /
// DownloadCodexAuthText，评分口径与上游 _match_cpa_file 完全一致（100/80/75/70/60）。

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turb/gpt-register/internal/codex"
	"github.com/turb/gpt-register/internal/domain"
)

const (
	downloadExportMaxIDs      = 1000
	preparedDownloadTTL       = 600 * time.Second
	preparedDownloadRoutePath = "/api/downloads/"
)

// preparedDownload 是一次「先准备、后用同源 GET 取走」的二进制载荷。
type preparedDownload struct {
	name      string
	mime      string
	payload   []byte
	createdAt time.Time
}

// preparedDownloadStore 对齐上游 _put_prepared_download 的进程内 TTL 字典。
type preparedDownloadStore struct {
	mu    sync.Mutex
	items map[string]preparedDownload
	seq   int64
}

func (p *preparedDownloadStore) put(name, mime string, payload []byte) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.items == nil {
		p.items = make(map[string]preparedDownload)
	}
	p.seq++
	id := fmt.Sprintf("dl%d-%d", time.Now().UnixNano(), p.seq)
	p.items[id] = preparedDownload{name: name, mime: mime, payload: payload, createdAt: time.Now()}
	p.pruneLocked()
	return id
}

func (p *preparedDownloadStore) take(id string) (preparedDownload, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	item, ok := p.items[id]
	if !ok {
		return preparedDownload{}, false
	}
	delete(p.items, id)
	return item, true
}

func (p *preparedDownloadStore) pruneLocked() {
	cutoff := time.Now().Add(-preparedDownloadTTL)
	for k, v := range p.items {
		if v.createdAt.Before(cutoff) {
			delete(p.items, k)
		}
	}
}

// handleDownloadFetch GET /api/downloads/{id}：取走即删。
func (s *Server) handleDownloadFetch(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		fail(w, http.StatusNotFound, "下载链接已失效，请重新生成")
		return
	}
	item, ok := s.downloads.take(id)
	if !ok {
		fail(w, http.StatusNotFound, "下载链接已失效，请重新生成")
		return
	}
	codexAttachment(w, item.name, item.mime, item.payload)
}

// -----------------------------------------------------------------------------
// Session JSON 导出
// -----------------------------------------------------------------------------

var downloadSafeNameRe = regexp.MustCompile(`[^A-Za-z0-9._@+\-]+`)

// downloadAccountSessionToken 取 session_token：先 payload 顶层，再 payload.extra。
func downloadAccountSessionToken(acc *domain.Account) string {
	if acc == nil || acc.Payload == nil {
		return ""
	}
	if v, ok := acc.Payload["session_token"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if extra, ok := acc.Payload["extra"].(map[string]any); ok {
		if v, ok := extra["session_token"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// handleAccountsSessionJSONDownloadBulk 对齐上游 session-json/download-bulk：
// 必须真回 ZIP，前端 index.html:8004 直接读 blob + Content-Disposition。
func (s *Server) handleAccountsSessionJSONDownloadBulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any `json:"account_ids"`
		IDs        []any `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > downloadExportMaxIDs {
		fail(w, http.StatusBadRequest, "单次最多下载 1000 个账号")
		return
	}

	ctx := r.Context()
	seen := map[int64]bool{}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	added := make([]map[string]any, 0, len(raw))
	errorsList := make([]map[string]any, 0)

	for _, item := range raw {
		var accID int64
		switch v := item.(type) {
		case float64:
			accID = int64(v)
		case int64:
			accID = v
		case int:
			accID = int64(v)
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				errorsList = append(errorsList, map[string]any{"id": v.String(), "error": "ID 非法"})
				continue
			}
			accID = n
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				errorsList = append(errorsList, map[string]any{"id": v, "error": "ID 非法"})
				continue
			}
			accID = n
		default:
			errorsList = append(errorsList, map[string]any{"id": item, "error": "ID 非法"})
			continue
		}
		if seen[accID] {
			continue
		}
		seen[accID] = true

		acc, err := s.store.GetAccount(ctx, accID)
		if err != nil || acc == nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "error": "账号不存在"})
			continue
		}
		email := strings.TrimSpace(acc.Email)
		sessionToken := downloadAccountSessionToken(acc)
		accessToken := strings.TrimSpace(extractAccountSecret(acc, "access_token"))
		if sessionToken == "" || accessToken == "" {
			errorsList = append(errorsList, map[string]any{
				"id":    accID,
				"email": email,
				"error": "缺少 sessionToken，请先执行查活刷新AT",
			})
			continue
		}
		user := map[string]any{"email": email}
		accountBlock := map[string]any{}
		if extra, ok := acc.Payload["extra"].(map[string]any); ok {
			if v, ok := extra["user"].(map[string]any); ok && len(v) > 0 {
				user = v
			}
			if v, ok := extra["account"].(map[string]any); ok && len(v) > 0 {
				accountBlock = v
			}
		}
		payload := map[string]any{
			"user":         user,
			"account":      accountBlock,
			"accessToken":  accessToken,
			"sessionToken": sessionToken,
		}
		pretty, _ := json.MarshalIndent(payload, "", "  ")
		safeEmail := downloadSafeNameRe.ReplaceAllString(email, "_")
		if safeEmail == "" {
			safeEmail = strconv.FormatInt(accID, 10)
		}
		filename := "session-" + safeEmail + ".json"
		fw, werr := zw.Create(filename)
		if werr != nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "email": email, "error": werr.Error()})
			continue
		}
		if _, werr := fw.Write(append(pretty, '\n')); werr != nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "email": email, "error": werr.Error()})
			continue
		}
		added = append(added, map[string]any{"id": accID, "email": email, "filename": filename})
	}

	manifest := map[string]any{
		"exported_at": time.Now().Format("2006-01-02T15:04:05"),
		"count":       len(added),
		"files":       added,
		"errors":      errorsList,
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if mw, merr := zw.Create("manifest.json"); merr == nil {
		_, _ = mw.Write(append(manifestJSON, '\n'))
	}
	_ = zw.Close()

	if len(added) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":     false,
			"error":  "没有可导出的 Session JSON，请先对账号执行查活刷新AT",
			"errors": errorsList,
		})
		return
	}
	name := "session-json-" + time.Now().Format("20060102-150405") + ".zip"
	codexAttachment(w, name, "application/zip", buf.Bytes())
}

// -----------------------------------------------------------------------------
// CPA / Codex JSON 导出
// -----------------------------------------------------------------------------

// cpaLocalFilenameIndex 建立 email -> 本地 codex 文件名索引，提升 CPA 匹配命中率。
// 对齐上游 db.list_codex_accounts() 的 local_by_email 构建口径。
func (s *Server) cpaLocalFilenameIndex(ctx context.Context) map[string]string {
	out := map[string]string{}
	page := 1
	for {
		items, total, err := s.store.ListCodexAccounts(ctx, page, 500, "")
		if err != nil {
			return out
		}
		for i := range items {
			emailKey := strings.ToLower(strings.TrimSpace(items[i].Email))
			fname := strings.TrimSpace(items[i].Filename)
			if emailKey != "" && fname != "" {
				if _, exists := out[emailKey]; !exists {
					out[emailKey] = fname
				}
			}
		}
		if len(items) == 0 || int64(page*500) >= total {
			break
		}
		page++
		if page > 400 {
			break
		}
	}
	return out
}

// uniqueArchiveName 处理 ZIP 内重名，对齐上游 arcname 去重逻辑。
func uniqueArchiveName(name string, used map[string]bool) string {
	if name == "" {
		name = "codex.json"
	}
	if !used[name] {
		return name
	}
	stem, ext, hasExt := strings.Cut(name, ".")
	for i := 2; ; i++ {
		var candidate string
		if hasExt {
			candidate = fmt.Sprintf("%s-%d.%s", stem, len(used)+i, ext)
		} else {
			candidate = fmt.Sprintf("%s-%d", name, len(used)+i)
		}
		if !used[candidate] {
			return candidate
		}
	}
}

// handleAccountsDownloadCPABulk 对齐上游 download-cpa-bulk：
// 支持 prepare:true 预置下载 -> {download_url, filename, added_count, error_count}。
func (s *Server) handleAccountsDownloadCPABulk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountIDs []any `json:"account_ids"`
		IDs        []any `json:"ids"`
		Prepare    bool  `json:"prepare"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	raw := body.AccountIDs
	if len(raw) == 0 {
		raw = body.IDs
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, "account_ids 必须是非空数组")
		return
	}
	if len(raw) > downloadExportMaxIDs {
		fail(w, http.StatusBadRequest, "单次最多下载 1000 个账号")
		return
	}

	ctx := r.Context()
	if _, err := codex.ListCPACodexAuthFiles(ctx); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":    false,
			"error": "读取 CPA auth-files 失败: " + err.Error(),
		})
		return
	}
	localByEmail := s.cpaLocalFilenameIndex(ctx)

	seen := map[int64]bool{}
	added := make([]map[string]any, 0, len(raw))
	errorsList := make([]map[string]any, 0)
	usedNames := map[string]bool{}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, item := range raw {
		var accID int64
		switch v := item.(type) {
		case float64:
			accID = int64(v)
		case int64:
			accID = v
		case int:
			accID = int64(v)
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				errorsList = append(errorsList, map[string]any{"id": v.String(), "error": "ID 非法"})
				continue
			}
			accID = n
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				errorsList = append(errorsList, map[string]any{"id": v, "error": "ID 非法"})
				continue
			}
			accID = n
		default:
			errorsList = append(errorsList, map[string]any{"id": item, "error": "ID 非法"})
			continue
		}
		if seen[accID] {
			continue
		}
		seen[accID] = true

		acc, err := s.store.GetAccount(ctx, accID)
		if err != nil || acc == nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "error": "账号不存在"})
			continue
		}
		email := strings.TrimSpace(acc.Email)
		if email == "" {
			errorsList = append(errorsList, map[string]any{"id": accID, "error": "账号缺少 email"})
			continue
		}
		localFilename := localByEmail[strings.ToLower(email)]
		text, cpaName, _, derr := codex.DownloadCodexAuthText(ctx, "", email, localFilename)
		if derr != nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "email": email, "error": derr.Error()})
			continue
		}
		arcname := uniqueArchiveName(cpaName, usedNames)
		usedNames[arcname] = true
		fw, werr := zw.Create(arcname)
		if werr != nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "email": email, "error": werr.Error()})
			continue
		}
		if _, werr := fw.Write([]byte(text)); werr != nil {
			errorsList = append(errorsList, map[string]any{"id": accID, "email": email, "error": werr.Error()})
			continue
		}
		added = append(added, map[string]any{
			"id":             accID,
			"email":          email,
			"local_filename": localFilename,
			"cpa_filename":   cpaName,
		})
		if localFilename != "" {
			_, _, _ = s.store.MarkCodexExported(ctx, localFilename)
		}
	}

	manifest := map[string]any{
		"exported_at": time.Now().Format("2006-01-02T15:04:05"),
		"source":      "accounts-cpa",
		"count":       len(added),
		"files":       added,
		"errors":      errorsList,
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	if mw, merr := zw.Create("manifest.json"); merr == nil {
		_, _ = mw.Write(append(manifestJSON, '\n'))
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

	name := "accounts-cpa-bulk-" + time.Now().Format("20060102-150405") + ".zip"
	zipBytes := buf.Bytes()
	if body.Prepare {
		id := s.downloads.put(name, "application/zip", zipBytes)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"prepared":     true,
			"download_id":  id,
			"download_url": preparedDownloadRoutePath + id,
			"filename":     name,
			"added_count":  len(added),
			"error_count":  len(errorsList),
			"files":        added,
			"errors":       errorsList,
		})
		return
	}
	codexAttachment(w, name, "application/zip", zipBytes)
}
