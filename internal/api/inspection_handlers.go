package api

import (
	"net/http"
	"strconv"
	"strings"
)

// 巡检记录只读接口，语义严格对齐上游 webui/inspection_history.py。
//
// 分页上限来自上游 page_offset()：1 <= page <= 1 + (2^63-1)/20，
// 越界与非法输入统一 400 {"ok":false,"error":"page必须为有效的正整数"}，
// 这样前端不会把「参数错」误当成「没记录」。

const inspectionPageSize = 20

// inspectionPageOffset 解析 page 并换算成 offset。
func inspectionPageOffset(r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("page"))
	if raw == "" {
		// 上游 request.args.get("page","1") 在缺省时给 1；显式空串会被 int() 拒绝。
		if _, present := r.URL.Query()["page"]; !present {
			return 0, true
		}
		return 0, false
	}
	page, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	const maxPage = 1 + (1<<63-1)/inspectionPageSize
	if page < 1 || page > maxPage {
		return 0, false
	}
	return int((page - 1) * inspectionPageSize), true
}

// handleAccountInspections GET /api/accounts/inspections?page=N
func (s *Server) handleAccountInspections(w http.ResponseWriter, r *http.Request) {
	offset, ok := inspectionPageOffset(r)
	if !ok {
		fail(w, http.StatusBadRequest, "page必须为有效的正整数")
		return
	}
	result, err := s.store.ListAccountInspections(r.Context(), inspectionPageSize, offset)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取巡检记录失败: "+err.Error())
		return
	}
	out := map[string]any{"ok": true}
	for k, v := range result {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAccountInspectionFailures GET /api/accounts/inspections/{id}/failures?page=N
func (s *Server) handleAccountInspectionFailures(w http.ResponseWriter, r *http.Request) {
	offset, ok := inspectionPageOffset(r)
	if !ok {
		fail(w, http.StatusBadRequest, "page必须为有效的正整数")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil {
		// 上游 <int:inspection_id> 对非整数直接 404。
		fail(w, http.StatusNotFound, "巡检任务不存在")
		return
	}
	result, found, err := s.store.ListAccountInspectionFailures(r.Context(), id, inspectionPageSize, offset)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取失败明细失败: "+err.Error())
		return
	}
	if !found {
		fail(w, http.StatusNotFound, "巡检任务不存在")
		return
	}
	out := map[string]any{"ok": true}
	for k, v := range result {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// handleInspectionHistoryPage GET /account-inspections
func (s *Server) handleInspectionHistoryPage(w http.ResponseWriter, r *http.Request) {
	s.serveEmbedded(w, "inspection_history.html")
}
