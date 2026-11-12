package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type promoAccountClass int

const (
	promoClassNoTrial promoAccountClass = iota
	promoClassProbeUnfinished
	promoClassPlusFreeTrial
	promoClassPlus501Month
	promoClassPlus502Months
	promoClassPlus503Months
	promoClassGoFreeTrial
	promoClassGo501Month
	promoClassGo502Months
	promoClassGo503Months
)

type promoSummaryResponse struct {
	OK                 bool   `json:"ok"`
	BatchID            string `json:"batch_id"`
	SuccessfulAccounts int    `json:"successful_accounts"`
	PlusFreeTrial      int    `json:"plus_free_trial"`
	Plus501Month       int    `json:"plus_50_1m"`
	Plus502Months      int    `json:"plus_50_2m"`
	Plus503Months      int    `json:"plus_50_3m"`
	GoFreeTrial        int    `json:"go_free_trial"`
	Go501Month         int    `json:"go_50_1m"`
	Go502Months        int    `json:"go_50_2m"`
	Go503Months        int    `json:"go_50_3m"`
	NoTrial            int    `json:"no_trial"`
	ProbeUnfinished    int    `json:"probe_unfinished"`
}

type promoOffer struct {
	plan       string
	freeTrial  bool
	is50       bool
	months     int
	recognized bool
	evidence   bool
}

var promoMonthPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b([123])\s*[-_ /]?\s*(?:months?|mos?)\b`),
	regexp.MustCompile(`([123])\s*个?\s*月`),
}

// handlePromoSummary 返回本批成功账号的优惠探测统计。所有计数均按账号去重，
// 且每个账号只进入一个分类。
func (s *Server) handlePromoSummary(w http.ResponseWriter, r *http.Request) {
	batchID := strings.TrimSpace(r.URL.Query().Get("batch_id"))
	if batchID == "" {
		var err error
		batchID, err = s.store.LatestJobBatchID(r.Context())
		if err != nil {
			fail(w, http.StatusInternalServerError, "读取最近注册批次失败: "+err.Error())
			return
		}
	}

	payloads, err := s.store.ListSuccessfulJobAccountPayloads(r.Context(), batchID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取批次优惠探测结果失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildPromoSummary(batchID, payloads))
}

func buildPromoSummary(batchID string, payloads []map[string]any) promoSummaryResponse {
	out := promoSummaryResponse{
		OK:                 true,
		BatchID:            batchID,
		SuccessfulAccounts: len(payloads),
	}
	for _, payload := range payloads {
		switch classifyPromoAccount(payload) {
		case promoClassPlusFreeTrial:
			out.PlusFreeTrial++
		case promoClassPlus501Month:
			out.Plus501Month++
		case promoClassPlus502Months:
			out.Plus502Months++
		case promoClassPlus503Months:
			out.Plus503Months++
		case promoClassGoFreeTrial:
			out.GoFreeTrial++
		case promoClassGo501Month:
			out.Go501Month++
		case promoClassGo502Months:
			out.Go502Months++
		case promoClassGo503Months:
			out.Go503Months++
		case promoClassProbeUnfinished:
			out.ProbeUnfinished++
		default:
			out.NoTrial++
		}
	}
	return out
}

// classifyPromoAccount 将单个账号 payload 归入一个固定分类。促销活动同时命中时，
// 按 Plus 免费 > Plus 五折 > Go 免费 > Go 五折 的顺序只取价值最高的一项。
func classifyPromoAccount(payload map[string]any) promoAccountClass {
	if payload == nil || !strings.EqualFold(strings.TrimSpace(strVal(payload["plan_check_status"])), "success") {
		return promoClassProbeUnfinished
	}

	offers := collectPromoOffers(payload)
	best := promoClassNoTrial
	bestRank := 0
	hasPromotionEvidence := false
	for _, offer := range offers {
		if offer.evidence {
			hasPromotionEvidence = true
		}
		if !offer.recognized {
			continue
		}
		class := promoClassForOffer(offer)
		rank := promoClassRank(class)
		if rank > bestRank {
			best = class
			bestRank = rank
		}
	}
	if bestRank > 0 {
		return best
	}
	if hasPromotionEvidence {
		return promoClassProbeUnfinished
	}
	return promoClassNoTrial
}

func promoClassForOffer(offer promoOffer) promoAccountClass {
	switch {
	case offer.plan == trialKindPlus && offer.freeTrial:
		return promoClassPlusFreeTrial
	case offer.plan == trialKindPlus && offer.is50 && offer.months == 1:
		return promoClassPlus501Month
	case offer.plan == trialKindPlus && offer.is50 && offer.months == 2:
		return promoClassPlus502Months
	case offer.plan == trialKindPlus && offer.is50 && offer.months == 3:
		return promoClassPlus503Months
	case offer.plan == trialKindGo && offer.freeTrial:
		return promoClassGoFreeTrial
	case offer.plan == trialKindGo && offer.is50 && offer.months == 1:
		return promoClassGo501Month
	case offer.plan == trialKindGo && offer.is50 && offer.months == 2:
		return promoClassGo502Months
	case offer.plan == trialKindGo && offer.is50 && offer.months == 3:
		return promoClassGo503Months
	default:
		return promoClassProbeUnfinished
	}
}

func promoClassRank(class promoAccountClass) int {
	switch class {
	case promoClassPlusFreeTrial:
		return 8
	case promoClassPlus501Month, promoClassPlus502Months, promoClassPlus503Months:
		return 7
	case promoClassGoFreeTrial:
		return 6
	case promoClassGo501Month, promoClassGo502Months, promoClassGo503Months:
		return 5
	default:
		return 0
	}
}

func collectPromoOffers(payload map[string]any) []promoOffer {
	var offers []promoOffer
	seen := map[string]bool{}
	add := func(offer promoOffer) {
		key := strings.Join([]string{
			offer.plan,
			strconvBool(offer.freeTrial),
			strconvBool(offer.is50),
			strconvItoa(offer.months),
			strconvBool(offer.recognized),
			strconvBool(offer.evidence),
		}, "|")
		if seen[key] {
			return
		}
		seen[key] = true
		offers = append(offers, offer)
	}

	collect := func(source any) {
		switch promos := source.(type) {
		case map[string]any:
			for key, raw := range promos {
				if campaign := asMapAny(raw); campaign != nil {
					add(classifyPromoCampaign(key, campaign))
				}
			}
		case []any:
			for _, raw := range promos {
				if campaign := asMapAny(raw); campaign != nil {
					key := strVal(campaign["id"])
					add(classifyPromoCampaign(key, campaign))
				}
			}
		}
	}
	collect(payload["eligible_promo_campaigns"])
	collect(payload["promos"])
	if account := asMapAny(payload["account"]); account != nil {
		collect(account["promos"])
	}

	if boolValue(payload["plus_trial_eligible"]) || strings.EqualFold(strVal(payload["trial_offer_kind"]), trialKindPlus) ||
		strings.Contains(strings.ToLower(strVal(payload["trial_offer_plan"])), "plus") ||
		payload["plus_trial_campaign_id"] != nil && strVal(payload["plus_trial_campaign_id"]) != "" {
		add(promoOffer{plan: trialKindPlus, freeTrial: true, recognized: true, evidence: true})
	}
	if boolValue(payload["go_trial_eligible"]) || strings.EqualFold(strVal(payload["trial_offer_kind"]), trialKindGo) ||
		strings.Contains(strings.ToLower(strVal(payload["trial_offer_plan"])), "go") ||
		payload["go_trial_campaign_id"] != nil && strVal(payload["go_trial_campaign_id"]) != "" {
		add(promoOffer{plan: trialKindGo, freeTrial: true, recognized: true, evidence: true})
	}

	discountID := strVal(payload["discount_offer_campaign_id"])
	if discountID == "" {
		discountID = strVal(payload["discount_promo_campaign_id"])
	}
	discountTitle := strVal(payload["discount_offer_title"])
	discountPercent := payload["discount_offer_percentage"]
	discountEligible := boolValue(payload["discount_offer_eligible"]) || boolValue(payload["has_50_discount"]) ||
		(discountID != "" && discountID != "<nil>") || (discountTitle != "" && discountTitle != "<nil>") ||
		toFloatPositive(discountPercent)
	if discountEligible {
		campaign := map[string]any{
			"id": discountID,
			"metadata": map[string]any{
				"title": discountTitle,
				"discount": map[string]any{
					"percentage": discountPercent,
				},
			},
		}
		offer := classifyPromoCampaign(discountID+" "+discountTitle, campaign)
		offer.evidence = true
		if boolValue(payload["has_50_discount"]) {
			offer.is50 = true
		}
		// has_50_discount 是解析器给出的明确结论；即使标题/百分比缺失，也保留为促销证据。
		if offer.is50 {
			if offer.plan == "" {
				offer.plan = promoPlanFromText(strings.Join([]string{
					discountID, discountTitle, strVal(payload["discount_type"]),
					strVal(payload["discount_offer_campaign_id"]),
				}, " "))
			}
			if offer.months == 0 {
				offer.months = promoMonthsFromText(discountID + " " + discountTitle)
			}
			offer.recognized = offer.plan != "" && offer.months >= 1 && offer.months <= 3
		}
		add(offer)
	}
	return offers
}

func classifyPromoCampaign(key string, campaign map[string]any) promoOffer {
	if campaign == nil {
		return promoOffer{}
	}
	meta := asMapAny(campaign["metadata"])
	if promotionExpired(campaignExpiry(meta), float64(time.Now().Unix())) {
		return promoOffer{}
	}

	textParts := []string{key, strVal(campaign["id"])}
	if meta != nil {
		for _, field := range []string{"title", "summary", "promotion_type_label", "plan", "plan_id", "plan_type", "plan_name", "product", "product_id", "product_name"} {
			textParts = append(textParts, strVal(meta[field]))
		}
	}
	text := strings.Join(textParts, " ")
	kind := promotionKind(key, campaign)
	if kind == "" {
		return promoOffer{}
	}

	percentage := float64(0)
	durationMonths := 0
	if meta != nil {
		if discount := asMapAny(meta["discount"]); discount != nil {
			percentage, _ = toFloat(discount["percentage"])
		}
		if duration := asMapAny(meta["duration"]); duration != nil {
			if n, ok := toFloat(duration["num_periods"]); ok && n >= 1 && n <= 3 {
				durationMonths = int(n)
			}
		}
	}
	if durationMonths == 0 {
		durationMonths = promoMonthsFromText(text)
	}
	offer := promoOffer{
		plan:     promoPlanFromText(text),
		is50:     promoIs50(text, percentage),
		months:   durationMonths,
		evidence: true,
	}
	if kind == "trial" {
		offer.freeTrial = true
		offer.recognized = offer.plan == trialKindPlus || offer.plan == trialKindGo
		return offer
	}
	if kind == "discount" && offer.is50 {
		offer.recognized = (offer.plan == trialKindPlus || offer.plan == trialKindGo) && offer.months >= 1 && offer.months <= 3
	}
	return offer
}

func campaignExpiry(meta map[string]any) any {
	if meta == nil {
		return nil
	}
	if discount := asMapAny(meta["discount"]); discount != nil && discount["expires_at"] != nil {
		return discount["expires_at"]
	}
	return meta["expires_at"]
}

func promoPlanFromText(text string) string {
	lower := strings.ToLower(strings.TrimSpace(text))
	if strings.Contains(lower, "chatgptplusplan") || strings.Contains(lower, "chatgpt_plus_plan") ||
		strings.Contains(lower, "chatgpt plus") || strings.Contains(lower, "plus-") ||
		strings.Contains(lower, "plus_") || strings.Contains(lower, " plus ") {
		return trialKindPlus
	}
	if strings.Contains(lower, "chatgptgoplan") || strings.Contains(lower, "chatgpt_go_plan") ||
		strings.Contains(lower, "chatgpt go") || strings.Contains(lower, "go-") ||
		strings.Contains(lower, "go_") || strings.HasPrefix(lower, "go ") ||
		strings.Contains(lower, " go ") || strings.HasSuffix(lower, " go") ||
		strings.Contains(lower, "go plan") || strings.Contains(lower, "try go") {
		return trialKindGo
	}
	return ""
}

func promoIs50(text string, percentage float64) bool {
	if percentage == 50 {
		return true
	}
	lower := strings.ToLower(text)
	for _, signal := range []string{"50%", "50-pct", "50_pct", "50 pct", "50 percent", "half price", "half-price", "五折"} {
		if strings.Contains(lower, signal) {
			return true
		}
	}
	return false
}

func promoMonthsFromText(text string) int {
	for _, pattern := range promoMonthPatterns {
		if matches := pattern.FindStringSubmatch(text); len(matches) == 2 {
			switch matches[1] {
			case "1":
				return 1
			case "2":
				return 2
			case "3":
				return 3
			}
		}
	}
	return 0
}

func boolValue(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			return true
		}
	case float64:
		return value != 0
	case float32:
		return value != 0
	case int:
		return value != 0
	case int64:
		return value != 0
	}
	return false
}

func toFloatPositive(v any) bool {
	f, ok := toFloat(v)
	return ok && f > 0
}

func strconvBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func strconvItoa(v int) string {
	return fmt.Sprint(v)
}
