package api

import "testing"

func promoCampaign(id, title string, percentage float64, months int) map[string]any {
	discount := map[string]any{}
	if percentage > 0 {
		discount["percentage"] = percentage
	}
	meta := map[string]any{
		"title":    title,
		"discount": discount,
	}
	if months > 0 {
		meta["duration"] = map[string]any{"num_periods": float64(months), "period": "month"}
	}
	return map[string]any{"id": id, "metadata": meta}
}

func promoPayload(campaigns ...map[string]any) map[string]any {
	promos := map[string]any{}
	for _, campaign := range campaigns {
		promos[strVal(campaign["id"])] = campaign
	}
	return map[string]any{
		"plan_check_status":        "success",
		"eligible_promo_campaigns": promos,
		"plus_trial_eligible":      false,
		"go_trial_eligible":        false,
		"discount_offer_eligible":  false,
		"has_50_discount":          false,
	}
}

func TestClassifyPromoAccount(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    promoAccountClass
	}{
		{
			name:    "Plus free trial",
			payload: promoPayload(promoCampaign("plus-1-month-free", "Try Plus free for 1 month", 100, 1)),
			want:    promoClassPlusFreeTrial,
		},
		{
			name:    "Go free trial",
			payload: promoPayload(promoCampaign("go-1-month-free", "Try Go free for 1 month", 100, 1)),
			want:    promoClassGoFreeTrial,
		},
		{
			name:    "Plus 50 one month",
			payload: promoPayload(promoCampaign("plus-50-pct-1-month", "Plus 50% off for 1 month", 50, 1)),
			want:    promoClassPlus501Month,
		},
		{
			name:    "Plus 50 two months",
			payload: promoPayload(promoCampaign("plus-50-pct-2-months", "Plus 50% off for 2 months", 50, 2)),
			want:    promoClassPlus502Months,
		},
		{
			name:    "Plus 50 three months",
			payload: promoPayload(promoCampaign("plus-50-pct-3-months", "Plus 50% off for 3 months", 50, 3)),
			want:    promoClassPlus503Months,
		},
		{
			name:    "Go 50 one month",
			payload: promoPayload(promoCampaign("go-50-pct-1-month", "Go 50% off for 1 month", 50, 1)),
			want:    promoClassGo501Month,
		},
		{
			name:    "Go 50 two months",
			payload: promoPayload(promoCampaign("go-50-pct-2-months", "Go 50% off for 2 months", 50, 2)),
			want:    promoClassGo502Months,
		},
		{
			name:    "Go 50 three months",
			payload: promoPayload(promoCampaign("go-50-pct-3-months", "Go 50% off for 3 months", 50, 3)),
			want:    promoClassGo503Months,
		},
		{
			name: "Plus free outranks plus discount",
			payload: promoPayload(
				promoCampaign("plus-50-pct-3-months", "Plus 50% off for 3 months", 50, 3),
				promoCampaign("plus-1-month-free", "Try Plus free for 1 month", 100, 1),
			),
			want: promoClassPlusFreeTrial,
		},
		{
			name: "Plus discount outranks Go free",
			payload: promoPayload(
				promoCampaign("go-1-month-free", "Try Go free for 1 month", 100, 1),
				promoCampaign("plus-50-pct-2-months", "Plus 50% off for 2 months", 50, 2),
			),
			want: promoClassPlus502Months,
		},
		{
			name: "Successful probe without promotion",
			payload: map[string]any{
				"plan_check_status":        "success",
				"eligible_promo_campaigns": map[string]any{},
				"plus_trial_eligible":      false,
				"go_trial_eligible":        false,
				"discount_offer_eligible":  false,
				"has_50_discount":          false,
			},
			want: promoClassNoTrial,
		},
		{
			name:    "Empty probe status",
			payload: map[string]any{},
			want:    promoClassProbeUnfinished,
		},
		{
			name:    "Running probe",
			payload: map[string]any{"plan_check_status": "running"},
			want:    promoClassProbeUnfinished,
		},
		{
			name:    "Failed probe",
			payload: map[string]any{"plan_check_status": "failed"},
			want:    promoClassProbeUnfinished,
		},
		{
			name:    "50 percent without plan",
			payload: promoPayload(promoCampaign("campaign-opaque", "50% off for 3 months", 50, 3)),
			want:    promoClassProbeUnfinished,
		},
		{
			name:    "50 percent unsupported duration",
			payload: promoPayload(promoCampaign("plus-50-pct-6-months", "Plus 50% off for 6 months", 50, 6)),
			want:    promoClassProbeUnfinished,
		},
		{
			name:    "Non-target promotion is unfinished",
			payload: promoPayload(promoCampaign("plus-20-pct-1-month", "Plus 20% off for 1 month", 20, 1)),
			want:    promoClassProbeUnfinished,
		},
		{
			name: "Explicit Plus trial fields",
			payload: map[string]any{
				"plan_check_status":      "success",
				"plus_trial_eligible":    true,
				"trial_offer_kind":       "plus",
				"trial_offer_plan":       "chatgptplusplan",
				"plus_trial_campaign_id": "plus-1-month-free",
			},
			want: promoClassPlusFreeTrial,
		},
		{
			name: "Explicit Go discount fields",
			payload: map[string]any{
				"plan_check_status":          "success",
				"discount_offer_eligible":    true,
				"discount_offer_campaign_id": "go-50-pct-2-months",
				"discount_offer_title":       "Go 50% off for 2 months",
				"discount_offer_percentage":  float64(50),
				"has_50_discount":            true,
			},
			want: promoClassGo502Months,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyPromoAccount(tt.payload); got != tt.want {
				t.Fatalf("classifyPromoAccount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPromoFreeTrialDurationIsNotMistakenForDiscount(t *testing.T) {
	payload := promoPayload(promoCampaign("plus-1-month-free", "Plus 1 month free trial", 100, 1))
	if got := classifyPromoAccount(payload); got != promoClassPlusFreeTrial {
		t.Fatalf("free trial classified as %d, want Plus free trial", got)
	}
}

func TestBuildPromoSummaryCountsEachAccountOnce(t *testing.T) {
	payloads := []map[string]any{
		promoPayload(promoCampaign("plus-1-month-free", "Try Plus free for 1 month", 100, 1)),
		promoPayload(promoCampaign("plus-50-pct-1-month", "Plus 50% off for 1 month", 50, 1)),
		promoPayload(promoCampaign("go-1-month-free", "Try Go free for 1 month", 100, 1)),
		{"plan_check_status": "success"},
		{"plan_check_status": "running"},
	}
	got := buildPromoSummary("batch_test", payloads)
	if !got.OK || got.BatchID != "batch_test" || got.SuccessfulAccounts != 5 {
		t.Fatalf("summary header = %+v", got)
	}
	if got.PlusFreeTrial != 1 || got.Plus501Month != 1 || got.GoFreeTrial != 1 || got.NoTrial != 1 || got.ProbeUnfinished != 1 {
		t.Fatalf("summary counts = %+v", got)
	}
}
