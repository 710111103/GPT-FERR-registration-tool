package api

import "testing"

func TestParseAccountsCheckSeparatesGoTrial(t *testing.T) {
	body := []byte(`{
		"accounts": {
			"default": {
				"account": {"plan_type": "free"},
				"eligible_promo_campaigns": {
					"go-1-month-free": {
						"id": "go-1-month-free",
						"metadata": {
							"title": "Try Go free for 1 month",
							"discount": {"percentage": 100}
						}
					}
				}
			}
		}
	}`)

	info, err := parseAccountsCheck(body)
	if err != nil {
		t.Fatalf("parseAccountsCheck() error = %v", err)
	}
	if info.TrialOfferKind != trialKindGo {
		t.Fatalf("trial kind = %q, want %q", info.TrialOfferKind, trialKindGo)
	}
	if info.TrialOfferPlan != "chatgptgoplan" {
		t.Fatalf("trial plan = %q, want chatgptgoplan", info.TrialOfferPlan)
	}
	if !info.TrialEligible {
		t.Fatal("Go offer should still be represented as a trial")
	}
}

func TestParseAccountsCheckClassifiesPlusTrial(t *testing.T) {
	body := []byte(`{
		"accounts": {
			"default": {
				"account": {"plan_type": "free"},
				"eligible_promo_campaigns": {
					"plus-1-month-free": {
						"id": "plus-1-month-free",
						"metadata": {
							"title": "Try Plus free for 1 month",
							"discount": {"percentage": 100}
						}
					}
				}
			}
		}
	}`)

	info, err := parseAccountsCheck(body)
	if err != nil {
		t.Fatalf("parseAccountsCheck() error = %v", err)
	}
	if info.TrialOfferKind != trialKindPlus {
		t.Fatalf("trial kind = %q, want %q", info.TrialOfferKind, trialKindPlus)
	}
	if info.TrialOfferPlan != "chatgptplusplan" {
		t.Fatalf("trial plan = %q, want chatgptplusplan", info.TrialOfferPlan)
	}
}

func TestPreferredTrialOfferChoosesPlusOverGo(t *testing.T) {
	goOffer := map[string]any{"id": "go-1-month-free"}
	plusOffer := map[string]any{"id": "plus-1-month-free"}
	if got := preferredTrialOffer(goOffer, plusOffer); got["id"] != "plus-1-month-free" {
		t.Fatalf("preferred offer = %#v, want Plus", got)
	}
}

func TestMergeBestTrialRegionSeparatesPlanFlags(t *testing.T) {
	regions := map[string]any{
		"DE": map[string]any{
			"ok":                  true,
			"trial_offer_kind":    trialKindGo,
			"trial_offer_plan":    "chatgptgoplan",
			"trial_campaign_id":   "go-1-month-free",
			"trial_title":         "Try Go free",
			"go_trial_eligible":   true,
			"plus_trial_eligible": false,
		},
	}
	payload := map[string]any{}
	mergeBestTrialRegion(payload, regions)
	if payload["plus_trial_eligible"] != false || payload["go_trial_eligible"] != true {
		t.Fatalf("merged flags = plus:%v go:%v", payload["plus_trial_eligible"], payload["go_trial_eligible"])
	}
}
