package protocol

import (
	"strings"
	"testing"
)

func TestResolveBrowserProfileKeepsTLSAndUAConsistent(t *testing.T) {
	image := ResolveBrowserProfile("http://user:pass@proxy.example:8080", "chrome_150", "en-US", "America/New_York")
	if image.TLSProfile != "chrome_150" {
		t.Fatalf("TLSProfile = %q, want chrome_150", image.TLSProfile)
	}
	if image.ChromeMajor != "150" {
		t.Fatalf("ChromeMajor = %q, want 150", image.ChromeMajor)
	}
	if !strings.Contains(image.UserAgent, "Chrome/150.0.0.0") {
		t.Fatalf("UserAgent = %q, want Chrome/150", image.UserAgent)
	}
	if hints := image.ClientHints(); !strings.Contains(hints, `v="150"`) {
		t.Fatalf("ClientHints = %q, want v=150", hints)
	}
}

func TestResolveBrowserProfileFromGermanProxy(t *testing.T) {
	image := ResolveBrowserProfile("http://user:pass@region-DE-proxy.example:8080", "", "", "")
	if image.Language != "de-DE" {
		t.Fatalf("Language = %q, want de-DE", image.Language)
	}
	if image.Timezone != "Europe/Berlin" {
		t.Fatalf("Timezone = %q, want Europe/Berlin", image.Timezone)
	}
	if image.TLSProfile != "chrome_152" {
		t.Fatalf("TLSProfile = %q, want chrome_152", image.TLSProfile)
	}
}

func TestSessionUsesSingleBrowserProfile(t *testing.T) {
	sess, err := NewSession(SessionOptions{
		Proxy:       "http://user:pass@region-DE-proxy.example:8080",
		ProfileName: "chrome_150",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if !strings.Contains(sess.UserAgent, "Chrome/150.0.0.0") {
		t.Fatalf("UserAgent = %q", sess.UserAgent)
	}
	if language := sess.baseHeaders().Get("Accept-Language"); !strings.HasPrefix(language, "de-DE,de") {
		t.Fatalf("Accept-Language = %q, want de-DE first", language)
	}
	if hints := sess.baseHeaders().Get("Sec-Ch-Ua"); !strings.Contains(hints, `v="150"`) {
		t.Fatalf("Sec-Ch-Ua = %q, want v=150", hints)
	}
	if sess.Profile() != (BrowserProfile{
		TLSProfile:  "chrome_150",
		ChromeMajor: "150",
		UserAgent:   sess.UserAgent,
		Language:    "de-DE",
		Timezone:    "Europe/Berlin",
		Screen:      "1920x1080",
	}) {
		t.Fatalf("Profile = %+v", sess.Profile())
	}
}

func TestBrowserProfileCompletePreservesStoredIdentity(t *testing.T) {
	stored := BrowserProfile{
		TLSProfile:  "chrome_131",
		ChromeMajor: "131",
		UserAgent:   "stored-ua",
		Language:    "ja-JP",
		Timezone:    "Asia/Tokyo",
		Screen:      "1440x900",
	}
	got := stored.Complete("http://region-DE-proxy.example:8080")
	if got != stored {
		t.Fatalf("Complete overwrote stored profile: got %+v, want %+v", got, stored)
	}
}

func TestBrowserProfileCompleteFillsLegacyAccount(t *testing.T) {
	got := (BrowserProfile{Language: "de-DE"}).Complete("http://region-DE-proxy.example:8080")
	if got.Timezone != "Europe/Berlin" {
		t.Fatalf("Timezone = %q, want Europe/Berlin", got.Timezone)
	}
	if got.Language != "de-DE" {
		t.Fatalf("Language = %q, want stored de-DE", got.Language)
	}
	if got.TLSProfile == "" || got.ChromeMajor == "" || got.UserAgent == "" || got.Screen == "" {
		t.Fatalf("legacy profile not completed: %+v", got)
	}
}

func TestBrowserProfileCompletesLanguageAndTimezoneAsOneRegion(t *testing.T) {
	got := (BrowserProfile{Language: "ja-JP"}).Complete("http://region-US-proxy.example:8080")
	if got.Timezone != "Asia/Tokyo" {
		t.Fatalf("Timezone = %q, want Asia/Tokyo", got.Timezone)
	}

	got = (BrowserProfile{Timezone: "Asia/Tokyo"}).Complete("http://region-DE-proxy.example:8080")
	if got.Language != "ja-JP" {
		t.Fatalf("Language = %q, want ja-JP", got.Language)
	}
}

func TestBrowserProfileNormalizesLegacyTLSConflictFromUA(t *testing.T) {
	got := (BrowserProfile{
		TLSProfile:  "chrome_152",
		ChromeMajor: "152",
		UserAgent:   "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36",
	}).Complete("")
	if got.TLSProfile != "chrome_131" || got.ChromeMajor != "131" {
		t.Fatalf("profile = %+v, want TLS and major normalized to Chrome 131", got)
	}
}

func TestSessionDerivesTLSFromUserAgentAndDeviceID(t *testing.T) {
	sess, err := NewSession(SessionOptions{
		UserAgent: "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if sess.TLSProfile != "chrome_131" || sess.ChromeMajor != "131" {
		t.Fatalf("TLS profile = %q major = %q, want Chrome 131", sess.TLSProfile, sess.ChromeMajor)
	}
	if sess.DeviceID == "" {
		t.Fatal("DeviceID is empty")
	}
	if got := sess.GetCookie("oai-did"); got != sess.DeviceID {
		t.Fatalf("oai-did cookie = %q, want %q", got, sess.DeviceID)
	}
}
