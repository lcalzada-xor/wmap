package cve

import (
	"context"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestCVEMatcher(t *testing.T) {
	// Setup: Create in-memory repository with test data
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	// Seed test CVEs
	testCVEs := []domain.CVERecord{
		{
			ID:            "CVE-2020-TEST-1",
			Vendor:        "cisco",
			Product:       "wap321",
			Description:   "Test vulnerability in Cisco WAP321",
			Severity:      9.8,
			AttackVector:  "NETWORK",
			PublishedDate: time.Now(),
		},
		{
			ID:            "CVE-2020-TEST-2",
			Vendor:        "tplink",
			Product:       "tl-wr940n",
			Description:   "Test vulnerability in TP-Link router",
			Severity:      8.5,
			AttackVector:  "NETWORK",
			PublishedDate: time.Now(),
		},
		{
			ID:            "CVE-2017-KRACK",
			Vendor:        "*",
			Product:       "*",
			Description:   "WPA2 KRACK attack vulnerability",
			Severity:      8.1,
			AttackVector:  "ADJACENT",
			PublishedDate: time.Now(),
		},
	}

	for _, cve := range testCVEs {
		if err := repo.UpsertCVE(ctx, cve); err != nil {
			t.Fatalf("Failed to seed CVE: %v", err)
		}
	}

	matcher := NewCVEMatcher(repo)

	// Test 1: Exact Match
	t.Run("ExactMatch", func(t *testing.T) {
		device := domain.Device{
			Vendor: "Cisco",
			Model:  "WAP321",
		}

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		if len(matches) == 0 {
			t.Error("Expected at least 1 match for Cisco WAP321")
		}

		// Verify exact match has high confidence
		if matches[0].Confidence < 0.9 {
			t.Errorf("Expected confidence >= 0.9, got %.2f", matches[0].Confidence)
		}

		if matches[0].MatchType != "exact" {
			t.Errorf("Expected match type 'exact', got %s", matches[0].MatchType)
		}
	})

	// Test 2: WPS Match
	t.Run("WPSMatch", func(t *testing.T) {
		device := domain.Device{
			Vendor: "Unknown",
			Model:  "Unknown",
			WPSDetails: &domain.WPSDetails{
				Manufacturer: "TP-Link",
				Model:        "TL-WR940N",
			},
		}

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		if len(matches) == 0 {
			t.Error("Expected at least 1 match via WPS details")
		}

		// Verify WPS match confidence
		if matches[0].Confidence < 0.8 {
			t.Errorf("Expected confidence >= 0.8, got %.2f", matches[0].Confidence)
		}

		if matches[0].MatchType != "wps" {
			t.Errorf("Expected match type 'wps', got %s", matches[0].MatchType)
		}
	})

	// Test 3: Keyword Match
	t.Run("KeywordMatch", func(t *testing.T) {
		device := domain.Device{
			Vendor:       "Unknown",
			Model:        "Unknown",
			Security:     "WPA2",
			Capabilities: []string{"WPA2-PSK"},
		}

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		// Should match KRACK CVE via WPA2 keyword
		if len(matches) == 0 {
			t.Error("Expected at least 1 match via keywords")
		}

		// Keyword matches have lower confidence
		if matches[0].Confidence > 0.8 {
			t.Errorf("Keyword match confidence too high: %.2f", matches[0].Confidence)
		}
	})

	// Test 4: No Match
	t.Run("NoMatch", func(t *testing.T) {
		device := domain.Device{
			Vendor: "NonExistentVendor",
			Model:  "NonExistentModel",
		}

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		if len(matches) != 0 {
			t.Errorf("Expected 0 matches, got %d", len(matches))
		}
	})

	// Test 5: Deduplication
	t.Run("Deduplication", func(t *testing.T) {
		// Device that matches via both exact and WPS
		device := domain.Device{
			Vendor: "Cisco",
			Model:  "WAP321",
			WPSDetails: &domain.WPSDetails{
				Manufacturer: "Cisco",
				Model:        "WAP321",
			},
		}

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		// Should deduplicate to single match with highest confidence
		cveIDs := make(map[string]int)
		for _, match := range matches {
			cveIDs[match.CVE.ID]++
		}

		for cveID, count := range cveIDs {
			if count > 1 {
				t.Errorf("CVE %s appears %d times (should be deduplicated)", cveID, count)
			}
		}
	})

	// Test 6: False Positive Reduction (Strict Vendor Check)
	t.Run("FalsePositiveReduction", func(t *testing.T) {
		// Scenario: Linksys device with WPA2 capability
		// Should NOT match Cisco CVE even if it mentions WPA2
		device := domain.Device{
			Vendor:       "Linksys",
			Model:        "WRT54G",
			Capabilities: []string{"WPA2"},
		}

		// Ensure we have a Cisco CVE with WPA2 keyword in DB
		ciscoCVE := domain.CVERecord{
			ID:            "CVE-CISCO-WPA2",
			Vendor:        "cisco",
			Product:       "any",
			Description:   "Cisco device vulnerability related to WPA2 protocol handling",
			Severity:      9.0,
			PublishedDate: time.Now(),
		}
		repo.UpsertCVE(ctx, ciscoCVE)

		matches, err := matcher.FindMatches(ctx, device)
		if err != nil {
			t.Errorf("FindMatches failed: %v", err)
		}

		// Check matches
		for _, m := range matches {
			if m.CVE.ID == "CVE-CISCO-WPA2" {
				t.Error("False positive detected: Linksys device matched Cisco-specific CVE via keyword")
			}
		}
	})
}

func TestNormalizeVendor(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"TP-Link", "tplink"},
		{"D-Link", "dlink"},
		{"Cisco", "cisco"},
		{"NETGEAR", "netgear"},
		{"  Cisco  ", "cisco"},
		{"Unknown Vendor", "unknown vendor"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeVendor(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeVendor(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractKeywords(t *testing.T) {
	device := domain.Device{
		Security:     "WPA2-PSK",
		Capabilities: []string{"WPA2", "WPS", "HT40"},
		Standard:     "802.11n",
	}

	keywords := extractKeywords(device)

	// Should extract WPA2, WPS, and 802.11n
	if len(keywords) < 3 {
		t.Errorf("Expected at least 3 keywords, got %d: %v", len(keywords), keywords)
	}

	// Verify WPA2 is extracted
	hasWPA2 := false
	for _, kw := range keywords {
		if kw == "WPA2" || kw == "WPA2-PSK" {
			hasWPA2 = true
			break
		}
	}
	if !hasWPA2 {
		t.Error("Expected WPA2 keyword to be extracted")
	}
}
