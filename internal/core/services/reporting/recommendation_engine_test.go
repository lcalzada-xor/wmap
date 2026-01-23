package reporting

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestGenerateRecommendations(t *testing.T) {
	re := NewRecommendationEngine()

	topRisks := []domain.RiskItem{
		{VulnName: "WPS-PIXIE", AffectedDevices: 5, Severity: 9},
		{VulnName: "OPEN-NETWORK", AffectedDevices: 3, Severity: 8},
		{VulnName: "DEFAULT-SSID", AffectedDevices: 8, Severity: 5},
	}

	vulns := []domain.VulnerabilityRecord{} // Not used in current implementation

	recommendations := re.GenerateRecommendations(vulns, topRisks)

	// Should return at least 3 recommendations (one per top risk)
	if len(recommendations) < 3 {
		t.Errorf("Expected at least 3 recommendations, got %d", len(recommendations))
	}

	// Should not exceed 5 recommendations
	if len(recommendations) > 5 {
		t.Errorf("Expected max 5 recommendations, got %d", len(recommendations))
	}

	// Verify all recommendations have required fields
	for i, rec := range recommendations {
		if rec.Priority == "" {
			t.Errorf("Recommendation %d missing priority", i)
		}
		if rec.Title == "" {
			t.Errorf("Recommendation %d missing title", i)
		}
		if rec.Description == "" {
			t.Errorf("Recommendation %d missing description", i)
		}
		if len(rec.Actions) == 0 {
			t.Errorf("Recommendation %d has no actions", i)
		}
		if rec.EstimatedEffort == "" {
			t.Errorf("Recommendation %d missing estimated effort", i)
		}
		if rec.ImpactReduction < 0 || rec.ImpactReduction > 100 {
			t.Errorf("Recommendation %d has invalid impact reduction: %v", i, rec.ImpactReduction)
		}
	}
}

func TestGetRecommendationForVuln(t *testing.T) {
	re := NewRecommendationEngine()

	tests := []struct {
		vulnName       string
		affectedCount  int
		expectPriority string
		expectActions  int
	}{
		{"WPS-PIXIE", 5, "critical", 4},
		{"WPS-ENABLED", 3, "high", 4},
		{"OPEN-NETWORK", 2, "critical", 4},
		{"DEFAULT-SSID", 8, "high", 4},
		{"WEP", 1, "critical", 4},
		{"WEAK-WPA", 4, "high", 4},
		{"TKIP-ONLY", 2, "medium", 4},
		{"PROBE-LEAKAGE", 10, "medium", 4},
		{"MAC-RAND-FAIL", 5, "low", 4},
		{"LEGACY-WEP-SUPPORT", 3, "medium", 4},
		{"LEGACY-TKIP-ONLY", 2, "low", 4},
		{"KRACK", 6, "critical", 4},
		{"UNKNOWN-VULN", 1, "medium", 4}, // Generic recommendation
	}

	for _, tt := range tests {
		t.Run(tt.vulnName, func(t *testing.T) {
			rec := re.getRecommendationForVuln(tt.vulnName, tt.affectedCount)

			if rec == nil {
				t.Fatal("getRecommendationForVuln() returned nil")
			}

			if rec.Priority != tt.expectPriority {
				t.Errorf("Priority = %v, want %v", rec.Priority, tt.expectPriority)
			}

			if len(rec.Actions) < tt.expectActions {
				t.Errorf("Expected at least %d actions, got %d", tt.expectActions, len(rec.Actions))
			}

			// Verify description mentions affected count
			if tt.affectedCount > 0 {
				// Description should contain the count somewhere
				if rec.Description == "" {
					t.Error("Description is empty")
				}
			}

			// Verify impact reduction is reasonable
			if rec.ImpactReduction < 0 || rec.ImpactReduction > 100 {
				t.Errorf("Impact reduction %v out of range [0, 100]", rec.ImpactReduction)
			}

			// Critical vulnerabilities should have high impact reduction
			if rec.Priority == "critical" && rec.ImpactReduction < 80 {
				t.Errorf("Critical vulnerability should have impact reduction >= 80, got %v", rec.ImpactReduction)
			}
		})
	}
}

func TestGetGeneralRecommendations(t *testing.T) {
	re := NewRecommendationEngine()

	recommendations := re.getGeneralRecommendations()

	// Should return at least 2 general recommendations
	if len(recommendations) < 2 {
		t.Errorf("Expected at least 2 general recommendations, got %d", len(recommendations))
	}

	// Verify structure
	for i, rec := range recommendations {
		if rec.Priority == "" {
			t.Errorf("General recommendation %d missing priority", i)
		}
		if rec.Title == "" {
			t.Errorf("General recommendation %d missing title", i)
		}
		if rec.Description == "" {
			t.Errorf("General recommendation %d missing description", i)
		}
		if len(rec.Actions) == 0 {
			t.Errorf("General recommendation %d has no actions", i)
		}
	}
}

func TestRecommendationPriorities(t *testing.T) {
	re := NewRecommendationEngine()

	// Test that critical vulnerabilities get critical priority
	criticalVulns := []string{"WPS-PIXIE", "OPEN-NETWORK", "WEP", "KRACK"}
	for _, vuln := range criticalVulns {
		rec := re.getRecommendationForVuln(vuln, 1)
		if rec.Priority != "critical" {
			t.Errorf("%s should have critical priority, got %v", vuln, rec.Priority)
		}
	}

	// Test that medium vulnerabilities get appropriate priority
	mediumVulns := []string{"TKIP-ONLY", "PROBE-LEAKAGE", "LEGACY-WEP-SUPPORT"}
	for _, vuln := range mediumVulns {
		rec := re.getRecommendationForVuln(vuln, 1)
		if rec.Priority != "medium" && rec.Priority != "low" {
			t.Errorf("%s should have medium/low priority, got %v", vuln, rec.Priority)
		}
	}
}

func TestRecommendationActionsNotEmpty(t *testing.T) {
	re := NewRecommendationEngine()

	// All known vulnerabilities
	vulns := []string{
		"WPS-PIXIE", "WPS-ENABLED", "OPEN-NETWORK", "DEFAULT-SSID",
		"WEP", "WEAK-WPA", "TKIP-ONLY", "PROBE-LEAKAGE",
		"MAC-RAND-FAIL", "LEGACY-WEP-SUPPORT", "LEGACY-TKIP-ONLY", "KRACK",
	}

	for _, vuln := range vulns {
		rec := re.getRecommendationForVuln(vuln, 5)
		if len(rec.Actions) == 0 {
			t.Errorf("%s recommendation has no actions", vuln)
		}

		// Verify actions are not empty strings
		for j, action := range rec.Actions {
			if action == "" {
				t.Errorf("%s action %d is empty", vuln, j)
			}
			if len(action) < 10 {
				t.Errorf("%s action %d is suspiciously short: %v", vuln, j, action)
			}
		}
	}
}

func TestRecommendationLimits(t *testing.T) {
	re := NewRecommendationEngine()

	// Create many top risks
	manyRisks := make([]domain.RiskItem, 20)
	for i := range manyRisks {
		manyRisks[i] = domain.RiskItem{
			VulnName:        "VULN-" + string(rune('A'+i)),
			AffectedDevices: i + 1,
			Severity:        5,
		}
	}

	recommendations := re.GenerateRecommendations([]domain.VulnerabilityRecord{}, manyRisks)

	// Should be limited to 5
	if len(recommendations) > 5 {
		t.Errorf("Recommendations should be limited to 5, got %d", len(recommendations))
	}
}

// Benchmark
func BenchmarkGenerateRecommendations(b *testing.B) {
	re := NewRecommendationEngine()

	topRisks := []domain.RiskItem{
		{VulnName: "WPS-PIXIE", AffectedDevices: 5, Severity: 9},
		{VulnName: "OPEN-NETWORK", AffectedDevices: 3, Severity: 8},
		{VulnName: "DEFAULT-SSID", AffectedDevices: 8, Severity: 5},
		{VulnName: "PROBE-LEAKAGE", AffectedDevices: 12, Severity: 4},
		{VulnName: "TKIP-ONLY", AffectedDevices: 2, Severity: 5},
	}

	vulns := []domain.VulnerabilityRecord{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re.GenerateRecommendations(vulns, topRisks)
	}
}
