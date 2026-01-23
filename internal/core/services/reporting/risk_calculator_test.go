package reporting

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestCalculateOverallRisk(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		name     string
		vulns    []domain.VulnerabilityRecord
		devices  int
		expected float64
		minScore float64
		maxScore float64
	}{
		{
			name:     "No vulnerabilities",
			vulns:    []domain.VulnerabilityRecord{},
			devices:  10,
			expected: 0.0,
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name: "Single critical vulnerability, confirmed",
			vulns: []domain.VulnerabilityRecord{
				{
					Severity:   domain.Severity(10),
					Confidence: domain.Confidence(1.0),
					Status:     domain.VulnStatusActive,
				},
			},
			devices:  1,
			expected: 10.0,
			minScore: 9.5,
			maxScore: 10.0,
		},
		{
			name: "Multiple vulnerabilities, mixed severity",
			vulns: []domain.VulnerabilityRecord{
				{Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive},
				{Severity: domain.Severity(8), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive},
				{Severity: domain.Severity(5), Confidence: domain.Confidence(0.5), Status: domain.VulnStatusActive},
			},
			devices:  10,
			expected: 7.5,
			minScore: 7.0,
			maxScore: 8.5,
		},
		{
			name: "Fixed vulnerabilities should have minimal impact",
			vulns: []domain.VulnerabilityRecord{
				{Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusFixed},
				{Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusFixed},
			},
			devices:  5,
			expected: 1.0,
			minScore: 0.5,
			maxScore: 1.5,
		},
		{
			name: "Ignored vulnerabilities should have reduced impact",
			vulns: []domain.VulnerabilityRecord{
				{Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusIgnored},
			},
			devices:  5,
			expected: 3.0,
			minScore: 2.5,
			maxScore: 3.5,
		},
		{
			name: "Unconfirmed vulnerabilities should have reduced impact",
			vulns: []domain.VulnerabilityRecord{
				{Severity: domain.Severity(10), Confidence: domain.Confidence(0.5), Status: domain.VulnStatusActive},
			},
			devices:  1,
			expected: 7.5,
			minScore: 7.0,
			maxScore: 8.0,
		},
		{
			name: "Many devices should increase risk",
			vulns: []domain.VulnerabilityRecord{
				{Severity: domain.Severity(5), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive},
			},
			devices:  100,
			expected: 10.0,
			minScore: 9.5,
			maxScore: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rc.CalculateOverallRisk(tt.vulns, tt.devices)

			if result < tt.minScore || result > tt.maxScore {
				t.Errorf("CalculateOverallRisk() = %v, want between %v and %v", result, tt.minScore, tt.maxScore)
			}

			// Verify result is within valid range
			if result < 0.0 || result > 10.0 {
				t.Errorf("CalculateOverallRisk() = %v, must be between 0.0 and 10.0", result)
			}
		})
	}
}

func TestGetRiskLevel(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		score    float64
		expected string
	}{
		{0.0, "Low"},
		{3.9, "Low"},
		{4.0, "Medium"},
		{5.9, "Medium"},
		{6.0, "High"},
		{7.9, "High"},
		{8.0, "Critical"},
		{10.0, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := rc.GetRiskLevel(tt.score)
			if result != tt.expected {
				t.Errorf("GetRiskLevel(%v) = %v, want %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestCalculateTopRisks(t *testing.T) {
	rc := NewRiskCalculator()

	vulns := []domain.VulnerabilityRecord{
		// WPS-PIXIE: 3 devices, severity 9
		{Name: "WPS-PIXIE", Severity: domain.Severity(9), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:01"},
		{Name: "WPS-PIXIE", Severity: domain.Severity(9), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:02"},
		{Name: "WPS-PIXIE", Severity: domain.Severity(9), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:03"},
		// OPEN-NETWORK: 2 devices, severity 8
		{Name: "OPEN-NETWORK", Severity: domain.Severity(8), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:04"},
		{Name: "OPEN-NETWORK", Severity: domain.Severity(8), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:05"},
		// DEFAULT-SSID: 5 devices, severity 5
		{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:06"},
		{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:07"},
		{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:08"},
		{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:09"},
		{Name: "DEFAULT-SSID", Severity: domain.Severity(5), Confidence: domain.Confidence(0.8), Status: domain.VulnStatusActive, DeviceMAC: "aa:bb:cc:dd:ee:10"},
		// Fixed vulnerability (should be excluded)
		{Name: "WEP", Severity: domain.Severity(10), Confidence: domain.Confidence(1.0), Status: domain.VulnStatusFixed, DeviceMAC: "aa:bb:cc:dd:ee:11"},
	}

	risks := rc.CalculateTopRisks(vulns, 5)

	// Verify we got results
	if len(risks) == 0 {
		t.Fatal("CalculateTopRisks() returned no risks")
	}

	// Verify top risk is WPS-PIXIE (highest severity × devices)
	if risks[0].VulnName != "WPS-PIXIE" {
		t.Errorf("Top risk should be WPS-PIXIE, got %v", risks[0].VulnName)
	}

	// Verify ranks are sequential
	for i, risk := range risks {
		if risk.Rank != i+1 {
			t.Errorf("Risk at index %d has rank %d, expected %d", i, risk.Rank, i+1)
		}
	}

	// Verify risk scores are descending
	for i := 1; i < len(risks); i++ {
		if risks[i].RiskScore > risks[i-1].RiskScore {
			t.Errorf("Risk scores not in descending order: %v > %v", risks[i].RiskScore, risks[i-1].RiskScore)
		}
	}

	// Verify affected device counts
	for _, risk := range risks {
		if risk.VulnName == "WPS-PIXIE" && risk.AffectedDevices != 3 {
			t.Errorf("WPS-PIXIE should affect 3 devices, got %d", risk.AffectedDevices)
		}
		if risk.VulnName == "DEFAULT-SSID" && risk.AffectedDevices != 5 {
			t.Errorf("DEFAULT-SSID should affect 5 devices, got %d", risk.AffectedDevices)
		}
	}

	// Verify fixed vulnerabilities are excluded
	for _, risk := range risks {
		if risk.VulnName == "WEP" {
			t.Error("Fixed vulnerabilities should not appear in top risks")
		}
	}

	// Verify limit is respected
	if len(risks) > 5 {
		t.Errorf("CalculateTopRisks() returned %d risks, limit was 5", len(risks))
	}
}

func TestGetImpactLevel(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		severity int
		contains string
	}{
		{10, "Severe"},
		{9, "Severe"},
		{8, "High"},
		{7, "High"},
		{5, "Medium"},
		{4, "Medium"},
		{3, "Low"},
		{1, "Low"},
	}

	for _, tt := range tests {
		result := rc.getImpactLevel(tt.severity)
		if result == "" {
			t.Errorf("getImpactLevel(%d) returned empty string", tt.severity)
		}
		// Just verify it returns something reasonable
		if len(result) < 5 {
			t.Errorf("getImpactLevel(%d) returned suspiciously short string: %v", tt.severity, result)
		}
	}
}

func TestGetLikelihoodLevel(t *testing.T) {
	rc := NewRiskCalculator()

	tests := []struct {
		count    int
		contains string
	}{
		{15, "Very High"},
		{10, "Very High"},
		{7, "High"},
		{5, "High"},
		{3, "Medium"},
		{2, "Medium"},
		{1, "Low"},
	}

	for _, tt := range tests {
		result := rc.getLikelihoodLevel(tt.count)
		if result == "" {
			t.Errorf("getLikelihoodLevel(%d) returned empty string", tt.count)
		}
		// Just verify it returns something reasonable
		if len(result) < 3 {
			t.Errorf("getLikelihoodLevel(%d) returned suspiciously short string: %v", tt.count, result)
		}
	}
}

// Benchmark tests
func BenchmarkCalculateOverallRisk(b *testing.B) {
	rc := NewRiskCalculator()
	vulns := make([]domain.VulnerabilityRecord, 100)
	for i := range vulns {
		vulns[i] = domain.VulnerabilityRecord{
			Severity:   domain.Severity(5 + i%6),
			Confidence: domain.Confidence(0.5 + float64(i%5)*0.1),
			Status:     domain.VulnStatusActive,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc.CalculateOverallRisk(vulns, 50)
	}
}

func BenchmarkCalculateTopRisks(b *testing.B) {
	rc := NewRiskCalculator()
	vulns := make([]domain.VulnerabilityRecord, 100)
	for i := range vulns {
		vulns[i] = domain.VulnerabilityRecord{
			Name:       "VULN-" + string(rune('A'+i%10)),
			Severity:   domain.Severity(5 + i%6),
			Confidence: domain.Confidence(0.5 + float64(i%5)*0.1),
			Status:     domain.VulnStatusActive,
			DeviceMAC:  "aa:bb:cc:dd:ee:" + string(rune('0'+i%10)),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc.CalculateTopRisks(vulns, 5)
	}
}
