package reporting

import (
	"bytes"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestPDFExporterExportExecutiveSummary(t *testing.T) {
	exporter := NewPDFExporter()

	// Create a sample report
	report := &domain.ExecutiveSummary{
		Metadata: domain.ReportMetadata{
			ID:               "test-report-123",
			Type:             domain.ReportTypeExecutive,
			Format:           domain.FormatPDF,
			Title:            "Test Executive Summary",
			GeneratedAt:      time.Now(),
			GeneratedBy:      "Test Suite",
			OrganizationName: "Test Organization",
			ScanPeriod: domain.DateRange{
				Start: time.Now().AddDate(0, 0, -30),
				End:   time.Now(),
			},
		},
		RiskScore:    7.5,
		RiskLevel:    "High",
		TotalDevices: 25,
		VulnStats: domain.VulnerabilityStats{
			Total:       18,
			Critical:    2,
			High:        5,
			Medium:      8,
			Low:         3,
			Confirmed:   12,
			Unconfirmed: 6,
			BySeverity: map[string]int{
				"critical": 2,
				"high":     5,
				"medium":   8,
				"low":      3,
			},
			ByCategory: map[string]int{
				"Configuration":     8,
				"Protocol Weakness": 6,
				"Client Security":   4,
			},
			ByStatus: map[string]int{
				"active":  15,
				"fixed":   2,
				"ignored": 1,
			},
		},
		TopRisks: []domain.RiskItem{
			{
				Rank:            1,
				VulnName:        "WPS-PIXIE",
				Severity:        9,
				AffectedDevices: 5,
				Impact:          "High - Significant data exposure",
				Likelihood:      "High - Multiple targets",
				RiskScore:       45.0,
			},
			{
				Rank:            2,
				VulnName:        "OPEN-NETWORK",
				Severity:        8,
				AffectedDevices: 3,
				Impact:          "High - Significant data exposure",
				Likelihood:      "Medium - Several targets",
				RiskScore:       24.0,
			},
			{
				Rank:            3,
				VulnName:        "DEFAULT-SSID",
				Severity:        5,
				AffectedDevices: 8,
				Impact:          "Medium - Limited exposure",
				Likelihood:      "High - Multiple targets",
				RiskScore:       40.0,
			},
		},
		Recommendations: []domain.Recommendation{
			{
				Priority:    "critical",
				Title:       "Disable WPS on All Access Points",
				Description: "5 devices vulnerable to WPS PIN attacks.",
				Actions: []string{
					"Disable WPS on all routers immediately",
					"Change WiFi passwords after disabling WPS",
					"Verify WPS is disabled via admin interface",
				},
				EstimatedEffort: "30 minutes",
				ImpactReduction: 95.0,
			},
			{
				Priority:    "critical",
				Title:       "Enable WPA3/WPA2 Encryption",
				Description: "3 open networks with no encryption.",
				Actions: []string{
					"Enable WPA3 encryption on all access points",
					"Use strong, unique passwords",
					"Disable guest networks or isolate them",
				},
				EstimatedEffort: "1-2 hours",
				ImpactReduction: 90.0,
			},
		},
	}

	// Export to PDF
	pdfData, err := exporter.ExportExecutiveSummary(report)

	if err != nil {
		t.Fatalf("ExportExecutiveSummary() error = %v", err)
	}

	// Verify PDF data is not empty
	if len(pdfData) == 0 {
		t.Fatal("PDF data is empty")
	}

	// Verify PDF header (PDF files start with %PDF-)
	if !bytes.HasPrefix(pdfData, []byte("%PDF-")) {
		t.Error("Generated data does not have PDF header")
	}

	// Verify reasonable file size (should be at least 2KB for a report)
	if len(pdfData) < 2000 {
		t.Errorf("PDF file size %d bytes seems too small", len(pdfData))
	}

	// Verify not too large (sanity check, should be < 1MB for this simple report)
	if len(pdfData) > 1000000 {
		t.Errorf("PDF file size %d bytes seems too large", len(pdfData))
	}

	t.Logf("Generated PDF size: %d bytes", len(pdfData))
}

func TestPDFExporterWithMinimalData(t *testing.T) {
	exporter := NewPDFExporter()

	// Minimal report
	report := &domain.ExecutiveSummary{
		Metadata: domain.ReportMetadata{
			ID:          "minimal-test",
			Type:        domain.ReportTypeExecutive,
			Title:       "Minimal Report",
			GeneratedAt: time.Now(),
			GeneratedBy: "Test",
		},
		RiskScore:       2.0,
		RiskLevel:       "Low",
		TotalDevices:    1,
		VulnStats:       domain.VulnerabilityStats{Total: 0},
		TopRisks:        []domain.RiskItem{},
		Recommendations: []domain.Recommendation{},
	}

	pdfData, err := exporter.ExportExecutiveSummary(report)

	if err != nil {
		t.Fatalf("ExportExecutiveSummary() with minimal data error = %v", err)
	}

	if len(pdfData) == 0 {
		t.Fatal("PDF data is empty for minimal report")
	}

	if !bytes.HasPrefix(pdfData, []byte("%PDF-")) {
		t.Error("Minimal report does not have PDF header")
	}

	t.Logf("Minimal PDF size: %d bytes", len(pdfData))
}

func TestPDFExporterWithMaximalData(t *testing.T) {
	exporter := NewPDFExporter()

	// Create report with maximum data
	topRisks := make([]domain.RiskItem, 5)
	for i := range topRisks {
		topRisks[i] = domain.RiskItem{
			Rank:            i + 1,
			VulnName:        "VULN-" + string(rune('A'+i)),
			Severity:        9 - i,
			AffectedDevices: 10 - i,
			Impact:          "Severe - Complete compromise possible",
			Likelihood:      "Very High - Widespread vulnerability",
			RiskScore:       float64(90 - i*10),
		}
	}

	recommendations := make([]domain.Recommendation, 5)
	for i := range recommendations {
		recommendations[i] = domain.Recommendation{
			Priority:    "critical",
			Title:       "Critical Recommendation " + string(rune('A'+i)),
			Description: "This is a very long description that should test the PDF layout capabilities and ensure that text wrapping works correctly even with very long sentences that might span multiple lines in the PDF output.",
			Actions: []string{
				"Action 1 for recommendation " + string(rune('A'+i)),
				"Action 2 for recommendation " + string(rune('A'+i)),
				"Action 3 for recommendation " + string(rune('A'+i)),
				"Action 4 for recommendation " + string(rune('A'+i)),
			},
			EstimatedEffort: "2-4 hours",
			ImpactReduction: 95.0,
		}
	}

	report := &domain.ExecutiveSummary{
		Metadata: domain.ReportMetadata{
			ID:               "maximal-test",
			Type:             domain.ReportTypeExecutive,
			Title:            "Comprehensive Security Assessment Report",
			GeneratedAt:      time.Now(),
			GeneratedBy:      "WMAP Advanced Scanner",
			OrganizationName: "Large Enterprise Corporation with Very Long Name",
			ScanPeriod: domain.DateRange{
				Start: time.Now().AddDate(0, -1, 0),
				End:   time.Now(),
			},
		},
		RiskScore:    9.5,
		RiskLevel:    "Critical",
		TotalDevices: 150,
		VulnStats: domain.VulnerabilityStats{
			Total:       75,
			Critical:    15,
			High:        25,
			Medium:      20,
			Low:         15,
			Confirmed:   60,
			Unconfirmed: 15,
			BySeverity: map[string]int{
				"critical": 15,
				"high":     25,
				"medium":   20,
				"low":      15,
			},
		},
		TopRisks:        topRisks,
		Recommendations: recommendations,
	}

	pdfData, err := exporter.ExportExecutiveSummary(report)

	if err != nil {
		t.Fatalf("ExportExecutiveSummary() with maximal data error = %v", err)
	}

	if len(pdfData) == 0 {
		t.Fatal("PDF data is empty for maximal report")
	}

	if !bytes.HasPrefix(pdfData, []byte("%PDF-")) {
		t.Error("Maximal report does not have PDF header")
	}

	t.Logf("Maximal PDF size: %d bytes", len(pdfData))
}

func TestGetRiskColor(t *testing.T) {
	exporter := &PDFExporter{}

	tests := []struct {
		score float64
		name  string
	}{
		{10.0, "Critical"},
		{8.0, "Critical"},
		{7.9, "High"},
		{6.0, "High"},
		{5.9, "Medium"},
		{4.0, "Medium"},
		{3.9, "Low"},
		{0.0, "Low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, g, b := exporter.getRiskColor(tt.score)

			// Verify RGB values are in valid range
			if r < 0 || r > 255 {
				t.Errorf("Red value %d out of range [0, 255]", r)
			}
			if g < 0 || g > 255 {
				t.Errorf("Green value %d out of range [0, 255]", g)
			}
			if b < 0 || b > 255 {
				t.Errorf("Blue value %d out of range [0, 255]", b)
			}

			// Verify colors are distinct for different risk levels
			// (just a basic sanity check)
			if r == 0 && g == 0 && b == 0 {
				t.Error("Color should not be pure black")
			}
		})
	}
}

func TestGetSeverityColor(t *testing.T) {
	exporter := &PDFExporter{}

	tests := []struct {
		severity int
		name     string
	}{
		{10, "Critical"},
		{9, "Critical"},
		{8, "High"},
		{7, "High"},
		{5, "Medium"},
		{4, "Medium"},
		{3, "Low"},
		{1, "Low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, g, b := exporter.getSeverityColor(tt.severity)

			// Verify RGB values are in valid range
			if r < 0 || r > 255 {
				t.Errorf("Red value %d out of range [0, 255]", r)
			}
			if g < 0 || g > 255 {
				t.Errorf("Green value %d out of range [0, 255]", g)
			}
			if b < 0 || b > 255 {
				t.Errorf("Blue value %d out of range [0, 255]", b)
			}
		})
	}
}

func TestGetPriorityColor(t *testing.T) {
	exporter := &PDFExporter{}

	priorities := []string{"critical", "high", "medium", "low"}

	for _, priority := range priorities {
		t.Run(priority, func(t *testing.T) {
			r, g, b := exporter.getPriorityColor(priority)

			// Verify RGB values are in valid range
			if r < 0 || r > 255 {
				t.Errorf("Red value %d out of range [0, 255]", r)
			}
			if g < 0 || g > 255 {
				t.Errorf("Green value %d out of range [0, 255]", g)
			}
			if b < 0 || b > 255 {
				t.Errorf("Blue value %d out of range [0, 255]", b)
			}
		})
	}
}

// Benchmark PDF generation
func BenchmarkPDFExport(b *testing.B) {
	exporter := NewPDFExporter()

	report := &domain.ExecutiveSummary{
		Metadata: domain.ReportMetadata{
			ID:               "benchmark-test",
			Type:             domain.ReportTypeExecutive,
			Title:            "Benchmark Report",
			GeneratedAt:      time.Now(),
			GeneratedBy:      "Benchmark",
			OrganizationName: "Test Org",
		},
		RiskScore:    7.5,
		RiskLevel:    "High",
		TotalDevices: 25,
		VulnStats: domain.VulnerabilityStats{
			Total:    18,
			Critical: 2,
			High:     5,
			Medium:   8,
			Low:      3,
		},
		TopRisks: []domain.RiskItem{
			{Rank: 1, VulnName: "WPS-PIXIE", Severity: 9, AffectedDevices: 5},
			{Rank: 2, VulnName: "OPEN-NETWORK", Severity: 8, AffectedDevices: 3},
		},
		Recommendations: []domain.Recommendation{
			{Priority: "critical", Title: "Fix WPS", Description: "Test", Actions: []string{"Action 1", "Action 2"}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.ExportExecutiveSummary(report)
		if err != nil {
			b.Fatal(err)
		}
	}
}
