package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// ExecutiveReportGenerator generates executive summary reports
type ExecutiveReportGenerator struct {
	storage        ports.Storage
	deviceRegistry ports.DeviceRegistry
	riskCalc       *RiskCalculator
	recommender    *RecommendationEngine
}

// NewExecutiveReportGenerator creates a new executive report generator
func NewExecutiveReportGenerator(
	storage ports.Storage,
	registry ports.DeviceRegistry,
) *ExecutiveReportGenerator {
	return &ExecutiveReportGenerator{
		storage:        storage,
		deviceRegistry: registry,
		riskCalc:       NewRiskCalculator(),
		recommender:    NewRecommendationEngine(),
	}
}

// Generate creates an executive summary report for the specified date range
func (g *ExecutiveReportGenerator) Generate(
	ctx context.Context,
	dateRange domain.DateRange,
	orgName string,
) (*domain.ExecutiveSummary, error) {

	// Fetch all vulnerabilities
	filter := domain.VulnerabilityFilter{}
	vulns, err := g.storage.GetVulnerabilities(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerabilities: %w", err)
	}

	// Filter by date range
	vulns = g.filterByDateRange(vulns, dateRange)

	// Get unique device count from vulnerabilities
	deviceMACs := make(map[string]bool)
	for _, v := range vulns {
		deviceMACs[v.DeviceMAC] = true
	}
	deviceCount := len(deviceMACs)

	// Calculate statistics
	stats := g.calculateStats(vulns)

	// Calculate risk score
	riskScore := g.riskCalc.CalculateOverallRisk(vulns, deviceCount)
	riskLevel := g.riskCalc.GetRiskLevel(riskScore)

	// Get top 5 risks
	topRisks := g.riskCalc.CalculateTopRisks(vulns, 5)

	// Generate recommendations
	recommendations := g.recommender.GenerateRecommendations(vulns, topRisks)

	// Build report
	report := &domain.ExecutiveSummary{
		Metadata: domain.ReportMetadata{
			ID:               uuid.New().String(),
			Type:             domain.ReportTypeExecutive,
			Format:           domain.FormatPDF,
			Title:            "Executive Security Summary",
			GeneratedAt:      time.Now(),
			GeneratedBy:      "WMAP Security Scanner",
			ScanPeriod:       dateRange,
			WorkspaceName:    "default", // TODO: get from context
			OrganizationName: orgName,
		},
		RiskScore:       riskScore,
		RiskLevel:       riskLevel,
		TotalDevices:    deviceCount,
		VulnStats:       stats,
		TopRisks:        topRisks,
		Recommendations: recommendations,
	}

	return report, nil
}

// calculateStats computes vulnerability statistics
func (g *ExecutiveReportGenerator) calculateStats(vulns []domain.VulnerabilityRecord) domain.VulnerabilityStats {
	stats := domain.VulnerabilityStats{
		Total:      len(vulns),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	for _, v := range vulns {
		// By severity level
		switch {
		case v.Severity >= 9:
			stats.Critical++
			stats.BySeverity["critical"]++
		case v.Severity >= 7:
			stats.High++
			stats.BySeverity["high"]++
		case v.Severity >= 4:
			stats.Medium++
			stats.BySeverity["medium"]++
		default:
			stats.Low++
			stats.BySeverity["low"]++
		}

		// By status
		stats.ByStatus[string(v.Status)]++

		// By confidence
		if v.Confidence >= 1.0 {
			stats.Confirmed++
		} else {
			stats.Unconfirmed++
		}

		// By category (infer from vulnerability name)
		category := g.inferCategory(v.Name)
		stats.ByCategory[category]++
	}

	return stats
}

// inferCategory determines the category of a vulnerability based on its name
func (g *ExecutiveReportGenerator) inferCategory(vulnName string) string {
	switch vulnName {
	case "WEP", "TKIP", "KRACK", "WEAK-WPA", "TKIP-ONLY":
		return "Protocol Weakness"
	case "WPS-PIXIE", "WPS-ENABLED", "OPEN-NETWORK", "DEFAULT-SSID", "FT-PSK", "FT-OVER-DS":
		return "Configuration"
	case "PROBE-LEAKAGE", "MAC-RAND-FAIL", "LEGACY-WEP-SUPPORT", "LEGACY-TKIP-ONLY":
		return "Client Security"
	case "PMKID-EXPOSURE", "PMKID", "DEAUTH-FLOOD", "ROGUE-AP":
		return "Attack Surface"
	case "KARMA", "KARMA-AP", "KARMA-CLIENT":
		return "Rogue Access Point"
	case "ZERO-NONCE", "BAD-RNG", "WEAK-CRYPTO":
		return "Cryptographic Flaw"
	case "DRAGONBLOOD", "NO-PMF":
		return "Protocol Weakness"
	default:
		return "Other"
	}
}

// filterByDateRange filters vulnerabilities by date range
func (g *ExecutiveReportGenerator) filterByDateRange(
	vulns []domain.VulnerabilityRecord,
	dateRange domain.DateRange,
) []domain.VulnerabilityRecord {
	// If date range is zero (not specified), return all
	if dateRange.Start.IsZero() && dateRange.End.IsZero() {
		return vulns
	}

	var filtered []domain.VulnerabilityRecord
	for _, v := range vulns {
		// Check if vulnerability was first seen within the date range
		if !dateRange.Start.IsZero() && v.FirstSeen.Before(dateRange.Start) {
			continue
		}
		if !dateRange.End.IsZero() && v.FirstSeen.After(dateRange.End) {
			continue
		}
		filtered = append(filtered, v)
	}
	return filtered
}
