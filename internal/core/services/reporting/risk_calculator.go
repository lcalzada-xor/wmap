package reporting

import (
	"math"
	"sort"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// RiskCalculator provides methods for calculating security risk scores
type RiskCalculator struct{}

// NewRiskCalculator creates a new risk calculator instance
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{}
}

// CalculateOverallRisk calculates the overall risk score (0-10) based on vulnerabilities and device count
func (rc *RiskCalculator) CalculateOverallRisk(vulns []domain.VulnerabilityRecord, devices int) float64 {
	if len(vulns) == 0 {
		return 0.0
	}

	// Weighted scoring based on severity and device count
	var totalRisk float64

	for _, vuln := range vulns {
		// Base risk from severity (0-10)
		severityRisk := float64(vuln.Severity)

		// Confidence multiplier (0.5 - 1.0)
		// Unconfirmed vulnerabilities count for 50%, confirmed for 100%
		confidenceMultiplier := 0.5 + (float64(vuln.Confidence) * 0.5)

		// Status multiplier
		statusMultiplier := 1.0
		if vuln.Status == domain.VulnStatusFixed {
			statusMultiplier = 0.1 // Fixed vulnerabilities have minimal impact
		} else if vuln.Status == domain.VulnStatusIgnored {
			statusMultiplier = 0.3 // Ignored vulnerabilities still pose some risk
		}

		totalRisk += severityRisk * confidenceMultiplier * statusMultiplier
	}

	// Normalize by vulnerability count to get average severity
	avgRisk := totalRisk / float64(len(vulns))

	// Device factor: more devices = higher risk
	// Formula: 1.0 + (devices / 100) caps at 2.0 for 100+ devices
	deviceFactor := 1.0 + math.Min(float64(devices)/100.0, 1.0)

	// Calculate final risk and apply device factor
	finalRisk := avgRisk * deviceFactor

	// Cap at 10.0
	return math.Min(finalRisk, 10.0)
}

// GetRiskLevel converts numeric score to human-readable level
func (rc *RiskCalculator) GetRiskLevel(score float64) string {
	switch {
	case score >= 8.0:
		return "Critical"
	case score >= 6.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	default:
		return "Low"
	}
}

// CalculateTopRisks identifies and ranks top security risks
func (rc *RiskCalculator) CalculateTopRisks(vulns []domain.VulnerabilityRecord, limit int) []domain.RiskItem {
	// Group vulnerabilities by name
	vulnGroups := make(map[string][]domain.VulnerabilityRecord)
	for _, vuln := range vulns {
		// Only consider active vulnerabilities
		if vuln.Status == domain.VulnStatusActive {
			vulnGroups[vuln.Name] = append(vulnGroups[vuln.Name], vuln)
		}
	}

	// Calculate risk for each group
	var risks []domain.RiskItem
	for name, group := range vulnGroups {
		if len(group) == 0 {
			continue
		}

		// Calculate average severity
		var totalSeverity int
		var totalConfidence float64
		for _, v := range group {
			totalSeverity += int(v.Severity)
			totalConfidence += float64(v.Confidence)
		}
		avgSeverity := totalSeverity / len(group)
		avgConfidence := totalConfidence / float64(len(group))

		// Risk score = severity * affected devices * confidence
		// This prioritizes widespread, high-severity, confirmed vulnerabilities
		riskScore := float64(avgSeverity) * float64(len(group)) * avgConfidence

		risks = append(risks, domain.RiskItem{
			VulnName:        name,
			Severity:        avgSeverity,
			AffectedDevices: len(group),
			Impact:          rc.getImpactLevel(avgSeverity),
			Likelihood:      rc.getLikelihoodLevel(len(group)),
			RiskScore:       riskScore,
		})
	}

	// Sort by risk score descending
	sort.Slice(risks, func(i, j int) bool {
		return risks[i].RiskScore > risks[j].RiskScore
	})

	// Assign ranks and limit to top N
	for i := range risks {
		risks[i].Rank = i + 1
		if i >= limit-1 {
			risks = risks[:i+1]
			break
		}
	}

	return risks
}

// getImpactLevel returns a human-readable impact description based on severity
func (rc *RiskCalculator) getImpactLevel(severity int) string {
	switch {
	case severity >= 9:
		return "Severe - Complete compromise possible"
	case severity >= 7:
		return "High - Significant data exposure"
	case severity >= 4:
		return "Medium - Limited exposure"
	default:
		return "Low - Minimal impact"
	}
}

// getLikelihoodLevel returns a human-readable likelihood description based on affected device count
func (rc *RiskCalculator) getLikelihoodLevel(affectedCount int) string {
	switch {
	case affectedCount >= 10:
		return "Very High - Widespread vulnerability"
	case affectedCount >= 5:
		return "High - Multiple targets"
	case affectedCount >= 2:
		return "Medium - Several targets"
	default:
		return "Low - Single target"
	}
}
