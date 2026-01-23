package reporting

import (
	"fmt"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// RecommendationEngine generates actionable security recommendations
type RecommendationEngine struct{}

// NewRecommendationEngine creates a new recommendation engine instance
func NewRecommendationEngine() *RecommendationEngine {
	return &RecommendationEngine{}
}

// GenerateRecommendations creates prioritized recommendations based on vulnerabilities and top risks
func (re *RecommendationEngine) GenerateRecommendations(
	vulns []domain.VulnerabilityRecord,
	topRisks []domain.RiskItem,
) []domain.Recommendation {

	var recommendations []domain.Recommendation

	// Generate recommendations based on top risks
	for _, risk := range topRisks {
		if rec := re.getRecommendationForVuln(risk.VulnName, risk.AffectedDevices); rec != nil {
			recommendations = append(recommendations, *rec)
		}
	}

	// Add general recommendations if we have fewer than 3
	if len(recommendations) < 3 {
		recommendations = append(recommendations, re.getGeneralRecommendations()...)
	}

	// Limit to top 5 recommendations
	if len(recommendations) > 5 {
		recommendations = recommendations[:5]
	}

	return recommendations
}

// getRecommendationForVuln returns a specific recommendation for a vulnerability type
func (re *RecommendationEngine) getRecommendationForVuln(vulnName string, affectedCount int) *domain.Recommendation {
	recommendations := map[string]domain.Recommendation{
		"OPEN-NETWORK": {
			Priority:    "critical",
			Title:       "Enable WPA3/WPA2 Encryption",
			Description: fmt.Sprintf("Found %d open networks with no encryption. All traffic is visible to attackers.", affectedCount),
			Actions: []string{
				"Enable WPA3 encryption on all access points",
				"Use strong, unique passwords (minimum 12 characters)",
				"Disable guest networks or isolate them properly",
				"Verify encryption is enabled via admin interface",
			},
			EstimatedEffort: "1-2 hours",
			ImpactReduction: 90.0,
		},
		"WPS-PIXIE": {
			Priority:    "critical",
			Title:       "Disable WPS on All Access Points",
			Description: fmt.Sprintf("%d devices vulnerable to WPS PIN attacks. Attackers can recover WiFi passwords in minutes.", affectedCount),
			Actions: []string{
				"Disable WPS on all routers immediately",
				"Change WiFi passwords after disabling WPS",
				"Verify WPS is disabled via admin interface",
				"Consider firmware updates if WPS cannot be disabled",
			},
			EstimatedEffort: "30 minutes",
			ImpactReduction: 95.0,
		},
		"WPS-ENABLED": {
			Priority:    "high",
			Title:       "Disable WPS Feature",
			Description: fmt.Sprintf("%d devices have WPS enabled. This feature is vulnerable to brute-force attacks.", affectedCount),
			Actions: []string{
				"Access router admin panel",
				"Navigate to WPS settings and disable",
				"Save configuration and reboot router",
				"Test that WPS is no longer broadcasting",
			},
			EstimatedEffort: "30 minutes",
			ImpactReduction: 80.0,
		},
		"DEFAULT-SSID": {
			Priority:    "high",
			Title:       "Change Default SSIDs and Passwords",
			Description: fmt.Sprintf("%d devices using default SSIDs, likely with default passwords.", affectedCount),
			Actions: []string{
				"Change SSIDs to non-identifying names (avoid personal info)",
				"Update admin passwords to strong, unique values",
				"Change WiFi passwords to complex passphrases",
				"Disable SSID broadcast if not needed for guest access",
			},
			EstimatedEffort: "1 hour",
			ImpactReduction: 70.0,
		},
		"WEP": {
			Priority:    "critical",
			Title:       "Upgrade from WEP to WPA3",
			Description: fmt.Sprintf("%d devices using WEP encryption, which can be cracked in minutes.", affectedCount),
			Actions: []string{
				"Check if device supports WPA2/WPA3 via firmware update",
				"Replace devices that only support WEP (end-of-life hardware)",
				"Migrate to WPA3 with strong passwords (16+ characters)",
				"Educate users on connecting to new network",
			},
			EstimatedEffort: "2-4 hours",
			ImpactReduction: 95.0,
		},
		"WEAK-WPA": {
			Priority:    "high",
			Title:       "Upgrade to WPA2/WPA3",
			Description: fmt.Sprintf("%d devices using WPA without WPA2/WPA3. Vulnerable to known attacks.", affectedCount),
			Actions: []string{
				"Enable WPA2 or WPA3 in router settings",
				"Use AES encryption (disable TKIP)",
				"Update firmware to latest version",
				"Test connectivity with all devices",
			},
			EstimatedEffort: "1-2 hours",
			ImpactReduction: 85.0,
		},
		"TKIP-ONLY": {
			Priority:    "medium",
			Title:       "Enable AES Encryption",
			Description: fmt.Sprintf("%d devices using TKIP-only encryption. AES provides stronger security.", affectedCount),
			Actions: []string{
				"Change encryption from TKIP to AES (CCMP)",
				"Enable WPA2-AES or WPA3 mode",
				"Verify all client devices support AES",
				"Monitor for connection issues after change",
			},
			EstimatedEffort: "30 minutes",
			ImpactReduction: 60.0,
		},
		"PROBE-LEAKAGE": {
			Priority:    "medium",
			Title:       "Educate Users on Privacy Settings",
			Description: fmt.Sprintf("%d client devices leaking network history via probe requests.", affectedCount),
			Actions: []string{
				"Enable MAC randomization on all devices (iOS, Android, Windows)",
				"Remove old WiFi networks from device memory",
				"Disable auto-connect for public networks",
				"Educate users on privacy implications",
			},
			EstimatedEffort: "User training session (1 hour)",
			ImpactReduction: 50.0,
		},
		"MAC-RAND-FAIL": {
			Priority:    "low",
			Title:       "Improve MAC Randomization",
			Description: fmt.Sprintf("%d devices have ineffective MAC randomization.", affectedCount),
			Actions: []string{
				"Update device OS to latest version",
				"Enable enhanced privacy features",
				"Check device manufacturer privacy settings",
				"Consider device replacement if unsupported",
			},
			EstimatedEffort: "Varies by device",
			ImpactReduction: 40.0,
		},
		"LEGACY-WEP-SUPPORT": {
			Priority:    "medium",
			Title:       "Update Client Device Security",
			Description: fmt.Sprintf("%d client devices still support legacy WEP protocol.", affectedCount),
			Actions: []string{
				"Update device drivers and firmware",
				"Disable WEP support in network adapter settings",
				"Replace very old devices that only support WEP",
				"Ensure devices connect using WPA2/WPA3",
			},
			EstimatedEffort: "2-3 hours",
			ImpactReduction: 55.0,
		},
		"LEGACY-TKIP-ONLY": {
			Priority:    "low",
			Title:       "Update Client Encryption Support",
			Description: fmt.Sprintf("%d client devices only support TKIP encryption.", affectedCount),
			Actions: []string{
				"Update device firmware/drivers",
				"Enable AES support in network settings",
				"Test connectivity with WPA2-AES networks",
				"Replace devices if AES not supported",
			},
			EstimatedEffort: "1-2 hours",
			ImpactReduction: 45.0,
		},
		"KRACK": {
			Priority:    "critical",
			Title:       "Patch KRACK Vulnerability",
			Description: fmt.Sprintf("%d devices vulnerable to KRACK (Key Reinstallation Attack).", affectedCount),
			Actions: []string{
				"Update router firmware immediately",
				"Update all client device operating systems",
				"Enable WPA3 if supported (immune to KRACK)",
				"Monitor vendor security bulletins for patches",
			},
			EstimatedEffort: "2-3 hours",
			ImpactReduction: 90.0,
		},
	}

	if rec, exists := recommendations[vulnName]; exists {
		return &rec
	}

	// Generic recommendation for unknown vulnerability types
	return &domain.Recommendation{
		Priority:    "medium",
		Title:       fmt.Sprintf("Address %s Vulnerability", vulnName),
		Description: fmt.Sprintf("Found %d devices affected by %s. Review and remediate.", affectedCount, vulnName),
		Actions: []string{
			"Research the specific vulnerability",
			"Check vendor documentation for patches",
			"Apply security updates",
			"Verify remediation effectiveness",
		},
		EstimatedEffort: "Varies",
		ImpactReduction: 50.0,
	}
}

// getGeneralRecommendations returns general security best practices
func (re *RecommendationEngine) getGeneralRecommendations() []domain.Recommendation {
	return []domain.Recommendation{
		{
			Priority:    "medium",
			Title:       "Implement Network Segmentation",
			Description: "Separate guest, IoT, and corporate networks to limit attack surface and contain potential breaches.",
			Actions: []string{
				"Create separate VLANs for different device types",
				"Implement firewall rules between segments",
				"Monitor inter-segment traffic for anomalies",
				"Document network architecture",
			},
			EstimatedEffort: "4-8 hours",
			ImpactReduction: 60.0,
		},
		{
			Priority:    "medium",
			Title:       "Enable Network Monitoring",
			Description: "Implement continuous monitoring to detect security incidents and unauthorized access attempts.",
			Actions: []string{
				"Deploy intrusion detection system (IDS)",
				"Enable logging on all network devices",
				"Set up alerts for suspicious activity",
				"Review logs weekly",
			},
			EstimatedEffort: "8-16 hours initial setup",
			ImpactReduction: 55.0,
		},
		{
			Priority:    "low",
			Title:       "Regular Security Audits",
			Description: "Schedule periodic wireless security assessments to identify new vulnerabilities and configuration drift.",
			Actions: []string{
				"Run WMAP scans monthly",
				"Review and update security policies quarterly",
				"Train staff on wireless security best practices",
				"Document findings and track remediation",
			},
			EstimatedEffort: "Ongoing (2 hours/month)",
			ImpactReduction: 40.0,
		},
		{
			Priority:    "low",
			Title:       "Implement Strong Password Policy",
			Description: "Enforce strong, unique passwords across all network devices and user accounts.",
			Actions: []string{
				"Require minimum 12-character passwords",
				"Enforce password complexity requirements",
				"Implement password rotation every 90 days",
				"Use password manager for admin credentials",
			},
			EstimatedEffort: "2-3 hours",
			ImpactReduction: 50.0,
		},
	}
}
