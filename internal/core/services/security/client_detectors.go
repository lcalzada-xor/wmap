package security

import (
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// detectClientVulnerabilities analyzes client devices for security issues
func detectClientVulnerabilities(device *domain.Device) []domain.VulnerabilityTag {
	tags := []domain.VulnerabilityTag{}

	// 1. Probe Request Leakage - Client reveals known SSIDs
	if len(device.ProbedSSIDs) > 0 {
		tags = append(tags, detectProbeRequestLeakage(device)...)
	}

	// 2. MAC Randomization Failure
	if vulnTag := detectRandomizedMACFailure(device); vulnTag != nil {
		tags = append(tags, *vulnTag)
	}

	// 3. Legacy Protocol Support
	if vulnTag := detectLegacyProtocolSupport(device); vulnTag != nil {
		tags = append(tags, *vulnTag)
	}

	return tags
}

// detectProbeRequestLeakage identifies clients broadcasting known SSIDs
func detectProbeRequestLeakage(device *domain.Device) []domain.VulnerabilityTag {
	tags := []domain.VulnerabilityTag{}

	if len(device.ProbedSSIDs) == 0 {
		return tags
	}

	// High number of probed SSIDs indicates privacy leak
	if len(device.ProbedSSIDs) >= 3 {
		ssidList := make([]string, 0, len(device.ProbedSSIDs))
		for ssid := range device.ProbedSSIDs {
			if ssid != "" {
				ssidList = append(ssidList, ssid)
			}
		}

		if len(ssidList) > 0 {
			tags = append(tags, domain.VulnerabilityTag{
				Name:        "PROBE-LEAKAGE",
				Severity:    domain.VulnSeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Evidence:    []string{strings.Join(ssidList, ", ")},
				DetectedAt:  time.Now(),
				Category:    "privacy",
				Description: "Client broadcasts known SSIDs in probe requests, revealing location history",
				Mitigation:  "Disable auto-connect for networks or use randomized MAC addresses",
			})
		}
	}

	return tags
}

// detectRandomizedMACFailure checks if MAC randomization is improperly implemented
func detectRandomizedMACFailure(device *domain.Device) *domain.VulnerabilityTag {
	// Check if MAC appears randomized but has consistent behavior
	// Randomized MACs typically have locally administered bit set (bit 1 of first octet)
	if len(device.MAC) < 2 {
		return nil
	}

	// Check if this looks like a randomized MAC but has persistent identifiers
	// This is a simplified check - real implementation would be more sophisticated
	if device.Vendor != "" && len(device.ProbedSSIDs) > 2 {
		// If we can identify vendor despite "randomized" MAC, it's likely failing
		return &domain.VulnerabilityTag{
			Name:        "MAC-RAND-FAIL",
			Severity:    domain.VulnSeverityLow,
			Confidence:  domain.ConfidenceMedium,
			Evidence:    []string{"Vendor identified: " + device.Vendor, "Probed SSIDs reveal identity"},
			DetectedAt:  time.Now(),
			Category:    "privacy",
			Description: "MAC randomization appears ineffective - device still identifiable",
			Mitigation:  "Update device firmware or use proper MAC randomization settings",
		}
	}

	return nil
}

// detectLegacyProtocolSupport identifies clients supporting insecure protocols
func detectLegacyProtocolSupport(device *domain.Device) *domain.VulnerabilityTag {
	// Check capabilities for legacy protocol support
	for _, cap := range device.Capabilities {
		capUpper := strings.ToUpper(cap)

		// Check for WEP support
		if strings.Contains(capUpper, "WEP") {
			return &domain.VulnerabilityTag{
				Name:        "LEGACY-WEP-SUPPORT",
				Severity:    domain.VulnSeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Evidence:    []string{"WEP capability advertised"},
				DetectedAt:  time.Now(),
				Category:    "protocol",
				Description: "Client supports legacy WEP protocol - vulnerable to downgrade attacks",
				Mitigation:  "Update device firmware to remove WEP support",
			}
		}

		// Check for TKIP-only support
		if strings.Contains(capUpper, "TKIP") && !strings.Contains(capUpper, "CCMP") && !strings.Contains(capUpper, "AES") {
			return &domain.VulnerabilityTag{
				Name:        "LEGACY-TKIP-ONLY",
				Severity:    domain.VulnSeverityMedium,
				Confidence:  domain.ConfidenceHigh,
				Evidence:    []string{"TKIP-only capability"},
				DetectedAt:  time.Now(),
				Category:    "protocol",
				Description: "Client only supports TKIP cipher - vulnerable to attacks",
				Mitigation:  "Update device to support AES/CCMP",
			}
		}
	}

	return nil
}
