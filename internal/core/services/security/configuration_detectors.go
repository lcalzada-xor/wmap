package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// detectConfigurationVulnerabilitiesEnhanced performs enhanced configuration-based detection
func detectConfigurationVulnerabilitiesEnhanced(device *domain.Device, vendorDB *VendorDatabase) []domain.VulnerabilityTag {
	tags := []domain.VulnerabilityTag{}

	// 1. Open Network Detection
	if vulnTag := detectOpenNetwork(device); vulnTag != nil {
		tags = append(tags, *vulnTag)
	}

	// 2. Default SSID Detection
	if vendorDB != nil {
		if vulnTag := detectDefaultSSID(device, vendorDB); vulnTag != nil {
			tags = append(tags, *vulnTag)
		}
	}

	// 3. Weak Cipher Suites
	if vulnTag := detectWeakCipherSuites(device); vulnTag != nil {
		tags = append(tags, *vulnTag)
	}

	return tags
}

// detectOpenNetwork identifies networks without encryption
func detectOpenNetwork(device *domain.Device) *domain.VulnerabilityTag {
	if device.Type != domain.DeviceTypeAP {
		return nil
	}

	securityUpper := strings.ToUpper(device.Security)

	// Check for open/no security
	if device.Security == "" || securityUpper == "OPEN" || securityUpper == "NONE" {
		return &domain.VulnerabilityTag{
			Name:        "OPEN-NETWORK",
			Severity:    domain.VulnSeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Evidence:    []string{"No encryption detected"},
			DetectedAt:  time.Now(),
			Category:    "configuration",
			Description: "Network is completely open - all traffic is visible to attackers",
			Mitigation:  "Enable WPA2-PSK (AES) or WPA3 encryption immediately",
		}
	}

	return nil
}

// detectDefaultSSID identifies networks using default manufacturer SSIDs
func detectDefaultSSID(device *domain.Device, vendorDB *VendorDatabase) *domain.VulnerabilityTag {
	if device.Type != domain.DeviceTypeAP || device.SSID == "" {
		return nil
	}

	isDefault, vendorInfo := vendorDB.IsDefaultSSID(device.SSID)
	if !isDefault {
		return nil
	}

	evidence := []string{
		fmt.Sprintf("SSID '%s' matches default pattern for %s", device.SSID, vendorInfo.Vendor),
	}

	if vendorInfo.DefaultPassword != "" {
		evidence = append(evidence, fmt.Sprintf("Default password likely: '%s'", vendorInfo.DefaultPassword))
	}

	return &domain.VulnerabilityTag{
		Name:        "DEFAULT-SSID",
		Severity:    domain.VulnSeverityMedium,
		Confidence:  domain.ConfidenceHigh,
		Evidence:    evidence,
		DetectedAt:  time.Now(),
		Category:    "configuration",
		Description: "Default SSID suggests router may have default configuration including weak password",
		Mitigation:  "Change SSID and password, review all router security settings",
	}
}

// detectWeakCipherSuites identifies use of deprecated or weak encryption
func detectWeakCipherSuites(device *domain.Device) *domain.VulnerabilityTag {
	if device.Type != domain.DeviceTypeAP {
		return nil
	}

	securityUpper := strings.ToUpper(device.Security)

	// Check for WPA (not WPA2/WPA3)
	if securityUpper == "WPA" || (strings.Contains(securityUpper, "WPA") && !strings.Contains(securityUpper, "WPA2") && !strings.Contains(securityUpper, "WPA3")) {
		return &domain.VulnerabilityTag{
			Name:        "WEAK-WPA",
			Severity:    domain.VulnSeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Evidence:    []string{"WPA (not WPA2/WPA3) detected"},
			DetectedAt:  time.Now(),
			Category:    "protocol",
			Description: "WPA without WPA2/WPA3 is vulnerable to various attacks",
			Mitigation:  "Upgrade to WPA2-PSK (AES) or WPA3",
		}
	}

	// Check RSN Info for weak ciphers
	if device.RSNInfo != nil {
		// Check for TKIP as the only cipher
		hasTKIP := false
		hasCCMP := false

		for _, cipher := range device.RSNInfo.PairwiseCiphers {
			cipherUpper := strings.ToUpper(cipher)
			if cipherUpper == "TKIP" {
				hasTKIP = true
			}
			if cipherUpper == "CCMP" || cipherUpper == "AES" {
				hasCCMP = true
			}
		}

		if hasTKIP && !hasCCMP {
			return &domain.VulnerabilityTag{
				Name:        "TKIP-ONLY",
				Severity:    domain.VulnSeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Evidence:    []string{"TKIP cipher without AES/CCMP"},
				DetectedAt:  time.Now(),
				Category:    "protocol",
				Description: "TKIP-only configuration is deprecated and vulnerable",
				Mitigation:  "Enable AES/CCMP cipher support",
			}
		}
	}

	return nil
}
