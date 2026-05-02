package security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// Detector defines the interface for security analysis modules.
type Detector interface {
	Name() string
	Analyze(device *domain.Device, registry ports.DeviceRegistry) []domain.Alert
}

// RetryRateDetector checks for devices with abnormally high retry rates.
// Requires >=200 packets to avoid noise from sparse samples, and a >40% rate
// to avoid FPs from weak-signal / congested-band scenarios (20% is too low).
// Devices with RSSI below -75 dBm are skipped: high retries at low signal
// are expected RF behaviour, not an attack indicator.
type RetryRateDetector struct{}

func (d *RetryRateDetector) Name() string { return "RetryRateDetector" }

func (d *RetryRateDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	if device.PacketsCount < 200 {
		return nil
	}
	// Weak signal → high retries are normal physics, not anomalous
	if device.RSSI != 0 && device.RSSI < -75 {
		return nil
	}

	rate := float64(device.RetryCount) / float64(device.PacketsCount)
	if rate <= 0.40 {
		return nil
	}

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "HIGH_RETRY_RATE",
		Severity:  "Medium",
		Message:   fmt.Sprintf("High retry rate detected (%.0f%%)", rate*100),
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}


// ClientKarmaDetector identifies stations sending an unusually high number of
// directed probe requests in a short window — a Karma/Honeypot attack indicator.
// The threshold is deliberately high (20) because any smartphone carries a long
// history of saved networks and probes for many of them passively. We also
// require at least 5 of those probes to have occurred within the last 2 minutes
// to distinguish active scanning from a stale historical list.
type ClientKarmaDetector struct{}

func (d *ClientKarmaDetector) Name() string { return "ClientKarmaDetector" }

func (d *ClientKarmaDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	const totalThreshold = 20
	const recentThreshold = 5
	const recentWindow = 2 * time.Minute

	if len(device.ProbedSSIDs) < totalThreshold {
		return nil
	}

	// Count probes seen within the recent window to avoid FPs from stale history
	now := time.Now()
	recentCount := 0
	for _, ts := range device.ProbedSSIDs {
		if now.Sub(ts) <= recentWindow {
			recentCount++
		}
	}
	if recentCount < recentThreshold {
		return nil
	}

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "KARMA_DETECTION",
		Severity:  "High",
		Message:   fmt.Sprintf("Excessive directed probes (%d total, %d recent)", len(device.ProbedSSIDs), recentCount),
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}

// EvilTwinDetector detects SSID mismatches or suspicious AP behavior.
type EvilTwinDetector struct{}

func (d *EvilTwinDetector) Name() string { return "EvilTwinDetector" }

func (d *EvilTwinDetector) Analyze(device *domain.Device, registry ports.DeviceRegistry) []domain.Alert {
	if device.SSID == "" || device.Type != "ap" {
		return nil
	}

	expectedSecurity, known := registry.GetSSIDSecurity(context.Background(), device.SSID)
	if !known || expectedSecurity == "" || device.Security == expectedSecurity {
		return nil
	}

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "EVIL_TWIN_DETECTED",
		Severity:  "Critical",
		Message:   "Evil Twin Detected: Security Mismatch",
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}

// SpoofingDetector identifies likely OUI spoofing: the MAC resolves to a known
// vendor (Vendor != "") yet the device carries no model fingerprint and fewer
// than 6 IE tags — a combination inconsistent with a genuine device from that
// vendor. Randomized MACs are excluded because their OUI is intentionally fake.
type SpoofingDetector struct{}

func (d *SpoofingDetector) Name() string { return "SpoofingDetector" }

func (d *SpoofingDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	// Need a vendor hit to have something to spoof
	if device.Vendor == "" {
		return nil
	}
	// Randomized MACs are deliberately using a fake OUI — not a spoof indicator
	if device.IsRandomized {
		return nil
	}
	// A genuine device from that vendor should have either a model fingerprint
	// or a reasonably rich IE set (≥6 tags). If both are absent, the OUI may
	// be spoofed.
	if device.Model != "" || len(device.IETags) >= 6 {
		return nil
	}

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "OUI_SPOOFING",
		Severity:  "Medium",
		Message:   "Possible OUI spoofing: vendor " + device.Vendor + " but no matching fingerprint",
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}

// APKarmaDetector identifies APs acting as Karma/Mana (single BSSID advertising
// many distinct SSIDs). A threshold of >=4 is used because it is completely
// normal for a home or enterprise AP to advertise 2–3 SSIDs via separate VAPs
// (main + guest, 2.4GHz + 5GHz band-steering, etc.). Karma/Mana APs typically
// answer every probe with a matching SSID, so they accumulate dozens quickly.
type APKarmaDetector struct{}

func (d *APKarmaDetector) Name() string { return "APKarmaDetector" }

func (d *APKarmaDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	const minSSIDs = 4

	if device.Type != "ap" || len(device.ObservedSSIDs) < minSSIDs {
		return nil
	}

	details := fmt.Sprintf("BSSID advertising %d distinct SSIDs: %v", len(device.ObservedSSIDs), device.ObservedSSIDs)

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "KARMA_AP_DETECTED",
		Severity:  "Critical",
		Message:   fmt.Sprintf("Karma/Mana AP: single BSSID with %d SSIDs", len(device.ObservedSSIDs)),
		Details:   details,
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}


// RuleDetector evaluates user-defined alert rules.
type RuleDetector struct {
	engine *SecurityEngine
}

func (d *RuleDetector) Name() string { return "RuleDetector" }

func (d *RuleDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	d.engine.mu.RLock()
	rules := make([]domain.AlertRule, len(d.engine.rules))
	copy(rules, d.engine.rules)
	d.engine.mu.RUnlock()

	var alerts []domain.Alert
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if d.matchRule(device, rule) {
			alerts = append(alerts, domain.Alert{
				Type:      rule.Type,
				Subtype:   "RULE_MATCH",
				RuleID:    rule.ID,
				Severity:  "High",
				Message:   "Security Rule Triggered: " + rule.Value,
				DeviceMAC: device.MAC,
				Timestamp: time.Now(),
			})
		}
	}
	return alerts
}

func (d *RuleDetector) matchRule(device *domain.Device, rule domain.AlertRule) bool {
	switch rule.Type {
	case domain.AlertSSID:
		if rule.Exact {
			return device.SSID == rule.Value
		}
		return strings.Contains(device.SSID, rule.Value)
	case domain.AlertMAC:
		return device.MAC == rule.Value
	case "VENDOR":
		return device.Vendor == rule.Value
	case "PROBE":
		for ssid := range device.ProbedSSIDs {
			if rule.Exact {
				if ssid == rule.Value {
					return true
				}
			} else if strings.Contains(ssid, rule.Value) {
				return true
			}
		}
	}
	return false
}
