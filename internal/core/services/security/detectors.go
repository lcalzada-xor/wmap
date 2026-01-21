package security

import (
	"context"
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
type RetryRateDetector struct{}

func (d *RetryRateDetector) Name() string { return "RetryRateDetector" }

func (d *RetryRateDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	if device.PacketsCount <= 50 {
		return nil
	}

	rate := float64(device.RetryCount) / float64(device.PacketsCount)
	if rate <= 0.2 {
		return nil
	}

	d.ensureBehavioral(device)
	device.Behavioral.AnomalyDetails["HIGH_RETRY_RATE"] = rate

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "HIGH_RETRY_RATE",
		Severity:  domain.SeverityMedium,
		Message:   "High retry rate detected",
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}

func (d *RetryRateDetector) ensureBehavioral(device *domain.Device) {
	if device.Behavioral == nil {
		device.Behavioral = &domain.BehavioralProfile{}
	}
	if device.Behavioral.AnomalyDetails == nil {
		device.Behavioral.AnomalyDetails = make(map[string]float64)
	}
}

// KarmaDetector identifies potential Karma or Honeypot attacks.
type KarmaDetector struct{}

func (d *KarmaDetector) Name() string { return "KarmaDetector" }

func (d *KarmaDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	if len(device.ProbedSSIDs) <= 5 {
		return nil
	}

	if device.Behavioral == nil {
		device.Behavioral = &domain.BehavioralProfile{}
	}
	if device.Behavioral.AnomalyDetails == nil {
		device.Behavioral.AnomalyDetails = make(map[string]float64)
	}
	device.Behavioral.AnomalyDetails["KARMA"] = 0.8

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "KARMA_DETECTION",
		Severity:  domain.SeverityHigh,
		Message:   "Potential Karma attack (many probed SSIDs)",
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

	if device.Behavioral == nil {
		device.Behavioral = &domain.BehavioralProfile{}
	}
	if device.Behavioral.AnomalyDetails == nil {
		device.Behavioral.AnomalyDetails = make(map[string]float64)
	}
	device.Behavioral.AnomalyDetails["EVIL_TWIN"] = 0.9

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "EVIL_TWIN_DETECTED",
		Severity:  domain.SeverityCritical,
		Message:   "Evil Twin Detected: Security Mismatch",
		DeviceMAC: device.MAC,
		Timestamp: time.Now(),
	}}
}

// SpoofingDetector identifies OUI spoofing based on signature inconsistencies.
type SpoofingDetector struct{}

func (d *SpoofingDetector) Name() string { return "SpoofingDetector" }

func (d *SpoofingDetector) Analyze(device *domain.Device, _ ports.DeviceRegistry) []domain.Alert {
	if device.Vendor == "" || device.Model != "" || len(device.IETags) <= 5 {
		return nil
	}

	return []domain.Alert{{
		Type:      domain.AlertAnomaly,
		Subtype:   "OUI_SPOOFING",
		Severity:  domain.SeverityMedium,
		Message:   "OUI Spoofing Detected: Vendor " + device.Vendor + " but generic signature",
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
				Severity:  domain.SeverityHigh,
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
	case domain.AlertVendor:
		return device.Vendor == rule.Value
	case domain.AlertProbe:
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
