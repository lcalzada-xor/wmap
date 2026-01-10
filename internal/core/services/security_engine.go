package services

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// SecurityEngine implements ports.SecurityEngine.
type SecurityEngine struct {
	registry ports.DeviceRegistry
	rules    []domain.AlertRule
	rulesMu  sync.RWMutex
	alerts   []domain.Alert
	alertsMu sync.Mutex
}

// NewSecurityEngine creates a new security engine.
func NewSecurityEngine(registry ports.DeviceRegistry) *SecurityEngine {
	return &SecurityEngine{
		registry: registry,
		rules:    make([]domain.AlertRule, 0),
	}
}

func (e *SecurityEngine) AddRule(rule domain.AlertRule) {
	e.rulesMu.Lock()
	defer e.rulesMu.Unlock()
	e.rules = append(e.rules, rule)
}

func (e *SecurityEngine) GetAlerts() []domain.Alert {
	e.alertsMu.Lock()
	defer e.alertsMu.Unlock()
	alerts := make([]domain.Alert, len(e.alerts))
	copy(alerts, e.alerts)
	return alerts
}

func (e *SecurityEngine) Analyze(device domain.Device) {
	if device.Behavioral == nil {
		return
	}

	// Reset details for this analysis run to avoid stale data if we re-calculate
	// (Though ideally we accumulate periodically)
	if device.Behavioral.AnomalyDetails == nil {
		device.Behavioral.AnomalyDetails = make(map[string]float64)
	}

	// 1. Rule Evaluation
	e.evaluateRules(device)

	// 2. Heuristics
	e.validateOUI(device)
	e.checkRetryRate(device)
	e.checkKarma(device)
	e.checkEvilTwin(device)

	// 3. Final Score Calculation
	var totalScore float64
	for _, contrib := range device.Behavioral.AnomalyDetails {
		totalScore += contrib
	}
	if totalScore > 1.0 {
		totalScore = 1.0
	}
	device.Behavioral.AnomalyScore = totalScore
}

func (e *SecurityEngine) evaluateRules(device domain.Device) {
	e.rulesMu.RLock()
	defer e.rulesMu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		triggered := false
		matches := ""

		switch rule.Type {
		case domain.AlertSSID:
			if rule.Exact {
				if device.SSID == rule.Value {
					triggered = true
					matches = fmt.Sprintf("SSID matches exact: %s", device.SSID)
				}
			} else {
				if strings.Contains(strings.ToLower(device.SSID), strings.ToLower(rule.Value)) {
					triggered = true
					matches = fmt.Sprintf("SSID contains: %s", device.SSID)
				}
			}
		case domain.AlertMAC:
			if strings.EqualFold(device.MAC, rule.Value) {
				triggered = true
				matches = fmt.Sprintf("MAC address match: %s", device.MAC)
			}
		case domain.AlertProbe:
			for ssid := range device.ProbedSSIDs {
				if rule.Exact {
					if ssid == rule.Value {
						triggered = true
						matches = fmt.Sprintf("Probed SSID match: %s", ssid)
						break
					}
				} else {
					if strings.Contains(strings.ToLower(ssid), strings.ToLower(rule.Value)) {
						triggered = true
						matches = fmt.Sprintf("Probed SSID contains: %s", ssid)
						break
					}
				}
			}
		}

		if triggered {
			e.addAlert(domain.Alert{
				ID:        uuid.New().String(),
				RuleID:    rule.ID,
				DeviceMAC: device.MAC,
				Timestamp: time.Now(),
				Message:   fmt.Sprintf("Rule '%s' triggered", rule.ID),
				Details:   matches,
			})
			// Custom rules add to anomaly score
			device.Behavioral.AnomalyDetails["CUSTOM_RULE_"+rule.ID] = 0.2
		}
	}
}

func (e *SecurityEngine) validateOUI(device domain.Device) {
	vendor := strings.ToLower(device.Vendor)
	if vendor == "apple" && device.OS != "iOS/macOS" && device.OS != "iOS" && len(device.IETags) > 5 {
		e.addAlert(domain.Alert{
			Type:      domain.AlertAnomaly,
			Subtype:   "OUI_SPOOFING",
			DeviceMAC: device.MAC,
			Timestamp: time.Now(),
			Message:   "Potential MAC Spoofing: Apple OUI but missing iOS IE patterns",
		})
		device.Behavioral.AnomalyDetails["OUI_SPOOFING"] = 0.5
	}
}

func (e *SecurityEngine) checkRetryRate(device domain.Device) {
	if device.PacketsCount > 20 {
		rate := float64(device.RetryCount) / float64(device.PacketsCount)
		if rate > 0.2 {
			e.addAlert(domain.Alert{
				Type:      domain.AlertAnomaly,
				Subtype:   "HIGH_RETRY_RATE",
				DeviceMAC: device.MAC,
				Timestamp: time.Now(),
				Message:   fmt.Sprintf("High Retry Rate detected: %.2f%%. Possible jamming or interference.", rate*100),
			})
			device.Behavioral.AnomalyDetails["HIGH_RETRY_RATE"] = 0.3
		}
	}
}

func (e *SecurityEngine) checkKarma(device domain.Device) {
	if device.Type != "ap" {
		return
	}
	if len(device.ProbedSSIDs) > 5 {
		e.addAlert(domain.Alert{
			Type:      domain.AlertAnomaly,
			Subtype:   "KARMA_DETECTION",
			DeviceMAC: device.MAC,
			Timestamp: time.Now(),
			Message:   "Potential Karma/Honeypot AP: Responding to multiple unique SSIDs.",
		})
		device.Behavioral.AnomalyDetails["KARMA"] = 0.8
	}
}

func (e *SecurityEngine) checkEvilTwin(device domain.Device) {
	if device.Type != "ap" || device.SSID == "" || device.SSID == "<HIDDEN>" {
		return
	}

	expected, ok := e.registry.GetSSIDSecurity(device.SSID)
	if !ok {
		return
	}

	if expected != device.Security {
		// Specific check for existing APs with same SSID but different security
		all := e.registry.GetAllDevices()
		for _, d := range all {
			if d.Type == "ap" && d.SSID == device.SSID && d.MAC != device.MAC {
				if d.Security != device.Security {
					e.addAlert(domain.Alert{
						ID:        uuid.New().String(),
						Type:      domain.AlertAnomaly,
						Subtype:   "EVIL_TWIN_DETECTED",
						DeviceMAC: device.MAC,
						TargetMAC: d.MAC,
						Timestamp: time.Now(),
						Message:   fmt.Sprintf("Potential Evil Twin: SSID '%s' seen with %s security (expected %s)", device.SSID, device.Security, d.Security),
					})
					device.Behavioral.AnomalyDetails["EVIL_TWIN"] = 0.9
					return
				}
			}
		}
	}
}

func (e *SecurityEngine) addAlert(alert domain.Alert) {
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	e.alertsMu.Lock()
	e.alerts = append(e.alerts, alert)
	e.alertsMu.Unlock()
	fmt.Printf("[ALERT] id=%s type=%s subtype=%s device=%s msg=%s\n", alert.ID, alert.Type, alert.Subtype, alert.DeviceMAC, alert.Message)
}
