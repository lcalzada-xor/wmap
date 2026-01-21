package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Domain Errors for Alerting
var (
	ErrInvalidRuleType = errors.New("invalid alert rule type")
	ErrEmptyRuleValue  = errors.New("alert rule value cannot be empty")
	ErrInvalidSeverity = errors.New("invalid alert severity level")
)

// AlertType defines the category of an alert.
type AlertType string

const (
	AlertSSID    AlertType = "SSID_MATCH"
	AlertMAC     AlertType = "MAC_MATCH"
	AlertVendor  AlertType = "VENDOR_MATCH"
	AlertProbe   AlertType = "PROBE_MATCH"
	AlertAnomaly AlertType = "ANOMALY" // e.g. Deauth Flood, Rogue AP
)

// AlertSeverity represents the criticality of a security event.
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityHigh     AlertSeverity = "high"
	SeverityMedium   AlertSeverity = "medium"
	SeverityLow      AlertSeverity = "low"
	SeverityInfo     AlertSeverity = "info"
)

// AlertRule defines the criteria used by the engine to trigger alerts.
type AlertRule struct {
	ID      string    `json:"id"`
	Type    AlertType `json:"type"`
	Value   string    `json:"value"` // The value to match (e.g., "HiddenLab", "AA:BB:CC...")
	Exact   bool      `json:"exact"` // If true, performs a literal match; otherwise, partial (case-insensitive)
	Enabled bool      `json:"enabled"`
}

// Validate performs internal consistency checks on the rule.
func (r *AlertRule) Validate() error {
	if strings.TrimSpace(r.Value) == "" {
		return ErrEmptyRuleValue
	}

	switch r.Type {
	case AlertSSID, AlertMAC, AlertVendor, AlertProbe, AlertAnomaly:
		return nil
	default:
		return ErrInvalidRuleType
	}
}

// Matches evaluates if a given input string satisfies the rule's criteria.
func (r *AlertRule) Matches(input string) bool {
	if !r.Enabled {
		return false
	}

	if r.Exact {
		return r.Value == input
	}

	return strings.Contains(
		strings.ToLower(input),
		strings.ToLower(r.Value),
	)
}

// Alert represents a specific security event triggered by the system.
type Alert struct {
	ID        string        `json:"id"`
	RuleID    string        `json:"rule_id,omitempty"` // Reference to the rule that triggered it
	Type      AlertType     `json:"type"`
	Subtype   string        `json:"subtype,omitempty"` // e.g., "DEAUTH_FLOOD"
	DeviceMAC string        `json:"device_mac"`        // Originating MAC address
	TargetMAC string        `json:"target_mac,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Message   string        `json:"message"`
	Details   string        `json:"details,omitempty"`
	Severity  AlertSeverity `json:"severity"`
}

// NewAlert creates a new Alert instance while ensuring the severity domain invariant.
func NewAlert(ruleID string, aType AlertType, deviceMac, message string, severity AlertSeverity) (*Alert, error) {
	if !isValidSeverity(severity) {
		return nil, ErrInvalidSeverity
	}

	return &Alert{
		ID:        fmt.Sprintf("alt_%d", time.Now().UnixNano()), // TODO: Integrate UUID v4 here
		RuleID:    ruleID,
		Type:      aType,
		DeviceMAC: deviceMac,
		Timestamp: time.Now().UTC(),
		Message:   message,
		Severity:  severity,
	}, nil
}

// isValidSeverity encapsulates the validation logic for severity levels.
func isValidSeverity(s AlertSeverity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

/*
ARCHITECTURAL NOTE:
AlertRule matching is currently string-based for simplicity. If rules expand to
complex RSSI thresholds or temporal patterns, consider extracting the logic to
a 'RuleMatcher' interface within the core/services layer while keeping the
criteria in this domain entity.
*/
