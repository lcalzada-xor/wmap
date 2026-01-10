package domain

import "time"

// AlertType defines the category of an alert.
type AlertType string

const (
	AlertSSID    AlertType = "SSID_MATCH"
	AlertMAC     AlertType = "MAC_MATCH"
	AlertVendor  AlertType = "VENDOR_MATCH"
	AlertProbe   AlertType = "PROBE_MATCH"
	AlertAnomaly AlertType = "ANOMALY" // e.g. Deauth Flood (future)
)

// AlertRule defines a condition to trigger an alert.
type AlertRule struct {
	ID      string    `json:"id"`
	Type    AlertType `json:"type"`
	Value   string    `json:"value"` // The value to match (e.g., "HiddenLab", "AA:BB:CC...")
	Exact   bool      `json:"exact"` // Exact match vs Contains
	Enabled bool      `json:"enabled"`
}

// Alert represents a triggered security event.
type Alert struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id,omitempty"`
	Type      AlertType `json:"type"`              // e.g. AlertAnomaly
	Subtype   string    `json:"subtype,omitempty"` // e.g. "DEAUTH"
	DeviceMAC string    `json:"device_mac"`        // Source MAC
	TargetMAC string    `json:"target_mac,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Severity  string    `json:"severity"` // "critical", "high", "medium", "low", "info"
}

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)
