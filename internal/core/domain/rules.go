package domain

import "time"

type AlertType string

const (
	AlertAnomaly AlertType = "anomaly"
	AlertSSID    AlertType = "ssid_match"
	AlertMAC     AlertType = "mac_match"
)

type Alert struct {
	ID        string    `json:"id"`
	Type      AlertType `json:"type"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	DeviceMAC string    `json:"device_mac,omitempty"`
	Subtype   string    `json:"subtype,omitempty"`
	TargetMAC string    `json:"target_mac,omitempty"`
	Details   string    `json:"details,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	HandshakeFile string    `json:"handshake_file,omitempty"`
}

type AlertRule struct {
	ID          string    `json:"id"`
	Type        AlertType `json:"type"`
	TargetValue string    `json:"target_value"`
	Enabled     bool      `json:"enabled"`
	Severity    string    `json:"severity"`
	Description string    `json:"description,omitempty"`
	Value       string    `json:"value,omitempty"`
	Exact       bool      `json:"exact,omitempty"`
}
