package domain

import "time"

// WPSAttackConfig contains the configuration for a WPS Pixie Dust attack
type WPSAttackConfig struct {
	// TargetBSSID is the MAC address of the target AP
	TargetBSSID string `json:"target_bssid"`

	// Interface is the network interface to use (monitor mode)
	Interface string `json:"interface"`

	// Channel is the channel the AP is on (optional, but recommended for speed)
	Channel int `json:"channel"`

	// TimeoutSeconds is the maximum duration to run the attack
	TimeoutSeconds int `json:"timeout_seconds"`
}

// WPSAttackStatus represents the current state of a WPS attack
type WPSAttackStatus struct {
	// ID is the unique identifier for this attack session
	ID string `json:"id"`

	// Status: "running", "success", "failed", "timeout"
	Status string `json:"status"`

	// OutputLog contains the raw stdout/stderr from the tool (for debugging)
	OutputLog string `json:"output_log"`

	// RecoveredPIN is the WPS PIN if found
	RecoveredPIN string `json:"recovered_pin,omitempty"`

	// RecoveredPSK is the WPA/WPA2 Pre-Shared Key if found
	RecoveredPSK string `json:"recovered_psk,omitempty"`

	// StartTime is when the attack started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the attack finished
	EndTime *time.Time `json:"end_time,omitempty"`

	// ErrorMessage details what went wrong
	ErrorMessage string `json:"error_message,omitempty"`
}

// WPSAttackService defines the interface for executing WPS attacks
type WPSAttackService interface {
	// StartAttack initiates a new Pixie Dust attack
	StartAttack(config WPSAttackConfig) (string, error)

	// StopAttack forces a stop of the attack with the given ID
	StopAttack(id string) error

	// GetStatus returns the current status of the attack
	GetStatus(id string) (WPSAttackStatus, error)
}
