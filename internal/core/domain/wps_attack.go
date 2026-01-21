package domain

import (
	"errors"
	"time"
)

// WPSStatus represents the current lifecycle state of a WPS attack.
type WPSStatus string

const (
	WPSStatusPending        WPSStatus = "pending"
	WPSStatusRunning        WPSStatus = "running"
	WPSStatusAssociating    WPSStatus = "associating"
	WPSStatusExchangingKeys WPSStatus = "exchanging_keys"
	WPSStatusCracking       WPSStatus = "cracking"
	WPSStatusSuccess        WPSStatus = "success"
	WPSStatusFailed         WPSStatus = "failed"
	WPSStatusTimeout        WPSStatus = "timeout"
)

// Domain Errors
var (
	ErrWPSInvalidConfig = errors.New("invalid wps attack configuration")
	ErrWPSAttackStopped = errors.New("wps attack was stopped prematurely")
)

// WPSAttackConfig contains the configuration for a WPS Pixie Dust attack.
// It maps to low-level tool parameters but provides a clean domain boundary.
type WPSAttackConfig struct {
	// TargetBSSID is the MAC address of the target AP.
	TargetBSSID string `json:"target_bssid"`

	// Interface is the network interface to use (must be in monitor mode).
	Interface string `json:"interface"`

	// Channel is the frequency channel the AP is operating on.
	Channel int `json:"channel"`

	// TimeoutSeconds is the maximum duration for the attack session.
	TimeoutSeconds int `json:"timeout_seconds"`

	// Advanced Pixie Dust Options
	ForcePixie   bool `json:"force_pixie"`   // -K: Force Pixie Dust attack
	UseSmallDH   bool `json:"use_small_dh"`  // -S: Use small DH keys
	IgnoreLocks  bool `json:"ignore_locks"`  // -L: Ignore AP locks
	NoNacks      bool `json:"no_nacks"`      // -N: Do not send NACKs
	ImitateWin7  bool `json:"imitate_win7"`  // -w: Imitate Windows 7 registrar behavior
	Delay        int  `json:"delay"`         // -d: Delay between PIN attempts (seconds)
	FailWait     int  `json:"fail_wait"`     // -f: Wait time after a failure (seconds)
	EAPOLTimeout int  `json:"eapol_timeout"` // -t: EAPOL receive timeout (seconds)
}

// NewWPSAttackConfig creates a new configuration with industry-standard defaults for Pixie Dust.
func NewWPSAttackConfig(bssid, iface string, channel int) WPSAttackConfig {
	return WPSAttackConfig{
		TargetBSSID:    bssid,
		Interface:      iface,
		Channel:        channel,
		TimeoutSeconds: 300, // 5 minutes default
		ForcePixie:     true,
		UseSmallDH:     true,
		IgnoreLocks:    true,
		NoNacks:        true,
		ImitateWin7:    false,
		Delay:          0,
		FailWait:       0,
		EAPOLTimeout:   5,
	}
}

// Validate ensures the configuration is semantically correct before execution.
func (c *WPSAttackConfig) Validate() error {
	if !IsValidMAC(c.TargetBSSID) {
		return errors.New("invalid target BSSID format")
	}
	if !IsValidInterface(c.Interface) {
		return errors.New("invalid network interface name")
	}
	if c.Channel < 1 || c.Channel > 165 {
		return errors.New("wifi channel out of valid range")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("timeout must be a positive value")
	}
	return nil
}

// WPSAttackStatus represents the snapshot of a WPS attack execution.
type WPSAttackStatus struct {
	// ID is the unique identifier for this attack session.
	ID string `json:"id"`

	// Status represents the current state (running, success, etc.).
	Status WPSStatus `json:"status"`

	// OutputLog contains raw diagnostic data from the underlying tool.
	OutputLog string `json:"output_log"`

	// Results
	RecoveredPIN string `json:"recovered_pin,omitempty"`
	RecoveredPSK string `json:"recovered_psk,omitempty"`

	// Timeline
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// ErrorMessage details if Status is WPSStatusFailed.
	ErrorMessage string `json:"error_message,omitempty"`
}

// IsActive returns true if the attack is in a non-terminal state.
func (s *WPSAttackStatus) IsActive() bool {
	return s.Status == WPSStatusRunning || s.Status == WPSStatusPending
}

// Duration calculates the elapsed time since the attack started.
func (s *WPSAttackStatus) Duration() time.Duration {
	if s.EndTime != nil {
		return s.EndTime.Sub(s.StartTime)
	}
	return time.Since(s.StartTime)
}

// WPSAttackService provides the domain-level ports for orchestrating WPS attacks.
// Implementations (adapters) should handle the translation to binary tool calls (e.g., reaver).
type WPSAttackService interface {
	// StartAttack initiates a new Pixie Dust session.
	StartAttack(config WPSAttackConfig) (string, error)

	// StopAttack signals an active attack session to terminate.
	StopAttack(id string) error

	// GetStatus retrieves the most recent state of an attack session.
	GetStatus(id string) (WPSAttackStatus, error)
}
