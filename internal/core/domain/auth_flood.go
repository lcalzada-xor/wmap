package domain

import (
	"errors"
	"fmt"
	"time"
)

// AuthFloodType represents the specific technical variant of the authentication flood.
type AuthFloodType string

const (
	// AuthFloodTypeAuthentication targets the 802.11 authentication phase.
	AuthFloodTypeAuthentication AuthFloodType = "auth"
	// AuthFloodTypeAssociation targets the 802.11 association/reassociation phase.
	AuthFloodTypeAssociation AuthFloodType = "assoc"
)

// AuthFloodAttackConfig defines the domain rules and parameters for an authentication flood attack.
type AuthFloodAttackConfig struct {
	// Infrastructure
	TargetBSSID string `json:"target_bssid"`
	Interface   string `json:"interface,omitempty"` // Optional, auto-selected if empty
	Channel     int    `json:"channel,omitempty"`   // Optional, will switch if provided

	// Flow Control
	PacketCount    int           `json:"packet_count"`    // 0 for continuous
	PacketInterval time.Duration `json:"packet_interval"` // Time between packets

	// Technical Strategy
	AttackType     AuthFloodType `json:"attack_type"`      // "auth" or "assoc"
	TargetSSID     string        `json:"target_ssid"`      // Required for Assoc
	UseRandomMAC   bool          `json:"use_random_mac"`   // True for random source MAC
	FixedSourceMAC string        `json:"fixed_source_mac"` // Used if UseRandomMAC is false
}

// NewAuthFloodDefaultConfig returns a configuration with sane defaults for a standard flood.
func NewAuthFloodDefaultConfig(targetBSSID string) AuthFloodAttackConfig {
	return AuthFloodAttackConfig{
		TargetBSSID:    targetBSSID,
		PacketCount:    0,
		PacketInterval: 100 * time.Millisecond,
		AttackType:     AuthFloodTypeAuthentication,
		UseRandomMAC:   true,
	}
}

// Validate ensures the configuration adheres to business and protocol rules.
func (c *AuthFloodAttackConfig) Validate() error {
	if !IsValidMAC(c.TargetBSSID) {
		return fmt.Errorf("invalid target BSSID: %s", c.TargetBSSID)
	}

	if c.Interface != "" && !IsValidInterface(c.Interface) {
		return fmt.Errorf("invalid interface name: %s", c.Interface)
	}

	if c.AttackType == AuthFloodTypeAssociation && c.TargetSSID == "" {
		return errors.New("target SSID is mandatory for association flood attacks")
	}

	if !c.UseRandomMAC && c.FixedSourceMAC != "" && !IsValidMAC(c.FixedSourceMAC) {
		return fmt.Errorf("invalid source MAC: %s", c.FixedSourceMAC)
	}

	if c.PacketInterval < 0 {
		return errors.New("packet interval cannot be negative")
	}

	return nil
}

// AuthFloodAttackStatus encapsulates the runtime state and life-cycle of an ongoing attack.
type AuthFloodAttackStatus struct {
	ID           string                `json:"id"`
	Config       AuthFloodAttackConfig `json:"config"`
	Status       AttackStatus          `json:"status"`
	PacketsSent  int                   `json:"packets_sent"`
	StartTime    time.Time             `json:"start_time"`
	EndTime      *time.Time            `json:"end_time,omitempty"`
	ErrorMessage string                `json:"error_message,omitempty"`
}

// NewAuthFloodAttackStatus initializes a new status tracker for a given configuration.
func NewAuthFloodAttackStatus(id string, config AuthFloodAttackConfig) AuthFloodAttackStatus {
	return AuthFloodAttackStatus{
		ID:        id,
		Config:    config,
		Status:    AttackPending,
		StartTime: time.Now(),
	}
}

// IsActive returns true if the attack is in a state where it might still be performing work.
func (s *AuthFloodAttackStatus) IsActive() bool {
	return s.Status == AttackRunning || s.Status == AttackPaused
}

// Duration calculates the total time elapsed since the start of the attack.
func (s *AuthFloodAttackStatus) Duration() time.Duration {
	if s.EndTime != nil {
		return s.EndTime.Sub(s.StartTime)
	}
	if s.StartTime.IsZero() {
		return 0
	}
	return time.Since(s.StartTime)
}

// Complete marks the attack as finished and records the timestamp.
func (s *AuthFloodAttackStatus) Complete(status AttackStatus, errMsg string) {
	now := time.Now()
	s.Status = status
	s.EndTime = &now
	s.ErrorMessage = errMsg
}
