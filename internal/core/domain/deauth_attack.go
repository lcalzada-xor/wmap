package domain

import (
	"errors"
	"fmt"
	"time"
)

// DeauthType represents the technical variant of the deauthentication attack.
type DeauthType string

const (
	// DeauthBroadcast targets all clients connected to an Access Point.
	DeauthBroadcast DeauthType = "broadcast"
	// DeauthUnicast targets a single specific client on an Access Point.
	DeauthUnicast DeauthType = "unicast"
	// DeauthTargeted performs a bidirectional attack between the AP and a specific client.
	DeauthTargeted DeauthType = "targeted"
)

// AttackStatus represents the lifecycle state of a security attack.
// Note: This type is shared across multiple attack domains (AuthFlood, WPS, Deauth).
type AttackStatus string

const (
	AttackPending AttackStatus = "pending"
	AttackRunning AttackStatus = "running"
	AttackPaused  AttackStatus = "paused"
	AttackStopped AttackStatus = "stopped"
	AttackFailed  AttackStatus = "failed"
)

// DeauthAttackConfig defines the parameters required to execute a deauthentication attack.
type DeauthAttackConfig struct {
	// TargetMAC is the MAC address of the Access Point or the primary target.
	TargetMAC string `json:"target_mac"`

	// ClientMAC is the specific station MAC address (required for unicast/targeted).
	ClientMAC string `json:"client_mac,omitempty"`

	// AttackType determines the 802.11 frame targeting strategy.
	AttackType DeauthType `json:"attack_type"`

	// PacketCount is the total number of frames to send (0 for infinite).
	PacketCount int `json:"packet_count"`

	// PacketInterval is the delay between individual frame bursts.
	PacketInterval time.Duration `json:"packet_interval"`

	// ReasonCode is the 802.11 Reason Code field value (standard: 7).
	ReasonCode uint16 `json:"reason_code"`

	// Channel is the physical frequency channel (1-165).
	Channel int `json:"channel"`

	// Interface is the monitor-mode interface to use.
	Interface string `json:"interface,omitempty"`

	// UseReasonFuzzing cycles through different reason codes to bypass some IDS.
	UseReasonFuzzing bool `json:"use_reason_fuzzing"`

	// UseJitter adds micro-randomization to packet intervals.
	UseJitter bool `json:"use_jitter"`

	// SpoofSource enables source MAC randomization for the injector.
	SpoofSource bool `json:"spoof_source"`
}

// Validate evaluates the configuration against protocol and domain rules.
func (c *DeauthAttackConfig) Validate() error {
	if !IsValidMAC(c.TargetMAC) {
		return fmt.Errorf("invalid target MAC: %s", c.TargetMAC)
	}

	if c.AttackType != DeauthBroadcast {
		if c.ClientMAC == "" {
			return errors.New("client MAC is required for unicast or targeted attacks")
		}
		if !IsValidMAC(c.ClientMAC) {
			return fmt.Errorf("invalid client MAC: %s", c.ClientMAC)
		}
	}

	// 802.11 channels range from 1 to 165 (encompassing 2.4GHz and 5GHz)
	if c.Channel < 1 || c.Channel > 165 {
		return fmt.Errorf("invalid WiFi channel: %d", c.Channel)
	}

	if c.PacketInterval < 0 {
		return errors.New("packet interval cannot be negative")
	}

	if c.Interface != "" && !IsValidInterface(c.Interface) {
		return fmt.Errorf("invalid interface name: %s", c.Interface)
	}

	return nil
}

// DeauthAttackStatus encapsulates the runtime state, metrics, and lifecycle of a deauth attack.
type DeauthAttackStatus struct {
	ID                string             `json:"id"`
	Config            DeauthAttackConfig `json:"config"`
	Status            AttackStatus       `json:"status"`
	PacketsSent       int                `json:"packets_sent"`
	StartTime         time.Time          `json:"start_time"`
	EndTime           *time.Time         `json:"end_time,omitempty"`
	ErrorMessage      string             `json:"error_message,omitempty"`
	HandshakeCaptured bool               `json:"handshake_captured"`
}

// NewDeauthAttack initializes a new deauth attack entity with valid configuration.
func NewDeauthAttack(id string, config DeauthAttackConfig) (*DeauthAttackStatus, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &DeauthAttackStatus{
		ID:     id,
		Config: config,
		Status: AttackPending,
	}, nil
}

// Start transitions the attack to the active running state.
func (s *DeauthAttackStatus) Start() error {
	if s.IsActive() {
		return errors.New("attack session is already active")
	}
	s.Status = AttackRunning
	s.StartTime = time.Now()
	s.EndTime = nil
	s.ErrorMessage = ""
	return nil
}

// Stop gracefully terminates the attack session.
func (s *DeauthAttackStatus) Stop() {
	if s.Status == AttackStopped || s.Status == AttackFailed {
		return
	}
	now := time.Now()
	s.Status = AttackStopped
	s.EndTime = &now
}

// Fail terminates the attack due to a critical runtime error.
func (s *DeauthAttackStatus) Fail(err string) {
	now := time.Now()
	s.Status = AttackFailed
	s.ErrorMessage = err
	s.EndTime = &now
}

// RecordPulse updates the attack progress metrics.
func (s *DeauthAttackStatus) RecordPulse(packets int, handshake bool) {
	if s.Status != AttackRunning {
		return
	}
	s.PacketsSent += packets
	if handshake {
		s.HandshakeCaptured = true
	}
}

// IsActive returns true if the attack is currently in a state that permits execution.
func (s *DeauthAttackStatus) IsActive() bool {
	return s.Status == AttackRunning || s.Status == AttackPaused
}

// Duration calculates the total wall-clock time the attack has been active.
func (s *DeauthAttackStatus) Duration() time.Duration {
	if s.StartTime.IsZero() {
		return 0
	}
	if s.EndTime != nil {
		return s.EndTime.Sub(s.StartTime)
	}
	return time.Since(s.StartTime)
}
