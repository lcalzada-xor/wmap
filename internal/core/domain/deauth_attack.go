package domain

import "time"

// DeauthType represents the type of deauthentication attack
type DeauthType string

const (
	// DeauthBroadcast deauthenticates all clients from an AP
	DeauthBroadcast DeauthType = "broadcast"
	// DeauthUnicast deauthenticates a specific client
	DeauthUnicast DeauthType = "unicast"
	// DeauthTargeted performs bidirectional deauth (AP<->Client)
	DeauthTargeted DeauthType = "targeted"
)

// AttackStatus represents the current state of an attack
type AttackStatus string

const (
	// AttackPending indicates the attack is queued but not started
	AttackPending AttackStatus = "pending"
	// AttackRunning indicates the attack is actively sending packets
	AttackRunning AttackStatus = "running"
	// AttackPaused indicates the attack is temporarily paused
	AttackPaused AttackStatus = "paused"
	// AttackStopped indicates the attack has been stopped
	AttackStopped AttackStatus = "stopped"
	// AttackFailed indicates the attack encountered an error
	AttackFailed AttackStatus = "failed"
)

// DeauthAttackConfig contains the configuration for a deauthentication attack
type DeauthAttackConfig struct {
	// TargetMAC is the MAC address of the AP or client to attack
	TargetMAC string `json:"target_mac"`

	// ClientMAC is the MAC address of the client (optional, for unicast/targeted)
	ClientMAC string `json:"client_mac,omitempty"`

	// AttackType specifies the type of deauth attack
	AttackType DeauthType `json:"attack_type"`

	// PacketCount is the number of packets to send (0 = continuous)
	PacketCount int `json:"packet_count"`

	// PacketInterval is the time between packets
	PacketInterval time.Duration `json:"packet_interval"`

	// ReasonCode is the 802.11 reason code for deauthentication
	ReasonCode uint16 `json:"reason_code"`

	// Channel is the WiFi channel to perform the attack on
	Channel int `json:"channel"`

	// Interface is the network interface to use for the attack
	Interface string `json:"interface,omitempty"`

	// UseReasonFuzzing enables cycling through effective reason codes
	UseReasonFuzzing bool `json:"use_reason_fuzzing"`

	// UseJitter enables randomized packet intervals to avoid detection matches
	UseJitter bool `json:"use_jitter"`

	// SpoofSource enables randomization of the source MAC address (Access Point spoofing)
	SpoofSource bool `json:"spoof_source"`
}

// DeauthAttackStatus represents the current status of a deauth attack
type DeauthAttackStatus struct {
	// ID is the unique identifier for this attack
	ID string `json:"id"`

	// Config is the attack configuration
	Config DeauthAttackConfig `json:"config"`

	// Status is the current state of the attack
	Status AttackStatus `json:"status"`

	// PacketsSent is the number of packets sent so far
	PacketsSent int `json:"packets_sent"`

	// StartTime is when the attack started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the attack ended (nil if still running)
	EndTime *time.Time `json:"end_time,omitempty"`

	// ErrorMessage contains error details if Status is AttackFailed
	ErrorMessage string `json:"error_message,omitempty"`

	// HandshakeCaptured indicates if a WPA handshake was detected during the attack
	HandshakeCaptured bool `json:"handshake_captured"`
}

// IsActive returns true if the attack is currently running or paused
func (s *DeauthAttackStatus) IsActive() bool {
	return s.Status == AttackRunning || s.Status == AttackPaused
}

// Duration returns the duration of the attack
func (s *DeauthAttackStatus) Duration() time.Duration {
	if s.EndTime != nil {
		return s.EndTime.Sub(s.StartTime)
	}
	return time.Since(s.StartTime)
}
