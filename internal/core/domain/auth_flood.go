package domain

import "time"

// AuthFloodAttackConfig defines configuration for an authentication flood attack
type AuthFloodAttackConfig struct {
	TargetBSSID    string        `json:"target_bssid"`
	Interface      string        `json:"interface,omitempty"` // Optional, auto-selected if empty
	Channel        int           `json:"channel,omitempty"`   // Optional, will switch if provided
	PacketCount    int           `json:"packet_count"`        // 0 for continuous
	PacketInterval time.Duration `json:"packet_interval"`     // Time between packets
}

// AuthFloodAttackStatus represents the current state of an authentication flood attack
type AuthFloodAttackStatus struct {
	ID           string                `json:"id"`
	Config       AuthFloodAttackConfig `json:"config"`
	Status       AttackStatus          `json:"status"`
	PacketsSent  int                   `json:"packets_sent"`
	StartTime    time.Time             `json:"start_time"`
	EndTime      *time.Time            `json:"end_time,omitempty"`
	ErrorMessage string                `json:"error_message,omitempty"`
}
