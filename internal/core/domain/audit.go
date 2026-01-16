package domain

import (
	"time"
)

// AuditAction constants
const (
	ActionLogin        = "LOGIN"
	ActionLogout       = "LOGOUT"
	ActionScan         = "SCAN_INITIATED"
	ActionDeauthStart  = "DEAUTH_STARTED"
	ActionDeauthStop   = "DEAUTH_STOPPED"
	ActionConfigChange = "CONFIG_CHANGE"
	ActionWorkspace    = "WORKSPACE_OP"
	ActionInfo         = "INFO"
)

// AuditLog represents a record of a critical system action.
type AuditLog struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"index"`
	Username  string    `json:"username"` // Denormalized for easier display
	Action    string    `json:"action" gorm:"index"`
	Target    string    `json:"target"` // Target resource (e.g. MAC address, Config Key)
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	Timestamp time.Time `json:"timestamp" gorm:"index"`
}
