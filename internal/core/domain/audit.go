package domain

import (
	"errors"
	"time"
)

// AuditAction represents a type-safe action identifier for the audit log.
type AuditAction string

// System Audit Actions
const (
	ActionLogin        AuditAction = "LOGIN"
	ActionLogout       AuditAction = "LOGOUT"
	ActionScan         AuditAction = "SCAN_INITIATED"
	ActionDeauthStart  AuditAction = "DEAUTH_STARTED"
	ActionDeauthStop   AuditAction = "DEAUTH_STOPPED"
	ActionConfigChange AuditAction = "CONFIG_CHANGE"
	ActionWorkspace    AuditAction = "WORKSPACE_OP"
	ActionInfo         AuditAction = "INFO"
)

// Domain Errors
var (
	ErrInvalidAction = errors.New("invalid audit action")
	ErrMissingUser   = errors.New("user identification is required for auditing")
)

// AuditLog represents a record of a critical system action.
// This is a pure domain entity, decoupled from persistence (GORM) or transport (JSON) constraints
// where possible, although JSON tags are kept for API compatibility.
type AuditLog struct {
	ID        uint        `json:"id"`
	UserID    string      `json:"user_id"`
	Username  string      `json:"username"` // Denormalized for display/reporting
	Action    AuditAction `json:"action"`
	Target    string      `json:"target"` // The resource affected (e.g., MAC, UUID, FieldName)
	Details   string      `json:"details"`
	IPAddress string      `json:"ip_address"`
	Timestamp time.Time   `json:"timestamp"`
}

// NewAuditLog is the designated factory for creating valid AuditLog entities.
// It ensures that all required invariant rules are satisfied.
func NewAuditLog(userID, username string, action AuditAction, target, details, ip string) (*AuditLog, error) {
	if userID == "" && username == "" {
		return nil, ErrMissingUser
	}

	if !isValidAction(action) {
		return nil, ErrInvalidAction
	}

	return &AuditLog{
		UserID:    userID,
		Username:  username,
		Action:    action,
		Target:    target,
		Details:   details,
		IPAddress: ip,
		Timestamp: time.Now().UTC(),
	}, nil
}

// isValidAction encapsulates the validation logic for audit actions.
func isValidAction(action AuditAction) bool {
	switch action {
	case ActionLogin, ActionLogout, ActionScan, ActionDeauthStart,
		ActionDeauthStop, ActionConfigChange, ActionWorkspace, ActionInfo:
		return true
	}
	return false
}

/*
ARCHITECTURAL NOTE:
The GORM tags were removed to prevent infrastructure leakage into the domain.
Persistence-specific metadata (indexes, primary keys) should be handled in the
repository layer (internal/adapters/storage) using a dedicated DB Model
or GORM's schema configuration.
*/
