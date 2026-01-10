package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AuditService defines the interface for logging audit events.
type AuditService interface {
	// Log records an action.
	Log(ctx context.Context, action, target, details string) error
	// GetLogs retrieves logs with optional filtering (implemented later).
	GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error)
}

// AuditRepository defines the persistence for audit logs.
type AuditRepository interface {
	SaveAuditLog(log domain.AuditLog) error
	ListAuditLogs(limit int) ([]domain.AuditLog, error)
}
