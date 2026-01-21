package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// AuditService handles the high-level business requirement for action tracking.
type AuditService interface {
	// Log records an administrative or security-sensitive action.
	Log(ctx context.Context, action domain.AuditAction, target, details string) error

	// GetLogs retrieves historical audit records.
	GetLogs(ctx context.Context, limit int) ([]domain.AuditLog, error)
}

// AuditRepository handles the low-level persistence of audit data.
type AuditRepository interface {
	// SaveAuditLog persists a single audit entry.
	SaveAuditLog(ctx context.Context, log domain.AuditLog) error

	// ListAuditLogs retrieves audit entries with a result limit.
	ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error)
}
