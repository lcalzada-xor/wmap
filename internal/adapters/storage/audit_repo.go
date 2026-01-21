package storage

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// Ensure compliance
var _ ports.AuditRepository = (*SQLiteAdapter)(nil)

// Aliases to match interface if needed (AuditRepository uses SaveAuditLog/ListAuditLogs)
func (a *SQLiteAdapter) SaveAuditLog(ctx context.Context, log domain.AuditLog) error {
	return a.db.WithContext(ctx).Create(&log).Error
}

func (a *SQLiteAdapter) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog
	if err := a.db.WithContext(ctx).Order("timestamp desc").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}
