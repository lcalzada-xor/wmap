package storage

import (
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// Ensure compliance
var _ ports.AuditRepository = (*SQLiteAdapter)(nil)

// Aliases to match interface if needed (AuditRepository uses SaveAuditLog/ListAuditLogs)
func (a *SQLiteAdapter) SaveAuditLog(log domain.AuditLog) error {
	return a.db.Create(&log).Error
}

func (a *SQLiteAdapter) ListAuditLogs(limit int) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog
	if err := a.db.Order("timestamp desc").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}
