package storage

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// SaveConnectionEvent persists a connection event.
func (a *SQLiteAdapter) SaveConnectionEvent(ctx context.Context, event domain.ConnectionEvent) error {
	model := ConnectionEventModel{
		DeviceMAC: event.SourceMAC,
		EventType: string(event.Type),
		TargetMAC: event.TargetMAC,
		Timestamp: event.Timestamp,
		Reason:    event.Reason,
	}
	return a.db.WithContext(ctx).Create(&model).Error
}

// GetConnectionHistory retrieves history for a device.
func (a *SQLiteAdapter) GetConnectionHistory(ctx context.Context, mac string, limit int) ([]domain.ConnectionEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	var models []ConnectionEventModel
	if err := a.db.WithContext(ctx).Where("device_mac = ?", mac).Order("timestamp desc").Limit(limit).Find(&models).Error; err != nil {
		return nil, err
	}

	events := make([]domain.ConnectionEvent, len(models))
	for i, m := range models {
		events[i] = domain.ConnectionEvent{
			Type:      domain.ConnectionEventType(m.EventType),
			SourceMAC: m.DeviceMAC,
			TargetMAC: m.TargetMAC,
			Timestamp: m.Timestamp,
			Reason:    m.Reason,
		}
	}
	return events, nil
}
