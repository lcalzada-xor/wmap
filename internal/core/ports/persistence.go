package ports

import (
	"context"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// PersistenceService provides an asynchronous, batch-oriented interface
// for long-term storage of device and connection data.
type PersistenceService interface {
	// Persist asynchronously queues a device for storage.
	Persist(device domain.Device)
	
	// PersistEvent asynchronously queues a connection event for storage.
	PersistEvent(event domain.ConnectionEvent)

	// IsEnabled returns whether persistence is currently active.
	IsEnabled() bool
	
	// SetEnabled toggles the persistence logic.
	SetEnabled(enabled bool)

	// GetConnectionHistory retrieves stored events for a given MAC.
	GetConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error)
	
	// Start begins the persistence background loops.
	Start(ctx context.Context)

	// Close performs a final flush and stops the background loops.
	Close() error
}
