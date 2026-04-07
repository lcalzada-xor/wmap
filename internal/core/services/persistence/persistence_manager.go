package persistence

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

var _ ports.PersistenceService = (*PersistenceManager)(nil)

// PersistenceManager handles background batch writing of devices to storage.
type PersistenceManager struct {
	storage     ports.Storage
	persistChan chan domain.Device
	eventChan   chan domain.ConnectionEvent
	batchSize   int
	interval    time.Duration
	enabled     bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewPersistenceManager creates a new manager.
func NewPersistenceManager(storage ports.Storage, bufferSize int) *PersistenceManager {
	return &PersistenceManager{
		storage:     storage,
		persistChan: make(chan domain.Device, bufferSize),
		eventChan:   make(chan domain.ConnectionEvent, bufferSize),
		batchSize:   100,
		interval:    5 * time.Second,
		enabled:     true, // Enabled by default
	}
}

// Persist queues a device for persistence if enabled.
func (p *PersistenceManager) Persist(device domain.Device) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.enabled {
		return
	}
	// Use non-blocking send or overflow check if needed
	// For now, simpler to just send
	select {
	case p.persistChan <- device:
	default:
		// Queue full, drop or handle? dropping for now to avoid blocking sniffer
	}
}

// PersistEvent queues a connection event for persistence.
func (p *PersistenceManager) PersistEvent(event domain.ConnectionEvent) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.enabled {
		return
	}
	select {
	case p.eventChan <- event:
	default:
		// Queue full
	}
}

// IsEnabled returns the current persistence status.
func (p *PersistenceManager) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// SetEnabled toggles the persistence logic.
func (p *PersistenceManager) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

// SetStorage updates the storage adapter used for persistence.
func (p *PersistenceManager) SetStorage(storage ports.Storage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.storage = storage
}

// Start begins the persistence loop.
func (p *PersistenceManager) Start(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Ensure we don't start multiple loops
	if p.ctx != nil {
		return
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	ticker := time.NewTicker(p.interval)
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		defer ticker.Stop()

		buffer := make(map[string]domain.Device)
		eventBuffer := make([]domain.ConnectionEvent, 0, p.batchSize)

		for {
			select {
			case <-p.ctx.Done():
				p.flushAll(buffer, eventBuffer)
				return
			case dev := <-p.persistChan:
				buffer[dev.MAC] = dev
				if len(buffer) >= p.batchSize {
					p.flushBuffer(buffer)
					buffer = make(map[string]domain.Device)
				}
			case evt := <-p.eventChan:
				eventBuffer = append(eventBuffer, evt)
				if len(eventBuffer) >= p.batchSize {
					p.flushEvents(eventBuffer)
					eventBuffer = eventBuffer[:0]
				}
			case <-ticker.C:
				if len(buffer) > 0 {
					p.flushBuffer(buffer)
					buffer = make(map[string]domain.Device)
				}
				if len(eventBuffer) > 0 {
					p.flushEvents(eventBuffer)
					eventBuffer = eventBuffer[:0]
				}
			}
		}
	}()
}

// Close performs a final flush and stops the background loop.
func (p *PersistenceManager) Close() error {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()

	// Wait for the loop to finish flushing
	p.wg.Wait()
	return nil
}

func (p *PersistenceManager) flushAll(buffer map[string]domain.Device, eventBuffer []domain.ConnectionEvent) {
	// Final flush on shutdown
	if len(buffer) > 0 {
		p.flushBuffer(buffer)
	}
	if len(eventBuffer) > 0 {
		p.flushEvents(eventBuffer)
	}
}

func (p *PersistenceManager) flushBuffer(buffer map[string]domain.Device) {
	if len(buffer) == 0 {
		return
	}

	p.mu.RLock()
	store := p.storage
	p.mu.RUnlock()

	if store == nil {
		return
	}

	var devices []domain.Device
	for _, d := range buffer {
		devices = append(devices, d)
	}

	// Use background context or a dedicated shutdown context to ensure this completes
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.SaveDevicesBatch(ctx, devices); err != nil {
		slog.Error("Failed to batch save devices", "error", err, "count", len(devices))
	}
}

func (p *PersistenceManager) flushEvents(events []domain.ConnectionEvent) {
	if len(events) == 0 {
		return
	}

	p.mu.RLock()
	store := p.storage
	p.mu.RUnlock()

	if store == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := store.SaveConnectionEventsBatch(ctx, events); err != nil {
		slog.Error("Failed to batch save connection events", "error", err, "count", len(events))
	}
}

// GetConnectionHistory retrieves stored connection events for a device.
func (p *PersistenceManager) GetConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error) {
	p.mu.RLock()
	store := p.storage
	p.mu.RUnlock()

	if store == nil {
		return nil, nil
	}
	// Default limit 100 for now, could be parameterized
	return store.GetConnectionHistory(ctx, mac, 100)
}
