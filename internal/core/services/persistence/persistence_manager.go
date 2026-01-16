package persistence

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// PersistenceManager handles background batch writing of devices to storage.
type PersistenceManager struct {
	storage     ports.Storage
	persistChan chan domain.Device
	batchSize   int
	interval    time.Duration
	enabled     bool
	mu          sync.RWMutex
}

// NewPersistenceManager creates a new manager.
func NewPersistenceManager(storage ports.Storage, bufferSize int) *PersistenceManager {
	return &PersistenceManager{
		storage:     storage,
		persistChan: make(chan domain.Device, bufferSize),
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
	ticker := time.NewTicker(p.interval)
	buffer := make(map[string]domain.Device)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				p.flushBuffer(buffer)
				return
			case dev := <-p.persistChan:
				buffer[dev.MAC] = dev
				if len(buffer) >= p.batchSize {
					p.flushBuffer(buffer)
					buffer = make(map[string]domain.Device)
				}
			case <-ticker.C:
				if len(buffer) > 0 {
					p.flushBuffer(buffer)
					buffer = make(map[string]domain.Device)
				}
			}
		}
	}()
}

func (p *PersistenceManager) flushBuffer(buffer map[string]domain.Device) {
	if len(buffer) == 0 || p.storage == nil {
		return
	}
	var devices []domain.Device
	for _, d := range buffer {
		devices = append(devices, d)
	}
	if err := p.storage.SaveDevicesBatch(devices); err != nil {
		fmt.Printf("[DB-ERR] Failed to batch save devices: %v\n", err)
	}
}
