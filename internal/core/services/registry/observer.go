package registry

import (
	"context"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceObserver defines the interface for components interested in device updates.
type DeviceObserver interface {
	OnDeviceUpdated(ctx context.Context, device domain.Device)
	OnDeviceAdded(ctx context.Context, device domain.Device)
}

// RegistrySubject manages observers and notifies them of events.
type RegistrySubject struct {
	observers []DeviceObserver
	mu        sync.RWMutex
}

// NewRegistrySubject creates a new subject.
func NewRegistrySubject() *RegistrySubject {
	return &RegistrySubject{
		observers: make([]DeviceObserver, 0),
	}
}

// AddObserver registers a new observer.
func (s *RegistrySubject) AddObserver(observer DeviceObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observers = append(s.observers, observer)
}

// NotifyUpdated notifies all observers of a device update.
func (s *RegistrySubject) NotifyUpdated(ctx context.Context, device domain.Device) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, obs := range s.observers {
		// Run in goroutine to avoid blocking registry?
		// For consistency, maybe synchronous is better for some, allowing internal queuing?
		// Let's do it inline for now, relying on observers to be fast or async themselves.
		// Actually, ScanScheduler/Vulnerability might be slow.
		// Let's use a fail-safe async pattern if robust, or just assume observers know what they are doing.
		// For thread safety, let's pass a copy if needed, but device is passed by value.
		go obs.OnDeviceUpdated(ctx, device)
	}
}

// NotifyAdded notifies all observers of a new device.
func (s *RegistrySubject) NotifyAdded(ctx context.Context, device domain.Device) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, obs := range s.observers {
		go obs.OnDeviceAdded(ctx, device)
	}
}
