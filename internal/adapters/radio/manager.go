package radio

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
)

// ChannelSetter is a function type for setting the channel
var channelSetter = driver.SetInterfaceChannel

// SetMockChannelSetter allows tests to inject a mock driver
func SetMockChannelSetter(mock func(string, int) error) {
	if mock == nil {
		channelSetter = driver.SetInterfaceChannel
	} else {
		channelSetter = mock
	}
}

// HopperPauser allows external components (Sniffer) to register for pause events
type HopperPauser interface {
	PauseHopper(duration time.Duration)
}

// RadioManager handles exclusive access to network interfaces.
// It ensures that only one operation controls a radio's channel at a time.
type RadioManager struct {
	interfaces sync.Map // map[string]*ifaceState
	handlers   sync.Map // map[string]HopperPauser
}

type ifaceState struct {
	mu            sync.Mutex
	activeChannel int
	lockCount     int
}

// NewRadioManager creates a new RadioManager
func NewRadioManager() *RadioManager {
	return &RadioManager{}
}

func (rm *RadioManager) getOrCreateIfaceState(iface string) *ifaceState {
	actual, _ := rm.interfaces.LoadOrStore(iface, &ifaceState{})
	return actual.(*ifaceState)
}

// RegisterHandler registers a component to be notified of lock events for an interface
func (rm *RadioManager) RegisterHandler(iface string, handler HopperPauser) {
	rm.handlers.Store(iface, handler)
}

// Lock acquires exclusive access to the interface on a specific channel.
func (rm *RadioManager) Lock(ctx context.Context, iface string, channel int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	state := rm.getOrCreateIfaceState(iface)
	state.mu.Lock()
	// Note: We don't defer Unlock here because we might need to hold it during IO
	// and only unlock when the entire Lock operation is done.
	// Actually, the original code used a defer on the interface-specific mutex.
	// But it held it during channelSetter. Let's keep that behavior but cleaner.
	
	succeeded := false
	defer func() {
		if !succeeded {
			state.mu.Unlock()
		}
	}()

	if state.lockCount > 0 {
		if state.activeChannel == channel {
			// Already locked on this channel, increment count
			state.lockCount++
			succeeded = true
			state.mu.Unlock()
			return nil
		}

		return fmt.Errorf("interface %s starts busy: locked on channel %d", iface, state.activeChannel)
	}

	// Not active. We claim it.
	state.activeChannel = channel
	state.lockCount = 1

	// Notify handler to pause hopping (if any)
	if h, ok := rm.handlers.Load(iface); ok && h != nil {
		handler := h.(HopperPauser)
		func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[RadioManager] Recovered from panic in handler: %v", r)
					}
				}()
			handler.PauseHopper(1 * time.Hour)
		}()
	}

	// Set Hardware Channel
	if err := channelSetter(iface, channel); err != nil {
		// Rollback on failure
		state.lockCount--
		if state.lockCount <= 0 {
			state.activeChannel = 0
			state.lockCount = 0
		}
		return fmt.Errorf("failed to set channel: %w", err)
	}

	succeeded = true
	state.mu.Unlock()
	return nil
}

// Unlock releases the lock on the interface
func (rm *RadioManager) Unlock(ctx context.Context, iface string) error {
	actual, ok := rm.interfaces.Load(iface)
	if !ok {
		return nil
	}
	state := actual.(*ifaceState)

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.lockCount <= 0 {
		return nil
	}

	state.lockCount--
	if state.lockCount <= 0 {
		// Fully release. 
		// We don't necessarily need to delete from the map to avoid overhead of recreation,
		// but we reset the state.
		state.activeChannel = 0
		state.lockCount = 0
		log.Printf("[RadioManager] Unlocked %s", iface)
	}
	return nil
}

// ExecuteWithLock runs the action under lock
func (rm *RadioManager) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	if err := rm.Lock(ctx, iface, channel); err != nil {
		return err
	}
	defer rm.Unlock(ctx, iface)
	return action()
}

// IsLocked checks if an interface is currently locked.
// Returns true if locked (active operation), false otherwise.
func (rm *RadioManager) IsLocked(ctx context.Context, iface string) bool {
	actual, ok := rm.interfaces.Load(iface)
	if !ok {
		return false
	}
	state := actual.(*ifaceState)
	
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.lockCount > 0
}
