package hopping

import "sync/atomic"

// HopperState represents the current state of the channel hopper.
type HopperState int32

const (
	StateIdle    HopperState = iota // Initial state, created but not running
	StateHopping                    // Actively switching channels
	StatePaused                     // Temporarily paused (timer stopped)
	StateLocked                     // Locked on a specific channel (hopping disabled)
	StateStopped                    // Permanently stopped
)

func (s HopperState) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateHopping:
		return "Hopping"
	case StatePaused:
		return "Paused"
	case StateLocked:
		return "Locked"
	case StateStopped:
		return "Stopped"
	}
	return "Unknown"
}

// AtomicState wraps atomic operations for HopperState
type AtomicState struct {
	v int32
}

func (a *AtomicState) Set(s HopperState) {
	atomic.StoreInt32(&a.v, int32(s))
}

func (a *AtomicState) Get() HopperState {
	return HopperState(atomic.LoadInt32(&a.v))
}

func (a *AtomicState) CompareAndSwap(old, new HopperState) bool {
	return atomic.CompareAndSwapInt32(&a.v, int32(old), int32(new))
}
