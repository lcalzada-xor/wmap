package domain

import (
	"sync"
	"time"
)

// ConnectionEventType defines the type of event affecting connection state.
type ConnectionEventType string

const (
	EventAuthReq      ConnectionEventType = "auth_req"
	EventAssocReq     ConnectionEventType = "assoc_req"
	EventEAPOL        ConnectionEventType = "eapol"
	EventDataTransfer ConnectionEventType = "data"
	EventDeauth       ConnectionEventType = "deauth"
	EventDisassoc     ConnectionEventType = "disassoc"
)

// ConnectionEvent represents an event that triggers a state transition.
type ConnectionEvent struct {
	Type      ConnectionEventType
	SourceMAC string
	TargetMAC string // BSSID for Station
	Timestamp time.Time
	Reason    int // For Deauth/Disassoc
}

// ConnectionStateManager manages the state transitions for device connections.
// It ensures valid transitions and filters out transient noise.
type ConnectionStateManager struct {
	// In-memory state tracking to support debouncing and validation
	// Key: DeviceMAC
	states map[string]*deviceConnectionState
	mu     sync.RWMutex
}

type deviceConnectionState struct {
	CurrentState    ConnectionState
	LastStateChange time.Time
	TargetBSSID     string
	PendingState    ConnectionState
	PendingTime     time.Time
}

// NewConnectionStateManager creates a new state manager.
func NewConnectionStateManager() *ConnectionStateManager {
	return &ConnectionStateManager{
		states: make(map[string]*deviceConnectionState),
	}
}

// UpdateState determines the new state based on an incoming event.
// It returns the new state and target BSSID.
func (sm *ConnectionStateManager) UpdateState(deviceMAC string, event ConnectionEvent) (ConnectionState, string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, exists := sm.states[deviceMAC]
	if !exists {
		state = &deviceConnectionState{
			CurrentState:    StateDisconnected,
			LastStateChange: time.Time{}, // Time zero
		}
		sm.states[deviceMAC] = state
	}

	// 1. Ordering Validation
	// If the event is older than the last state change, it's likely an out-of-order packet.
	// We ignore it to prevent state regression.
	// Exception: If LastStateChange is zero (initial), process it.
	if !state.LastStateChange.IsZero() && event.Timestamp.Before(state.LastStateChange) {
		return state.CurrentState, state.TargetBSSID
	}

	newState := state.CurrentState
	newTarget := state.TargetBSSID

	// 2. State Machine Logic with Debouncing
	switch event.Type {
	case EventAuthReq:
		newState = StateAuthenticating
		newTarget = event.TargetMAC
	case EventAssocReq:
		newState = StateAssociating
		newTarget = event.TargetMAC
	case EventEAPOL:
		newState = StateHandshake
		if newTarget == "" {
			newTarget = event.TargetMAC
		}
	case EventDataTransfer:
		// Debounce: If we recently disconnected (e.g. within 500ms), ignore isolated data frames
		// This prevents "ghost" reconnections from buffered frames arriving after a Deauth.
		// We use event timestamps to be robust against processing delays.
		if state.CurrentState == StateDisconnected && event.Timestamp.Sub(state.LastStateChange) < 500*time.Millisecond {
			// Ignore data frame during cool-down
			return state.CurrentState, state.TargetBSSID
		}

		// Transition to Connected
		newState = StateConnected
		if event.TargetMAC != "" {
			newTarget = event.TargetMAC
		}
	case EventDeauth, EventDisassoc:
		newState = StateDisconnected
		newTarget = ""
	}

	// Update internal state
	if newState != state.CurrentState || newTarget != state.TargetBSSID {
		state.CurrentState = newState
		state.TargetBSSID = newTarget
		state.LastStateChange = event.Timestamp
	}

	return newState, newTarget
}

// GetState returns the current known state for a device
func (sm *ConnectionStateManager) GetState(deviceMAC string) ConnectionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if state, ok := sm.states[deviceMAC]; ok {
		return state.CurrentState
	}
	return StateDisconnected
}
