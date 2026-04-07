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

const (
	shardCount      = 16
	dataDebounceTTL = 500 * time.Millisecond
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
// It uses sharding to minimize mutex contention in high-traffic environments.
type ConnectionStateManager struct {
	shards [shardCount]*stateShard
}

type stateShard struct {
	states map[string]*deviceConnectionState
	mu     sync.RWMutex
}

type deviceConnectionState struct {
	CurrentState    ConnectionState
	LastStateChange time.Time
	TargetBSSID     string
}

// NewConnectionStateManager creates a new state manager.
func NewConnectionStateManager() *ConnectionStateManager {
	sm := &ConnectionStateManager{}
	for i := 0; i < shardCount; i++ {
		sm.shards[i] = &stateShard{
			states: make(map[string]*deviceConnectionState),
		}
	}
	return sm
}

func (sm *ConnectionStateManager) getShard(mac string) *stateShard {
	// Simple additive hash for the MAC string to select a shard
	var hash uint32
	for i := 0; i < len(mac); i++ {
		hash = 31*hash + uint32(mac[i])
	}
	return sm.shards[hash%shardCount]
}

// UpdateState determines the new state based on an incoming event.
// It returns the new state and target BSSID.
func (sm *ConnectionStateManager) UpdateState(deviceMAC string, event ConnectionEvent) (ConnectionState, string) {
	shard := sm.getShard(deviceMAC)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.states[deviceMAC]
	if !exists {
		state = &deviceConnectionState{
			CurrentState:    StateDisconnected,
			LastStateChange: time.Time{}, // Time zero
		}
		shard.states[deviceMAC] = state
	}

	// 1. Ordering Validation
	// If the event is older than the last state change, it's likely an out-of-order packet.
	// We ignore it to prevent state regression.
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
		// Transition to Handshake if we are in expected preliminary states
		// Or if we see EAPOL frames, we strongly suspect a handshake is in progress.
		newState = StateHandshake
		if newTarget == "" || newTarget != event.TargetMAC {
			newTarget = event.TargetMAC
		}
	case EventDataTransfer:
		// Debounce: If we recently disconnected, ignore isolated data frames
		// This prevents "ghost" reconnections from buffered frames arriving after a Deauth.
		if state.CurrentState == StateDisconnected && !state.LastStateChange.IsZero() {
			if event.Timestamp.Sub(state.LastStateChange) < dataDebounceTTL {
				return state.CurrentState, state.TargetBSSID
			}
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
	shard := sm.getShard(deviceMAC)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	if state, ok := shard.states[deviceMAC]; ok {
		return state.CurrentState
	}
	return StateDisconnected
}

// Cleanup removes device states that haven't changed for longer than the provided TTL.
// Returns the number of evicted entries.
func (sm *ConnectionStateManager) Cleanup(ttl time.Duration) int {
	evicted := 0
	now := time.Now()

	for i := 0; i < shardCount; i++ {
		shard := sm.shards[i]
		shard.mu.Lock()
		for mac, state := range shard.states {
			if now.Sub(state.LastStateChange) > ttl {
				delete(shard.states, mac)
				evicted++
			}
		}
		shard.mu.Unlock()
	}

	return evicted
}
