package registry

import (
	"context"
	"sync"
)

// SSIDManager handles storage and retrieval of SSID information.
type SSIDManager struct {
	ssids        map[string]bool
	ssidSecurity map[string]string
	mu           sync.RWMutex
}

// NewSSIDManager creates a new SSID manager.
func NewSSIDManager() *SSIDManager {
	return &SSIDManager{
		ssids:        make(map[string]bool),
		ssidSecurity: make(map[string]string),
	}
}

// UpdateSSID registers an SSID and its security characteristic.
func (sm *SSIDManager) Update(ctx context.Context, ssid, security string) {
	if ssid == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.ssids[ssid] = true
	if security != "" {
		// Only update security if not already known, or maybe we should allow update?
		// Previous logic: if _, ok := r.ssidSecurity[ssid]; !ok { ... }
		// Use existing logic for now.
		if _, ok := sm.ssidSecurity[ssid]; !ok {
			sm.ssidSecurity[ssid] = security
		}
	}
}

// GetSSIDs returns a copy of all known SSIDs.
func (sm *SSIDManager) GetSSIDs(ctx context.Context) map[string]bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copy := make(map[string]bool, len(sm.ssids))
	for k, v := range sm.ssids {
		copy[k] = v
	}
	return copy
}

// GetSecurity returns the security type for a given SSID.
func (sm *SSIDManager) GetSecurity(ctx context.Context, ssid string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sec, ok := sm.ssidSecurity[ssid]
	return sec, ok
}

// Clear wipes the mockStorage.
func (sm *SSIDManager) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.ssids = make(map[string]bool)
	sm.ssidSecurity = make(map[string]string)
}
