package cache

import (
	"log"
	"sync"

	"github.com/google/gopacket"
)

// NetworkCache manages concurrent access to BSSID mappings and cached Beacons.
type NetworkCache struct {
	mu            sync.RWMutex
	bssidToEssid  map[string]string
	bssidToBeacon map[string]gopacket.Packet
}

func NewNetworkCache() *NetworkCache {
	return &NetworkCache{
		bssidToEssid:  make(map[string]string),
		bssidToBeacon: make(map[string]gopacket.Packet),
	}
}

// RegisterNetwork associates an ESSID with a BSSID manually.
func (c *NetworkCache) RegisterNetwork(bssid, essid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bssidToEssid[bssid] = essid
}

// GetESSID returns the stored ESSID for a given BSSID, or "unknown" if not found.
func (c *NetworkCache) GetESSID(bssid string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if essid, ok := c.bssidToEssid[bssid]; ok && essid != "" {
		return essid
	}
	return "unknown"
}

// StoreBeacon saves or updates the beacon packet and ESSID for a BSSID.
func (c *NetworkCache) StoreBeacon(bssid string, essid string, packet gopacket.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bssidToEssid[bssid] = essid
	c.bssidToBeacon[bssid] = packet
	log.Printf("DEBUG: Stored beacon for BSSID %s (SSID: %s)", bssid, essid)
}

// GetBeacon returns the cached beacon for a BSSID, if available.
func (c *NetworkCache) GetBeacon(bssid string) gopacket.Packet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if beacon, ok := c.bssidToBeacon[bssid]; ok {
		return beacon
	}
	return nil
}
