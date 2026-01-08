package services

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

const numShards = 16

type deviceShard struct {
	mu       sync.RWMutex
	devices  map[string]domain.Device
	profiles map[string]domain.BehavioralProfile
}

// DeviceRegistry implements ports.DeviceRegistry.
type DeviceRegistry struct {
	shards       []*deviceShard
	ssids        map[string]bool
	ssidSecurity map[string]string
	ssidsMu      sync.RWMutex
	discoCache   map[string]string // MAC -> Last processed Signature
	discoCacheMu sync.RWMutex
	sigMatcher   ports.SignatureMatcher
}

// NewDeviceRegistry creates a new sharded registry.
func NewDeviceRegistry(sigMatcher ports.SignatureMatcher) *DeviceRegistry {
	r := &DeviceRegistry{
		shards:       make([]*deviceShard, numShards),
		ssids:        make(map[string]bool),
		ssidSecurity: make(map[string]string),
		discoCache:   make(map[string]string),
		sigMatcher:   sigMatcher,
	}

	for i := 0; i < numShards; i++ {
		r.shards[i] = &deviceShard{
			devices:  make(map[string]domain.Device),
			profiles: make(map[string]domain.BehavioralProfile),
		}
	}
	return r
}

func (r *DeviceRegistry) getShard(mac string) *deviceShard {
	hash := uint32(0)
	for i := 0; i < len(mac); i++ {
		hash = hash*31 + uint32(mac[i])
	}
	return r.shards[hash%uint32(len(r.shards))]
}

func (r *DeviceRegistry) ProcessDevice(newDevice domain.Device) (domain.Device, bool) {
	shard := r.getShard(newDevice.MAC)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	existing, ok := shard.devices[newDevice.MAC]
	if !ok {
		// New Device initialization
		if newDevice.ProbedSSIDs == nil {
			newDevice.ProbedSSIDs = make(map[string]time.Time)
		}
		if newDevice.FirstSeen.IsZero() {
			newDevice.FirstSeen = newDevice.LastPacketTime
		}
		if newDevice.LastSeen.IsZero() {
			newDevice.LastSeen = newDevice.LastPacketTime
		}

		r.updateBehavioralProfile(shard, newDevice)
		r.performDiscovery(&newDevice)

		// MAC Correlation for randomized addresses
		// Move correlation outside of the primary shard lock to avoid deadlock
		shard.mu.Unlock()
		correlatedMAC, confidence := r.correlateMAC(newDevice)
		shard.mu.Lock()

		if confidence >= 0.8 {
			fmt.Printf("[CORRELATION] Device %s looks like %s (conf=%.2f)\n", newDevice.MAC, correlatedMAC, confidence)
			if p, ok := shard.profiles[newDevice.MAC]; ok {
				p.LinkedMAC = correlatedMAC
				shard.profiles[newDevice.MAC] = p
			}
		}

		if p, ok := shard.profiles[newDevice.MAC]; ok {
			newDevice.Behavioral = &p
		}

		shard.devices[newDevice.MAC] = newDevice
		r.updateSSIDsInternal(newDevice)

		// Populate discovery cache for new device to prevent immediate re-discovery
		r.discoCacheMu.Lock()
		r.discoCache[newDevice.MAC] = newDevice.Signature
		r.discoCacheMu.Unlock()

		return newDevice, true
	}

	// Discovery Cache Check
	shouldPerformDiscovery := r.checkDiscoveryNeeded(existing, newDevice)

	// Merge Logic
	r.mergeDeviceData(&existing, newDevice)

	if shouldPerformDiscovery {
		r.performDiscovery(&existing)
		r.discoCacheMu.Lock()
		r.discoCache[existing.MAC] = existing.Signature
		r.discoCacheMu.Unlock()
	}

	r.updateBehavioralProfile(shard, newDevice)
	if p, ok := shard.profiles[existing.MAC]; ok {
		existing.Behavioral = &p
	}

	shard.devices[newDevice.MAC] = existing
	r.updateSSIDsInternal(existing)

	return existing, shouldPerformDiscovery
}

func (r *DeviceRegistry) checkDiscoveryNeeded(existing, newDevice domain.Device) bool {
	r.discoCacheMu.RLock()
	lastSig, cached := r.discoCache[existing.MAC]
	r.discoCacheMu.RUnlock()
	return !cached || lastSig != newDevice.Signature || existing.Model == ""
}

func (r *DeviceRegistry) mergeDeviceData(existing *domain.Device, newDevice domain.Device) {
	existing.LastPacketTime = newDevice.LastPacketTime
	existing.LastSeen = newDevice.LastPacketTime
	existing.RSSI = newDevice.RSSI
	existing.Latitude = newDevice.Latitude
	existing.Longitude = newDevice.Longitude

	if newDevice.Vendor != "" {
		existing.Vendor = newDevice.Vendor
	}

	if newDevice.Signature != "" {
		existing.Signature = newDevice.Signature
		existing.IETags = newDevice.IETags
	}

	// Merge other fields
	if newDevice.Security != "" {
		existing.Security = newDevice.Security
	}
	if newDevice.Standard != "" {
		existing.Standard = newDevice.Standard
	}
	if newDevice.Model != "" {
		existing.Model = newDevice.Model
	}
	if newDevice.Frequency > 0 {
		existing.Frequency = newDevice.Frequency
	}
	if newDevice.WPSInfo != "" {
		existing.WPSInfo = newDevice.WPSInfo
	}
	if newDevice.HasHandshake {
		existing.HasHandshake = true
	}

	existing.DataTransmitted += newDevice.DataTransmitted
	existing.DataReceived += newDevice.DataReceived
	existing.PacketsCount += newDevice.PacketsCount
	existing.RetryCount += newDevice.RetryCount
	if newDevice.ChannelWidth > 0 {
		existing.ChannelWidth = newDevice.ChannelWidth
	}

	if existing.ProbedSSIDs == nil {
		existing.ProbedSSIDs = make(map[string]time.Time)
	}
	for ssid, ts := range newDevice.ProbedSSIDs {
		existing.ProbedSSIDs[ssid] = ts
	}

	if newDevice.SSID != "" {
		existing.SSID = newDevice.SSID
	}
	if newDevice.ConnectedSSID != "" {
		existing.ConnectedSSID = newDevice.ConnectedSSID
	}
}

func (r *DeviceRegistry) updateSSIDsInternal(d domain.Device) {
	r.ssidsMu.Lock()
	defer r.ssidsMu.Unlock()

	if d.SSID != "" {
		r.ssids[d.SSID] = true
		if d.Security != "" {
			if _, ok := r.ssidSecurity[d.SSID]; !ok {
				r.ssidSecurity[d.SSID] = d.Security
			}
		}
	}
	for ssid := range d.ProbedSSIDs {
		r.ssids[ssid] = true
	}
}

func (r *DeviceRegistry) GetDevice(mac string) (domain.Device, bool) {
	shard := r.getShard(mac)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	d, ok := shard.devices[mac]
	return d, ok
}

func (r *DeviceRegistry) GetAllDevices() []domain.Device {
	var all []domain.Device
	for _, shard := range r.shards {
		shard.mu.RLock()
		for _, d := range shard.devices {
			all = append(all, d)
		}
		shard.mu.RUnlock()
	}
	return all
}

func (r *DeviceRegistry) PruneOldDevices(ttl time.Duration) int {
	threshold := time.Now().Add(-ttl)
	profileThreshold := time.Now().Add(-24 * time.Hour) // Profiles last 24h by default
	deletedCount := 0
	for _, shard := range r.shards {
		shard.mu.Lock()
		for mac, d := range shard.devices {
			if d.LastSeen.Before(threshold) {
				delete(shard.devices, mac)
				deletedCount++
			}
		}
		// Also prune profiles that are very old
		for mac, p := range shard.profiles {
			if p.LastUpdated.Before(profileThreshold) {
				delete(shard.profiles, mac)
			}
		}
		shard.mu.Unlock()
	}
	return deletedCount
}

// Clear wipes all in-memory state.
func (r *DeviceRegistry) Clear() {
	for _, shard := range r.shards {
		shard.mu.Lock()
		shard.devices = make(map[string]domain.Device)
		shard.profiles = make(map[string]domain.BehavioralProfile)
		shard.mu.Unlock()
	}

	r.ssidsMu.Lock()
	r.ssids = make(map[string]bool)
	r.ssidSecurity = make(map[string]string)
	r.ssidsMu.Unlock()

	r.discoCacheMu.Lock()
	r.discoCache = make(map[string]string)
	r.discoCacheMu.Unlock()
}

func (r *DeviceRegistry) GetActiveCount() int {
	count := 0
	for _, shard := range r.shards {
		shard.mu.RLock()
		count += len(shard.devices)
		shard.mu.RUnlock()
	}
	return count
}

func (r *DeviceRegistry) UpdateSSID(ssid, security string) {
	r.ssidsMu.Lock()
	defer r.ssidsMu.Unlock()
	r.ssids[ssid] = true
	if security != "" {
		if _, ok := r.ssidSecurity[ssid]; !ok {
			r.ssidSecurity[ssid] = security
		}
	}
}

func (r *DeviceRegistry) GetSSIDs() map[string]bool {
	r.ssidsMu.RLock()
	defer r.ssidsMu.RUnlock()
	copy := make(map[string]bool)
	for k, v := range r.ssids {
		copy[k] = v
	}
	return copy
}

func (r *DeviceRegistry) GetSSIDSecurity(ssid string) (string, bool) {
	r.ssidsMu.RLock()
	defer r.ssidsMu.RUnlock()
	sec, ok := r.ssidSecurity[ssid]
	return sec, ok
}

func (r *DeviceRegistry) updateBehavioralProfile(shard *deviceShard, device domain.Device) {
	profile, ok := shard.profiles[device.MAC]
	if !ok {
		profile = domain.BehavioralProfile{
			MAC:         device.MAC,
			ActiveHours: make([]int, 0),
			LastUpdated: time.Now(),
		}
	}

	if device.Type == "station" || device.Type == "" {
		hour := device.LastPacketTime.Hour()
		exists := false
		for _, h := range profile.ActiveHours {
			if h == hour {
				exists = true
				break
			}
		}
		if !exists {
			profile.ActiveHours = append(profile.ActiveHours, hour)
		}

		isProbe := false
		for _, cap := range device.Capabilities {
			if cap == "Probe" {
				isProbe = true
				break
			}
		}

		if isProbe {
			if !profile.LastProbeTime.IsZero() {
				interval := device.LastPacketTime.Sub(profile.LastProbeTime)
				if interval > 0 {
					if profile.ProbeFrequency == 0 {
						profile.ProbeFrequency = interval
					} else {
						profile.ProbeFrequency = time.Duration(float64(profile.ProbeFrequency)*0.7 + float64(interval)*0.3)
					}
				}
			}
			profile.LastProbeTime = device.LastPacketTime
		}
	}

	profile.UniqueSSIDs = len(device.ProbedSSIDs)
	profile.SSIDSignature = r.generateSSIDSignature(device.ProbedSSIDs)
	if len(device.IETags) > 0 {
		profile.IETags = device.IETags
	}
	profile.LastUpdated = time.Now()
	shard.profiles[device.MAC] = profile
}

func (r *DeviceRegistry) generateSSIDSignature(probes map[string]time.Time) string {
	if len(probes) == 0 {
		return ""
	}
	ssids := make([]string, 0, len(probes))
	for s := range probes {
		ssids = append(ssids, s)
	}
	sort.Strings(ssids)
	return strings.Join(ssids, ",")
}

func (r *DeviceRegistry) correlateMAC(newDevice domain.Device) (string, float64) {
	// Only correlate randomized MACs
	// A simple check for randomized MAC (locally administered bit)
	if len(newDevice.MAC) < 2 {
		return "", 0
	}
	firstByte, _ := hex.DecodeString(newDevice.MAC[0:2])
	if len(firstByte) > 0 && (firstByte[0]&0x02) == 0 {
		// Not a randomized MAC
		return "", 0
	}

	newSig := r.generateSSIDSignature(newDevice.ProbedSSIDs)
	if newSig == "" {
		return "", 0
	}

	bestMAC := ""
	maxScore := 0.0

	for _, shard := range r.shards {
		shard.mu.RLock()
		for mac, p := range shard.profiles {
			if p.SSIDSignature == "" {
				continue
			}

			// Score based on SSID signature similarity
			score := 0.0
			if p.SSIDSignature == newSig {
				score = 0.8
			} else if strings.Contains(p.SSIDSignature, newSig) || strings.Contains(newSig, p.SSIDSignature) {
				score = 0.4
			}

			// Add IE tag similarity if available
			if len(p.IETags) > 0 && len(newDevice.IETags) > 0 {
				ieMatch := 0
				minLen := len(p.IETags)
				if len(newDevice.IETags) < minLen {
					minLen = len(newDevice.IETags)
				}
				for i := 0; i < minLen; i++ {
					if p.IETags[i] == newDevice.IETags[i] {
						ieMatch++
					}
				}
				ieScore := float64(ieMatch) / float64(minLen)
				score = (score * 0.6) + (ieScore * 0.4)
			}

			if score > maxScore {
				maxScore = score
				bestMAC = mac
			}
		}
		shard.mu.RUnlock()
	}

	return bestMAC, maxScore
}

func (r *DeviceRegistry) performDiscovery(device *domain.Device) {
	if r.sigMatcher == nil {
		return
	}
	match := r.sigMatcher.MatchSignature(*device)
	if match != nil && match.Confidence >= 0.6 {
		device.Model = match.Signature.Model
		device.OS = match.Signature.OS
		device.Type = match.Signature.DeviceType
	}
}
