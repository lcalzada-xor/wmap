package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/security"
)

const numShards = 16

type deviceShard struct {
	mu       sync.RWMutex
	devices  map[string]domain.Device
	profiles map[string]domain.BehavioralProfile
}

// DeviceRegistry implements ports.DeviceRegistry.
type DeviceRegistry struct {
	shards      []*deviceShard
	ssidManager *SSIDManager
	merger      *DeviceMerger
	subject     *RegistrySubject
	discoCache  map[string]string

	// Services
	BehaviorEngine *security.BehaviorEngine
	// MAC -> Last processed Signature
	discoCacheMu sync.RWMutex
	sigMatcher   ports.SignatureMatcher

	// Vulnerability Persistence
	VulnPersistence *security.VulnerabilityPersistenceService
	VulnDetector    *security.VulnerabilityDetector
}

// NewDeviceRegistry creates a new sharded registry.
func NewDeviceRegistry(sigMatcher ports.SignatureMatcher, vulnStore *security.VulnerabilityPersistenceService) *DeviceRegistry {
	r := &DeviceRegistry{
		shards:          make([]*deviceShard, numShards),
		ssidManager:     NewSSIDManager(),
		merger:          NewDeviceMerger(),
		subject:         NewRegistrySubject(),
		discoCache:      make(map[string]string),
		BehaviorEngine:  security.NewBehaviorEngine(),
		sigMatcher:      sigMatcher,
		VulnPersistence: vulnStore,
	}
	// r.VulnDetector will be set after 'r' is created to avoid circular dep issues in constructor params,
	// but we can set it here using 'r' reference.
	r.VulnDetector = security.NewVulnerabilityDetector(r)

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

func (r *DeviceRegistry) ProcessDevice(ctx context.Context, newDevice domain.Device) (domain.Device, bool) {
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
		r.performDiscovery(ctx, &newDevice)

		// Move correlation outside of the primary shard lock to avoid deadlock
		shard.mu.Unlock()
		correlatedMAC, confidence := r.correlateMAC(newDevice)
		shard.mu.Lock()

		// Race Condition Fix: Check if another thread created the device while we were unlocked
		if raceExisting, raceOk := shard.devices[newDevice.MAC]; raceOk {
			// Another thread beat us to it. Merge our data into the existing one.
			r.merger.Merge(&raceExisting, newDevice)
			shard.devices[newDevice.MAC] = raceExisting
			// Strictly speaking, it's not "new" to the registry anymore, but we might want to return true/false based on discovery?
			// Let's return false as it's an update now.
			return raceExisting, false
		}

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
		r.ssidManager.Update(ctx, newDevice.SSID, newDevice.Security)
		r.ssidManager.Update(ctx, "", "") // Dummy to trigger internal SSID update for ProbedSSIDs?
		// Actually SSIDManager Update only takes one SSID. We need to iterate probed SSIDs.
		for ssid := range newDevice.ProbedSSIDs {
			r.ssidManager.Update(ctx, ssid, "")
		}

		// Populate discovery cache for new device to prevent immediate re-discovery
		r.discoCacheMu.Lock()
		r.discoCache[newDevice.MAC] = newDevice.Signature
		r.discoCacheMu.Unlock()

		r.subject.NotifyAdded(ctx, newDevice) // Notify Observers

		// Vulnerability Detection for New Devices (All Types)
		if r.VulnPersistence != nil && r.VulnDetector != nil {
			go func(d domain.Device) {
				vulns := r.VulnDetector.DetectVulnerabilities(&d)
				if len(vulns) > 0 {
					deviceDesc := d.SSID
					if deviceDesc == "" {
						deviceDesc = string(d.Type)
					}
					fmt.Printf("[VULN] Detected %d vulnerabilities for new device %s (%s)\n", len(vulns), d.MAC, deviceDesc)
					if err := r.VulnPersistence.ProcessDetections(d.MAC, vulns); err != nil {
						fmt.Printf("[VULN] Error persisting vulnerabilities for %s: %v\n", d.MAC, err)
					}
				}
			}(newDevice)
		}

		return newDevice, true
	}

	// Discovery Cache Check
	shouldPerformDiscovery := r.checkDiscoveryNeeded(existing, newDevice)

	// Merge Logic
	r.merger.Merge(&existing, newDevice)

	if shouldPerformDiscovery {
		r.performDiscovery(ctx, &existing)
		r.discoCacheMu.Lock()
		r.discoCache[existing.MAC] = existing.Signature
		r.discoCacheMu.Unlock()
	}

	r.updateBehavioralProfile(shard, newDevice)
	if p, ok := shard.profiles[existing.MAC]; ok {
		existing.Behavioral = &p
	}

	shard.devices[newDevice.MAC] = existing

	r.ssidManager.Update(ctx, existing.SSID, existing.Security)
	for ssid := range existing.ProbedSSIDs {
		r.ssidManager.Update(ctx, ssid, "")
	}

	r.subject.NotifyUpdated(ctx, existing) // Notify Observers

	// Vulnerability Detection for Updated Devices (All Types)
	if r.VulnPersistence != nil && r.VulnDetector != nil {
		go func(d domain.Device) {
			vulns := r.VulnDetector.DetectVulnerabilities(&d)
			if len(vulns) > 0 {
				deviceDesc := d.SSID
				if deviceDesc == "" {
					deviceDesc = string(d.Type)
				}
				fmt.Printf("[VULN] Detected %d vulnerabilities for device %s (%s)\n", len(vulns), d.MAC, deviceDesc)
				if err := r.VulnPersistence.ProcessDetections(d.MAC, vulns); err != nil {
					fmt.Printf("[VULN] Error persisting vulnerabilities for %s: %v\n", d.MAC, err)
				}
			}
		}(existing)
	}

	return existing, shouldPerformDiscovery
}

func (r *DeviceRegistry) LoadDevice(ctx context.Context, device domain.Device) {
	shard := r.getShard(device.MAC)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 1. Restore Device
	shard.devices[device.MAC] = device

	// 2. Restore Profile if present
	if device.Behavioral != nil {
		shard.profiles[device.MAC] = *device.Behavioral
	}

	// 3. Update Lookup Maps
	r.ssidManager.Update(ctx, device.SSID, device.Security)
	for ssid := range device.ProbedSSIDs {
		r.ssidManager.Update(ctx, ssid, "")
	}

	// 4. Populate Disco Cache to avoid immediate re-discovery upon next packet
	r.discoCacheMu.Lock()
	r.discoCache[device.MAC] = device.Signature
	r.discoCacheMu.Unlock()
}

func (r *DeviceRegistry) checkDiscoveryNeeded(existing, newDevice domain.Device) bool {
	r.discoCacheMu.RLock()
	lastSig, cached := r.discoCache[existing.MAC]
	r.discoCacheMu.RUnlock()
	return !cached || lastSig != newDevice.Signature || existing.Model == ""
}

// DELETED: func (r *DeviceRegistry) mergeDeviceData...
// DELETED: func (r *DeviceRegistry) updateSSIDsInternal...

func (r *DeviceRegistry) GetDevice(ctx context.Context, mac string) (domain.Device, bool) {
	shard := r.getShard(mac)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	d, ok := shard.devices[mac]
	return d, ok
}

func (r *DeviceRegistry) GetAllDevices(ctx context.Context) []domain.Device {
	var all []domain.Device
	for _, shard := range r.shards {
		shard.mu.RLock()
		for _, d := range shard.devices {
			// Deep copy maps to prevent race conditions
			// ProbedSSIDs is read by GraphBuilder while potentially being written by mergeDeviceData
			dCopy := d
			if d.ProbedSSIDs != nil {
				dCopy.ProbedSSIDs = make(map[string]time.Time, len(d.ProbedSSIDs))
				for k, v := range d.ProbedSSIDs {
					dCopy.ProbedSSIDs[k] = v
				}
			}
			// IETags is a slice, might need copy if modified (append creates new slice usually, but modifying elements?)
			// Typically IETags are just replaced, but safer to copy if we want true snapshot.
			if d.IETags != nil {
				dCopy.IETags = make([]int, len(d.IETags))
				copy(dCopy.IETags, d.IETags)
			}

			all = append(all, dCopy)
		}
		shard.mu.RUnlock()
	}
	return all
}

func (r *DeviceRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int {
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

// CleanupStaleConnections degrades connections to "disconnected" if silent for too long.
func (r *DeviceRegistry) CleanupStaleConnections(ctx context.Context, timeout time.Duration) int {
	threshold := time.Now().Add(-timeout)
	count := 0

	for _, shard := range r.shards {
		shard.mu.Lock()
		for mac, d := range shard.devices {
			// Only check active connections
			if d.ConnectionState == domain.StateConnected || d.ConnectionState == domain.StateHandshake || d.ConnectionState == domain.StateAssociating {
				if d.LastPacketTime.Before(threshold) {
					// Downgrade state
					d.ConnectionState = domain.StateDisconnected
					d.ConnectionTarget = ""
					// We keep ConnectedSSID as "last known" or clear it?
					// Ideally we keep it for implicit history until they move.
					// But for graph cleanliness, maybe valid to keep it but state=disconnected prevents line drawing?
					// GraphBuilder checks: if ConnectionState != Disconnected -> draw line.
					// So clearing ConnectedSSID isn't strictly necessary if strict state check is used,
					// but let's clear it to be consistent with "Clean" disconnection.
					d.ConnectedSSID = ""

					shard.devices[mac] = d
					count++
				}
			}
		}
		shard.mu.Unlock()
	}
	return count
}

// Clear wipes all in-memory state.
func (r *DeviceRegistry) Clear(ctx context.Context) {
	for _, shard := range r.shards {
		shard.mu.Lock()
		shard.devices = make(map[string]domain.Device)
		shard.profiles = make(map[string]domain.BehavioralProfile)
		shard.mu.Unlock()
	}

	r.ssidManager.Clear()

	r.discoCacheMu.Lock()
	r.discoCache = make(map[string]string)
	r.discoCacheMu.Unlock()
}

func (r *DeviceRegistry) GetActiveCount(ctx context.Context) int {
	count := 0
	for _, shard := range r.shards {
		shard.mu.RLock()
		count += len(shard.devices)
		shard.mu.RUnlock()
	}
	return count
}

func (r *DeviceRegistry) UpdateSSID(ctx context.Context, ssid, security string) {
	r.ssidManager.Update(ctx, ssid, security)
}

func (r *DeviceRegistry) GetSSIDs(ctx context.Context) map[string]bool {
	return r.ssidManager.GetSSIDs(ctx)
}

func (r *DeviceRegistry) GetSSIDSecurity(ctx context.Context, ssid string) (string, bool) {
	return r.ssidManager.GetSecurity(ctx, ssid)
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

	// Delegate logic to BehaviorEngine
	updatedProfile := r.BehaviorEngine.UpdateProfile(profile, device)
	shard.profiles[device.MAC] = updatedProfile
}

func (r *DeviceRegistry) correlateMAC(newDevice domain.Device) (string, float64) {
	// Only correlate randomized MACs
	if !r.BehaviorEngine.IsRandomizedMAC(newDevice.MAC) {
		// Not a randomized MAC
		return "", 0
	}

	bestMAC := ""
	maxScore := 0.0

	for _, shard := range r.shards {
		shard.mu.RLock()
		for mac, p := range shard.profiles {
			// Skip correlation with itself? (though MACs are different)

			score := r.BehaviorEngine.CalculateMatchScore(p, newDevice)
			if score > maxScore {
				maxScore = score
				bestMAC = mac
			}
		}
		shard.mu.RUnlock()
	}

	return bestMAC, maxScore
}

func (r *DeviceRegistry) performDiscovery(ctx context.Context, device *domain.Device) {
	if r.sigMatcher == nil {
		return
	}
	match := r.sigMatcher.MatchSignature(ctx, *device)
	if match != nil && match.Confidence >= 0.6 {
		device.Model = match.Signature.Model
		device.OS = match.Signature.OS
		device.Type = domain.DeviceType(match.Signature.DeviceType)
	}
}
