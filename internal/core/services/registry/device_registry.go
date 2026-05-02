package registry

import (
	"context"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

const numShards = 16

type deviceShard struct {
	mu       sync.RWMutex
	devices  map[string]domain.Device
}

// DeviceRegistry implements ports.DeviceRegistry.
type DeviceRegistry struct {
	shards      []*deviceShard
	ssidManager *SSIDManager
	subject     *RegistrySubject
	discoCache  map[string]string

	// MAC -> Last processed Signature
	discoCacheMu sync.RWMutex
	sigMatcher   ports.SignatureMatcher
}

// NewDeviceRegistry creates a new sharded registry.
func NewDeviceRegistry(sigMatcher ports.SignatureMatcher) *DeviceRegistry {
	r := &DeviceRegistry{
		shards:         make([]*deviceShard, numShards),
		ssidManager:    NewSSIDManager(),
		subject:        NewRegistrySubject(),
		discoCache:     make(map[string]string),
		sigMatcher:     sigMatcher,
	}

	for i := 0; i < numShards; i++ {
		r.shards[i] = &deviceShard{
			devices:  make(map[string]domain.Device),
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

		r.performDiscovery(ctx, &newDevice)

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

		return newDevice, true
	}

	// Discovery Cache Check
	shouldPerformDiscovery := r.checkDiscoveryNeeded(existing, newDevice)

	// Merge Logic
	existing.UpdateFrom(newDevice)

	if shouldPerformDiscovery {
		r.performDiscovery(ctx, &existing)
		r.discoCacheMu.Lock()
		r.discoCache[existing.MAC] = existing.Signature
		r.discoCacheMu.Unlock()
	}

	shard.devices[newDevice.MAC] = existing

	r.ssidManager.Update(ctx, existing.SSID, existing.Security)
	for ssid := range existing.ProbedSSIDs {
		r.ssidManager.Update(ctx, ssid, "")
	}

	r.subject.NotifyUpdated(ctx, existing) // Notify Observers

	return existing, shouldPerformDiscovery
}

func (r *DeviceRegistry) LoadDevice(ctx context.Context, device domain.Device) {
	shard := r.getShard(device.MAC)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 1. Restore Device
	shard.devices[device.MAC] = device

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
			// Use domain-level deep copy to prevent race conditions
			all = append(all, d.Clone())
		}
		shard.mu.RUnlock()
	}
	return all
}

func (r *DeviceRegistry) PruneOldDevices(ctx context.Context, ttl time.Duration) int {
	threshold := time.Now().Add(-ttl)
	deletedCount := 0
	for _, shard := range r.shards {
		shard.mu.Lock()
		for mac, d := range shard.devices {
			if d.LastSeen.Before(threshold) {
				delete(shard.devices, mac)
				deletedCount++
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

// AddObserver registers a new observer to receive device updates.
func (r *DeviceRegistry) AddObserver(observer ports.DeviceObserver) {
	r.subject.AddObserver(observer)
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
