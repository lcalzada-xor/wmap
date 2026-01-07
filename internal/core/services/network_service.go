package services

import (
	"context"
	"fmt"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	packetsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wmap_packets_processed_total",
		Help: "The total number of processed packets",
	})
	devicesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wmap_devices_active_total",
		Help: "The total number of active devices in memory",
	})
	cleanupRuns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "wmap_cleanup_runs_total",
		Help: "The total number of cleanup cycles executed",
	})
)

// NetworkService orchestrates the discovery and analysis of network devices.
type NetworkService struct {
	registry     ports.DeviceRegistry
	security     ports.SecurityEngine
	persistence  *PersistenceManager
	sniffer      ports.Sniffer
	graphBuilder *GraphBuilder
	deauthEngine *sniffer.DeauthEngine
}

// NewNetworkService creates a new orchestrator service.
func NewNetworkService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
	persistence *PersistenceManager,
	sniffer ports.Sniffer,
) *NetworkService {
	return &NetworkService{
		registry:     registry,
		security:     security,
		persistence:  persistence,
		sniffer:      sniffer,
		graphBuilder: NewGraphBuilder(registry),
	}

	// Initialize Deauth Engine
	// We check if sniffer implements the Locker interface.
	// Since ports.Sniffer is an interface, we might need to update ports.
	// For now, let's assume valid injection.
	// Actually, we need to update ports/ports.go to include Lock/Unlock or
	// cast it here if we know the implementation.
	// Better approach: Update ports.Sniffer to include ChannelLocker methods or
	// check type assertion.

	// Quick fix: Type assert if possible, or update ports.
	// Let's assume we update ports.Sniffer.
}

// SetDeauthEngine injects the deauth engine dependency
func (s *NetworkService) SetDeauthEngine(engine *sniffer.DeauthEngine) {
	s.deauthEngine = engine
}

// SetDeauthLogger sets the logger for the deauth engine
func (s *NetworkService) SetDeauthLogger(logger func(string, string)) {
	if s.deauthEngine != nil {
		s.deauthEngine.SetLogger(logger)
	}
}

// ProcessDevice handles a newly captured device packet.
func (s *NetworkService) ProcessDevice(newDevice domain.Device) {
	packetsProcessed.Inc()

	// 1. Registry: Merge state and perform discovery
	merged, _ := s.registry.ProcessDevice(newDevice)

	// 2. Security: Perform analysis on the merged state
	s.security.Analyze(merged)

	// 3. Persistence: Queue for background write
	if s.persistence != nil {
		s.persistence.Persist(merged)
	}

	// 4. Placeholder logic for APs (if station is connected to unknown AP)
	if merged.ConnectedSSID != "" {
		if _, ok := s.registry.GetDevice(merged.ConnectedSSID); !ok {
			placeholder := domain.Device{
				MAC:            merged.ConnectedSSID,
				Type:           "ap",
				FirstSeen:      time.Now(),
				LastSeen:       time.Now(),
				LastPacketTime: time.Now(),
			}
			s.registry.ProcessDevice(placeholder)
		}
	}
}

// GetGraph returns the graph projection for visualization.
// GetGraph returns the graph projection for visualization.
func (s *NetworkService) GetGraph() domain.GraphData {
	return s.graphBuilder.BuildGraph()
}

// AddRule delegates to the Security Engine.
func (s *NetworkService) AddRule(rule domain.AlertRule) {
	s.security.AddRule(rule)
}

// GetAlerts delegates to the Security Engine.
func (s *NetworkService) GetAlerts() []domain.Alert {
	return s.security.GetAlerts()
}

// TriggerScan delegates to the Sniffer.
func (s *NetworkService) TriggerScan() error {
	if s.sniffer == nil {
		return nil
	}
	return s.sniffer.Scan("")
}

// StartCleanupLoop manages the periodic removal of old devices.
func (s *NetworkService) StartCleanupLoop(ctx context.Context, ttl time.Duration, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupRuns.Inc()
				deleted := s.registry.PruneOldDevices(ttl)
				if deleted > 0 {
					devicesActive.Set(float64(s.registry.GetActiveCount()))
				}
			}
		}
	}()
}

// SetPersistenceEnabled toggles the database persistence.
func (s *NetworkService) SetPersistenceEnabled(enabled bool) {
	if s.persistence != nil {
		s.persistence.SetEnabled(enabled)
	}
}

// IsPersistenceEnabled returns the current persistence status.
func (s *NetworkService) IsPersistenceEnabled() bool {
	if s.persistence != nil {
		return s.persistence.IsEnabled()
	}
	return false
}

// ResetSession wipes the current in-memory discovery state.
func (s *NetworkService) ResetSession() {
	s.registry.Clear()
}

// SetChannels updates the sniffer's channel hopping list.
func (s *NetworkService) SetChannels(channels []int) {
	if s.sniffer != nil {
		s.sniffer.SetChannels(channels)
	}
}

func (s *NetworkService) GetChannels() []int {
	if s.sniffer != nil {
		return s.sniffer.GetChannels()
	}
	return []int{}
}

// SetInterfaceChannels updates the sniffer's channel hopping list for a specific interface.
func (s *NetworkService) SetInterfaceChannels(iface string, channels []int) {
	if s.sniffer != nil {
		s.sniffer.SetInterfaceChannels(iface, channels)
	}
}

// GetInterfaceChannels returns the current channel hopping list for a specific interface.
func (s *NetworkService) GetInterfaceChannels(iface string) []int {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceChannels(iface)
	}
	return []int{}
}

// GetInterfaces returns the list of available interfaces.
func (s *NetworkService) GetInterfaces() []string {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaces()
	}
	return []string{}
}

// GetInterfaceDetails returns detailed info for all interfaces.
func (s *NetworkService) GetInterfaceDetails() []domain.InterfaceInfo {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceDetails()
	}
	return []domain.InterfaceInfo{}
}

// Deauth Attack Methods

// StartDeauthAttack initiates a new deauthentication attack
func (s *NetworkService) StartDeauthAttack(config domain.DeauthAttackConfig) (string, error) {
	if s.deauthEngine == nil {
		return "", fmt.Errorf("deauth engine not initialized")
	}

	// Auto-detect channel if not specified
	if config.Channel == 0 {
		device, exists := s.registry.GetDevice(config.TargetMAC)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		} else {
			return "", fmt.Errorf("channel is 0 and could not be auto-detected for target %s", config.TargetMAC)
		}
	}

	return s.deauthEngine.StartAttack(config)
}

// StopDeauthAttack stops a running deauth attack
func (s *NetworkService) StopDeauthAttack(id string) error {
	if s.deauthEngine == nil {
		return fmt.Errorf("deauth engine not initialized")
	}
	return s.deauthEngine.StopAttack(id)
}

// GetDeauthStatus returns the status of a specific attack
func (s *NetworkService) GetDeauthStatus(id string) (domain.DeauthAttackStatus, error) {
	if s.deauthEngine == nil {
		return domain.DeauthAttackStatus{}, fmt.Errorf("deauth engine not initialized")
	}
	return s.deauthEngine.GetAttackStatus(id)
}

// ListDeauthAttacks returns all active deauth attacks
func (s *NetworkService) ListDeauthAttacks() []domain.DeauthAttackStatus {
	if s.deauthEngine == nil {
		return []domain.DeauthAttackStatus{}
	}
	return s.deauthEngine.ListActiveAttacks()
}
