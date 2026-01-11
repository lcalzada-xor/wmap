package services

import (
	"context"
	"fmt"
	"sync"
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
	registry        ports.DeviceRegistry
	security        ports.SecurityEngine
	persistence     *PersistenceManager
	sniffer         ports.Sniffer
	graphBuilder    *GraphBuilder
	deauthEngine    ports.DeauthService
	wpsEngine       ports.WPSAttackService
	authFloodEngine *sniffer.AuthFloodEngine
	auditService    ports.AuditService

	// Optimization: Graph Caching
	cachedGraph     *domain.GraphData
	lastGraphUpdate time.Time
	graphMu         sync.RWMutex
}

// NewNetworkService creates a new orchestrator service.
func NewNetworkService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
	persistence *PersistenceManager,
	sniffer ports.Sniffer,
	auditService ports.AuditService,
) *NetworkService {
	return &NetworkService{
		registry:     registry,
		security:     security,
		persistence:  persistence,
		sniffer:      sniffer,
		auditService: auditService,
		graphBuilder: NewGraphBuilder(registry),
	}
}

// SetDeauthEngine injects the deauth engine dependency
func (s *NetworkService) SetDeauthEngine(engine ports.DeauthService) {
	s.deauthEngine = engine
}

// SetWPSEngine injects the WPS engine dependency
func (s *NetworkService) SetWPSEngine(engine ports.WPSAttackService) {
	s.wpsEngine = engine
}

// SetAuthFloodEngine injects the Auth Flood engine dependency
func (s *NetworkService) SetAuthFloodEngine(engine *sniffer.AuthFloodEngine) {
	s.authFloodEngine = engine
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
	s.graphMu.RLock()
	if s.cachedGraph != nil && time.Since(s.lastGraphUpdate) < 2*time.Second {
		defer s.graphMu.RUnlock()
		return *s.cachedGraph
	}
	s.graphMu.RUnlock()

	s.graphMu.Lock()
	defer s.graphMu.Unlock()

	// Double-check check optimization (standard pattern)
	if s.cachedGraph != nil && time.Since(s.lastGraphUpdate) < 2*time.Second {
		return *s.cachedGraph
	}

	g := s.graphBuilder.BuildGraph()
	s.cachedGraph = &g
	s.lastGraphUpdate = time.Now()
	return g
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

				// Cleanup Stale Connections (Every 30s check, 2m threshold)
				// We can re-use the ticker interval for now, or use a separate timer if needed.
				// Assuming 'interval' is small enough (e.g. 5-30s).
				// StartCleanupLoop is called in server.go with 30s usually.
				cleaned := s.registry.CleanupStaleConnections(2 * time.Minute)
				if cleaned > 0 {
					// Optionally log or metric update
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

// ResetWorkspace wipes the current in-memory discovery state.
func (s *NetworkService) ResetWorkspace() {
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

	// Auto-detect interface if not provided (fallback)
	if config.Interface == "" {
		if s.sniffer != nil {
			interfaces := s.sniffer.GetInterfaces()
			if len(interfaces) > 0 {
				// Strategy: Find interface that already has this channel, or fallback to first
				found := false
				for _, iface := range interfaces {
					chans := s.sniffer.GetInterfaceChannels(iface)
					for _, ch := range chans {
						if ch == config.Channel {
							config.Interface = iface
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					config.Interface = interfaces[0]
				}
			}
		}
	}

	id, err := s.deauthEngine.StartAttack(config)
	if err == nil && s.auditService != nil {
		s.auditService.Log(context.Background(), domain.ActionDeauthStart, config.TargetMAC, fmt.Sprintf("Type: %s, Ch: %d", config.AttackType, config.Channel))
	}
	return id, err
}

// StopDeauthAttack stops a running deauth attack
func (s *NetworkService) StopDeauthAttack(id string, force bool) error {
	if s.deauthEngine == nil {
		return fmt.Errorf("deauth engine not initialized")
	}
	err := s.deauthEngine.StopAttack(id, force)
	if err == nil && s.auditService != nil {
		msg := "Attack stopped by user"
		if force {
			msg += " (forced)"
		}
		s.auditService.Log(context.Background(), domain.ActionDeauthStop, id, msg)
	}
	return err
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

// WPS Attack Methods

// StartWPSAttack initiates a new WPS Pixie Dust attack
func (s *NetworkService) StartWPSAttack(config domain.WPSAttackConfig) (string, error) {
	if s.wpsEngine == nil {
		return "", fmt.Errorf("WPS engine not initialized")
	}

	// Basic validation
	if config.TargetBSSID == "" {
		return "", fmt.Errorf("target BSSID is required")
	}

	// Auto-detect channel if not specified
	if config.Channel == 0 {
		device, exists := s.registry.GetDevice(config.TargetBSSID)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		} else {
			return "", fmt.Errorf("channel is 0 and could not be auto-detected for target %s", config.TargetBSSID)
		}
	}

	// Auto-detect interface if not provided (fallback)
	if config.Interface == "" {
		if s.sniffer != nil {
			interfaces := s.sniffer.GetInterfaces()
			if len(interfaces) > 0 {
				// Strategy: Find interface that already has this channel, or fallback to first
				found := false
				if config.Channel > 0 {
					for _, iface := range interfaces {
						chans := s.sniffer.GetInterfaceChannels(iface)
						for _, ch := range chans {
							if ch == config.Channel {
								config.Interface = iface
								found = true
								break
							}
						}
						if found {
							break
						}
					}
				}
				if !found {
					config.Interface = interfaces[0]
				}
			} else {
				return "", fmt.Errorf("no interfaces available for attack")
			}
		} else {
			return "", fmt.Errorf("sniffer not initialized, cannot auto-detect interface")
		}
	}

	return s.wpsEngine.StartAttack(config)
}

// StopWPSAttack stops a running WPS attack
func (s *NetworkService) StopWPSAttack(id string, force bool) error {
	if s.wpsEngine == nil {
		return fmt.Errorf("WPS engine not initialized")
	}
	return s.wpsEngine.StopAttack(id, force)
}

// GetWPSStatus returns the status of a specific attack
func (s *NetworkService) GetWPSStatus(id string) (domain.WPSAttackStatus, error) {
	if s.wpsEngine == nil {
		return domain.WPSAttackStatus{}, fmt.Errorf("WPS engine not initialized")
	}
	return s.wpsEngine.GetStatus(id)
}

// GetSystemStats calculates aggregate intelligence metrics.
func (s *NetworkService) GetSystemStats() domain.SystemStats {
	devices := s.registry.GetAllDevices()
	stats := domain.SystemStats{
		DeviceCount:   len(devices),
		AlertCount:    len(s.security.GetAlerts()),
		VendorStats:   make(map[string]int),
		SecurityStats: make(map[string]int),
	}

	var totalRetry float64
	var packetDevices int

	for _, d := range devices {
		// Vendor
		v := d.Vendor
		if v == "" {
			v = "Unknown"
		}
		stats.VendorStats[v]++

		// Security (only for networks/APs usually, but keeping general)
		if d.Security != "" {
			stats.SecurityStats[d.Security]++
		}

		// Global Retry Rate
		if d.PacketsCount > 0 {
			rate := float64(d.RetryCount) / float64(d.PacketsCount)
			totalRetry += rate
			packetDevices++
		}
	}

	if packetDevices > 0 {
		stats.GlobalRetry = totalRetry / float64(packetDevices)
	}

	return stats
}

// Auth Flood Attack Methods

func (s *NetworkService) StartAuthFloodAttack(config domain.AuthFloodAttackConfig) (string, error) {
	if s.authFloodEngine == nil {
		return "", fmt.Errorf("auth flood engine not initialized")
	}

	// Auto-detect channel if not specified
	if config.Channel == 0 && config.TargetBSSID != "" {
		device, exists := s.registry.GetDevice(config.TargetBSSID)
		if exists && device.Channel > 0 {
			config.Channel = device.Channel
		}
	}

	// Auto-detect interface
	if config.Interface == "" && s.sniffer != nil {
		interfaces := s.sniffer.GetInterfaces()
		if len(interfaces) > 0 {
			config.Interface = interfaces[0]
		}
	}

	id, err := s.authFloodEngine.StartAttack(config)
	if err == nil && s.auditService != nil {
		s.auditService.Log(context.Background(), domain.ActionDeauthStart, config.TargetBSSID, "Started Auth Flood")
	}
	return id, err
}

func (s *NetworkService) StopAuthFloodAttack(id string, force bool) error {
	if s.authFloodEngine == nil {
		return fmt.Errorf("auth flood engine not initialized")
	}
	return s.authFloodEngine.StopAttack(id, force)
}

func (s *NetworkService) GetAuthFloodStatus(id string) (domain.AuthFloodAttackStatus, error) {
	if s.authFloodEngine == nil {
		return domain.AuthFloodAttackStatus{}, fmt.Errorf("auth flood engine not initialized")
	}
	return s.authFloodEngine.GetStatus(id)
}
