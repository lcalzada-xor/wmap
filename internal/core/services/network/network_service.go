package network

import (
	"context"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/attack/authflood"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
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
// It acts as a facade, delegating specific responsibilities to specialized services.
type NetworkService struct {
	registry     ports.DeviceRegistry
	security     ports.SecurityEngine
	persistence  *persistence.PersistenceManager
	sniffer      ports.Sniffer
	auditService ports.AuditService

	// Sub-Services
	statsService      *StatsService
	attackCoordinator *AttackCoordinator

	// Initialization state
	mu sync.RWMutex
}

// NewNetworkService creates a new orchestrator service.
func NewNetworkService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
	persistence *persistence.PersistenceManager,
	sniffer ports.Sniffer,
	auditService ports.AuditService,
) *NetworkService {
	return &NetworkService{
		registry:          registry,
		security:          security,
		persistence:       persistence,
		sniffer:           sniffer,
		auditService:      auditService,
		statsService:      NewStatsService(registry, security),
		attackCoordinator: NewAttackCoordinator(registry, sniffer, auditService),
	}
}

// SetDeauthEngine injects the deauth engine dependency
func (s *NetworkService) SetDeauthEngine(engine ports.DeauthService) {
	s.attackCoordinator.SetDeauthEngine(engine)
}

// SetWPSEngine injects the WPS engine dependency
func (s *NetworkService) SetWPSEngine(engine ports.WPSAttackService) {
	s.attackCoordinator.SetWPSEngine(engine)
}

// SetAuthFloodEngine injects the Auth Flood engine dependency
func (s *NetworkService) SetAuthFloodEngine(engine *authflood.AuthFloodEngine) {
	s.attackCoordinator.SetAuthFloodEngine(engine)
}

// SetDeauthLogger sets the logger for the deauth engine
func (s *NetworkService) SetDeauthLogger(logger func(string, string)) {
	// Wrapper to access protected/private engine inside coordinator if needed,
	// or assume the engine is configured before set.
	// Since deauthEngine inside Coordinator is public or accessible via setter,
	// we assume the caller configures the engine on the coordinator if they have access,
	// OR we expose a method on Coordinator.
	// For now, if the engine interacts directly via interface, we can't easily set logger here
	// unless we cast. But sticking to existing API:
	if s.attackCoordinator.deauthEngine != nil {
		s.attackCoordinator.deauthEngine.SetLogger(logger)
	}
}

// ProcessDevice handles a newly captured device packet.
func (s *NetworkService) ProcessDevice(ctx context.Context, newDevice domain.Device) error {
	packetsProcessed.Inc()

	// 1. Registry: Merge state and perform discovery
	merged, _ := s.registry.ProcessDevice(ctx, newDevice)

	// 2. Security: Perform analysis on the merged state
	s.security.Analyze(ctx, merged)

	// 3. Persistence: Queue for background write
	if s.persistence != nil {
		s.persistence.Persist(merged)
	}

	// 4. Placeholder logic for APs (if station is connected to unknown AP)
	if merged.ConnectedSSID != "" {
		if _, ok := s.registry.GetDevice(ctx, merged.ConnectedSSID); !ok {
			placeholder := domain.Device{
				MAC:            merged.ConnectedSSID,
				Type:           "ap",
				FirstSeen:      time.Now(),
				LastSeen:       time.Now(),
				LastPacketTime: time.Now(),
			}
			s.registry.ProcessDevice(ctx, placeholder)
		}
	}
	return nil
}

// GetGraph returns the graph projection for visualization.
func (s *NetworkService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	return s.statsService.GetGraph(ctx)
}

// AddRule delegates to the Security Engine.
func (s *NetworkService) AddRule(ctx context.Context, rule domain.AlertRule) error {
	s.security.AddRule(ctx, rule)
	return nil
}

// GetAlerts delegates to the Security Engine.
func (s *NetworkService) GetAlerts(ctx context.Context) ([]domain.Alert, error) {
	return s.security.GetAlerts(ctx), nil
}

// TriggerScan delegates to the Sniffer.
func (s *NetworkService) TriggerScan(ctx context.Context) error {
	if s.sniffer == nil {
		return nil
	}
	// Sniffer Scan interface also updated to accept context (assumed)
	return s.sniffer.Scan(ctx, "")
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
				deleted := s.registry.PruneOldDevices(ctx, ttl)
				if deleted > 0 {
					devicesActive.Set(float64(s.registry.GetActiveCount(ctx)))
				}

				s.registry.CleanupStaleConnections(ctx, 2*time.Minute)
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
func (s *NetworkService) ResetWorkspace(ctx context.Context) error {
	s.registry.Clear(ctx)
	return nil
}

// SetChannels updates the sniffer's channel hopping list.
func (s *NetworkService) SetChannels(ctx context.Context, channels []int) error {
	if s.sniffer != nil {
		s.sniffer.SetChannels(ctx, channels)
	}
	return nil
}

func (s *NetworkService) GetChannels(ctx context.Context) ([]int, error) {
	if s.sniffer != nil {
		return s.sniffer.GetChannels(ctx), nil
	}
	return []int{}, nil
}

// SetInterfaceChannels updates the sniffer's channel hopping list for a specific interface.
func (s *NetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	if s.sniffer != nil {
		s.sniffer.SetInterfaceChannels(ctx, iface, channels)
	}
	return nil
}

// GetInterfaceChannels returns the current channel hopping list for a specific interface.
func (s *NetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceChannels(ctx, iface)
	}
	return []int{}, nil
}

// GetInterfaces returns the list of available interfaces.
func (s *NetworkService) GetInterfaces(ctx context.Context) ([]string, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaces(ctx)
	}
	return []string{}, nil
}

// GetInterfaceDetails returns detailed info for all interfaces.
func (s *NetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceDetails(ctx)
	}
	return []domain.InterfaceInfo{}, nil
}

// Deauth Attack Methods - Delegated to Coordinator

func (s *NetworkService) StartDeauthAttack(ctx context.Context, config domain.DeauthAttackConfig) (string, error) {
	return s.attackCoordinator.StartDeauthAttack(ctx, config)
}

func (s *NetworkService) StopDeauthAttack(ctx context.Context, id string, force bool) error {
	return s.attackCoordinator.StopDeauthAttack(ctx, id, force)
}

func (s *NetworkService) GetDeauthStatus(ctx context.Context, id string) (domain.DeauthAttackStatus, error) {
	return s.attackCoordinator.GetDeauthStatus(ctx, id)
}

func (s *NetworkService) ListDeauthAttacks(ctx context.Context) ([]domain.DeauthAttackStatus, error) {
	return s.attackCoordinator.ListDeauthAttacks(ctx), nil
}

// WPS Attack Methods - Delegated to Coordinator

func (s *NetworkService) StartWPSAttack(ctx context.Context, config domain.WPSAttackConfig) (string, error) {
	return s.attackCoordinator.StartWPSAttack(ctx, config)
}

func (s *NetworkService) StopWPSAttack(ctx context.Context, id string, force bool) error {
	return s.attackCoordinator.StopWPSAttack(ctx, id, force)
}

func (s *NetworkService) GetWPSStatus(ctx context.Context, id string) (domain.WPSAttackStatus, error) {
	return s.attackCoordinator.GetWPSStatus(ctx, id)
}

// GetSystemStats - Delegated to StatsService
func (s *NetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	return s.statsService.GetSystemStats(ctx)
}

// Auth Flood Attack Methods - Delegated to Coordinator

func (s *NetworkService) StartAuthFloodAttack(ctx context.Context, config domain.AuthFloodAttackConfig) (string, error) {
	return s.attackCoordinator.StartAuthFloodAttack(ctx, config)
}

func (s *NetworkService) StopAuthFloodAttack(ctx context.Context, id string, force bool) error {
	return s.attackCoordinator.StopAuthFloodAttack(ctx, id, force)
}

func (s *NetworkService) GetAuthFloodStatus(ctx context.Context, id string) (domain.AuthFloodAttackStatus, error) {
	return s.attackCoordinator.GetAuthFloodStatus(ctx, id)
}

func (s *NetworkService) GetWPSEngine() ports.WPSAttackService {
	return s.attackCoordinator.wpsEngine
}

// Close stops all active services and attacks.
func (s *NetworkService) Close() error {
	s.attackCoordinator.StopAll(context.Background())
	return nil
}
