package network

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"github.com/lcalzada-xor/wmap/internal/core/services/persistence"
)

type NetworkService struct {
	registry     ports.DeviceRegistry
	security     ports.SecurityEngine
	persistence  *persistence.PersistenceManager
	sniffer      ports.Sniffer

	statsService *StatsService
	mu           sync.RWMutex
}

func NewNetworkService(
	registry ports.DeviceRegistry,
	security ports.SecurityEngine,
	persistence *persistence.PersistenceManager,
	sniffer ports.Sniffer,
) *NetworkService {
	return &NetworkService{
		registry:     registry,
		security:     security,
		persistence:  persistence,
		sniffer:      sniffer,
		statsService: NewStatsService(registry, security),
	}
}

func (s *NetworkService) ProcessDevice(ctx context.Context, newDevice domain.Device) error {
	merged, _ := s.registry.ProcessDevice(ctx, newDevice)
	s.security.Analyze(ctx, merged)
	if s.persistence != nil {
		s.persistence.Persist(merged)
	}
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

func (s *NetworkService) GetGraph(ctx context.Context) (domain.GraphData, error) {
	return s.statsService.GetGraph(ctx)
}

func (s *NetworkService) AddRule(ctx context.Context, rule domain.AlertRule) error {
	s.security.AddRule(ctx, rule)
	return nil
}

func (s *NetworkService) GetAlerts(ctx context.Context) ([]domain.Alert, error) {
	return s.security.GetAlerts(ctx), nil
}

func (s *NetworkService) GetDeviceConnectionHistory(ctx context.Context, mac string) ([]domain.ConnectionEvent, error) {
	if s.persistence == nil {
		return nil, nil
	}
	return s.persistence.GetConnectionHistory(ctx, mac)
}

func (s *NetworkService) TriggerScan(ctx context.Context) error {
	if s.sniffer == nil {
		return nil
	}
	return s.sniffer.Scan(ctx, "")
}

func (s *NetworkService) StartCleanupLoop(ctx context.Context, ttl time.Duration, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[NETWORK-SERVICE] Panic in cleanup loop: %v", r)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.registry.PruneOldDevices(ctx, ttl)
				s.registry.CleanupStaleConnections(ctx, 2*time.Minute)
			}
		}
	}()
}

func (s *NetworkService) SetPersistenceEnabled(enabled bool) {
	if s.persistence != nil {
		s.persistence.SetEnabled(enabled)
	}
}

func (s *NetworkService) IsPersistenceEnabled() bool {
	if s.persistence != nil {
		return s.persistence.IsEnabled()
	}
	return false
}

func (s *NetworkService) ResetWorkspace(ctx context.Context) error {
	s.registry.Clear(ctx)
	return nil
}

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

func (s *NetworkService) SetInterfaceChannels(ctx context.Context, iface string, channels []int) error {
	if s.sniffer != nil {
		s.sniffer.SetInterfaceChannels(ctx, iface, channels)
	}
	return nil
}

func (s *NetworkService) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceChannels(ctx, iface)
	}
	return []int{}, nil
}

func (s *NetworkService) GetInterfaces(ctx context.Context) ([]string, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaces(ctx)
	}
	return []string{}, nil
}

func (s *NetworkService) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	if s.sniffer != nil {
		return s.sniffer.GetInterfaceDetails(ctx)
	}
	return []domain.InterfaceInfo{}, nil
}

func (s *NetworkService) GetSystemStats(ctx context.Context) (domain.SystemStats, error) {
	return s.statsService.GetSystemStats(ctx)
}

func (s *NetworkService) Close() error {
	return nil
}
