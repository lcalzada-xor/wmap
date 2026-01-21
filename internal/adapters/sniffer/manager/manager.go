package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/capture"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/geo"
)

// SnifferStatus tracks the operational status of a sniffer instance.
type SnifferStatus struct {
	Interface string
	Status    string // "starting", "running", "failed", "stopped"
	Error     error
}

// SnifferManager manages multiple Sniffer instances across different interfaces.
type SnifferManager struct {
	Interfaces []string
	Sniffers   []*capture.Sniffer
	Output     chan domain.Device
	Alerts     chan domain.Alert
	// Config
	DwellTime int
	Debug     bool
	Loc       geo.Provider
	// Status tracking
	statuses map[string]*SnifferStatus
	mu       sync.RWMutex

	// Shared components
	HandshakeManager *handshake.HandshakeManager
	VendorRepo       fingerprint.VendorRepository
}

// NewManager creates a manager for the given interfaces.
func NewManager(interfaces []string, dwell int, debug bool, loc geo.Provider, repo fingerprint.VendorRepository) *SnifferManager {
	// Use XDG-compliant path for handshakes
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not resolve home directory, using fallback path: %v", err)
		home = "."
	}
	handshakeDir := filepath.Join(home, ".local", "share", "wmap", "handshakes")

	return &SnifferManager{
		Interfaces: interfaces,
		DwellTime:  dwell,
		Debug:      debug,
		Loc:        loc,
		VendorRepo: repo,
		Output:     make(chan domain.Device, 1000), // Aggregated output
		Alerts:     make(chan domain.Alert, 100),   // Aggregated alerts
		statuses:   make(map[string]*SnifferStatus),
		// Initialize shared HandshakeManager
		HandshakeManager: handshake.NewHandshakeManager(handshakeDir),
	}
}

// Start initializes internal sniffers, partitions channels, and starts them.
func (m *SnifferManager) Start(ctx context.Context) error {
	if len(m.Interfaces) == 0 {
		return nil
	}

	// 1. Define Channel Pool (2.4GHz + limited 5GHz for now)
	// TODO: Make this configurable or dynamic based on hardware capabilities
	allChannels := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161}

	// 2. Load Config from Disk (Phase 3 Persistence)
	savedConfig, err := m.loadChannelConfig()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to load channel config: %v", err)
	}

	// 2b. Partition Channels (Default fallback)
	partitioned := partitionChannels(allChannels, len(m.Interfaces))

	var wg sync.WaitGroup

	// 3. Create and Start Sniffers
	for i, iface := range m.Interfaces {
		// Determine channels: Saved Config -> Partitioned Default
		var channels []int
		if saved, ok := savedConfig[iface]; ok {
			channels = saved
			log.Printf("Loaded saved configuration for %s: %v", iface, channels)
		} else {
			channels = partitioned[i]
			log.Printf("Assigning default channels to %s: %v", iface, channels)
		}

		cfg := capture.SnifferConfig{
			Interface: iface,
			Debug:     m.Debug,
			Channels:  channels,
			DwellTime: m.DwellTime,
		}

		// Create Sniffer
		// Note: We need to bridge the individual Output channels to the manager's aggregated Output
		// Or we can pass the manager's channel directly IF it was send-only, but Sniffer expects chan<-
		// Yes, we can pass m.Output directly.
		sniff := capture.New(cfg, m.Output, m.Alerts, m.Loc, m.HandshakeManager, m.VendorRepo)
		m.Sniffers = append(m.Sniffers, sniff)

		wg.Add(1)
		go func(s *capture.Sniffer, ifaceName string) {
			defer wg.Done()

			// Initialize status tracking
			status := &SnifferStatus{
				Interface: ifaceName,
				Status:    "starting",
			}
			m.mu.Lock()
			m.statuses[ifaceName] = status
			m.mu.Unlock()

			// Start Hopper if exists
			if s.Hopper != nil {
				go s.Hopper.Start()
			}

			if err := s.Start(ctx); err != nil {
				// Update status
				m.mu.Lock()
				status.Status = "failed"
				status.Error = err
				m.mu.Unlock()

				log.Printf("CRITICAL: Sniffer %s failed: %v", ifaceName, err)

				// Send alert to frontend
				select {
				case m.Alerts <- domain.Alert{
					Type:    "system",
					Message: fmt.Sprintf("Interface %s failed to start: %v", ifaceName, err),
				}:
				default:
					// Alert channel full, log only
					log.Printf("Failed to send alert for interface %s failure", ifaceName)
				}
			} else {
				// Sniffer stopped gracefully
				m.mu.Lock()
				status.Status = "stopped"
				m.mu.Unlock()
				log.Printf("Sniffer %s stopped gracefully", ifaceName)
			}
		}(sniff, iface)
	}

	// Wait for all to finish (when ctx is cancelled)
	wg.Wait()
	return nil
}

// partitionChannels divides channels by frequency band for optimal hardware utilization.
// This reduces channel hopping latency by avoiding unnecessary frequency band switches.
func partitionChannels(channels []int, n int) [][]int {
	if n <= 0 {
		return nil
	}

	// Separate channels by frequency band
	band24 := []int{}
	band5 := []int{}

	for _, ch := range channels {
		if ch <= 14 {
			band24 = append(band24, ch)
		} else {
			band5 = append(band5, ch)
		}
	}

	result := make([][]int, n)

	// Strategy: Assign complete bands to interfaces when possible
	// This minimizes hardware reconfiguration overhead
	if n == 1 {
		// Single interface gets all channels
		result[0] = append(band24, band5...)
	} else if n == 2 {
		// Optimal case: One interface per band
		result[0] = band24
		result[1] = band5
		log.Printf("Channel partitioning: Interface 0 → 2.4GHz (%d channels), Interface 1 → 5GHz (%d channels)",
			len(band24), len(band5))
	} else {
		// Multiple interfaces: Distribute bands using round-robin within each band
		// This keeps interfaces focused on specific frequency ranges
		for i, ch := range band24 {
			result[i%n] = append(result[i%n], ch)
		}
		for i, ch := range band5 {
			result[i%n] = append(result[i%n], ch)
		}
		log.Printf("Channel partitioning: Distributed %d channels across %d interfaces",
			len(channels), n)
	}

	return result
}

// GetChannels returns the list of all channels being scanned across all sniffers.
func (m *SnifferManager) GetChannels(ctx context.Context) []int {
	var all []int
	for _, s := range m.Sniffers {
		if s.Hopper != nil {
			all = append(all, s.Hopper.GetChannels()...)
		}
	}
	return all
}

// SetChannels updates the channels... effectively redistributing them?
// For now, this is complex to implement dynamically for all sniffers.
// Let's implement a dummy one or a simple one to satisfy interface if needed.
// The port probably requires it.
func (m *SnifferManager) SetChannels(ctx context.Context, channels []int) {
	// Re-partitioning at runtime is tricky because sniffers are running.
	// For now, let's just log a warning or partial implementation.
	log.Printf("Warning: SetChannels not fully implemented for SnifferManager yet")
}

// Scan performs an active scan by broadcasting probe requests.
func (m *SnifferManager) Scan(ctx context.Context, target string) error {
	// Broadcast scan on all interfaces? Or just one?
	// Probably all to maximize chance of hitting the AP.
	for _, s := range m.Sniffers {
		if err := s.Scan(ctx, target); err != nil {
			log.Printf("Active scan failed on %s: %v", s.Config.Interface, err)
		}
	}
	return nil
}

// GetInterfaces returns the list of managed interfaces.
func (m *SnifferManager) GetInterfaces(ctx context.Context) ([]string, error) {
	return m.Interfaces, nil
}

// GetInterfaceChannels returns the channel list for a specific interface.
func (m *SnifferManager) GetInterfaceChannels(ctx context.Context, iface string) ([]int, error) {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface && s.Hopper != nil {
			return s.Hopper.GetChannels(), nil
		}
	}
	return []int{}, nil
}

// SetInterfaceChannels updates the channels for a specific interface.
func (m *SnifferManager) SetInterfaceChannels(ctx context.Context, iface string, channels []int) {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface {
			// Update runtime
			s.SetInterfaceChannels(iface, channels)

			// Update persistence
			if err := m.saveChannelConfig(iface, channels); err != nil {
				log.Printf("Failed to save channel config for %s: %v", iface, err)
			}
			return
		}
	}
}

// Config Persistence
type ChannelConfig map[string][]int

func (m *SnifferManager) saveChannelConfig(iface string, channels []int) error {
	cfg, err := m.loadChannelConfig()
	if err != nil {
		cfg = make(ChannelConfig) // Start fresh if load fails (or file missing)
	}
	cfg[iface] = channels

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := m.getChannelConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (m *SnifferManager) loadChannelConfig() (ChannelConfig, error) {
	path := m.getChannelConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ChannelConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// getChannelConfigPath tries to resolve the absolute path to data/channels.json
// It searches for the project root by looking for go.mod
func (m *SnifferManager) getChannelConfigPath() string {
	// Start with default relative path
	defaultPath := "data/channels.json"

	// If it exists relative to CWD, use it
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}

	// Try to find project root by walking up
	dir, err := os.Getwd()
	if err != nil {
		return defaultPath
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "data", "channels.json")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return defaultPath
}

// GetInterfaceDetails returns detailed capabilities for all managed interfaces.
func (m *SnifferManager) GetInterfaceDetails(ctx context.Context) ([]domain.InterfaceInfo, error) {
	infos := []domain.InterfaceInfo{}
	for _, s := range m.Sniffers {
		// Use the Sniffer's own capability method if possible, or utility directly
		// Ideally Sniffer struct should hold this info to avoid re-parsing every time?
		// For now, let's call the utility directly or delegate to Sniffer.
		// Let's delegate to Sniffer as it holds the config.
		infos = append(infos, s.GetInterfaceDetails()...)
	}
	return infos, nil
}

// Lock delegates to the appropriate sniffer.
func (m *SnifferManager) Lock(ctx context.Context, iface string, channel int) error {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface {
			return s.Lock(ctx, iface, channel)
		}
	}
	return fmt.Errorf("interface %s not found in manager", iface)
}

// Unlock delegates to the appropriate sniffer.
func (m *SnifferManager) Unlock(ctx context.Context, iface string) error {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface {
			return s.Unlock(ctx, iface)
		}
	}
	return nil
}

// ExecuteWithLock delegates to the appropriate sniffer.
func (m *SnifferManager) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface {
			return s.ExecuteWithLock(ctx, iface, channel, action)
		}
	}
	return fmt.Errorf("interface %s not found in manager", iface)
}

// GetInjector returns the injector for a specific interface if managed.
func (m *SnifferManager) GetInjector(iface string) *injection.Injector {
	for _, s := range m.Sniffers {
		if s.Config.Interface == iface {
			return s.Injector
		}
	}
	return nil
}

// Close releases all resources managed by the manager.
func (m *SnifferManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close HandshakeManager
	if m.HandshakeManager != nil {
		m.HandshakeManager.Close()
	}

	for _, s := range m.Sniffers {
		s.Close()
	}
	return nil
}
