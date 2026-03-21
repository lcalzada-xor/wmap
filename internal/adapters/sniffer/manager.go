package sniffer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/radio"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
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
	Sniffers   []*Sniffer
	Output     chan domain.Device
	Alerts     chan domain.Alert
	Events     chan domain.ConnectionEvent
	// Config
	DwellTime int
	Debug     bool
	// Status tracking
	statuses map[string]*SnifferStatus
	mu       sync.RWMutex

	HandshakeManager  *handshake.HandshakeManager
	VendorRepo        fingerprint.VendorRepository
	RadioManager      *radio.RadioManager
	channelConfigPath string
}

// NewManager creates a manager for the given interfaces.
func NewManager(interfaces []string, dwell int, debug bool, repo fingerprint.VendorRepository, radioMgr *radio.RadioManager, handshakeDir string, channelConfigPath string) *SnifferManager {
	return &SnifferManager{
		Interfaces:        interfaces,
		DwellTime:         dwell,
		Debug:             debug,
		VendorRepo:        repo,
		Output:            make(chan domain.Device, 1000), // Aggregated output
		Alerts:            make(chan domain.Alert, 100),   // Aggregated alerts
		Events:            make(chan domain.ConnectionEvent, 1000),
		statuses:          make(map[string]*SnifferStatus),
		HandshakeManager:  handshake.NewHandshakeManager(handshakeDir),
		RadioManager:      radioMgr,
		channelConfigPath: channelConfigPath,
	}
}

// Start initializes internal sniffers, partitions channels, and starts them.
func (m *SnifferManager) Start(ctx context.Context) error {
	if len(m.Interfaces) == 0 {
		return nil
	}

	// 1. Define Channel Pool (2.4GHz + limited 5GHz for now)
	allChannels := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161}

	// 2. Load Config from Disk (Phase 3 Persistence)
	savedConfig, err := m.loadChannelConfig()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to load channel config: %v", err)
	}

	// 2b. Query Capabilities
	capabilities := make(map[string][]int)
	for _, iface := range m.Interfaces {
		// We use the driver package directly.
		// Ideally this should be abstracted (e.g. s.Driver.Get... but sniffer not created yet)
		// Or injected into Manager. For now, direct call is safe as per app design.
		_, chans, err := driver.GetInterfaceCapabilities(iface)
		if err != nil {
			log.Printf("Warning: Failed to get capabilities for %s: %v. Assuming full support.", iface, err)
		} else {
			capabilities[iface] = chans
		}
	}

	// 2c. Partition Channels
	partitioned := partitionChannelsWithCapabilities(allChannels, m.Interfaces, capabilities)

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
			log.Printf("Assigning capability-aware channels to %s: %v", iface, channels)
		}

		cfg := SnifferConfig{
			Interface: iface,
			Debug:     m.Debug,
			Channels:  channels,
			DwellTime: m.DwellTime,
		}

		// Create Sniffer
		// Yes, we can pass m.Output directly.
		sniff := New(cfg, m.Output, m.Alerts, m.Events, m.HandshakeManager, m.VendorRepo)
		m.Sniffers = append(m.Sniffers, sniff)

		// Register with RadioManager for pausing
		if m.RadioManager != nil {
			m.RadioManager.RegisterHandler(iface, sniff)
		}

		wg.Add(1)
		go func(s *Sniffer, ifaceName string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Recovered from panic in SnifferManager goroutine for %s: %v", ifaceName, r)
					m.mu.Lock()
					if m.statuses[ifaceName] != nil {
						m.statuses[ifaceName].Status = "failed"
						m.statuses[ifaceName].Error = fmt.Errorf("panic: %v", r)
					}
					m.mu.Unlock()
				}
			}()

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
// partitionChannels divides channels by frequency band, respecting hardware capabilities.
func partitionChannelsWithCapabilities(targetChannels []int, interfaces []string, capabilities map[string][]int) [][]int {
	n := len(interfaces)
	if n <= 0 {
		return nil
	}

	result := make([][]int, n)

	// Create a map of channel -> supported interfaces count (heuristic for contention)
	// And a map of interface -> assigned channel count (load balancing)
	assignedCount := make([]int, n)

	// Strategy:
	// 1. Identify "Special" channels (5GHz) that might only be supported by some cards.
	// 2. Assign channels to the best candidate.

	// Separate 2.4 and 5GHz for logical grouping preference
	band24 := []int{}
	band5 := []int{}
	for _, ch := range targetChannels {
		if ch <= 14 {
			band24 = append(band24, ch)
		} else {
			band5 = append(band5, ch)
		}
	}

	// Helper to find best interface for a channel
	assignChannel := func(ch int) {
		bestIdx := -1
		minLoad := 999999

		// Candidates: Interfaces that support this channel
		candidates := []int{}
		for i, iface := range interfaces {
			supported, ok := capabilities[iface]
			// If no capabilities info (e.g. mock or error), assume supported
			if !ok || len(supported) == 0 {
				candidates = append(candidates, i)
				continue
			}

			// Check support
			isSupported := false
			for _, capCh := range supported {
				if capCh == ch {
					isSupported = true
					break
				}
			}
			if isSupported {
				candidates = append(candidates, i)
			}
		}

		if len(candidates) == 0 {
			log.Printf("Warning: Channel %d is not supported by any active interface. Skipping.", ch)
			return
		}

		// Selection Logic:
		// 1. Prefer Band Separation (if n=2, try to keep 2.4 on one and 5 on another)
		// 2. Load Balancing (Interface with fewest channels)

		// Simple Load Balancing implementation:
		for _, idx := range candidates {
			load := assignedCount[idx]
			if load < minLoad {
				minLoad = load
				bestIdx = idx
			}
		}

		if bestIdx != -1 {
			result[bestIdx] = append(result[bestIdx], ch)
			assignedCount[bestIdx]++
		}
	}

	// Assign 5GHz first (constrained resource)
	for _, ch := range band5 {
		assignChannel(ch)
	}

	// Assign 2.4GHz next
	for _, ch := range band24 {
		assignChannel(ch)
	}

	return result
}

// partitionChannels Legacy wrapper for backward compatibility or default behavior
func partitionChannels(channels []int, n int) [][]int {
	// Dummy implementation that calls the new one with empty caps (assumes all supported)
	dummyCaps := make(map[string][]int)
	dummyIfaces := make([]string, n)
	for i := 0; i < n; i++ {
		dummyIfaces[i] = fmt.Sprintf("iface%d", i)
	}
	return partitionChannelsWithCapabilities(channels, dummyIfaces, dummyCaps)
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

// getChannelConfigPath returns the path to the channel configuration file.
func (m *SnifferManager) getChannelConfigPath() string {
	return m.channelConfigPath
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

// Lock delegates to the RadioManager.
func (m *SnifferManager) Lock(ctx context.Context, iface string, channel int) error {
	if m.RadioManager != nil {
		return m.RadioManager.Lock(ctx, iface, channel)
	}
	return fmt.Errorf("RadioManager not initialized")
}

// Unlock delegates to the RadioManager.
func (m *SnifferManager) Unlock(ctx context.Context, iface string) error {
	if m.RadioManager != nil {
		return m.RadioManager.Unlock(ctx, iface)
	}
	return nil
}

// ExecuteWithLock delegates to the RadioManager.
func (m *SnifferManager) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	if m.RadioManager != nil {
		return m.RadioManager.ExecuteWithLock(ctx, iface, channel, action)
	}
	return fmt.Errorf("RadioManager not initialized")
}

// IsLocked checks if the interface is locked via RadioManager.
func (m *SnifferManager) IsLocked(ctx context.Context, iface string) bool {
	if m.RadioManager != nil {
		return m.RadioManager.IsLocked(ctx, iface)
	}
	return false
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
