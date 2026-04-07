package sniffer

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/radio"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/channelplan"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/channelstore"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/injection"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// CapabilityProvider abstracts hardware capability queries so the manager
// does not depend directly on the driver package (improves testability).
type CapabilityProvider interface {
	GetCapabilities(iface string) ([]int, error)
}

// driverCapabilityProvider is the production adapter that delegates to the
// driver package.
type driverCapabilityProvider struct{}

func (driverCapabilityProvider) GetCapabilities(iface string) ([]int, error) {
	_, chans, err := driver.GetInterfaceCapabilities(iface)
	return chans, err
}

// DefaultCapabilityProvider is the production CapabilityProvider backed by
// the driver package. Pass it to NewManager unless testing with a mock.
var DefaultCapabilityProvider CapabilityProvider = driverCapabilityProvider{}

// SnifferStatus tracks the operational status of a sniffer instance.
type SnifferStatus struct {
	Interface string
	Status    string // "starting" | "running" | "failed" | "stopped"
	Error     error
}

// SnifferManager orchestrates multiple Sniffer instances across network interfaces.
// Each interface gets its own Sniffer and a disjoint channel set computed at
// Start time, respecting the hardware capabilities reported by CapabilityProvider.
type SnifferManager struct {
	// Shared output channels – consumed by app.go.
	Output chan domain.Device
	Alerts chan domain.Alert
	Events chan domain.ConnectionEvent

	// Config
	Interfaces []string
	DwellTime  int
	Debug      bool

	// Sub-systems
	HandshakeManager   *handshake.HandshakeManager
	VendorRepo         fingerprint.VendorRepository
	RadioManager       *radio.RadioManager
	capabilityProvider CapabilityProvider
	channelStore       *channelstore.Store

	// Internal state
	sniffers  map[string]*Sniffer              // keyed by interface name – O(1) lookups
	injectors map[string]*injection.Injector   // keyed by interface name
	statuses  map[string]*SnifferStatus
	mu        sync.RWMutex
	wg        sync.WaitGroup // tracks running sniffer goroutines
}

// NewManager creates a SnifferManager for the given interfaces.
// Pass channelConfigPath for persistent channel assignment across restarts.
// capProvider may be nil – DefaultCapabilityProvider is used in that case.
func NewManager(
	interfaces []string,
	dwell int,
	debug bool,
	repo fingerprint.VendorRepository,
	radioMgr *radio.RadioManager,
	handshakeDir string,
	channelConfigPath string,
	capProvider CapabilityProvider,
) *SnifferManager {
	if capProvider == nil {
		capProvider = DefaultCapabilityProvider
	}
	return &SnifferManager{
		Interfaces:         interfaces,
		DwellTime:          dwell,
		Debug:              debug,
		VendorRepo:         repo,
		Output:             make(chan domain.Device, 1000),
		Alerts:             make(chan domain.Alert, 100),
		Events:             make(chan domain.ConnectionEvent, 1000),
		HandshakeManager:   handshake.NewHandshakeManager(handshakeDir),
		RadioManager:       radioMgr,
		capabilityProvider: capProvider,
		channelStore:       channelstore.New(channelConfigPath),
		sniffers:           make(map[string]*Sniffer),
		injectors:          make(map[string]*injection.Injector),
		statuses:           make(map[string]*SnifferStatus),
	}
}

// Start initialises per-interface sniffers, partitions channels respecting
// hardware capabilities, and runs each sniffer in its own goroutine.
// It blocks until ctx is cancelled (all sniffers have stopped).
func (m *SnifferManager) Start(ctx context.Context) error {
	if len(m.Interfaces) == 0 {
		return nil
	}

	// Load persisted channel assignments (Phase 3 persistence).
	saved, err := m.channelStore.Load()
	if err != nil {
		log.Printf("sniffer: warning: failed to load channel config: %v", err)
		saved = channelstore.ChannelConfig{}
	}

	// Query hardware capabilities for every interface.
	capabilities := make(map[string][]int, len(m.Interfaces))
	for _, iface := range m.Interfaces {
		chans, err := m.capabilityProvider.GetCapabilities(iface)
		if err != nil {
			log.Printf("sniffer: warning: failed to get capabilities for %s: %v – assuming full support", iface, err)
		} else {
			capabilities[iface] = chans
		}
	}

	// Partition the default channel pool respecting capabilities.
	partitioned := channelplan.Partition(channelplan.DefaultChannels, m.Interfaces, capabilities)

	for i, iface := range m.Interfaces {
		channels, ok := saved[iface]
		if ok {
			log.Printf("sniffer: loaded saved channel config for %s: %v", iface, channels)
		} else {
			channels = partitioned[i]
			log.Printf("sniffer: assigning capability-aware channels to %s: %v", iface, channels)
		}

		cfg := SnifferConfig{
			Interface: iface,
			Debug:     m.Debug,
			Channels:  channels,
			DwellTime: m.DwellTime,
		}

		sniff := New(cfg, m.Output, m.Alerts, m.Events, m.HandshakeManager, m.VendorRepo)
		m.sniffers[iface] = sniff

		if m.RadioManager != nil {
			m.RadioManager.RegisterHandler(iface, sniff)
		}

		inj, err := injection.NewInjector(iface)
		if err != nil {
			log.Printf("sniffer: warning: failed to initialize injector for %s: %v", iface, err)
		} else {
			m.injectors[iface] = inj
		}

		m.wg.Add(1)
		go m.runSniffer(ctx, sniff, iface)
	}

	m.wg.Wait()
	return nil
}

// runSniffer is the per-interface goroutine managed by Start.
func (m *SnifferManager) runSniffer(ctx context.Context, s *Sniffer, iface string) {
	defer m.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sniffer: recovered from panic on %s: %v", iface, r)
			m.mu.Lock()
			if st := m.statuses[iface]; st != nil {
				st.Status = "failed"
				st.Error = fmt.Errorf("panic: %v", r)
			}
			m.mu.Unlock()
		}
	}()

	m.mu.Lock()
	m.statuses[iface] = &SnifferStatus{Interface: iface, Status: "starting"}
	m.mu.Unlock()

	if s.Hopper != nil {
		go s.Hopper.Start()
	}

	if err := s.Start(ctx); err != nil {
		m.mu.Lock()
		m.statuses[iface].Status = "failed"
		m.statuses[iface].Error = err
		m.mu.Unlock()

		log.Printf("sniffer: CRITICAL: %s failed: %v", iface, err)

		select {
		case m.Alerts <- domain.Alert{
			Type:    "system",
			Message: fmt.Sprintf("interface %s failed to start: %v", iface, err),
		}:
		default:
			log.Printf("sniffer: alert channel full for %s", iface)
		}
		return
	}

	m.mu.Lock()
	m.statuses[iface].Status = "stopped"
	m.mu.Unlock()
	log.Printf("sniffer: %s stopped gracefully", iface)
}

// ───────────────────────── Channel management ─────────────────────────

// GetChannels returns all channels being scanned across all interfaces.
func (m *SnifferManager) GetChannels(_ context.Context) []int {
	var all []int
	for _, s := range m.sniffers {
		if s.Hopper != nil {
			all = append(all, s.Hopper.GetChannels()...)
		}
	}
	return all
}

// SetChannels is reserved for future dynamic re-partitioning at runtime.
// It is a no-op today because re-distributing channels while sniffers are
// running without downtime is non-trivial. Use SetInterfaceChannels for
// per-interface updates.
func (m *SnifferManager) SetChannels(_ context.Context, _ []int) {
	log.Printf("sniffer: SetChannels – per-interface redistribution not yet implemented; use SetInterfaceChannels")
}

// GetInterfaceChannels returns the active channel list for a specific interface.
func (m *SnifferManager) GetInterfaceChannels(_ context.Context, iface string) ([]int, error) {
	s, ok := m.sniffers[iface]
	if !ok || s.Hopper == nil {
		return []int{}, nil
	}
	return s.Hopper.GetChannels(), nil
}

// SetInterfaceChannels updates the channels for a single interface and persists
// the change to disk so it survives restarts.
func (m *SnifferManager) SetInterfaceChannels(_ context.Context, iface string, channels []int) {
	s, ok := m.sniffers[iface]
	if !ok {
		return
	}
	s.SetInterfaceChannels(iface, channels)

	if err := m.channelStore.Save(iface, channels); err != nil {
		log.Printf("sniffer: failed to persist channel config for %s: %v", iface, err)
	}
}

// ───────────────────────── Interface info ─────────────────────────

// GetInterfaces returns the list of managed interface names.
func (m *SnifferManager) GetInterfaces(_ context.Context) ([]string, error) {
	return m.Interfaces, nil
}

// GetInterfaceDetails returns detailed capability and metrics info for all interfaces.
func (m *SnifferManager) GetInterfaceDetails(_ context.Context) ([]domain.InterfaceInfo, error) {
	var infos []domain.InterfaceInfo
	for _, s := range m.sniffers {
		infos = append(infos, s.GetInterfaceDetails()...)
	}
	return infos, nil
}

// ───────────────────────── Active scan ─────────────────────────

// Scan broadcasts probe requests on all managed interfaces.
func (m *SnifferManager) Scan(ctx context.Context, target string) error {
	for iface, inj := range m.injectors {
		if inj == nil {
			continue
		}
		log.Printf("Broadcasting Probe Request for target: '%s' on %s", target, iface)
		if err := inj.BroadcastProbe(target); err != nil {
			log.Printf("sniffer: active scan failed on %s: %v", iface, err)
		}
	}
	return nil
}

// ───────────────────────── Radio / lock delegation ─────────────────────────

// Lock delegates to RadioManager to stop hopping and fix a channel.
func (m *SnifferManager) Lock(ctx context.Context, iface string, channel int) error {
	if m.RadioManager != nil {
		return m.RadioManager.Lock(ctx, iface, channel)
	}
	return fmt.Errorf("sniffer: RadioManager not initialised")
}

// Unlock delegates to RadioManager to resume hopping.
func (m *SnifferManager) Unlock(ctx context.Context, iface string) error {
	if m.RadioManager != nil {
		return m.RadioManager.Unlock(ctx, iface)
	}
	return nil
}

// ExecuteWithLock runs action while holding a channel lock via RadioManager.
func (m *SnifferManager) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	if m.RadioManager != nil {
		return m.RadioManager.ExecuteWithLock(ctx, iface, channel, action)
	}
	return fmt.Errorf("sniffer: RadioManager not initialised")
}

// IsLocked reports whether the given interface is currently channel-locked.
func (m *SnifferManager) IsLocked(ctx context.Context, iface string) bool {
	if m.RadioManager != nil {
		return m.RadioManager.IsLocked(ctx, iface)
	}
	return false
}

// GetInjector returns the packet injector for a specific interface.
func (m *SnifferManager) GetInjector(iface string) *injection.Injector {
	return m.injectors[iface]
}

// ───────────────────────── Lifecycle ─────────────────────────

// Close stops all sniffers and the HandshakeManager, then closes the shared
// output channels so downstream consumers exit their range loops cleanly.
// Call Close only after the context passed to Start has been cancelled and
// Start has returned.
func (m *SnifferManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.HandshakeManager != nil {
		m.HandshakeManager.Close()
	}

	for _, s := range m.sniffers {
		s.Close()
	}

	for _, inj := range m.injectors {
		if inj != nil {
			inj.Close()
		}
	}

	// Safe to close channels now – all goroutines have finished
	// (Start's wg.Wait() completed before the caller reached Close).
	close(m.Output)
	close(m.Alerts)
	close(m.Events)

	return nil
}
