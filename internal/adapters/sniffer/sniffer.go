package sniffer

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/lcalzada-xor/wmap/geo"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Internal variable for testing
var channelSetter = SetInterfaceChannel

// SnifferConfig holds configuration for the Sniffer.
type SnifferConfig struct {
	Interface string
	PcapPath  string
	Debug     bool
	// Channels is the list of channels to hop on. If empty, hopper is disabled or default is used?
	// Plan says we pass specific channels.
	Channels  []int
	DwellTime int // milliseconds
}

// ChannelLocker overrides the channel hopper to lock on a specific channel.
type ChannelLocker interface {
	Lock(iface string, channel int) error
	Unlock(iface string) error
	ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error
}

// Sniffer handles packet capture and parsing.
type Sniffer struct {
	Config     SnifferConfig
	Output     chan<- domain.Device
	Alerts     chan<- domain.Alert
	handler    *PacketHandler
	Injector   *Injector
	Hopper     *ChannelHopper
	pcapWriter *pcapgo.Writer
	pcapFile   *os.File
	handle     *pcap.Handle // Expose handle to get stats

	// Capability caching
	capabilitiesCache *domain.InterfaceCapabilities
	capsCacheMu       sync.RWMutex

	// Metrics state
	metrics   domain.InterfaceMetrics
	metricsMu sync.RWMutex

	// Locking state
	hopperPaused bool
	lockMu       sync.Mutex
	lockCount    int // Reference counting for channel locking
	lockChannel  int // The channel currently locked
}

// New creates a new Sniffer instance.
func New(config SnifferConfig, out chan<- domain.Device, alerts chan<- domain.Alert, loc geo.Provider, hm *HandshakeManager) *Sniffer {
	inj, err := NewInjector(config.Interface)
	if err != nil {
		log.Printf("Warning: Failed to initialize injector: %v", err)
	}

	s := &Sniffer{
		Config:   config,
		Output:   out,
		Alerts:   alerts,
		Injector: inj,
	}

	// Create handler with pause callback
	s.handler = NewPacketHandler(loc, config.Debug, hm, s.PauseHopper)

	// Initialize Hopper if channels are provided
	if len(config.Channels) > 0 {
		dwell := time.Duration(config.DwellTime) * time.Millisecond
		if dwell == 0 {
			dwell = 300 * time.Millisecond
		}
		s.Hopper = NewHopper(config.Interface, config.Channels, dwell)
	}

	return s
}

// Scan performs an active scan by broadcasting probe requests.
func (s *Sniffer) Scan(target string) error {
	if s.Injector == nil {
		return fmt.Errorf("active injection not available (check permissions/interface)")
	}
	log.Printf("Broadcasting Probe Request for target: '%s'", target)
	return s.Injector.BroadcastProbe(target)
}

// Start begins capturing packets using a worker pool.
func (s *Sniffer) Start(ctx context.Context) error {
	// Open device
	handle, err := pcap.OpenLive(s.Config.Interface, 2500, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Store handle for metrics collection
	s.handle = handle

	// Set filter
	// Optimization: Exclude Control Frames (ACK/RTS/CTS) but allow ALL Mgmt (Deauth/Assoc) and Data
	if err := handle.SetBPFFilter("type mgt or type data"); err != nil {
		return err
	}

	// Initialize PCAP Writer if path is set
	if s.Config.PcapPath != "" {
		f, err := os.Create(s.Config.PcapPath)
		if err != nil {
			log.Printf("Failed to create PCAP file: %v", err)
		} else {
			s.pcapFile = f
			s.pcapWriter = pcapgo.NewWriter(f)
			// Write file header with correct LinkType
			if err := s.pcapWriter.WriteFileHeader(65536, handle.LinkType()); err != nil {
				log.Printf("Failed to write PCAP header: %v", err)
			}
			log.Printf("Packet capture enabled. Saving to %s", s.Config.PcapPath)
		}
	}

	defer func() {
		if s.pcapFile != nil {
			s.pcapFile.Close()
		}
	}()

	log.Printf("Starting Enterprise Sniffer on %s...", s.Config.Interface)

	// Optimization: Direct loop without intermediate channel
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Worker Pool setup
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	// Optimization: Queue Size 1000 -> 5000 to absorb bursts
	packetChan := make(chan gopacket.Packet, 5000)
	var wg sync.WaitGroup

	log.Printf("Starting %d packet processing workers", numWorkers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, packetChan)
	}

	// Start metrics collection ticker
	go s.collectMetrics(ctx)

	// Packet dispatcher loop
	// Optimization 2: Non-blocking dispatch
	var packet gopacket.Packet
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			log.Println("Sniffer stopping...")
			close(packetChan)
			wg.Wait()
			return nil
		default:
			// Continue
		}

		// Read packet directly (blocking read from handle)
		// This uses the underlying handle which blocks until a packet arrives
		// or timeout (we used BlockForever/large timeout).
		packet, err = packetSource.NextPacket()
		if err != nil {
			// This usually happens when handle is closed or EOF
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			log.Printf("Sniffer stopped reading: %v", err)
			close(packetChan)
			wg.Wait()
			return nil
		}

		// Save to PCAP synchronously to preserve order
		if s.pcapWriter != nil {
			_ = s.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		// Non-blocking send
		select {
		case packetChan <- packet:
			// Dispatched successfully
		default:
			// Channel buffer full - drop packet to avoid blocking the kernel read
			s.metricsMu.Lock()
			s.metrics.AppPacketsDropped++
			s.metricsMu.Unlock()
		}
	}
}

// worker processes packets from the channel.
func (s *Sniffer) worker(ctx context.Context, wg *sync.WaitGroup, packets <-chan gopacket.Packet) {
	defer wg.Done()
	for p := range packets {
		// Recover inside worker to prevent one bad packet from crashing the whole sniffer
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Recovered from panic in packet worker: %v", r)
				}
			}()
			device, alert := s.handler.HandlePacket(p)

			if device != nil {
				select {
				case s.Output <- *device:
				case <-ctx.Done():
					return
				}
			}
			if alert != nil {
				select {
				case s.Alerts <- *alert:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// SetChannels updates the hopper's channel list.
func (s *Sniffer) SetChannels(channels []int) {
	if s.Hopper != nil {
		s.Hopper.SetChannels(channels)
	}
}

// GetChannels returns the current hopper channel list.
func (s *Sniffer) GetChannels() []int {
	if s.Hopper != nil {
		return s.Hopper.GetChannels()
	}
	return []int{}
}

// GetInterfaces returns the list of managed interfaces.
func (s *Sniffer) GetInterfaces() []string {
	return []string{s.Config.Interface}
}

// GetInterfaceChannels returns the channel list for a specific interface.
func (s *Sniffer) GetInterfaceChannels(iface string) []int {
	if s.Config.Interface == iface && s.Hopper != nil {
		return s.Hopper.GetChannels()
	}
	return []int{}
}

// SetInterfaceChannels updates the channels for a specific interface.
func (s *Sniffer) SetInterfaceChannels(iface string, channels []int) {
	if s.Config.Interface != iface {
		return
	}

	// Validation: Filter out unsupported channels
	infos := s.GetInterfaceDetails()
	if len(infos) > 0 && len(infos[0].Capabilities.SupportedChannels) > 0 {
		supported := infos[0].Capabilities.SupportedChannels
		supportedSet := make(map[int]bool)
		for _, ch := range supported {
			supportedSet[ch] = true
		}

		var validChannels []int
		var ignored []int
		for _, ch := range channels {
			if supportedSet[ch] {
				validChannels = append(validChannels, ch)
			} else {
				ignored = append(ignored, ch)
			}
		}

		if len(ignored) > 0 {
			log.Printf("Warning: Ignoring unsupported channels for %s: %v", iface, ignored)
		}
		channels = validChannels
	}

	// Case 1: Empty channels provided -> Stop Hopper if active
	if len(channels) == 0 {
		if s.Hopper != nil {
			log.Printf("Stopping hopper on %s (no channels selected)", iface)
			s.Hopper.Stop()
			s.Hopper = nil
		}
		return
	}

	// Case 2: Hopper exists -> Update channels
	if s.Hopper != nil {
		s.Hopper.SetChannels(channels)
		return
	}

	// Case 3: Hopper doesn't exist but channels provided -> Start new Hopper
	log.Printf("Starting new hopper on %s with channels: %v", iface, channels)
	dwell := time.Duration(s.Config.DwellTime) * time.Millisecond
	if dwell == 0 {
		dwell = 300 * time.Millisecond
	}
	s.Hopper = NewHopper(iface, channels, dwell)
	// Start in goroutine
	go s.Hopper.Start()
}

// GetInterfaceDetails returns detailed info for this sniffer's interface.
func (s *Sniffer) GetInterfaceDetails() []domain.InterfaceInfo {
	// Helper to get MAC
	getMAC := func(ifaceName string) string {
		if iface, err := net.InterfaceByName(ifaceName); err == nil {
			return iface.HardwareAddr.String()
		}
		return "Unknown"
	}

	// Get current metrics
	s.metricsMu.RLock()
	currentMetrics := s.metrics
	s.metricsMu.RUnlock()

	// Check cache first
	s.capsCacheMu.RLock()
	if s.capabilitiesCache != nil {
		caps := *s.capabilitiesCache
		s.capsCacheMu.RUnlock()
		return []domain.InterfaceInfo{{
			Name:            s.Config.Interface,
			MAC:             getMAC(s.Config.Interface),
			Capabilities:    caps,
			CurrentChannels: s.GetChannels(),
			Metrics:         currentMetrics,
		}}
	}
	s.capsCacheMu.RUnlock()

	// Fetch capabilities from hardware
	bandsMap, supportedChans, err := GetInterfaceCapabilities(s.Config.Interface)
	if err != nil {
		log.Printf("Error getting capabilities for %s: %v", s.Config.Interface, err)
		// Return basic info without capabilities
		return []domain.InterfaceInfo{{
			Name:            s.Config.Interface,
			MAC:             getMAC(s.Config.Interface),
			CurrentChannels: s.GetChannels(),
			Metrics:         currentMetrics,
		}}
	}

	var bands []string
	for b := range bandsMap {
		bands = append(bands, b)
	}

	caps := domain.InterfaceCapabilities{
		SupportedBands:    bands,
		SupportedChannels: supportedChans,
	}

	// Cache the result
	s.capsCacheMu.Lock()
	s.capabilitiesCache = &caps
	s.capsCacheMu.Unlock()

	return []domain.InterfaceInfo{{
		Name:            s.Config.Interface,
		MAC:             getMAC(s.Config.Interface),
		Capabilities:    caps,
		CurrentChannels: s.GetChannels(),
		Metrics:         currentMetrics,
	}}
}

// Lock stops channel hopping and sets a specific channel for the interface.
func (s *Sniffer) Lock(iface string, channel int) error {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()

	if s.Config.Interface != iface {
		return channelSetter(iface, channel)
	}

	// Reference Counting Logic
	if s.hopperPaused {
		// Already locked.
		if s.lockChannel == channel {
			// Same channel, increment ref count
			s.lockCount++
			log.Printf("[SNIFFER] Lock ref count incremented (count=%d) for channel %d", s.lockCount, channel)
			return nil
		}
		// Different channel! Busy.
		return fmt.Errorf("interface busy: locked on channel %d (ref count: %d)", s.lockChannel, s.lockCount)
	}

	// Not locked yet. Lock it.
	if s.Hopper != nil {
		log.Printf("[SNIFFER] Pausing hopper on %s to lock channel %d", iface, channel)
		s.Hopper.Stop()
	}

	if err := channelSetter(iface, channel); err != nil {
		// Failed to set channel, rollback (resume hopper if needed) could go here
		// But usually we want to retry or just fail.
		// If we resume hopper here, we must be careful.
		if s.Hopper != nil {
			go s.Hopper.Start()
		}
		return err
	}

	s.hopperPaused = true
	s.lockChannel = channel
	s.lockCount = 1

	return nil
}

// Unlock resumes channel hopping if it was paused.
func (s *Sniffer) Unlock(iface string) error {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()

	if s.Config.Interface != iface {
		return nil
	}

	if !s.hopperPaused {
		return nil
	}

	s.lockCount--
	if s.lockCount > 0 {
		log.Printf("[SNIFFER] Unlock called (remaining ref count: %d)", s.lockCount)
		return nil
	}

	// Count reached 0, fully unlock
	log.Printf("[SNIFFER] Unlock releasing interface %s (resuming hopper)", iface)
	if len(s.Config.Channels) > 0 {
		dwell := time.Duration(s.Config.DwellTime) * time.Millisecond
		if dwell == 0 {
			dwell = 300 * time.Millisecond
		}
		s.Hopper = NewHopper(s.Config.Interface, s.Config.Channels, dwell)
		go s.Hopper.Start()
	}

	s.hopperPaused = false
	s.lockChannel = 0
	return nil
}

// ExecuteWithLock runs an action while holding a channel lock
func (s *Sniffer) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	if err := s.Lock(iface, channel); err != nil {
		return err
	}
	defer s.Unlock(iface)

	// We can check context before running action
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return action()
}

// PauseHopper pauses the channel hopper for a duration.
func (s *Sniffer) PauseHopper(duration time.Duration) {
	if s.Hopper != nil {
		s.Hopper.Pause(duration)
	}
}

// collectMetrics periodically collects packet capture statistics.
func (s *Sniffer) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.handle != nil {
				stats, err := s.handle.Stats()
				if err != nil {
					log.Printf("Failed to get pcap stats: %v", err)
					continue
				}

				s.metricsMu.Lock()
				s.metrics.PacketsReceived = int64(stats.PacketsReceived)
				s.metrics.PacketsDropped = int64(stats.PacketsDropped)
				s.metrics.PacketsIfDropped = int64(stats.PacketsIfDropped)
				// AppPacketsDropped is updated in the loop
				s.metricsMu.Unlock()
			}
		}
	}
}
