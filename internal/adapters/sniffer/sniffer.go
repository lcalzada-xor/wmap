package sniffer

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/handshake"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/hopping"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/metrics"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/monitor"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/pcapcapture"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Internal variable for testing
var channelSetter = driver.SetInterfaceChannel

// SnifferConfig holds configuration for the Sniffer.
type SnifferConfig struct {
	Interface string
	PcapPath  string
	Debug     bool
	Channels  []int
	DwellTime int // milliseconds
}

// ChannelLocker overrides the channel hopper to lock on a specific channel.
type ChannelLocker interface {
	Lock(ctx context.Context, iface string, channel int) error
	Unlock(ctx context.Context, iface string) error
	ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error
}

// Sniffer handles packet capture and parsing.
type Sniffer struct {
	Config     SnifferConfig
	Output     chan<- domain.Device
	Alerts     chan<- domain.Alert
	Events     chan<- domain.ConnectionEvent
	handler    *parser.PacketHandler
	Hopper     *hopping.ChannelHopper
	VendorRepo fingerprint.VendorRepository
	handle     *pcap.Handle // Expose handle to get stats

	monitor    *monitor.DeviceMonitor
	Metrics    *metrics.Collector
	chanFreq   map[int]int // channel → MHz, kept for hopper recreation

	// Ready is closed once the pcap engine has successfully opened the handle.
	// The manager uses this to delay injector socket creation until after
	// rfmon is active (opening AF_PACKET before SetRFMon breaks several drivers).
	Ready chan struct{}

	appPacketsDropped atomic.Int64 // Lock-free metrics counter
}

// New creates a new Sniffer instance.
func New(config SnifferConfig, out chan<- domain.Device, alerts chan<- domain.Alert, events chan<- domain.ConnectionEvent, hm *handshake.HandshakeManager, repo fingerprint.VendorRepository) *Sniffer {
	s := &Sniffer{
		Ready:      make(chan struct{}),
		Config:     config,
		Output:     out,
		Alerts:     alerts,
		Events:     events,
		VendorRepo: repo,
		monitor:    monitor.NewDeviceMonitor(config.Interface),
	}
	s.Metrics = metrics.NewCollector(&s.appPacketsDropped)

	s.handler = parser.NewPacketHandler(config.Debug, hm, repo, s.PauseHopper)

	// Initialize Hopper
	targetChans := config.Channels
	if caps := s.monitor.GetCapabilities(); caps != nil {
		if len(targetChans) == 0 && len(caps.SupportedChannels) > 0 {
			targetChans = caps.SupportedChannels
		}
		s.chanFreq = caps.ChannelFreq
	}

	if len(targetChans) > 0 {
		s.Hopper = s.newHopper(config.Interface, targetChans)
	}

	return s
}

// newHopper creates a ChannelHopper with the correct switcher for iface,
// including the channel→frequency map needed for DFS channels.
func (s *Sniffer) newHopper(iface string, channels []int) *hopping.ChannelHopper {
	dwell := time.Duration(s.Config.DwellTime) * time.Millisecond
	if dwell == 0 {
		dwell = 300 * time.Millisecond
	}
	sw := hopping.NewLinuxChannelSwitcher()
	sw.ChannelFreq = s.chanFreq
	return hopping.NewHopper(iface, channels, dwell, sw)
}

// Close stops the sniffer and releases resources.
func (s *Sniffer) Close() {
	// Stop Hopper
	if s.Hopper != nil {
		s.Hopper.Stop()
	}

	// Internal PCAP handle is closed by Start's defer if it returns,
	// but if Start is running, we need to cancel the context passed to Start.
	// Ideally, Sniffer logic relies on Context cancellation for stopping the loop.
}

// Start begins capturing packets using a worker pool.
func (s *Sniffer) Start(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in Sniffer.Start: %v", r)
			log.Printf("Recovered from panic in Sniffer.Start: %v", r)
		}
	}()

	engine := pcapcapture.NewEngine(s.Config.Interface, "", s.Config.PcapPath)
	packetChan, handle, err := engine.Start(ctx)
	if err != nil {
		return fmt.Errorf("capture engine failed on %s: %w", s.Config.Interface, err)
	}

	// Signal that the pcap handle is open. Consumers waiting on Ready (e.g.
	// the injector) can now open their own sockets without racing SetRFMon.
	close(s.Ready)

	// Store handle for metrics collection
	s.handle = handle
	s.Metrics.SetHandle(handle)

	// Start metrics collection ticker
	go s.Metrics.Start(ctx)

	// Start channel hopper AFTER pcap handle is ready to avoid a race where
	// 'iw set channel' commands interfere with the monitor-mode transition.
	// A short settle delay lets the kernel stabilise the interface state.
	if s.Hopper != nil {
		go func() {
			select {
			case <-time.After(500 * time.Millisecond):
				mode, _, err := driver.GetInterfaceCurrentConfig(s.Config.Interface)
				if err == nil {
					log.Printf("[HOPPER] Starting on %s — current mode=%s channels=%v dwell=%dms",
						s.Config.Interface, mode, s.Hopper.GetChannels(), s.Config.DwellTime)
				} else {
					log.Printf("[HOPPER] Starting on %s — could not read current mode: %v", s.Config.Interface, err)
				}
				s.Hopper.Start()
			case <-ctx.Done():
			}
		}()
	} else {
		log.Printf("[HOPPER] No hopper configured for %s — interface will stay on its current channel", s.Config.Interface)
	}

	// Worker Pool setup
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	var wg sync.WaitGroup

	log.Printf("Starting %d packet processing workers on %s", numWorkers, s.Config.Interface)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, packetChan)
	}

	// Packet dispatcher loop (now handled internally by the engine, Sniffer just waits)
	select {
	case <-ctx.Done():
		log.Printf("Sniffer on %s stopping (waiting for workers)...", s.Config.Interface)
		wg.Wait()
		return nil
	}
}

// worker processes packets from the channel.
func (s *Sniffer) worker(ctx context.Context, wg *sync.WaitGroup, packets <-chan gopacket.Packet) {
	defer wg.Done()
	var packetCount uint64
	for p := range packets {
		packetCount++
		if packetCount%100 == 0 {
			log.Printf("[DEBUG] Sniffer %s: Received %d packets so far...", s.Config.Interface, packetCount)
		}
		// Quick check before processing heavy layers
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Recover inside worker to prevent one bad packet from crashing the whole sniffer
		shouldExit := func() bool {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Recovered from panic in packet worker: %v", r)
				}
			}()
			device, alert, event := s.handler.HandlePacket(p)

			if device != nil {
				select {
				case s.Output <- *device:
				case <-ctx.Done():
					return true
				}
			}
			if alert != nil {
				select {
				case s.Alerts <- *alert:
				case <-ctx.Done():
					return true
				}
			}
			if event != nil && s.Events != nil {
				select {
				case s.Events <- *event:
				case <-ctx.Done():
					return true
				}
			}
			return false
		}()

		if shouldExit {
			return
		}
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
	s.Hopper = s.newHopper(iface, channels)
	go s.Hopper.Start()
}

// GetInterfaceDetails returns detailed info for this sniffer's interface.
func (s *Sniffer) GetInterfaceDetails() []domain.InterfaceInfo {
	var caps domain.InterfaceCapabilities
	var mac string = "Unknown"
	if s.monitor != nil {
		if hwCaps := s.monitor.GetCapabilities(); hwCaps != nil {
			caps = *hwCaps
		}
		mac = s.monitor.GetMAC()
	}

	var m domain.InterfaceMetrics
	if s.Metrics != nil {
		m = s.Metrics.GetMetrics()
	}

	currentCh := 0
	if s.Hopper != nil {
		currentCh = s.Hopper.GetCurrentChannel()
	}

	return []domain.InterfaceInfo{{
		Name:            s.Config.Interface,
		MAC:             mac,
		Capabilities:    caps,
		CurrentChannels: s.GetChannels(),
		CurrentChannel:  currentCh,
		Metrics:         m,
	}}
}

// Lock stops channel hopping and sets a specific channel for the interface.
func (s *Sniffer) Lock(ctx context.Context, iface string, channel int) error {
	if s.Config.Interface != iface {
		return channelSetter(iface, channel)
	}

	if s.Hopper != nil {
		return s.Hopper.Lock(channel)
	}

	return channelSetter(iface, channel)
}

// Unlock resumes channel hopping if it was paused.
func (s *Sniffer) Unlock(ctx context.Context, iface string) error {
	if s.Config.Interface == iface && s.Hopper != nil {
		s.Hopper.Unlock()
	}
	return nil
}

// ExecuteWithLock runs an action while holding a channel lock
func (s *Sniffer) ExecuteWithLock(ctx context.Context, iface string, channel int, action func() error) error {
	if err := s.Lock(ctx, iface, channel); err != nil {
		return err
	}
	defer s.Unlock(ctx, iface)

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
