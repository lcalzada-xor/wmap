package pcapcapture

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/pcapdumper"
)

// Engine groups the hardware PCAP interface setup, BPF filtering, and disk writing.
type Engine struct {
	iface    string
	bpf      string
	pcapPath string
}

// NewEngine creates a highly focused packet capture engine config.
func NewEngine(iface, bpf, pcapPath string) *Engine {
	return &Engine{
		iface:    iface,
		bpf:      bpf,
		pcapPath: pcapPath,
	}
}

// Start opens the interface, sets filters, starts the dumper, and yields a stream of packets.
func (e *Engine) Start(ctx context.Context) (<-chan gopacket.Packet, *pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(e.iface)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create inactive handle for %s: %w", e.iface, err)
	}
	defer inactive.CleanUp()

	// Configure handle
	if err := inactive.SetSnapLen(2500); err != nil {
		return nil, nil, fmt.Errorf("failed to set snaplen: %w", err)
	}
	// SetRFMon enables 802.11 raw capture with RadioTap headers.
	// This is required for monitor-mode sniffing; SetPromisc alone is not
	// sufficient on drivers like iwlmvm (Intel AX series).
	if err := inactive.SetRFMon(true); err != nil {
		log.Printf("Warning: failed to set RF monitor mode on %s: %v (capture may not work)", e.iface, err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		return nil, nil, fmt.Errorf("failed to set promisc: %w", err)
	}
	if err := inactive.SetTimeout(10 * time.Millisecond); err != nil {
		return nil, nil, fmt.Errorf("failed to set timeout: %w", err)
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		log.Printf("Warning: failed to set immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to activate handle on %s: %w", e.iface, err)
	}

	if e.bpf != "" {
		if err := handle.SetBPFFilter(e.bpf); err != nil {
			handle.Close()
			return nil, nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	var dumper *pcapdumper.Dumper
	if e.pcapPath != "" {
		d, err := pcapdumper.NewDumper(e.pcapPath, handle.LinkType())
		if err != nil {
			log.Printf("Failed to create PCAP dumper: %v", err)
		} else {
			dumper = d
			go dumper.Start(ctx)
			log.Printf("Packet capture enabled. Saving asynchronously to %s", e.pcapPath)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	outChan := make(chan gopacket.Packet, 5000)

	log.Printf("Starting Enterprise Capture Engine hardware stream on %s (LinkType: %v)...", e.iface, handle.LinkType())

	go func() {
		defer handle.Close()
		defer close(outChan)
		var rawCount uint64

		statsTicker := time.NewTicker(2 * time.Second)
		defer statsTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				if stats, err := handle.Stats(); err == nil {
					log.Printf("[DEBUG] pcap stats on %s: Recv=%d, Drop=%d, IfDrop=%d", e.iface, stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
				}
			default:
			}

			packet, err := packetSource.NextPacket()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				log.Printf("Capture Engine stopped reading on %s: %v", e.iface, err)
				return
			}

			rawCount++
			if rawCount%10 == 0 {
				log.Printf("[DEBUG] Engine %s: Captured %d raw packets from pcap", e.iface, rawCount)
			}

			if dumper != nil {
				select {
				case dumper.In <- packet:
				default:
				}
			}

			select {
			case outChan <- packet:
			default:
			}
		}
	}()

	return outChan, handle, nil
}
