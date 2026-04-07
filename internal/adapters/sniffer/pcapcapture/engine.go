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
	handle, err := pcap.OpenLive(e.iface, 2500, true, 1*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open device %s: %w", e.iface, err)
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

	log.Printf("Starting Enterprise Capture Engine hardware stream on %s...", e.iface)

	go func() {
		defer handle.Close()
		defer close(outChan)

		for {
			select {
			case <-ctx.Done():
				return
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
