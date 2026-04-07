package pcapdumper

import (
	"context"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Dumper handles asynchronous packet writing to a PCAP file.
type Dumper struct {
	In   chan gopacket.Packet
	file *os.File
	w    *pcapgo.Writer
}

// NewDumper creates a new PCAP dumper with a buffered channel.
func NewDumper(path string, linkType layers.LinkType) (*Dumper, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, linkType); err != nil {
		f.Close()
		return nil, err
	}

	return &Dumper{
		In:   make(chan gopacket.Packet, 5000), // Buffer to absorb disk I/O latency
		file: f,
		w:    w,
	}, nil
}

// Start begins processing the packet queue in the background.
func (d *Dumper) Start(ctx context.Context) {
	defer d.file.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.In:
			if !ok {
				return
			}
			_ = d.w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
		}
	}
}
