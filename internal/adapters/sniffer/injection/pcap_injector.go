package injection

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

type PcapInjector struct {
	handle *pcap.Handle
}

func NewPcapInjector(iface string) (PacketInjector, error) {
	handle, err := pcap.OpenLive(iface, 1024, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open failed: %w", err)
	}
	return &PcapInjector{handle: handle}, nil
}

func (p *PcapInjector) Inject(packet []byte) error {
	return p.handle.WritePacketData(packet)
}

func (p *PcapInjector) Close() {
	p.handle.Close()
}
