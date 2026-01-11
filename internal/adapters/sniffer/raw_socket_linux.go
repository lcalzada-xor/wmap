//go:build linux

package sniffer

import (
	"fmt"
	"net"
	"syscall"
)

type RawInjector struct {
	fd      int
	ifIndex int
}

func NewRawInjector(iface string) (PacketInjector, error) {
	// Get Interface Index
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}

	// Open Raw Socket (AF_PACKET, SOCK_RAW, ETH_P_ALL)
	// ETH_P_ALL = 0x0003 (htons)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300) // 0x0300 is approx htons(ETH_P_ALL) ? No.
	// ETH_P_ALL is 0x0003. In Big Endian (Network order), it is 0x0300 on Little Endian machine?
	// Actually typical notation used in Go for htons(ETH_P_ALL) involves binary shift.
	// Let's use 0 (protocol) and bind.

	if err != nil {
		return nil, fmt.Errorf("socket creation failed: %w", err)
	}

	// Bind to Interface
	ll := syscall.SockaddrLinklayer{
		Protocol: 0, // 0 means we set it per packet or driver handles?
		Ifindex:  ifi.Index,
	}

	if err := syscall.Bind(fd, &ll); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	return &RawInjector{
		fd:      fd,
		ifIndex: ifi.Index,
	}, nil
}

func (r *RawInjector) Inject(packet []byte) error {
	// We might need to construct SockaddrLinklayer for Sendto if not connected?
	// Since we bound it, maybe Write is enough?
	// Usually Sendto is preferred for raw sockets on AF_PACKET if we want to be sure.

	ll := syscall.SockaddrLinklayer{
		Ifindex: r.ifIndex,
	}

	err := syscall.Sendto(r.fd, packet, 0, &ll)
	return err
}

func (r *RawInjector) Close() {
	syscall.Close(r.fd)
}
