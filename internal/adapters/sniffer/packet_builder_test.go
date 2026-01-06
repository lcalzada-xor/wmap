package sniffer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketBuilder helps construct valid 802.11 packets for testing using raw bytes
type PacketBuilder struct {
	data []byte
}

func NewPacketBuilder() *PacketBuilder {
	return &PacketBuilder{
		data: make([]byte, 0),
	}
}

func (pb *PacketBuilder) AddMgmtBeacon(sa, bssid net.HardwareAddr, ssid string) *PacketBuilder {
	// Header: Type=Beacon (0x80), Flags=0
	// Addr1=Broadcast, Addr2=SA, Addr3=BSSID
	broadcast := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	header := buildDot11Header(0x80, broadcast, sa, bssid)
	pb.data = append(pb.data, header...)

	// Fixed Param: Timestamp(8), Interval(2), CapInfo(2)
	fixed := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
		0x64, 0x00, // Interval 100
		0x01, 0x00, // Caps: ESS
	}
	pb.data = append(pb.data, fixed...)

	pb.AddIE(layers.Dot11InformationElementIDSSID, []byte(ssid))
	return pb
}

func (pb *PacketBuilder) AddMgmtProbeReq(sa net.HardwareAddr, ssid string) *PacketBuilder {
	// Header: Type=ProbeReq (0x40), Flags=0
	// Addr1=Broadcast, Addr2=SA, Addr3=Broadcast
	broadcast := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	header := buildDot11Header(0x40, broadcast, sa, broadcast)
	pb.data = append(pb.data, header...)

	pb.AddIE(layers.Dot11InformationElementIDSSID, []byte(ssid))
	return pb
}

func (pb *PacketBuilder) AddDataFrame(toDS, fromDS bool, addr1, addr2, addr3 net.HardwareAddr, payload []byte) *PacketBuilder {
	// Type: Data (0x08 for Data)
	// Byte 0: 0x08
	// Byte 1: Flags (ToDS=bit0, FromDS=bit1 of flags byte? No. Bit0=ToDS, Bit1=FromDS)
	// Flags structure in byte 1: [Order][WEP][MoreData][PwrMgmt][Retry][MoreFrag][FromDS][ToDS] ?
	// Actually:
	// Byte 1 bits:
	// 0: ToDS
	// 1: FromDS
	// 2: MoreFrag
	// 3: Retry
	// ...
	var flags byte
	if toDS {
		flags |= 0x01
	}
	if fromDS {
		flags |= 0x02
	}

	header := buildDot11Header(0x08, addr1, addr2, addr3)
	header[1] = flags // Set flags in 2nd byte of header

	pb.data = append(pb.data, header...)
	pb.data = append(pb.data, payload...)
	return pb
}

func (pb *PacketBuilder) AddIE(id layers.Dot11InformationElementID, data []byte) *PacketBuilder {
	ie := []byte{byte(id), byte(len(data))}
	ie = append(ie, data...)
	pb.data = append(pb.data, ie...)
	return pb
}

// AddRSNIE adds a WPA2 RSN Information Element
func (pb *PacketBuilder) AddRSNIE() *PacketBuilder {
	data := []byte{
		0x01, 0x00, // Version
		0x00, 0x0F, 0xAC, 0x04, // Group Cipher
		0x01, 0x00, // Pairwise Count
		0x00, 0x0F, 0xAC, 0x04, // Pairwise
		0x01, 0x00, // Auth Count
		0x00, 0x0F, 0xAC, 0x02, // Auth
		0x00, 0x00, // Caps
	}
	return pb.AddIE(layers.Dot11InformationElementID(48), data)
}

// AddWPSIE adds a Vendor Specific IE for WPS with a specific model name
func (pb *PacketBuilder) AddWPSIE(modelName string) *PacketBuilder {
	prefix := []byte{0x00, 0x50, 0xF2, 0x04}
	mNameBytes := []byte(modelName)
	tlv := []byte{0x10, 0x23, byte(len(mNameBytes) >> 8), byte(len(mNameBytes))}
	tlv = append(tlv, mNameBytes...)
	data := append(prefix, tlv...)
	return pb.AddIE(layers.Dot11InformationElementIDVendor, data)
}

func (pb *PacketBuilder) Build() gopacket.Packet {
	// Add FCS (Frame Check Sequence) - 4 bytes dummy
	pb.data = append(pb.data, 0xDE, 0xAD, 0xBE, 0xEF)
	return gopacket.NewPacket(pb.data, layers.LayerTypeDot11, gopacket.Default)
}

// Helper: buildDot11Header (Basic MGMT/DATA header 24 bytes)
func buildDot11Header(fcType byte, a1, a2, a3 net.HardwareAddr) []byte {
	h := make([]byte, 24)
	h[0] = fcType
	h[1] = 0x00 // Default flags
	// Duration (2 bytes) = 0
	// Addr1
	copy(h[4:], a1)
	// Addr2
	copy(h[10:], a2)
	// Addr3
	copy(h[16:], a3)
	// Seq (2 bytes) = 0
	return h
}
