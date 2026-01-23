package sniffer

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EAPOLOptions struct {
	ReplayCounter uint64
	Nonce         []byte
	IsFromDS      bool
}

func createEAPOLPacket(src, dst, bssid string, messageNum int, opts ...EAPOLOptions) gopacket.Packet {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	srcMac, _ := net.ParseMAC(src)
	dstMac, _ := net.ParseMAC(dst)
	bssidMac, _ := net.ParseMAC(bssid)

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeData,
		Flags:    0,
		Address1: dstMac,
		Address2: srcMac,
		Address3: bssidMac,
	}

	// Apply Options
	if len(opts) > 0 {
		opt := opts[0]
		if opt.IsFromDS {
			dot11.Flags |= layers.Dot11FlagsFromDS
		}
	}

	// EAPOL Key Frame Construction (simplified for testing)
	// We need Key Info to distinguish M1, M2, M3, M4
	// M1: No MIC, Ack=1
	// M2: MIC, KeyDataLen > 0
	// M3: MIC, Ack=1
	// M4: MIC, Ack=0

	var keyInfo uint16
	if messageNum == 1 {
		keyInfo = 0x0088 // Ack=1, No MIC, Pairwise=1
	} else if messageNum == 2 {
		keyInfo = 0x0108 // MIC=1, No Ack, Pairwise=1
	} else if messageNum == 3 {
		keyInfo = 0x0188 // MIC=1, Ack=1, Pairwise=1
	} else {
		keyInfo = 0x0108 // M4: MIC=1, Pairwise=1
	}

	eapol := &layers.EAPOL{
		Version: 1,
		Type:    layers.EAPOLTypeKey,
		Length:  95, // Min length
	}

	// Payload with Key Info
	payload := make([]byte, 100)
	binary.BigEndian.PutUint16(payload[1:3], keyInfo)

	// Apply Options
	if len(opts) > 0 {
		opt := opts[0]
		binary.BigEndian.PutUint64(payload[5:13], opt.ReplayCounter)
		if len(opt.Nonce) == 32 {
			copy(payload[13:45], opt.Nonce)
		}
	}

	if messageNum == 2 {
		// Set Key Data Len for M2 detection
		binary.BigEndian.PutUint16(payload[93:95], 20) // Some data
	}

	// Determine if MIC is needed (Bit 8 of KeyInfo)
	if (keyInfo & 0x0100) != 0 {
		for i := 77; i < 93; i++ {
			payload[i] = 0x77 // Dummy valid MIC
		}
	}

	// LLC/SNAP Headers for EAPOL
	// LLC: DSAP=0xAA, SSAP=0xAA, Control=0x03
	// SNAP: OUI=00:00:00, Type=0x888E (EAPOL)
	llc := &layers.LLC{
		DSAP:    0xAA,
		SSAP:    0xAA,
		Control: 0x03,
	}
	snap := &layers.SNAP{
		OrganizationalCode: []byte{0, 0, 0},
		Type:               layers.EthernetTypeEAPOL,
	}

	gopacket.SerializeLayers(buffer, options,
		dot11,
		llc,
		snap,
		eapol,
		gopacket.Payload(payload),
	)

	pkt := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeDot11, gopacket.Default)
	pkt.Metadata().CaptureInfo.CaptureLength = len(buffer.Bytes())
	pkt.Metadata().CaptureInfo.Length = len(buffer.Bytes())
	pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	return pkt
}
