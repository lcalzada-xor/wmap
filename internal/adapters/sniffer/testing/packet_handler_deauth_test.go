package sniffer

import (
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestHandlePacket_APResetsConnection_Repro(t *testing.T) {
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, false, nil, nil)

	apMacStr := "00:11:22:33:44:55"
	staMacStr := "aa:bb:cc:dd:ee:ff"

	apMac, _ := net.ParseMAC(apMacStr)
	staMac, _ := net.ParseMAC(staMacStr)

	// Construct Deauth Frame: AP -> Station
	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtDeauthentication,
		Address1: staMac, // DA = Station (Target)
		Address2: apMac,  // SA = AP (Source)
		Address3: apMac,  // BSSID = AP
	}

	deauthLayer := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11Reason(6),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	gopacket.SerializeLayers(buf, opts, dot11, deauthLayer)
	// Append dummy FCS (4 bytes) because gopacket parser might check for it or minimum length
	// This was seen in packet_handler_test.go as well.
	existingBytes := buf.Bytes()
	fcs := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	totalBytes := append(existingBytes, fcs...)

	// IMPORTANT: We need to decode it as Dot11 to test the parser logic
	packet := gopacket.NewPacket(totalBytes, layers.LayerTypeDot11, gopacket.Default)

	// Act
	device, alert := handler.HandlePacket(packet)

	// Assert
	if assert.NotNil(t, alert, "Should generate an alert") {
		// assert.Equal(t, "DEAUTH_DETECTED", alert.Subtype)
	}

	if assert.NotNil(t, device, "Should return a device update") {
		assert.Equal(t, staMacStr, device.MAC, "The updated device should be the Station (Destination), but we got %s", device.MAC)
	}
}
