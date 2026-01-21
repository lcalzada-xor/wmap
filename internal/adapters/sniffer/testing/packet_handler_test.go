package sniffer

import (
	"log"
	"net"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
	"github.com/lcalzada-xor/wmap/internal/core/domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Helper to create a basic Beacon frame
func createBeaconPacket(bssid, ssid string, channel int) gopacket.Packet {
	bssidMac, _ := net.ParseMAC(bssid)
	srcMac, _ := net.ParseMAC(bssid) // SA = BSSID for Beacon

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtBeacon,
		Address1: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // DA = Broadcast
		Address2: srcMac,
		Address3: bssidMac,
	}

	// Payload must start with Beacon Fixed Parameters:
	// Timestamp (8 bytes) + Beacon Interval (2 bytes) + Capability Info (2 bytes) = 12 bytes
	payload := make([]byte, 12)
	// Leave them as zeros or set defaults if needed, parser just skips them to get to IEs usually

	// SSID IE
	payload = append(payload, 0, byte(len(ssid)))
	payload = append(payload, []byte(ssid)...)

	// Channel IE
	payload = append(payload, 3, 1, byte(channel))

	// RSN IE (WPA2) for fun
	// Tag 48, len 16 (approx)
	rsnIE := []byte{48, 20, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00}
	payload = append(payload, rsnIE...)

	// Append FCS dummy bytes (4 bytes) because Dot11 parser might strip them
	payload = append(payload, 0xDE, 0xAD, 0xBE, 0xEF)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: false, // Ensure we control FCS
	}
	// Note: We need to register that we consider this payload as Dot11MgmtBeacon if we were strict,
	// but gopacket's generic parser should handle it if Dot11 type is set correctly.
	// Actually, SerializeLayers with just Dot11 and payload bytes might not be enough for Re-Parsing if
	// we rely on it being decoded as Dot11MgmtBeacon layer.
	// But let's try just fixing the bytes first.
	gopacket.SerializeLayers(buf, opts, dot11, gopacket.Payload(payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeDot11, gopacket.Default)
}

func TestHandlePacket_BeaconParsing(t *testing.T) {
	// Setup
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, false, nil, nil, nil)

	bssid := "00:11:22:33:44:55"
	ssid := "TestSSID"
	channel := 6

	packet := createBeaconPacket(bssid, ssid, channel)

	device, alert := handler.HandlePacket(packet)

	assert.Nil(t, alert)
	assert.NotNil(t, device)

	assert.Equal(t, bssid, device.MAC)
	assert.Equal(t, domain.DeviceTypeAP, device.Type)
	assert.Equal(t, ssid, device.SSID)
	assert.Equal(t, channel, device.Channel)
	assert.Equal(t, "WPA2-PSK", device.Security)
}

func TestHandlePacket_IgnoreJunk(t *testing.T) {
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, false, nil, nil, nil)

	// Empty Packet
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &layers.Ethernet{}) // Not Dot11
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	device, alert := handler.HandlePacket(packet)
	assert.Nil(t, device)
	assert.Nil(t, alert)
}

// MockGeo is defined in parser_test.go, reusing it.
// Or if parser_test.go is not included in this build, we need it.
// But we run ./internal/adapters/sniffer/... so it is.
// Removing duplicate definition.

// Silence Log output during tests if needed
func init() {
	log.SetOutput(log.Writer())
}
