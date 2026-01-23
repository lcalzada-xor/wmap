package sniffer

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser"
)

func TestHandlePacket_Karma_ObservedSSIDs(t *testing.T) {
	mockLoc := MockGeo{}
	handler := parser.NewPacketHandler(mockLoc, true, nil, nil, nil)

	bssid := "aa:bb:cc:dd:ee:ff"

	// Helper to create Beacon
	createBeacon := func(ssid string) gopacket.Packet {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{}

		mac, _ := net.ParseMAC(bssid)
		broadcast, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

		dot11 := &layers.Dot11{
			Type:     layers.Dot11TypeMgmtBeacon,
			Address1: broadcast,
			Address2: mac, // SA = BSSID
			Address3: mac,
		}

		// Payload: Fixed Params (12 bytes) + IEs
		payload := make([]byte, 12) // Timestamp(8)+Interval(2)+Cap(2)

		payload = append(payload, 0, uint8(len(ssid)))
		payload = append(payload, []byte(ssid)...)

		// Append FCS (4 bytes)
		payload = append(payload, 0xDE, 0xAD, 0xBE, 0xEF)

		gopacket.SerializeLayers(buffer, options, dot11, gopacket.Payload(payload))
		return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeDot11, gopacket.Default)
	}

	// 1. Send Beacon with SSID "Home"
	p1 := createBeacon("Home")
	dev1, _ := handler.HandlePacket(p1)

	if dev1 == nil {
		t.Fatal("Expected device from packet 1")
	}

	// Check if ObservedSSIDs contains "Home"
	// Note: PacketHandler sets ObservedSSIDs = []string{SSID} for the current packet.
	// Accumulation happens in DeviceMerger (Registry).
	// So here we verify that PacketHandler outputs the correct single-item list.

	if len(dev1.ObservedSSIDs) != 1 || dev1.ObservedSSIDs[0] != "Home" {
		t.Errorf("Expected ObservedSSIDs=['Home'], got %v", dev1.ObservedSSIDs)
	}

	// 2. Send Beacon with SSID "FreeWiFi" (Same BSSID)
	// Wait to bypass throttling (500ms cache)
	time.Sleep(600 * time.Millisecond)
	p2 := createBeacon("FreeWiFi")
	dev2, _ := handler.HandlePacket(p2)

	if dev2 == nil {
		t.Fatal("Expected device from packet 2")
	}

	if len(dev2.ObservedSSIDs) != 1 || dev2.ObservedSSIDs[0] != "FreeWiFi" {
		t.Errorf("Expected ObservedSSIDs=['FreeWiFi'], got %v", dev2.ObservedSSIDs)
	}

	// The merging logic is in Registry/DeviceMerger, verified by unit tests there?
	// We should verify that DeviceMerger correctly merges these checks.
	// But sticking to PacketHandler scope: it works as expected.
}
