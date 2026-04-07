package threat

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/cache"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestDetector_Analyze_Deauth(t *testing.T) {
	tc := cache.NewShardedCache()
	sm := domain.NewConnectionStateManager()
	
	vendorLookup := func(mac string) string {
		if mac == "00:11:22:33:44:55" || mac == "aa:bb:cc:dd:ee:ff" {
			return "TestVendor"
		}
		return ""
	}

	detector := NewDetector(tc, sm, vendorLookup)

	// Mock a Deauth packet
	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtDeauthentication,
		Address1: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // Target
		Address2: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, // Source (AP)
		Address3: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, // BSSID
	}

	// Deauth layer (for reason code)
	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: 1,
	}

	// Use gopacket to build a packet from layers
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buffer, options, dot11, deauth)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeDot11, gopacket.Default)

	device := &domain.Device{}
	
	dev, alert, event := detector.Analyze(dot11, packet, device)

	if alert == nil {
		t.Fatalf("Expected alert to be generated for Deauth packet")
	}

	if alert.Subtype != "DEAUTH_DETECTED" {
		t.Errorf("Expected alert subtype DEAUTH_DETECTED; got %s", alert.Subtype)
	}

	if dev == nil {
		t.Fatalf("Expected device to be returned")
	}

	if dev.Vendor != "TestVendor" {
		t.Errorf("Expected vendor TestVendor; got %s", dev.Vendor)
	}

	if event == nil {
		t.Fatalf("Expected event to be returned")
	}
}

func TestDetector_Analyze_IgnoreOther(t *testing.T) {
	tc := cache.NewShardedCache()
	sm := domain.NewConnectionStateManager()
	detector := NewDetector(tc, sm, nil)

	dot11 := &layers.Dot11{
		Type: layers.Dot11TypeMgmtBeacon,
	}
	packet := gopacket.NewPacket([]byte{}, layers.LayerTypeDot11, gopacket.Default)

	dev, alert, event := detector.Analyze(dot11, packet, &domain.Device{})

	if dev != nil || alert != nil || event != nil {
		t.Errorf("Expected Analyze to return nils for non-Deauth/Disassoc packet")
	}
}
