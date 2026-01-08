package sniffer

import (
	"net"
	"testing"

	"github.com/lcalzada-xor/wmap/geo"
)

// MockGeo implements geo.Provider for testing
type MockGeo struct{}

func (m MockGeo) GetLocation() geo.Location {
	return geo.Location{Latitude: 10.0, Longitude: 20.0}
}

func TestHandlePacket(t *testing.T) {
	broadcast := net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	apMac := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	// staMac must be unicast (LSB of first byte == 0). 0x11 is multicast!
	staMac := net.HardwareAddr{0x00, 0x22, 0x33, 0x44, 0x55, 0x66}

	mockLoc := MockGeo{}
	handler := NewPacketHandler(mockLoc, true, nil, nil)

	tests := []struct {
		name         string
		packetFunc   func() *PacketBuilder
		wantType     string
		wantMAC      string
		wantSSID     string
		wantSecurity string
		wantModel    string
		wantNil      bool
	}{
		{
			name: "Beacon Frame (Open)",
			packetFunc: func() *PacketBuilder {
				return NewPacketBuilder().AddMgmtBeacon(apMac, apMac, "Open-AP")
			},
			wantType:     "ap",
			wantMAC:      apMac.String(),
			wantSSID:     "Open-AP",
			wantSecurity: "OPEN",
			wantNil:      false,
		},
		{
			name: "Beacon Frame (WPA2 + WPS)",
			packetFunc: func() *PacketBuilder {
				return NewPacketBuilder().
					AddMgmtBeacon(apMac, apMac, "Secure-AP").
					AddRSNIE().
					AddWPSIE("SuperRouter 3000")
			},
			wantType:     "ap",
			wantMAC:      apMac.String(),
			wantSSID:     "Secure-AP",
			wantSecurity: "WPA2",
			wantModel:    "SuperRouter 3000",
			wantNil:      false,
		},
		{
			name: "Probe Request (Wildcard)",
			packetFunc: func() *PacketBuilder {
				return NewPacketBuilder().AddMgmtProbeReq(staMac, "")
			},
			wantType: "station",
			wantMAC:  staMac.String(),
			wantSSID: "",
			wantNil:  false,
		},
		{
			name: "Data Frame (Upload: STA->AP)",
			packetFunc: func() *PacketBuilder {
				// ToDS=1, FromDS=0. Addr1=BSSID, Addr2=SA
				return NewPacketBuilder().AddDataFrame(true, false, apMac, staMac, broadcast, []byte("payload"))
			},
			wantType: "station",
			wantMAC:  staMac.String(),
			wantNil:  false,
		},
		{
			name: "Data Frame (Download: AP->STA)",
			packetFunc: func() *PacketBuilder {
				// ToDS=0, FromDS=1. Addr1=DA(STA), Addr2=BSSID
				return NewPacketBuilder().AddDataFrame(false, true, staMac, apMac, broadcast, []byte("payload"))
			},
			wantType: "station",
			wantMAC:  staMac.String(), // We track the receiver
			wantNil:  false,
		},
		{
			name: "Multicast Data (Download)",
			packetFunc: func() *PacketBuilder {
				// ToDS=0, FromDS=1. Addr1=Broadcast, Addr2=BSSID
				return NewPacketBuilder().AddDataFrame(false, true, broadcast, apMac, broadcast, []byte("data"))
			},
			wantNil: true, // Should ignore multicast
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := tt.packetFunc()
			packet := pb.Build()
			if packet == nil {
				t.Fatalf("Failed to build packet")
			}

			// Debug: Log layers
			// t.Logf("Packet Layers for %s:", tt.name)
			// for _, l := range packet.Layers() {
			// 	t.Logf("- %v", l.LayerType())
			// }

			got, _ := handler.HandlePacket(packet)

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Logf("Failed Packet Layers for %s:", tt.name)
				for _, l := range packet.Layers() {
					t.Logf("- %v", l.LayerType())
				}
				t.Fatalf("expected device, got nil")
			}

			if got.Type != tt.wantType {
				t.Errorf("Type: got %s, want %s", got.Type, tt.wantType)
			}
			if got.MAC != tt.wantMAC {
				t.Errorf("MAC: got %s, want %s", got.MAC, tt.wantMAC)
			}
			if tt.wantSSID != "" && got.SSID != tt.wantSSID {
				t.Errorf("SSID: got %s, want %s", got.SSID, tt.wantSSID)
			}
			if tt.wantSecurity != "" && got.Security != tt.wantSecurity {
				t.Errorf("Security: got %s, want %s", got.Security, tt.wantSecurity)
			}
			if tt.wantModel != "" && got.Model != tt.wantModel {
				t.Errorf("Model: got %s, want %s", got.Model, tt.wantModel)
			}
		})
	}
}

func BenchmarkHandlePacket_Beacon(b *testing.B) {
	mockLoc := MockGeo{}
	handler := NewPacketHandler(mockLoc, false, nil, nil)
	apMac := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	packet := NewPacketBuilder().
		AddMgmtBeacon(apMac, apMac, "Bench-SSID").
		AddRSNIE().
		Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.HandlePacket(packet)
	}
}

func BenchmarkHandlePacket_Data(b *testing.B) {
	mockLoc := MockGeo{}
	handler := NewPacketHandler(mockLoc, false, nil, nil)
	apMac := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	staMac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	packet := NewPacketBuilder().
		AddDataFrame(true, false, apMac, staMac, apMac, []byte("payload data")).
		Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.HandlePacket(packet)
	}
}
