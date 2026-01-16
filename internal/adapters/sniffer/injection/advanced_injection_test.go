package injection

import (
	"context"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// TestAdvancedInjectionFeatures verifies NAV, No-ACK, SeqNum, and Disassoc logic.
func TestAdvancedInjectionFeatures(t *testing.T) {
	injector := &Injector{}
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("66:77:88:99:AA:BB")
	reason := uint16(7)

	t.Run("NAV_Duration_Jamming", func(t *testing.T) {
		pkt, err := injector.serializeDeauthPacket(mac1, mac2, mac2, reason, 100)
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		d11 := getDot11Layer(t, pkt)
		expectedDuration := uint16(0x1388) // 5000us
		if d11.DurationID != expectedDuration {
			t.Errorf("NAV Duration mismatch: got %d, want %d (5000us)", d11.DurationID, expectedDuration)
		}
	})

	t.Run("No_ACK_Flag", func(t *testing.T) {
		pkt, err := injector.serializeDeauthPacket(mac1, mac2, mac2, reason, 100)
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		rt := getRadiotapLayer(t, pkt)
		// Check bit 3 (0x0008)
		if rt.Flags&0x0008 == 0 {
			t.Errorf("No-ACK flag (0x0008) NOT set. Flags: 0x%x", rt.Flags)
		}
	})

	t.Run("Sequence_Number_Randomization", func(t *testing.T) {
		seq1 := uint16(100)
		seq2 := uint16(101)

		pkt1, _ := injector.serializeDeauthPacket(mac1, mac2, mac2, reason, seq1)
		pkt2, _ := injector.serializeDeauthPacket(mac1, mac2, mac2, reason, seq2)

		d11_1 := getDot11Layer(t, pkt1)
		d11_2 := getDot11Layer(t, pkt2)

		if d11_1.SequenceNumber != seq1 {
			t.Errorf("SeqNum mismatch 1: got %d, want %d", d11_1.SequenceNumber, seq1)
		}
		if d11_2.SequenceNumber != seq2 {
			t.Errorf("SeqNum mismatch 2: got %d, want %d", d11_2.SequenceNumber, seq2)
		}
	})

	t.Run("Disassociation_Packet_Structure", func(t *testing.T) {
		pkt, err := injector.serializeDisassocPacket(mac1, mac2, mac2, reason, 200)
		if err != nil {
			t.Fatalf("Serialize Disassoc failed: %v", err)
		}

		d11 := getDot11Layer(t, pkt)

		// Check Type
		if d11.Type != layers.Dot11TypeMgmtDisassociation {
			t.Errorf("Wrong Packet Type: got %v, want MgmtDisassociation", d11.Type)
		}

		// Check Optimizations present on Disassoc too
		if d11.DurationID != 0x1388 {
			t.Errorf("Disassoc NAV Duration missing")
		}

		rt := getRadiotapLayer(t, pkt)
		if rt.Flags&0x0008 == 0 {
			t.Errorf("Disassoc No-ACK flag missing")
		}
	})
}

func getDot11Layer(t *testing.T, data []byte) *layers.Dot11 {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)
	l := packet.Layer(layers.LayerTypeDot11)
	if l == nil {
		t.Fatal("Dot11 layer not found")
	}
	return l.(*layers.Dot11)
}

func getRadiotapLayer(t *testing.T, data []byte) *layers.RadioTap {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)
	l := packet.Layer(layers.LayerTypeRadioTap)
	if l == nil {
		t.Fatal("Radiotap layer not found")
	}
	return l.(*layers.RadioTap)
}

// Mock Injector
type mockInjector struct {
	packets [][]byte
}

func (m *mockInjector) Inject(packet []byte) error {
	copied := make([]byte, len(packet))
	copy(copied, packet)
	m.packets = append(m.packets, copied)
	return nil
}

func (m *mockInjector) Close() {}

func TestSmartReasonLogic(t *testing.T) {
	mock := &mockInjector{}
	injector := &Injector{
		mechanism: mock,
		seq:       100,
	}

	apMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	clientMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

	config := domain.DeauthAttackConfig{
		TargetMAC:        apMAC.String(),
		ClientMAC:        clientMAC.String(),
		AttackType:       domain.DeauthTargeted,
		PacketCount:      1, // 1 pair
		UseReasonFuzzing: true,
		ReasonCode:       7, // Should be overridden to 3 for Client->AP
		// No SpoofSource needed for logic check, usually
	}

	// Use background context
	err := injector.SendDeauthBurst(context.Background(), config)
	if err != nil {
		t.Fatalf("Burst failed: %v", err)
	}

	// We expect multiple packets because burst loop runs 'PacketCount' times.
	// PacketCount=1 means 1 iteration.
	// In 1 iteration, targeted sends:
	// 1. AP -> Client
	// 2. Client -> AP
	// So at least 2 packets.
	if len(mock.packets) < 2 {
		t.Fatalf("Expected at least 2 packets, got %d", len(mock.packets))
	}

	// Packet 2 should be Client -> AP (Packet index 1)
	pkt2 := mock.packets[1]
	d11 := getDot11Layer(t, pkt2)

	// Check Direction
	if d11.Address1.String() != apMAC.String() {
		t.Errorf("Packet 2 Dest should be AP. Got %s, Want %s", d11.Address1, apMAC)
	}
	if d11.Address2.String() != clientMAC.String() {
		t.Errorf("Packet 2 Source should be Client. Got %s, Want %s", d11.Address2, clientMAC)
	}

	// Parse Reason Code
	packet := gopacket.NewPacket(pkt2, layers.LayerTypeRadioTap, gopacket.Default)
	if deauthLayer := packet.Layer(layers.LayerTypeDot11MgmtDeauthentication); deauthLayer != nil {
		deauth, _ := deauthLayer.(*layers.Dot11MgmtDeauthentication)
		// Reason 3 = Deauth because sending station is leaving
		if deauth.Reason != layers.Dot11Reason(3) {
			t.Errorf("Client->AP Reason Code mismatch. Got %d, Want 3", deauth.Reason)
		} else {
			t.Logf("Success: Client->AP packet used Reason Code 3 (Station Leaving)")
		}
	} else if disassocLayer := packet.Layer(layers.LayerTypeDot11MgmtDisassociation); disassocLayer != nil {
		// If it used Disassoc, verify logic (currently inject uses Deauth for leaving usually)
		t.Logf("Packet 2 is Disassoc")
	} else {
		t.Error("Packet 2 is not Deauth/Disassoc")
	}
}
