package sniffer

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
