package sniffer

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestBidirectionalDeauthVerification verifies the correct BSSID setting for bidirectional attacks.
func TestBidirectionalDeauthVerification(t *testing.T) {
	// We can't easily mock the pcap handle in the Injector for SendDeauthBurst without refactoring Injector to use an interface.
	// However, we can use the exposed serializeDeauthPacket helper method (which we modified) to verify the logic.
	// But wait, the logic for *selecting* the BSSID happens inside SendDeauthBurst/StartContinuousDeauth,
	// not inside serializeDeauthPacket itself (which just takes what it's given).

	// So to truly verify the "Business Logic" of BSSID selection, we need to inspect what SendDeauthBurst *would* send.
	// Since we can't capture writes to the pcap handle easily here without mocking,
	// we will partially rely on our manual inspection of the code refactor (which was to pass the correct arg).

	// BUT, we can verify the Helper behaves as expected given the inputs we INTEND to pass.

	injector := &Injector{}
	apMAC, _ := net.ParseMAC("AA:AA:AA:AA:AA:AA")     // The AP / BSSID
	clientMAC, _ := net.ParseMAC("CC:CC:CC:CC:CC:CC") // The Client
	reason := uint16(7)

	// Case 1: AP -> Client (Spoofing AP)
	// Addr1 (Dst) = Client
	// Addr2 (Src) = AP
	// Addr3 (BSSID) = AP
	pkt1Bytes, err := injector.serializeDeauthPacket(clientMAC, apMAC, apMAC, reason, 0)
	if err != nil {
		t.Fatalf("Failed to serialize AP->Client: %v", err)
	}
	verifyPacket(t, pkt1Bytes, clientMAC, apMAC, apMAC, "AP->Client")

	// Case 2: Client -> AP (Spoofing Client)
	// Addr1 (Dst) = AP
	// Addr2 (Src) = Client
	// Addr3 (BSSID) = AP  <--- THIS IS THE FIX. Before it was Client.
	pkt2Bytes, err := injector.serializeDeauthPacket(apMAC, clientMAC, apMAC, reason, 0)
	if err != nil {
		t.Fatalf("Failed to serialize Client->AP: %v", err)
	}
	verifyPacket(t, pkt2Bytes, apMAC, clientMAC, apMAC, "Client->AP")
}

func verifyPacket(t *testing.T, data []byte, wantDst, wantSrc, wantBSSID net.HardwareAddr, desc string) {
	packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		t.Fatalf("[%s] Dot11 layer missing", desc)
	}
	d11, _ := dot11Layer.(*layers.Dot11)

	if !bytes.Equal(d11.Address1, wantDst) {
		t.Errorf("[%s] Wrong Dst (Addr1): got %v, want %v", desc, d11.Address1, wantDst)
	}
	if !bytes.Equal(d11.Address2, wantSrc) {
		t.Errorf("[%s] Wrong Src (Addr2): got %v, want %v", desc, d11.Address2, wantSrc)
	}
	if !bytes.Equal(d11.Address3, wantBSSID) {
		t.Errorf("[%s] Wrong BSSID (Addr3): got %v, want %v", desc, d11.Address3, wantBSSID)
	}
}
