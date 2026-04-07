package parser

import (
	"context"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/cache"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/handlers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/rf"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/threat"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// HandshakeManager defines the interface required by parser to interact with handshakes.
type HandshakeManager interface {
	ProcessFrame(packet gopacket.Packet) bool
	SavePMKID(packet gopacket.Packet, bssid string, station string)
	HasHandshake(mac string) bool
	GetHandshakeFile(mac string) string
}

// PacketHandler acts as a coordinator for packet parsing and delegation.
type PacketHandler struct {
	Debug            bool
	HandshakeManager HandshakeManager
	VendorRepo       fingerprint.VendorRepository
	PauseCallback    func(time.Duration)

	// Managed Components
	Throttler      *cache.ShardedCache
	ThreatDetector *threat.Detector
	MgmtHandler    *handlers.MgmtHandler
	DataHandler    *handlers.DataHandler
	StateManager   *domain.ConnectionStateManager
}

// NewPacketHandler creates a new PacketHandler with all its sub-components initialized.
func NewPacketHandler(debug bool, hm HandshakeManager, repo fingerprint.VendorRepository, pauseFunc func(time.Duration)) *PacketHandler {
	sm := domain.NewConnectionStateManager()
	tc := cache.NewShardedCache()
	fe := fingerprint.NewFingerprintEngine(fingerprint.NewSignatureStore(nil))

	h := &PacketHandler{
		Debug:            debug,
		HandshakeManager: hm,
		VendorRepo:       repo,
		PauseCallback:    pauseFunc,
		Throttler:        tc,
		StateManager:     sm,
	}

	// Initialize sub-handlers
	h.ThreatDetector = threat.NewDetector(tc, sm, h.getVendor)
	h.MgmtHandler = &handlers.MgmtHandler{
		FingerprintEngine: fe,
		StateManager:      sm,
		VendorLookup:      h.getVendor,
		Debug:             debug,
	}
	h.DataHandler = &handlers.DataHandler{
		FingerprintEngine: fe,
		StateManager:      sm,
		VendorLookup:      h.getVendor,
	}

	return h
}

// HandlePacket processes a single packet and returns a Device if relevant info is found.
func (h *PacketHandler) HandlePacket(packet gopacket.Packet) (dev *domain.Device, alt *domain.Alert, evt *domain.ConnectionEvent) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in PacketHandler: %v", r)
		}
	}()

	// 1. Handshake Capture (Passive)
	if stop, alert := h.handleHandshakeCapture(packet); stop || alert != nil {
		return nil, alert, nil
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil, nil, nil
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil, nil, nil
	}

	// 2. Throttling
	if h.shouldThrottlePacket(dot11, packet) {
		return nil, nil, nil
	}

	// 3. Physical Layer info
	rssi, freq, channelWidth := rf.ExtractBasicDeviceInfo(packet)
	device := &domain.Device{
		RSSI:           rssi,
		Frequency:      freq,
		Channel:        rf.FrequencyToChannel(freq),
		ChannelWidth:   channelWidth,
		LastPacketTime: time.Now(),
		LastSeen:       time.Now(),
	}

	// 4. Threat Detection (Deauth/Disassoc)
	if threatDev, threatAlert, threatEvt := h.ThreatDetector.Analyze(dot11, packet, device); threatAlert != nil {
		return threatDev, threatAlert, threatEvt
	}

	// 5. Frame Type Dispatch
	mainType := dot11.Type.MainType()
	if mainType == layers.Dot11TypeMgmt {
		d, e := h.MgmtHandler.Process(packet, dot11, device)
		
		// Post-processing for APs and Handshakes
		if d != nil && d.Type == "ap" && h.HandshakeManager != nil {
			d.HasHandshake = h.HandshakeManager.HasHandshake(d.MAC)
			if d.HasHandshake {
				d.HandshakeFile = h.HandshakeManager.GetHandshakeFile(d.MAC)
			}
		}
		return d, nil, e
	} else if mainType == layers.Dot11TypeData {
		d, e := h.DataHandler.Process(packet, dot11, device, isEAPOLKey(packet))
		return d, nil, e
	}

	return nil, nil, nil
}

func (h *PacketHandler) shouldThrottlePacket(dot11 *layers.Dot11, packet gopacket.Packet) bool {
	sourceMAC := dot11.Address2.String()
	isCritical := dot11.Type == layers.Dot11TypeMgmtDeauthentication ||
		dot11.Type == layers.Dot11TypeMgmtDisassociation ||
		dot11.Type == layers.Dot11TypeMgmtAssociationReq ||
		dot11.Type == layers.Dot11TypeMgmtReassociationReq ||
		dot11.Type == layers.Dot11TypeMgmtAuthentication ||
		dot11.Type.MainType() == layers.Dot11TypeData ||
		isEAPOLKey(packet)

	if !isCritical {
		if h.Throttler.ShouldThrottle(sourceMAC, 500*time.Millisecond) {
			return true
		}
	}
	return false
}

func (h *PacketHandler) getVendor(macStr string) string {
	mac, err := fingerprint.ParseMAC(macStr)
	if err != nil {
		return ""
	}
	if h.VendorRepo == nil {
		return ""
	}
	vendor, err := h.VendorRepo.LookupVendor(context.Background(), mac)
	if err != nil {
		return ""
	}
	return vendor
}
