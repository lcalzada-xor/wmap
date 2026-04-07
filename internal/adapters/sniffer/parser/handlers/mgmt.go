package handlers

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint/ie"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/rf"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// MgmtHandler encapsulates the logic to process 802.11 Management frames
type MgmtHandler struct {
	FingerprintEngine *fingerprint.FingerprintEngine
	StateManager      *domain.ConnectionStateManager
	VendorLookup      func(string) string
	Debug             bool
}

// Process parses a management frame and updates device state
func (h *MgmtHandler) Process(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.MAC = dot11.Address2.String()
	if h.VendorLookup != nil {
		device.Vendor = h.VendorLookup(device.MAC)
	}
	device.PacketsCount = 1
	device.DataTransmitted = int64(len(packet.Data()))

	var ieData []byte
	isBeacon := false
	isProbe := false

	switch dot11.Type {
	case layers.Dot11TypeMgmtBeacon:
		h.handleBeacon(packet, device, &ieData)
		isBeacon = true
	case layers.Dot11TypeMgmtProbeReq:
		h.handleProbeReq(packet, device, &ieData)
		isProbe = true
	case layers.Dot11TypeMgmtProbeResp:
		h.handleProbeResp(packet, device, &ieData)
		isBeacon = true
	case layers.Dot11TypeMgmtAssociationReq, layers.Dot11TypeMgmtReassociationReq:
		return h.handleAssocReq(dot11, device)
	case layers.Dot11TypeMgmtAuthentication:
		return h.handleAuth(packet, dot11, device)
	case layers.Dot11TypeMgmtAction:
		h.handleAction(packet, dot11, device, &ieData)
	case layers.Dot11TypeMgmtDeauthentication, layers.Dot11TypeMgmtDisassociation:
		return h.handleDeauth(dot11, device)
	default:
		return nil, nil
	}

	// Fallback: If ieData is empty, check if gopacket decoded IEs into individual layers
	if len(ieData) == 0 {
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeDot11InformationElement {
				if opt, ok := layer.(*layers.Dot11InformationElement); ok {
					// Reconstruct IE bytes: [ID, Length, Value]
					ieData = append(ieData, byte(opt.ID), opt.Length)
					ieData = append(ieData, opt.Info...)
				}
			}
		}
	}

	// Log debug info for interesting packets
	if h.Debug && len(ieData) > 0 {
		log.Printf("DEBUG Handler: MAC=%s Type=%s PayloadLen=%d", device.MAC, device.Type, len(ieData))
	}

	ie.ParseIEs(ieData, device)

	// Randomized MAC Check & Fingerprinting
	if h.FingerprintEngine != nil {
		h.FingerprintEngine.AnalyzeRandomization(dot11.Address2, device)
	}

	if isProbe && device.SSID != "" {
		if device.ProbedSSIDs == nil {
			device.ProbedSSIDs = make(map[string]time.Time)
		}
		device.ProbedSSIDs[device.SSID] = device.LastPacketTime
	}

	// Capture AP SSID variations (Advanced Karma Detection)
	if isBeacon && device.SSID != "" && device.Type == "ap" {
		device.ObservedSSIDs = []string{device.SSID}
	}

	// Only return if we actually classified it
	if isBeacon || isProbe || device.ConnectionState == domain.StateAssociating || device.ConnectionState == domain.StateAuthenticating || device.ConnectionState == domain.StateDisconnected || device.ConnectionState == domain.StateConnected || device.ConnectionState == domain.StateHandshake {
		return device, nil
	}
	return nil, nil
}

func (h *MgmtHandler) handleBeacon(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "ap"
	device.Capabilities = append(device.Capabilities, "Beacon")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtBeacon); layer != nil {
		if beacon, ok := layer.(*layers.Dot11MgmtBeacon); ok {
			*ieData = beacon.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *MgmtHandler) handleProbeReq(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "Probe")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); layer != nil {
		if probe, ok := layer.(*layers.Dot11MgmtProbeReq); ok {
			*ieData = probe.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *MgmtHandler) handleProbeResp(packet gopacket.Packet, device *domain.Device, ieData *[]byte) {
	device.Type = "ap"
	device.Capabilities = append(device.Capabilities, "ProbeResp")
	if layer := packet.Layer(layers.LayerTypeDot11MgmtProbeResp); layer != nil {
		if resp, ok := layer.(*layers.Dot11MgmtProbeResp); ok {
			*ieData = resp.LayerPayload()
		} else {
			*ieData = layer.LayerPayload()
		}
	}
}

func (h *MgmtHandler) handleAssocReq(dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "AssocReq")

	target := dot11.Address1.String()
	event := domain.ConnectionEvent{
		Type:      domain.EventAssocReq,
		SourceMAC: device.MAC,
		TargetMAC: target,
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget

	return device, &event
}

func (h *MgmtHandler) handleAuth(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	device.Type = "station"
	device.Capabilities = append(device.Capabilities, "Auth")

	if authLayer := packet.Layer(layers.LayerTypeDot11MgmtAuthentication); authLayer != nil {
		if auth, ok := authLayer.(*layers.Dot11MgmtAuthentication); ok {
			if auth.Status != 0 {
				device.ConnectionError = fmt.Sprintf("auth_failed_code_%d", auth.Status)
			}
		}
	}

	target := dot11.Address1.String()
	event := domain.ConnectionEvent{
		Type:      domain.EventAuthReq,
		SourceMAC: device.MAC,
		TargetMAC: target,
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(device.MAC, event)
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget

	return device, &event
}

func (h *MgmtHandler) handleAction(packet gopacket.Packet, dot11 *layers.Dot11, device *domain.Device, ieData *[]byte) {
	device.Type = "station"
	if rf.IsAP(dot11) {
		device.Type = "ap"
	}

	if layer := packet.Layer(layers.LayerTypeDot11MgmtAction); layer != nil {
		payload := layer.LayerPayload()
		if len(payload) > 0 {
			category := payload[0]
			switch category {
			case 0:
				device.Capabilities = append(device.Capabilities, "11h")
			case 5:
				device.Has11k = true
				device.Capabilities = append(device.Capabilities, "11k")
			case 6:
				device.Has11r = true
				device.Capabilities = append(device.Capabilities, "11r")
			case 10:
				device.Has11v = true
				device.Capabilities = append(device.Capabilities, "11v")
			}
		}
		*ieData = payload
	}
}

func (h *MgmtHandler) handleDeauth(dot11 *layers.Dot11, device *domain.Device) (*domain.Device, *domain.ConnectionEvent) {
	eventType := domain.EventDeauth
	if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		eventType = domain.EventDisassoc
	}

	isAPKicking := dot11.Address2.String() == dot11.Address3.String()
	targetMAC := dot11.Address2.String()
	if isAPKicking {
		targetMAC = dot11.Address1.String()
	}

	event := domain.ConnectionEvent{
		Type:      eventType,
		SourceMAC: dot11.Address2.String(),
		TargetMAC: dot11.Address1.String(),
		Timestamp: time.Now(),
	}
	newState, newTarget := h.StateManager.UpdateState(targetMAC, event)

	if targetMAC == device.MAC {
		device.ConnectionState = newState
		device.ConnectionTarget = newTarget
		device.ConnectedSSID = ""
	}

	return device, &event
}
