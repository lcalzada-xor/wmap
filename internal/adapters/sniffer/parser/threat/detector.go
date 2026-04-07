package threat

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/parser/cache"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Detector isolates the logic for passive threat detection (e.g. Deauth/Disassoc attacks)
type Detector struct {
	Throttler    *cache.ShardedCache
	StateManager *domain.ConnectionStateManager
	VendorLookup func(mac string) string
}

// NewDetector creates a new threat detector
func NewDetector(tc *cache.ShardedCache, sm *domain.ConnectionStateManager, vl func(string) string) *Detector {
	return &Detector{
		Throttler:    tc,
		StateManager: sm,
		VendorLookup: vl,
	}
}

// Analyze inspects a packet for anomalous behavior and returns parsed entities if a threat is found
func (d *Detector) Analyze(dot11 *layers.Dot11, packet gopacket.Packet, device *domain.Device) (*domain.Device, *domain.Alert, *domain.ConnectionEvent) {
	if dot11.Type != layers.Dot11TypeMgmtDeauthentication && dot11.Type != layers.Dot11TypeMgmtDisassociation {
		return nil, nil, nil
	}

	// Throttle Alert Generation to prevent UI flooding
	throttleKey := "alert:deauth:" + dot11.Address2.String()
	if d.Throttler.ShouldThrottle(throttleKey, 200*time.Millisecond) {
		return nil, nil, nil
	}

	// Create Alert
	alert := &domain.Alert{
		Type:      domain.AlertAnomaly,
		Subtype:   "DEAUTH_DETECTED",
		DeviceMAC: dot11.Address2.String(), // Source
		TargetMAC: dot11.Address1.String(), // Dest
		Timestamp: time.Now(),
		Message:   "Deauthentication/Disassociation Frame Detected",
		Details:   "BSSID: " + dot11.Address3.String(),
	}
	if dot11.Address1.String() == "ff:ff:ff:ff:ff:ff" {
		alert.Subtype = "BROADCAST_DEAUTH"
	}

	// Logic: Identify who is disconnecting
	isAPKicking := dot11.Address2.String() == dot11.Address3.String()

	targetMAC := ""
	if isAPKicking {
		targetMAC = dot11.Address1.String()
		if targetMAC == "ff:ff:ff:ff:ff:ff" {
			return nil, alert, nil
		}
	} else {
		targetMAC = dot11.Address2.String()
	}

	// Extract Reason Code First
	var reasonCode layers.Dot11Reason
	foundReason := false

	if dot11.Type == layers.Dot11TypeMgmtDeauthentication {
		if layer := packet.Layer(layers.LayerTypeDot11MgmtDeauthentication); layer != nil {
			if deauth, ok := layer.(*layers.Dot11MgmtDeauthentication); ok {
				reasonCode = deauth.Reason
				foundReason = true
			}
		}
	} else if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		if layer := packet.Layer(layers.LayerTypeDot11MgmtDisassociation); layer != nil {
			if disassoc, ok := layer.(*layers.Dot11MgmtDisassociation); ok {
				reasonCode = disassoc.Reason
				foundReason = true
			}
		}
	}

	// Update State via Manager
	eventType := domain.EventDeauth
	if dot11.Type == layers.Dot11TypeMgmtDisassociation {
		eventType = domain.EventDisassoc
	}

	event := domain.ConnectionEvent{
		Type:      eventType,
		SourceMAC: dot11.Address2.String(),
		TargetMAC: dot11.Address1.String(),
		Timestamp: time.Now(),
		Reason:    int(reasonCode),
	}

	newState, newTarget := d.StateManager.UpdateState(targetMAC, event)

	// Update Device State for the Station
	device.MAC = targetMAC
	device.ConnectionState = newState
	device.ConnectionTarget = newTarget
	device.ConnectedSSID = "" // Clear connected SSID on deauth
	
	if d.VendorLookup != nil {
		device.Vendor = d.VendorLookup(device.MAC)
	}

	if foundReason {
		alert.Details += fmt.Sprintf(", Reason: %d", reasonCode)
		if reasonCode == 2 || reasonCode == 15 || reasonCode == 23 {
			device.ConnectionError = "auth_failed"
		}
	}

	return device, alert, &event
}
