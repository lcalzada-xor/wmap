package registry

import (
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// DeviceMerger handles the logic of merging new device information into an existing device record.
type DeviceMerger struct{}

// NewDeviceMerger creates a new DeviceMerger.
func NewDeviceMerger() *DeviceMerger {
	return &DeviceMerger{}
}

// Merge updates 'existing' with fields from 'newDevice'.
func (dm *DeviceMerger) Merge(existing *domain.Device, newDevice domain.Device) {
	existing.LastPacketTime = newDevice.LastPacketTime
	existing.LastSeen = newDevice.LastPacketTime
	existing.RSSI = newDevice.RSSI
	existing.Latitude = newDevice.Latitude
	existing.Longitude = newDevice.Longitude

	if newDevice.Vendor != "" {
		existing.Vendor = newDevice.Vendor
	}

	// APs take precedence over stations
	if newDevice.Type != "" {
		if newDevice.Type == "ap" || existing.Type == "" {
			existing.Type = newDevice.Type
		}
	}

	if newDevice.Signature != "" {
		existing.Signature = newDevice.Signature
		existing.IETags = newDevice.IETags
	}

	if newDevice.Security != "" {
		existing.Security = newDevice.Security
	}
	if newDevice.Standard != "" {
		existing.Standard = newDevice.Standard
	}
	if newDevice.Model != "" {
		existing.Model = newDevice.Model
	}
	if newDevice.Frequency > 0 {
		existing.Frequency = newDevice.Frequency
	}
	if newDevice.WPSInfo != "" {
		existing.WPSInfo = newDevice.WPSInfo
	}
	if newDevice.HasHandshake {
		existing.HasHandshake = true
	}
	if newDevice.MobilityDomain != nil {
		existing.MobilityDomain = newDevice.MobilityDomain
	}
	if newDevice.LastANonce != "" {
		existing.LastANonce = newDevice.LastANonce
	}

	if newDevice.Channel > 0 {
		existing.Channel = newDevice.Channel
	}

	if newDevice.Has11k {
		existing.Has11k = true
	}
	if newDevice.Has11v {
		existing.Has11v = true
	}
	if newDevice.Has11r {
		existing.Has11r = true
	}

	existing.DataTransmitted += newDevice.DataTransmitted
	existing.DataReceived += newDevice.DataReceived
	existing.PacketsCount += newDevice.PacketsCount
	existing.RetryCount += newDevice.RetryCount
	if newDevice.ChannelWidth > 0 {
		existing.ChannelWidth = newDevice.ChannelWidth
	}

	if existing.ProbedSSIDs == nil {
		existing.ProbedSSIDs = make(map[string]time.Time)
	}
	for ssid, ts := range newDevice.ProbedSSIDs {
		existing.ProbedSSIDs[ssid] = ts
	}

	if len(newDevice.ObservedSSIDs) > 0 {
		if existing.ObservedSSIDs == nil {
			existing.ObservedSSIDs = make([]string, 0)
		}
		// Merge unique SSIDs
		for _, newSSID := range newDevice.ObservedSSIDs {
			found := false
			for _, existingSSID := range existing.ObservedSSIDs {
				if existingSSID == newSSID {
					found = true
					break
				}
			}
			if !found {
				existing.ObservedSSIDs = append(existing.ObservedSSIDs, newSSID)
			}
		}
	}

	if newDevice.SSID != "" {
		existing.SSID = newDevice.SSID
	}
	if newDevice.ConnectedSSID != "" {
		existing.ConnectedSSID = newDevice.ConnectedSSID
	}

	if newDevice.ConnectionState != "" {
		existing.ConnectionState = newDevice.ConnectionState
		existing.ConnectionTarget = newDevice.ConnectionTarget
		existing.ConnectionError = newDevice.ConnectionError
	}
}
