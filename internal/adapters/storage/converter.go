package storage

import (
	"encoding/json"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// toDomain converts a database model to a domain entity.
func toDomain(m DeviceModel) *domain.Device {
	probes := make(map[string]time.Time)
	for _, p := range m.ProbedSSIDs {
		probes[p.SSID] = p.LastSeen
	}

	dev := &domain.Device{
		MAC:              m.MAC,
		Type:             domain.DeviceType(m.Type),
		Vendor:           m.Vendor,
		RSSI:             m.RSSI,
		SSID:             m.SSID,
		Channel:          m.Channel,
		Crypto:           m.Crypto,
		Security:         m.Security,
		Standard:         m.Standard,
		Frequency:        m.Frequency,
		ChannelWidth:     m.ChannelWidth,
		WPSInfo:          m.WPSInfo,
		LastPacketTime:   m.LastPacketTime,
		FirstSeen:        m.FirstSeen,
		LastSeen:         m.LastSeen,
		ConnectedSSID:    m.ConnectedSSID,
		Model:            m.Model,
		OS:               m.OS,
		IsRandomized:     m.IsRandomized,
		IsWiFi6:          m.IsWiFi6,
		IsWiFi7:          m.IsWiFi7,
		Signature:        m.Signature,
		Has11k:           m.Has11k,
		Has11v:           m.Has11v,
		Has11r:           m.Has11r,
		DataTransmitted:  m.DataTransmitted,
		DataReceived:     m.DataReceived,
		PacketsCount:     m.PacketsCount,
		RetryCount:       m.RetryCount,
		ProbedSSIDs:      probes,
		ConnectionState:  domain.ConnectionState(m.ConnectionState),
		ConnectionTarget: m.ConnectionTarget,
		ConnectionError:  m.ConnectionError,
	}

	// Map Security & Cracking fields (Restoration)
	dev.HasHandshake = m.HasHandshake
	dev.HandshakeFile = m.HandshakeFile
	dev.IEFingerprint = m.IEFingerprint

	// --- Restore Missing Fields ---
	dev.LastANonce = m.LastANonce
	dev.ProbeHash = m.ProbeHash
	dev.ManufacturerRaw = m.ManufacturerRaw
	dev.VendorConfidence = m.VendorConfidence

	if m.Capabilities != "" {
		_ = json.Unmarshal([]byte(m.Capabilities), &dev.Capabilities)
	}
	if m.MobilityDomain != "" {
		_ = json.Unmarshal([]byte(m.MobilityDomain), &dev.MobilityDomain)
	}
	if m.BSSLoad != "" {
		_ = json.Unmarshal([]byte(m.BSSLoad), &dev.BSSLoad)
	}
	if m.ObservedSSIDs != "" {
		_ = json.Unmarshal([]byte(m.ObservedSSIDs), &dev.ObservedSSIDs)
	}
	if m.IETags != "" {
		_ = json.Unmarshal([]byte(m.IETags), &dev.IETags)
	}
	// ------------------------------

	if m.EncryptionDetails != "" {
		_ = json.Unmarshal([]byte(m.EncryptionDetails), &dev.RSNInfo)
	}

	if m.WPSData != "" {
		_ = json.Unmarshal([]byte(m.WPSData), &dev.WPSDetails)
	}

	return dev
}

// toModel converts a domain entity to a database model.
func toModel(d domain.Device) DeviceModel {
	model := DeviceModel{
		MAC:              d.MAC,
		Type:             string(d.Type),
		Vendor:           d.Vendor,
		RSSI:             d.RSSI,
		SSID:             d.SSID,
		Channel:          d.Channel,
		Crypto:           d.Crypto,
		Security:         d.Security,
		Standard:         d.Standard,
		Frequency:        d.Frequency,
		ChannelWidth:     d.ChannelWidth,
		WPSInfo:          d.WPSInfo,
		LastPacketTime:   d.LastPacketTime,
		FirstSeen:        d.FirstSeen,
		LastSeen:         d.LastSeen,
		ConnectedSSID:    d.ConnectedSSID,
		Model:            d.Model,
		OS:               d.OS,
		IsRandomized:     d.IsRandomized,
		IsWiFi6:          d.IsWiFi6,
		IsWiFi7:          d.IsWiFi7,
		Signature:        d.Signature,
		Has11k:           d.Has11k,
		Has11v:           d.Has11v,
		Has11r:           d.Has11r,
		DataTransmitted:  d.DataTransmitted,
		DataReceived:     d.DataReceived,
		PacketsCount:     d.PacketsCount,
		RetryCount:       d.RetryCount,
		ConnectionState:  string(d.ConnectionState),
		ConnectionTarget: d.ConnectionTarget,
		ConnectionError:  d.ConnectionError,
	}

	// Map Security & Cracking fields
	model.HasHandshake = d.HasHandshake
	model.HandshakeFile = d.HandshakeFile
	model.IEFingerprint = d.IEFingerprint

	// --- Map Missing Fields ---
	model.LastANonce = d.LastANonce
	model.ProbeHash = d.ProbeHash
	model.ManufacturerRaw = d.ManufacturerRaw
	model.VendorConfidence = d.VendorConfidence

	if len(d.Capabilities) > 0 {
		b, _ := json.Marshal(d.Capabilities)
		model.Capabilities = string(b)
	}
	if d.MobilityDomain != nil {
		b, _ := json.Marshal(d.MobilityDomain)
		model.MobilityDomain = string(b)
	}
	if d.BSSLoad != nil {
		b, _ := json.Marshal(d.BSSLoad)
		model.BSSLoad = string(b)
	}
	if len(d.ObservedSSIDs) > 0 {
		b, _ := json.Marshal(d.ObservedSSIDs)
		model.ObservedSSIDs = string(b)
	}
	if len(d.IETags) > 0 {
		b, _ := json.Marshal(d.IETags)
		model.IETags = string(b)
	}
	// --------------------------

	if d.RSNInfo != nil {
		rsnBytes, _ := json.Marshal(d.RSNInfo)
		model.EncryptionDetails = string(rsnBytes)
	}

	if d.WPSDetails != nil {
		wpsBytes, _ := json.Marshal(d.WPSDetails)
		model.WPSData = string(wpsBytes)
	}

	return model
}
