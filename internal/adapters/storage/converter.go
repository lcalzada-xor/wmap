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
		MAC:             m.MAC,
		Type:            m.Type,
		Vendor:          m.Vendor,
		RSSI:            m.RSSI,
		SSID:            m.SSID,
		Channel:         m.Channel,
		Crypto:          m.Crypto,
		Security:        m.Security,
		Standard:        m.Standard,
		Frequency:       m.Frequency,
		ChannelWidth:    m.ChannelWidth,
		WPSInfo:         m.WPSInfo,
		Latitude:        m.Latitude,
		Longitude:       m.Longitude,
		LastPacketTime:  m.LastPacketTime,
		FirstSeen:       m.FirstSeen,
		LastSeen:        m.LastSeen,
		ConnectedSSID:   m.ConnectedSSID,
		Model:           m.Model,
		OS:              m.OS,
		IsRandomized:    m.IsRandomized,
		IsWiFi6:         m.IsWiFi6,
		IsWiFi7:         m.IsWiFi7,
		Signature:       m.Signature,
		Has11k:          m.Has11k,
		Has11v:          m.Has11v,
		Has11r:          m.Has11r,
		DataTransmitted: m.DataTransmitted,
		DataReceived:    m.DataReceived,
		PacketsCount:    m.PacketsCount,
		RetryCount:      m.RetryCount,
		ProbedSSIDs:     probes,
	}

	// Behavioral Reconstruction
	var activeHours []int
	if m.ActiveHours != "" {
		_ = json.Unmarshal([]byte(m.ActiveHours), &activeHours)
	}
	dev.Behavioral = &domain.BehavioralProfile{
		MAC:            m.MAC,
		ProbeFrequency: time.Duration(m.ProbeFrequency),
		UniqueSSIDs:    m.UniqueSSIDs,
		AnomalyScore:   m.AnomalyScore,
		ActiveHours:    activeHours,
		LastUpdated:    m.LastSeen,
	}

	return dev
}

// toModel converts a domain entity to a database model.
func toModel(d domain.Device) DeviceModel {
	model := DeviceModel{
		MAC:             d.MAC,
		Type:            d.Type,
		Vendor:          d.Vendor,
		RSSI:            d.RSSI,
		SSID:            d.SSID,
		Channel:         d.Channel,
		Crypto:          d.Crypto,
		Security:        d.Security,
		Standard:        d.Standard,
		Frequency:       d.Frequency,
		ChannelWidth:    d.ChannelWidth,
		WPSInfo:         d.WPSInfo,
		Latitude:        d.Latitude,
		Longitude:       d.Longitude,
		LastPacketTime:  d.LastPacketTime,
		FirstSeen:       d.FirstSeen,
		LastSeen:        d.LastSeen,
		ConnectedSSID:   d.ConnectedSSID,
		Model:           d.Model,
		OS:              d.OS,
		IsRandomized:    d.IsRandomized,
		IsWiFi6:         d.IsWiFi6,
		IsWiFi7:         d.IsWiFi7,
		Signature:       d.Signature,
		Has11k:          d.Has11k,
		Has11v:          d.Has11v,
		Has11r:          d.Has11r,
		DataTransmitted: d.DataTransmitted,
		DataReceived:    d.DataReceived,
		PacketsCount:    d.PacketsCount,
		RetryCount:      d.RetryCount,
	}

	if d.Behavioral != nil {
		model.ProbeFrequency = int64(d.Behavioral.ProbeFrequency)
		model.UniqueSSIDs = d.Behavioral.UniqueSSIDs
		model.AnomalyScore = d.Behavioral.AnomalyScore
		if d.Behavioral.ActiveHours != nil {
			hBytes, _ := json.Marshal(d.Behavioral.ActiveHours)
			model.ActiveHours = string(hBytes)
		}
	}

	return model
}
