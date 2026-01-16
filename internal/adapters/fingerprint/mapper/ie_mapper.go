package mapper

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// ParseIEs extracts information from 802.11 Information Elements and populates the Device model.
func ParseIEs(data []byte, device *domain.Device) {
	// Defaults
	device.Security = "OPEN"
	device.Standard = "802.11g/a" // baseline

	ie.IterateIEs(data, func(id int, val []byte) {
		device.IETags = append(device.IETags, id)

		switch id {
		case 0: // SSID
			valStr := string(val)
			// Check for Hidden SSID (Empty or Null bytes)
			isHidden := len(val) == 0 || val[0] == 0x00

			if isHidden {
				device.SSID = "<HIDDEN>"
			} else {
				device.SSID = valStr
			}
		case 3: // DS Parameter Set (Channel)
			if len(val) > 0 {
				device.Channel = int(val[0])
			}
		case 48: // RSN (WPA2/WPA3)
			if rsn, err := ie.ParseRSN(val); err == nil {
				// Determine security type based on AKM
				if containsString(rsn.AKMSuites, "SAE") {
					device.Security = "WPA3"
				} else if containsString(rsn.AKMSuites, "PSK") {
					device.Security = "WPA2-PSK"
				} else if containsString(rsn.AKMSuites, "802.1X") {
					device.Security = "WPA2-Enterprise"
				} else {
					device.Security = "WPA2"
				}
				device.RSNInfo = &domain.RSNInfo{
					Version:         rsn.Version,
					GroupCipher:     rsn.GroupCipher,
					PairwiseCiphers: rsn.PairwiseCiphers,
					AKMSuites:       rsn.AKMSuites,
					Capabilities: domain.RSNCapabilities{
						PreAuth:          rsn.Capabilities.PreAuth,
						NoPairwise:       rsn.Capabilities.NoPairwise,
						PTKSAReplayCount: rsn.Capabilities.PTKSAReplayCount,
						GTKSAReplayCount: rsn.Capabilities.GTKSAReplayCount,
						MFPRequired:      rsn.Capabilities.MFPRequired,
						MFPCapable:       rsn.Capabilities.MFPCapable,
						PeerKeyEnabled:   rsn.Capabilities.PeerKeyEnabled,
					},
				}
			} else {
				device.Security = "WPA2"
			}
		case 54: // Mobility Domain (802.11r)
			device.Has11r = true
			device.Capabilities = append(device.Capabilities, "11r")
		case 70: // Radio Measurement (802.11k)
			device.Has11k = true
			device.Capabilities = append(device.Capabilities, "11k")
		case 45: // HT Capabilities (802.11n)
			device.Standard = "802.11n (WiFi 4)"
		case 191: // VHT Capabilities (802.11ac)
			device.Standard = "802.11ac (WiFi 5)"
		case 255: // Extension Tag (HE/EHT/etc)
			if len(val) >= 1 {
				extID := int(val[0])
				switch extID {
				case 35: // HE Capabilities (802.11ax)
					device.Standard = "802.11ax (WiFi 6)"
					device.IsWiFi6 = true
				case 108: // EHT Capabilities (802.11be)
					device.Standard = "802.11be (WiFi 7)"
					device.IsWiFi7 = true
					device.IsWiFi6 = true
				}
			}
		case 127: // Extended Capabilities (often contains 802.11v)
			// Check bit 19 for BSS Transition Management
			if len(val) >= 3 {
				if (val[2] & 0x08) != 0 {
					device.Has11v = true
					device.Capabilities = append(device.Capabilities, "11v")
				}
			}
		case 221: // Vendor Specific
			// Microsoft WPS check (OUI: 00 50 F2, Type: 04)
			if len(val) >= 4 && val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 && val[3] == 0x04 {
				wpsInfo := ie.ParseWPSAttributes(val[4:])

				// Map to domain.Device
				device.WPSDetails = &domain.WPSDetails{
					Manufacturer:  wpsInfo.Manufacturer,
					Model:         wpsInfo.Model,
					DeviceName:    wpsInfo.DeviceName,
					State:         wpsInfo.State,
					Version:       wpsInfo.Version,
					Locked:        wpsInfo.Locked,
					ConfigMethods: wpsInfo.ConfigMethods,
				}

				if wpsInfo.State != "" {
					device.WPSInfo = wpsInfo.State
					if wpsInfo.Version != "" {
						device.WPSInfo += " (WPS " + wpsInfo.Version + ")"
					}
				}

				// Construct Model String
				model := wpsInfo.Model
				if model == "" && wpsInfo.DeviceName != "" {
					model = wpsInfo.DeviceName
				}
				if model != "" {
					if wpsInfo.Manufacturer != "" {
						device.Model = wpsInfo.Manufacturer + " " + model
					} else {
						device.Model = model
					}
				}
			}
		}
	})

	// Compute Signature if we have tags
	if len(device.IETags) > 0 {
		device.Signature = ComputeSignature(device.IETags, nil)
	}
}

// ComputeSignature builds a hash based on IE tags and optional values
func ComputeSignature(tags []int, specificValues []string) string {
	// We do NOT sort tags because order matters for fingerprinting

	var sb strings.Builder
	for _, t := range tags {
		sb.WriteString(fmt.Sprintf("%d,", t))
	}
	sb.WriteString("|")
	for _, v := range specificValues {
		sb.WriteString(v + ",")
	}

	hash := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
