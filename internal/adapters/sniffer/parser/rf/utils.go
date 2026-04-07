package rf

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ExtractBasicDeviceInfo extracts physical layer information from the RadioTap header
func ExtractBasicDeviceInfo(packet gopacket.Packet) (rssi, freq, channelWidth int) {
	rssi = -100
	if radiotapLayer := packet.Layer(layers.LayerTypeRadioTap); radiotapLayer != nil {
		if radiotap, ok := radiotapLayer.(*layers.RadioTap); ok {
			rssi = int(radiotap.DBMAntennaSignal)
			freq = int(radiotap.ChannelFrequency)
			// Channel width is better extracted from IEs or specific Radiotap xchannel fields
			// For now, we trust Frequency which is most reliable across cards.
		}
	}
	return
}

// FrequencyToChannel converts WiFi frequency (MHz) to channel number
func FrequencyToChannel(freq int) int {
	// 2.4 GHz band (channels 1-14)
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	}

	// 5 GHz band (channels 36-165)
	if freq >= 5170 && freq <= 5825 {
		return (freq - 5000) / 5
	}

	// 6 GHz band - WiFi 6E (channels 1-233)
	if freq >= 5955 && freq <= 7115 {
		return (freq - 5950) / 5
	}

	return 0
}

// IsAP tries to guess if the frame sender is an AP based on addressing or type
func IsAP(dot11 *layers.Dot11) bool {
	// Simple heuristic: If FromDS=1, ToDS=0 -> AP.
	// But Mgmt frames have ToDS=0, FromDS=0.
	// We rely on BSSID position?
	// Addr1=DA, Addr2=SA, Addr3=BSSID.
	// If SA == BSSID, it's likely an AP.
	return dot11.Address2.String() == dot11.Address3.String()
}
