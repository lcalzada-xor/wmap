package utils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"log"
)

func IsEAPOLKey(packet gopacket.Packet) bool {
	eapol := packet.Layer(layers.LayerTypeEAPOL)
	if eapol == nil {
		return false
	}
	e, ok := eapol.(*layers.EAPOL)
	return ok && e.Type == layers.EAPOLTypeKey
}

func IsWPSFrame(packet gopacket.Packet) bool {
	eapol := packet.Layer(layers.LayerTypeEAPOL)
	if eapol == nil {
		return false
	}
	e, ok := eapol.(*layers.EAPOL)
	if !ok {
		return false
	}
	return e.Type == layers.EAPOLTypeEAP || e.Type == layers.EAPOLTypeStart
}

func DetectLinkType(packet gopacket.Packet) layers.LinkType {
	if packet.Layer(layers.LayerTypeRadioTap) != nil {
		return layers.LinkTypeIEEE80211Radio
	}
	return layers.LinkType(105) // DLT_IEEE802_11
}

func GetSSIDFromPacket(packet gopacket.Packet) string {
	if beacon := packet.Layer(layers.LayerTypeDot11MgmtBeacon); beacon != nil {
		payload := beacon.LayerPayload()
		ssid := ie.ParseSSID(payload)
		if !ssid.Hidden {
			return ssid.Value
		}
		log.Printf("DEBUG: ParseSSID failed (Hidden=%v) for payload len %d: %x", ssid.Hidden, len(payload), payload)

		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeDot11InformationElement {
				ieLayer, _ := layer.(*layers.Dot11InformationElement)
				if ieLayer.ID == 0 { // SSID
					return string(ieLayer.Info)
				}
			}
		}
	}
	return ""
}

func SanitizeFilename(s string) string {
	res := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			res += string(c)
		} else {
			res += "_"
		}
	}
	return res
}
