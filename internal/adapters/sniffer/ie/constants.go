package ie

// 802.11 Information Element Tag IDs.
// This is the single canonical source of truth for all IE tag numbers used
// across both the sniffer (low-level parsing) and fingerprint (high-level
// semantic mapping) layers.
const (
	TagSSID                 = 0
	TagSupportedRates       = 1
	TagDSParameterSet       = 3   // Channel
	TagTrafficIndicationMap = 5
	TagBSSLoad              = 11
	TagERP                  = 42
	TagHTCapabilities       = 45  // 802.11n / WiFi 4
	TagRSN                  = 48  // WPA2 / WPA3 security info
	TagExtendedRates        = 50
	TagMobilityDomain       = 54  // 802.11r Fast BSS Transition
	TagFastBssTransition    = 55  // 802.11r FTE
	TagHTOperation          = 61
	TagRadioMeasurement     = 70  // 802.11k Neighbor Reports
	TagExtendedCapabilities = 127 // 802.11v BSS Transition Management
	TagVHTCapabilities      = 191 // 802.11ac / WiFi 5
	TagVHTOperation         = 192
	TagVendorSpecific       = 221 // 0xDD
	TagExtension            = 255 // Contains a sub-tag (ExtTag*)
)

// Extension Element IDs — sub-tags used when the outer tag is TagExtension (255).
const (
	ExtTagHECapabilities  = 35  // 802.11ax / WiFi 6
	ExtTagHEOperation     = 36
	ExtTagEHTOperation    = 107 // 802.11be / WiFi 7
	ExtTagEHTCapabilities = 108
)

// Vendor OUI prefixes for Vendor-Specific IEs (TagVendorSpecific).
// All values are byte slices so callers can use bytes.HasPrefix / bytes.Equal.
var (
	// OUIWiFiAlliance is the Wi-Fi Alliance OUI, used as the group cipher suite
	// prefix in RSN IEs (00-0F-AC).
	OUIWiFiAlliance = []byte{0x00, 0x0F, 0xAC}

	// OUIWiFiAllianceWPS is the full 4-byte vendor OUI+type header identifying
	// a WPS Information Element inside a Vendor-Specific IE.
	OUIWiFiAllianceWPS = []byte{0x00, 0x50, 0xF2, 0x04}

	// OUIMicrosoft is the 3-byte Microsoft OUI (00-50-F2).
	OUIMicrosoft = []byte{0x00, 0x50, 0xF2}

	// OUIApple is the 3-byte Apple Inc. OUI (00-17-F2).
	OUIApple = []byte{0x00, 0x17, 0xF2}
)
