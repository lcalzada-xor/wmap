package mapper

// 802.11 Information Element IDs
const (
	IETagSSID                 = 0
	IETagSupportedRates       = 1
	IETagDSParameterSet       = 3 // Channel
	IETagTrafficIndicationMap = 5
	IETagERP                  = 42
	IETagHTCapabilities       = 45 // 802.11n
	IETagRSN                  = 48 // WPA2/WPA3
	IETagExtendedRates        = 50
	IETagMobilityDomain       = 54 // 802.11r
	IETagHTOperation          = 61
	IETagRadioMeasurement     = 70  // 802.11k
	IETagExtendedCapabilities = 127 // 802.11v
	IETagVHTCapabilities      = 191 // 802.11ac
	IETagVHTOperation         = 192
	IETagVendorSpecific       = 221
	IETagExtension            = 255
)

// Extension Element IDs (Tag 255)
const (
	ExtTagHECapabilities  = 35  // 802.11ax
	ExtTagHEOperation     = 36  // 802.11ax
	ExtTagEHTCapabilities = 108 // 802.11be
	ExtTagEHTOperation    = 107 // 802.11be
)

// Vendor OUI Prefixes
var (
	VendorMicrosoftWPS = []byte{0x00, 0x50, 0xF2, 0x04}
	VendorApple        = []byte{0x00, 0x17, 0xF2}
	VendorMicrosoft    = []byte{0x00, 0x50, 0xF2}
)
