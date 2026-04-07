package ie

import (
	"bytes"

	snifferIE "github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// Handler defines the interface for parsing a specific 802.11 Information Element.
type Handler interface {
	// Tag returns the IE tag ID this handler is responsible for.
	Tag() int
	// Handle parses the IE value and updates the device model.
	Handle(val []byte, device *domain.Device) error
}

// HandlerRegistry manages the collection of IE handlers.
type HandlerRegistry struct {
	handlers map[int]Handler
}

// NewHandlerRegistry creates a new registry pre-populated with the default handlers.
func NewHandlerRegistry() *HandlerRegistry {
	r := &HandlerRegistry{
		handlers: make(map[int]Handler),
	}
	r.registerDefaults()
	return r
}

func (r *HandlerRegistry) registerDefaults() {
	r.Register(&SSIDHandler{})
	r.Register(&ChannelHandler{})
	r.Register(&RSNHandler{})
	r.Register(&MobilityHandler{})
	r.Register(&RadioMeasurementHandler{})
	r.Register(&HTCapabilitiesHandler{})
	r.Register(&HTOperationHandler{})
	r.Register(&VHTCapabilitiesHandler{})
	r.Register(&VHTOperationHandler{})
	r.Register(&ExtensionHandler{})
	r.Register(&ExtendedCapabilitiesHandler{})
	r.Register(&VendorSpecificHandler{})
	r.Register(&SupportedRatesHandler{})
	r.Register(&ExtendedRatesHandler{})
	r.Register(&TIMHandler{})
	r.Register(&BSSLoadHandler{})
	r.Register(&ERPHandler{})
	r.Register(&FTEHandler{})
}

// Register adds a handler to the registry.
func (r *HandlerRegistry) Register(h Handler) {
	r.handlers[h.Tag()] = h
}

// Get returns the handler for a specific tag ID, and whether it was found.
func (r *HandlerRegistry) Get(tag int) (Handler, bool) {
	h, ok := r.handlers[tag]
	return h, ok
}

// --- Specific Handlers ---

type SSIDHandler struct{}

func (h *SSIDHandler) Tag() int { return snifferIE.TagSSID }
func (h *SSIDHandler) Handle(val []byte, device *domain.Device) error {
	isHidden := len(val) == 0 || val[0] == 0x00
	if isHidden {
		device.SSID = "<HIDDEN>"
	} else {
		device.SSID = string(val)
	}
	return nil
}

type ChannelHandler struct{}

func (h *ChannelHandler) Tag() int { return snifferIE.TagDSParameterSet }
func (h *ChannelHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) > 0 {
		device.Channel = int(val[0])
	}
	return nil
}

type RSNHandler struct{}

func (h *RSNHandler) Tag() int { return snifferIE.TagRSN }
func (h *RSNHandler) Handle(val []byte, device *domain.Device) error {
	rsn, err := snifferIE.ParseRSN(val)
	if err != nil {
		device.Security = "WPA2" // Fallback: RSN IE present but unparseable
		return nil
	}

	device.Security = "WPA2" // Default

	// Determine Security based on AKM Suites
	for _, akm := range rsn.AKMSuites {
		if akm == "SAE" || akm == "FT-SAE" || akm == "AKM-SUITE-B-SHA256" || akm == "AKM-SUITE-B-SHA384" {
			device.Security = "WPA3"
			break // WPA3 takes precedence
		} else if akm == "OWE" {
			device.Security = "OWE"
			break
		} else if akm == "802.1X" || akm == "FT-802.1X" || akm == "802.1X-SHA256" {
			device.Security = "WPA2-Enterprise"
		} else if akm == "PSK" || akm == "FT-PSK" || akm == "PSK-SHA256" || akm == "PSK-SHA384" || akm == "FT-PSK-SHA384" {
			// Don't overwrite if we already found Enterprise
			if device.Security == "WPA2" {
				device.Security = "WPA2-PSK"
			}
		}
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
			JointMultiBand:   rsn.Capabilities.JointMultiBand,
			OCVC:             rsn.Capabilities.OCVC,
		},
		PMKIDs:          rsn.PMKIDs,
		GroupMgmtCipher: rsn.GroupMgmtCipher,
	}
	return nil
}

type MobilityHandler struct{}

func (h *MobilityHandler) Tag() int { return snifferIE.TagMobilityDomain }
func (h *MobilityHandler) Handle(val []byte, device *domain.Device) error {
	device.Has11r = true
	addCapabilityIfAbsent(device, "11r")

	if mdie, err := snifferIE.ParseMDIE(val); err == nil {
		device.MobilityDomain = &domain.MobilityDomain{
			MDID:        mdie.MDID,
			OverDS:      mdie.OverDS,
			ResourceReq: mdie.ResourceReq,
		}
	}
	return nil
}

type RadioMeasurementHandler struct{}

func (h *RadioMeasurementHandler) Tag() int { return snifferIE.TagRadioMeasurement }
func (h *RadioMeasurementHandler) Handle(val []byte, device *domain.Device) error {
	device.Has11k = true
	addCapabilityIfAbsent(device, "11k")
	return nil
}

type HTCapabilitiesHandler struct{}

func (h *HTCapabilitiesHandler) Tag() int { return snifferIE.TagHTCapabilities }
func (h *HTCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	device.Standard = "802.11n (WiFi 4)"
	if len(val) >= 16 {
		// Supported MCS Set starts at byte 12 (length 16)
		nss := 0
		if val[12] != 0 {
			nss = 1
		}
		if val[13] != 0 {
			nss = 2
		}
		if val[14] != 0 {
			nss = 3
		}
		if val[15] != 0 {
			nss = 4
		}

		if nss > 0 {
			switch nss {
			case 1:
				addCapabilityIfAbsent(device, "MIMO 1x1")
			case 2:
				addCapabilityIfAbsent(device, "MIMO 2x2")
			case 3:
				addCapabilityIfAbsent(device, "MIMO 3x3")
			case 4:
				addCapabilityIfAbsent(device, "MIMO 4x4")
			}
		}
	}
	return nil
}

type HTOperationHandler struct{}

func (h *HTOperationHandler) Tag() int { return snifferIE.TagHTOperation }
func (h *HTOperationHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) >= 2 {
		// HT Information Subset 1 (Byte 1)
		// Bits 0-1: Secondary Channel Offset (0: none, 1: above, 3: below)
		offset := val[1] & 0x03
		if offset != 0 {
			device.ChannelWidth = 40
		} else if device.ChannelWidth == 0 {
			device.ChannelWidth = 20
		}
	}
	return nil
}

type VHTCapabilitiesHandler struct{}

func (h *VHTCapabilitiesHandler) Tag() int { return snifferIE.TagVHTCapabilities }
func (h *VHTCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	device.Standard = "802.11ac (WiFi 5)"
	if len(val) >= 8 {
		// Supported VHT-MCS and NSS Set starts at byte 4 (length 4)
		// Each Max VHT-MCS is 2 bits. NSS 1 (bits 0-1), NSS 2 (bits 2-3)...
		// We just want to find the highest NSS that is supported (value != 3)
		maxNSS := 0
		mcsSet := val[4:8]
		for n := 1; n <= 8; n++ {
			byteIdx := (n - 1) * 2 / 8
			bitShift := ((n - 1) * 2) % 8
			mcs := (mcsSet[byteIdx] >> bitShift) & 0x03
			if mcs != 3 {
				maxNSS = n
			}
		}

		if maxNSS > 0 {
			switch maxNSS {
			case 1:
				addCapabilityIfAbsent(device, "MIMO 1x1")
			case 2:
				addCapabilityIfAbsent(device, "MIMO 2x2")
			case 3:
				addCapabilityIfAbsent(device, "MIMO 3x3")
			case 4:
				addCapabilityIfAbsent(device, "MIMO 4x4")
			case 8:
				addCapabilityIfAbsent(device, "MIMO 8x8")
			}
		}
	}
	return nil
}

type VHTOperationHandler struct{}

func (h *VHTOperationHandler) Tag() int { return snifferIE.TagVHTOperation }
func (h *VHTOperationHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) >= 1 {
		// VHT Operation Information (Byte 0)
		// 0: 20/40, 1: 80, 2: 160, 3: 80+80
		switch val[0] {
		case 1:
			device.ChannelWidth = 80
		case 2:
			device.ChannelWidth = 160
		case 3:
			device.ChannelWidth = 160 // 80+80 is technically 160
		}
	}
	return nil
}

type ExtensionHandler struct{}

func (h *ExtensionHandler) Tag() int { return snifferIE.TagExtension }
func (h *ExtensionHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) < 1 {
		return nil
	}
	switch int(val[0]) {
	case snifferIE.ExtTagHECapabilities, snifferIE.ExtTagHEOperation:
		device.Standard = "802.11ax (WiFi 6)"
		device.IsWiFi6 = true
	case snifferIE.ExtTagEHTCapabilities, snifferIE.ExtTagEHTOperation:
		device.Standard = "802.11be (WiFi 7)"
		device.IsWiFi7 = true
		device.IsWiFi6 = true
	}
	return nil
}

type ExtendedCapabilitiesHandler struct{}

func (h *ExtendedCapabilitiesHandler) Tag() int { return snifferIE.TagExtendedCapabilities }
func (h *ExtendedCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	// Bit 19: BSS Transition Management (802.11v)
	// Octet 3 (index 2), bit 3 within that octet (19 - 16 = 3 → mask 0x08)
	if len(val) >= 3 && (val[2]&0x08) != 0 {
		device.Has11v = true
		addCapabilityIfAbsent(device, "11v")
	}
	return nil
}

type VendorSpecificHandler struct{}

func (h *VendorSpecificHandler) Tag() int { return snifferIE.TagVendorSpecific }
func (h *VendorSpecificHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) < 3 {
		return nil
	}

	// OS detection from vendor OUI — integrated here to avoid a separate IE pass.
	switch {
	case bytes.HasPrefix(val, snifferIE.OUIApple):
		device.OS = "iOS/macOS"
		if device.IsRandomized {
			device.Vendor = "Apple (Randomized)"
		}
	case bytes.HasPrefix(val, snifferIE.OUIMicrosoft):
		if device.OS == "" {
			device.OS = "Windows"
		}
	}

	// WPS parsing — requires the full 4-byte OUI+type header match.
	if len(val) >= 4 && bytes.Equal(val[:4], snifferIE.OUIWiFiAllianceWPS) {
		wpsInfo := snifferIE.ParseWPSAttributes(val[4:])

		device.WPSDetails = &domain.WPSDetails{
			Manufacturer:     wpsInfo.Manufacturer,
			Model:            wpsInfo.Model,
			DeviceName:       wpsInfo.DeviceName,
			State:            wpsInfo.State,
			Version:          wpsInfo.Version,
			Locked:           wpsInfo.Locked,
			ConfigMethods:    wpsInfo.ConfigMethods,
			DevicePasswordID: wpsInfo.DevicePasswordID,
		}

		if wpsInfo.State != "" {
			device.WPSInfo = wpsInfo.State
			if wpsInfo.Version != "" {
				device.WPSInfo += " (WPS " + wpsInfo.Version + ")"
			}
		}

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
	return nil
}

// addCapabilityIfAbsent appends a capability string only if not already present.
func addCapabilityIfAbsent(device *domain.Device, capability string) {
	if !containsString(device.Capabilities, capability) {
		device.Capabilities = append(device.Capabilities, capability)
	}
}

// containsString checks slice membership.
func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// --- newly added handlers ---

type SupportedRatesHandler struct{}

func (h *SupportedRatesHandler) Tag() int { return snifferIE.TagSupportedRates }
func (h *SupportedRatesHandler) Handle(val []byte, device *domain.Device) error {
	if device.Standard == "" {
		device.Standard = "802.11b/a"
	}
	return nil
}

type ExtendedRatesHandler struct{}

func (h *ExtendedRatesHandler) Tag() int { return snifferIE.TagExtendedRates }
func (h *ExtendedRatesHandler) Handle(val []byte, device *domain.Device) error {
	if device.Standard == "802.11b/a" || device.Standard == "" {
		device.Standard = "802.11g"
	}
	return nil
}

type TIMHandler struct{}

func (h *TIMHandler) Tag() int { return snifferIE.TagTrafficIndicationMap }
func (h *TIMHandler) Handle(val []byte, device *domain.Device) error {
	// Acknowledge presence
	return nil
}

type BSSLoadHandler struct{}

func (h *BSSLoadHandler) Tag() int { return snifferIE.TagBSSLoad }
func (h *BSSLoadHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) >= 5 {
		stationCount := uint16(val[0]) | (uint16(val[1]) << 8)
		channelUtilization := val[2]
		admissionCapacity := uint16(val[3]) | (uint16(val[4]) << 8)

		device.BSSLoad = &domain.BSSLoad{
			StationCount:       stationCount,
			ChannelUtilization: channelUtilization,
			AvailableAdmission: admissionCapacity,
		}
	}
	return nil
}

type ERPHandler struct{}

func (h *ERPHandler) Tag() int { return snifferIE.TagERP }
func (h *ERPHandler) Handle(val []byte, device *domain.Device) error {
	if device.Standard == "" || device.Standard == "802.11b/a" {
		device.Standard = "802.11g (ERP)"
	}
	return nil
}

type FTEHandler struct{}

func (h *FTEHandler) Tag() int { return snifferIE.TagFastBssTransition }
func (h *FTEHandler) Handle(val []byte, device *domain.Device) error {
	device.Has11r = true
	addCapabilityIfAbsent(device, "11r")
	return nil
}

