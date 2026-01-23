package mapper

import (
	"bytes"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// IEHandler defines the interface for parsing specific Information Elements
type IEHandler interface {
	// ID returns the IE Tag ID this handler is responsible for
	ID() int
	// Handle parses the IE value and updates the device model
	Handle(val []byte, device *domain.Device) error
}

// HandlerRegistry manages the collection of IE handlers
type HandlerRegistry struct {
	handlers map[int]IEHandler
}

// NewHandlerRegistry creates a new registry with default handlers
func NewHandlerRegistry() *HandlerRegistry {
	r := &HandlerRegistry{
		handlers: make(map[int]IEHandler),
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
	r.Register(&VHTCapabilitiesHandler{})
	r.Register(&ExtensionHandler{})
	r.Register(&ExtendedCapabilitiesHandler{})
	r.Register(&VendorSpecificHandler{})
}

// Register adds a handler to the registry
func (r *HandlerRegistry) Register(h IEHandler) {
	r.handlers[h.ID()] = h
}

// Get returns the handler for a specific tag ID
func (r *HandlerRegistry) Get(id int) (IEHandler, bool) {
	h, ok := r.handlers[id]
	return h, ok
}

// --- Specific Handlers ---

type SSIDHandler struct{}

func (h *SSIDHandler) ID() int { return IETagSSID }
func (h *SSIDHandler) Handle(val []byte, device *domain.Device) error {
	// Check for Hidden SSID (Empty or Null bytes)
	isHidden := len(val) == 0 || (len(val) > 0 && val[0] == 0x00)

	if isHidden {
		device.SSID = "<HIDDEN>"
	} else {
		device.SSID = string(val)
	}
	return nil
}

type ChannelHandler struct{}

func (h *ChannelHandler) ID() int { return IETagDSParameterSet }
func (h *ChannelHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) > 0 {
		device.Channel = int(val[0])
	}
	return nil
}

type RSNHandler struct{}

func (h *RSNHandler) ID() int { return IETagRSN }
func (h *RSNHandler) Handle(val []byte, device *domain.Device) error {
	rsn, err := ie.ParseRSN(val)
	if err != nil {
		device.Security = "WPA2" // Default fallbock if RSN present but unparseable
		return nil
	}

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
	return nil
}

type MobilityHandler struct{}

func (h *MobilityHandler) ID() int { return IETagMobilityDomain }
func (h *MobilityHandler) Handle(val []byte, device *domain.Device) error {
	device.Has11r = true
	addCapabilityIfNotExists(device, "11r")

	if mdie, err := ie.ParseMDIE(val); err == nil {
		device.MobilityDomain = &domain.MobilityDomain{
			MDID:        mdie.MDID,
			OverDS:      mdie.OverDS,
			ResourceReq: mdie.ResourceReq,
		}
	}
	return nil
}

type RadioMeasurementHandler struct{}

func (h *RadioMeasurementHandler) ID() int { return IETagRadioMeasurement }
func (h *RadioMeasurementHandler) Handle(val []byte, device *domain.Device) error {
	device.Has11k = true
	addCapabilityIfNotExists(device, "11k")
	return nil
}

type HTCapabilitiesHandler struct{}

func (h *HTCapabilitiesHandler) ID() int { return IETagHTCapabilities }
func (h *HTCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	device.Standard = "802.11n (WiFi 4)"
	return nil
}

type VHTCapabilitiesHandler struct{}

func (h *VHTCapabilitiesHandler) ID() int { return IETagVHTCapabilities }
func (h *VHTCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	device.Standard = "802.11ac (WiFi 5)"
	return nil
}

type ExtensionHandler struct{}

func (h *ExtensionHandler) ID() int { return IETagExtension }
func (h *ExtensionHandler) Handle(val []byte, device *domain.Device) error {
	if len(val) < 1 {
		return nil
	}
	extID := int(val[0])
	switch extID {
	case ExtTagHECapabilities: // 802.11ax
		device.Standard = "802.11ax (WiFi 6)"
		device.IsWiFi6 = true
	case ExtTagEHTCapabilities: // 802.11be
		device.Standard = "802.11be (WiFi 7)"
		device.IsWiFi7 = true
		device.IsWiFi6 = true
	}
	return nil
}

type ExtendedCapabilitiesHandler struct{}

func (h *ExtendedCapabilitiesHandler) ID() int { return IETagExtendedCapabilities }
func (h *ExtendedCapabilitiesHandler) Handle(val []byte, device *domain.Device) error {
	// Check bit 19 for BSS Transition Management
	// Byte 2 (index 2), bit 3 (0x08) -> 8 + 8*2 = 24? Wait.
	// Octet 1: bits 0-7. Octet 2: bits 8-15. Octet 3: bits 16-23.
	// Bit 19 is in Octet 3 (index 2). 19 - 16 = 3. 2^3 = 8 -> 0x08. Correct.
	if len(val) >= 3 {
		if (val[2] & 0x08) != 0 {
			device.Has11v = true
			addCapabilityIfNotExists(device, "11v")
		}
	}
	return nil
}

type VendorSpecificHandler struct{}

func (h *VendorSpecificHandler) ID() int { return IETagVendorSpecific }
func (h *VendorSpecificHandler) Handle(val []byte, device *domain.Device) error {
	// Microsoft WPS check
	if len(val) >= 4 && bytes.Equal(val[:4], VendorMicrosoftWPS) {
		wpsInfo := ie.ParseWPSAttributes(val[4:])

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
	return nil
}

// addCapabilityIfNotExists adds a capability to the device only if it doesn't already exist
func addCapabilityIfNotExists(device *domain.Device, capability string) {
	if !containsString(device.Capabilities, capability) {
		device.Capabilities = append(device.Capabilities, capability)
	}
}
