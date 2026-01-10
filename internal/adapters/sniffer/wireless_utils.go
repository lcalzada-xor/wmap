package sniffer

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// HardwareCapabilities defines what a WiFi card supports.
type HardwareCapabilities struct {
	Supported frequencies
}

type frequencies struct {
	Bands map[string][]int
}

// GetInterfaceCapabilities returns the supported channels for a given interface.
func GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	// 1. Map Interface -> Phy
	phy, err := getPhyForInterface(iface)
	if err != nil {
		return nil, nil, err
	}

	// 2. Get Phy Capabilities
	return getPhyCapabilities(phy)
}

func getPhyForInterface(iface string) (string, error) {
	cmd := exec.Command("iw", "dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Output format:
	// phy#0
	// 		Interface wlan0
	//      ...
	// phy#1
	//      Interface wlan1

	scanner := bufio.NewScanner(bytes.NewReader(out))
	currentPhy := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phy#") {
			currentPhy = line // e.g., "phy#0"
		} else if strings.HasPrefix(line, "Interface "+iface) {
			// Found our interface under currentPhy
			// Return format "phy0" (remove #) usually works for `iw phy phy0 info`?
			// `iw list` uses "Wiphy phy0". `iw phy` uses "phy0".
			// "phy#0" -> "phy0"
			return strings.Replace(currentPhy, "#", "", 1), nil
		}
	}
	return "", fmt.Errorf("interface %s not found in iw dev output", iface)
}

func getPhyCapabilities(phy string) (map[string]bool, []int, error) {
	// "iw phy phy0 info" gives the same output as "iw list" but just for that phy
	cmd := exec.Command("iw", "phy", phy, "info")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}

	bands := make(map[string]bool)
	supportedChannels := []int{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inFrequencies := false
	// Regex to capture channel number in [...]
	// Example: * 2412 MHz [1] (20.0 dBm)
	// Example: * 5180 MHz [36] (22.0 dBm) (disabled)
	reChannel := regexp.MustCompile(`\[([0-9]+)\]`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "Frequencies:" {
			inFrequencies = true
			continue
		}

		// If we hit a new section that is not indented or starts with something else, stop frequencies
		// `iw` output indentation is significant.
		// Frequencies are indented.
		if inFrequencies {
			if strings.HasPrefix(line, "*") {
				// Process frequency line
				// If "(disabled)", skip
				if strings.Contains(line, "(disabled)") || strings.Contains(line, "(no IR)") {
					// no IR (No Initiate Radiation) often means we can listen but not beacon?
					// For sniffing, passive listening might be okay even with no IR?
					// But "disabled" definitely means unusable.
					// Let's exclude disabled.
					if strings.Contains(line, "(disabled)") {
						continue
					}
				}

				matches := reChannel.FindStringSubmatch(line)
				if len(matches) > 1 {
					ch, _ := strconv.Atoi(matches[1])
					supportedChannels = append(supportedChannels, ch)

					// Detect band based on channel number as heuristic if band header parsing failed/complex
					if ch >= 1 && ch <= 14 {
						bands["2.4ghz"] = true
					} else if ch >= 36 {
						bands["5ghz"] = true
					}
				}
			} else {
				// End of frequencies section usually indented or empty
				// We can rely on next "Band" or other headers to reset `inFrequencies`?
				// Actually, `iw` output implies Frequencies block ends when indentation changes or new section starts.
				// But simply running regex on lines starting with * usually works fine globally if we track "disabled"
				// Just need to be careful not to match other lists.
				// "Frequencies:" starts the block.
				// The lines start with "*".
				// If a line doesn't start with "*", it might be end of block?
				// Warning: "Bitrates:" also has lines with "*".
				if !strings.HasPrefix(line, "*") {
					inFrequencies = false
				}
			}
		}
	}

	return bands, supportedChannels, nil
}

// SetInterfaceChannel sets the WiFi channel for a given interface.
func SetInterfaceChannel(iface string, channel int) error {
	if channel <= 0 {
		return fmt.Errorf("invalid channel: %d", channel)
	}
	cmd := exec.Command("iw", iface, "set", "channel", fmt.Sprintf("%d", channel))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set channel %d on %s: %v (%s)", channel, iface, err, string(output))
	}
	return nil
}

// KillConflictingProcesses stops NetworkManager and wpa_supplicant to prevent interference.
// This is critical for reliable monitor mode operation.
func KillConflictingProcesses() error {
	commands := [][]string{
		{"systemctl", "stop", "NetworkManager"},
		{"systemctl", "stop", "wpa_supplicant"},
		// Stronger kill if systemctl isn't enough or for non-systemd systems (optional, keeping safe for now)
		// {"killall", "wpa_supplicant"},
	}

	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		// We use exec.Command directly here. runCmd helper is in main package, not here.
		// We can add a local helper or just run it.
		cmd := exec.Command(cmdName, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Don't error out immediately, just log and try next?
			// But for now, returning error is safer so main knows something went wrong.
			// However, stopping a stopped service might fail or return different codes?
			// systemctl usually exits 0 if already stopped.
			return fmt.Errorf("failed to execute %s %v: %v (%s)", cmdName, cmdArgs, err, string(out))
		}
	}
	return nil
}

// RestoreNetworkServices restarts NetworkManager and wpa_supplicant.
func RestoreNetworkServices() error {
	commands := [][]string{
		{"systemctl", "start", "wpa_supplicant"}, // Start supplicant first usually
		{"systemctl", "start", "NetworkManager"},
	}

	var lastErr error
	for _, cmdParts := range commands {
		cmdName := cmdParts[0]
		cmdArgs := cmdParts[1:]
		cmd := exec.Command(cmdName, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// We try to restore everything even if one fails
			lastErr = fmt.Errorf("failed to execute %s %v: %v (%s)", cmdName, cmdArgs, err, string(out))
		}
	}
	return lastErr
}

// ParseIEs extracts information from 802.11 Information Elements.
func ParseIEs(data []byte, device *domain.Device) {
	offset := 0
	limit := len(data)

	// Defaults
	device.Security = "OPEN"
	device.Standard = "802.11g/a" // baseline

	for offset < limit {
		if offset+1 >= limit {
			break
		}
		id := int(data[offset])
		length := int(data[offset+1])
		offset += 2

		if offset+length > limit {
			break
		}
		val := data[offset : offset+length]

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
			if rsn, err := ParseRSN(val); err == nil {
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
			// Microsoft WPS check
			if len(val) >= 4 && val[0] == 0x00 && val[1] == 0x50 && val[2] == 0xF2 && val[3] == 0x04 {
				if model := ParseWPSAttributes(val[4:], device); model != "" {
					device.Model = model
				}
			}
		}

		offset += length
	}

	// Compute Signature if we have tags
	if len(device.IETags) > 0 {
		device.Signature = computeSignature(device.IETags, nil)
	}
}

// ParseWPSAttributes extracts Model/Manufacturer/State from WPS IEs
// Returns "Manufacturer Model" string
func ParseWPSAttributes(data []byte, device *domain.Device) string {
	details := &domain.WPSDetails{}
	model := ""
	manufacturer := ""
	deviceName := ""

	offset := 0
	limit := len(data)

	for offset < limit {
		if offset+4 > limit {
			break
		}
		attrType := (int(data[offset]) << 8) | int(data[offset+1])
		attrLen := (int(data[offset+2]) << 8) | int(data[offset+3])
		offset += 4

		if offset+attrLen > limit {
			break
		}

		valBytes := data[offset : offset+attrLen]
		val := string(valBytes)

		switch attrType {
		case 0x1021: // Manufacturer
			manufacturer = val
			details.Manufacturer = val
		case 0x1023: // Model Name
			model = val
			details.Model = val
		case 0x1011: // Device Name
			deviceName = val
			details.DeviceName = val
		case 0x1044: // WPS State
			if len(valBytes) > 0 {
				switch valBytes[0] {
				case 0x01:
					details.State = "Unconfigured"
				case 0x02:
					details.State = "Configured"
				}
			}
		case 0x104A: // WPS Version
			if len(valBytes) > 0 {
				ver := valBytes[0]
				if ver == 0x10 {
					details.Version = "1.0"
				} else if ver >= 0x20 {
					details.Version = "2.0"
				}
			}
		case 0x1057: // AP Setup Locked
			if len(valBytes) > 0 && valBytes[0] == 0x01 {
				details.Locked = true
			}
		case 0x1012: // Device Password ID
			if len(valBytes) >= 2 {
				pwdID := (int(valBytes[0]) << 8) | int(valBytes[1])
				switch pwdID {
				case 0x0000:
					details.ConfigMethods = append(details.ConfigMethods, "PIN")
				case 0x0004:
					details.ConfigMethods = append(details.ConfigMethods, "PBC")
				}
			}
		}

		offset += attrLen
	}

	device.WPSDetails = details
	if details.State != "" {
		device.WPSInfo = details.State
		if details.Version != "" {
			device.WPSInfo += " (WPS " + details.Version + ")"
		}
	}

	// Fallback to DeviceName if Model is empty
	if model == "" && deviceName != "" {
		model = deviceName
	}

	if model != "" {
		if manufacturer != "" {
			return manufacturer + " " + model
		}
		return model
	}
	return ""
}

// Internal RSN Parsing Structs
type internalRSNInfo struct {
	Version         uint16
	GroupCipher     string
	PairwiseCiphers []string
	AKMSuites       []string
	Capabilities    internalRSNCapabilities
}

type internalRSNCapabilities struct {
	PreAuth          bool
	NoPairwise       bool
	PTKSAReplayCount uint8
	GTKSAReplayCount uint8
	MFPRequired      bool
	MFPCapable       bool
	PeerKeyEnabled   bool
}

// ParseRSN parses IE 48 (RSN Information Element)
func ParseRSN(data []byte) (*internalRSNInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("RSN IE too short")
	}

	rsn := &internalRSNInfo{}
	offset := 0

	// Version (2 bytes)
	rsn.Version = uint16(data[offset]) | uint16(data[offset+1])<<8
	offset += 2

	// Group Cipher Suite (4 bytes: OUI + Type)
	if offset+4 <= len(data) {
		rsn.GroupCipher = parseCipherSuite(data[offset : offset+4])
		offset += 4
	}

	// Pairwise Cipher Suite Count + List
	if offset+2 <= len(data) {
		count := int(data[offset]) | int(data[offset+1])<<8
		offset += 2
		for i := 0; i < count && offset+4 <= len(data); i++ {
			rsn.PairwiseCiphers = append(rsn.PairwiseCiphers, parseCipherSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// AKM Suite Count + List
	if offset+2 <= len(data) {
		count := int(data[offset]) | int(data[offset+1])<<8
		offset += 2
		for i := 0; i < count && offset+4 <= len(data); i++ {
			rsn.AKMSuites = append(rsn.AKMSuites, parseAKMSuite(data[offset:offset+4]))
			offset += 4
		}
	}

	// RSN Capabilities (2 bytes)
	if offset+2 <= len(data) {
		caps := uint16(data[offset]) | uint16(data[offset+1])<<8
		rsn.Capabilities = parseRSNCapabilities(caps)
	}

	return rsn, nil
}

func parseCipherSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}
	// OUI: 00-0F-AC (standard)
	cipherType := data[3]
	switch cipherType {
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP" // AES
	case 5:
		return "WEP-104"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", cipherType)
	}
}

func parseAKMSuite(data []byte) string {
	if len(data) < 4 {
		return "UNKNOWN"
	}
	akmType := data[3]
	switch akmType {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE" // WPA3-Personal
	case 9:
		return "FT-SAE"
	case 18:
		return "OWE" // Opportunistic Wireless Encryption
	default:
		return fmt.Sprintf("UNKNOWN(%d)", akmType)
	}
}

func parseRSNCapabilities(caps uint16) internalRSNCapabilities {
	return internalRSNCapabilities{
		PreAuth:          (caps & 0x0001) != 0,
		NoPairwise:       (caps & 0x0002) != 0,
		PTKSAReplayCount: uint8((caps >> 2) & 0x03),
		GTKSAReplayCount: uint8((caps >> 4) & 0x03),
		MFPRequired:      (caps & 0x0040) != 0,
		MFPCapable:       (caps & 0x0080) != 0,
		PeerKeyEnabled:   (caps & 0x0200) != 0,
	}
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
