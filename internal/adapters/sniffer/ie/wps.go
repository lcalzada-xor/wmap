package ie

import "strings"

// WPSInfo contains details extracted from WPS IEs
type WPSInfo struct {
	Manufacturer     string
	Model            string
	DeviceName       string
	State            string // "Unconfigured" | "Configured"
	Version          string // "1.0" | "2.0"
	Locked           bool
	ConfigMethods    []string
	DevicePasswordID string // "PIN", "PBC", etc.
}

// ParseWPSAttributes parses the attributes within a WPS Data Element (after OUI/Type headers).
// Returns a filled WPSInfo struct.
func ParseWPSAttributes(data []byte) *WPSInfo {
	info := &WPSInfo{}
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

		switch attrType {
		case 0x1021: // Manufacturer
			info.Manufacturer = safeString(valBytes)
		case 0x1023: // Model Name
			info.Model = safeString(valBytes)
		case 0x1011: // Device Name
			info.DeviceName = safeString(valBytes)
		case 0x1044: // WPS State
			if len(valBytes) > 0 {
				switch valBytes[0] {
				case 0x01:
					info.State = "Unconfigured"
				case 0x02:
					info.State = "Configured"
				}
			}
		case 0x104A: // WPS Version
			if len(valBytes) > 0 {
				ver := valBytes[0]
				if ver == 0x10 {
					info.Version = "1.0"
				} else if ver >= 0x20 {
					info.Version = "2.0"
				}
			}
		case 0x1057: // AP Setup Locked
			if len(valBytes) > 0 && valBytes[0] == 0x01 {
				info.Locked = true
			}
		case 0x1012: // Device Password ID
			if len(valBytes) >= 2 {
				pwdID := (int(valBytes[0]) << 8) | int(valBytes[1])
				switch pwdID {
				case 0x0000:
					info.DevicePasswordID = "PIN"
				case 0x0004:
					info.DevicePasswordID = "PBC"
				}
			}
		case 0x1008: // Config Methods
			if len(valBytes) >= 2 {
				methods := (int(valBytes[0]) << 8) | int(valBytes[1])
				if methods&0x0001 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "USBA")
				}
				if methods&0x0002 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "Ethernet")
				}
				if methods&0x0004 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "Label")
				}
				if methods&0x0008 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "Display")
				}
				if methods&0x0010 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "ExtNFC")
				}
				if methods&0x0020 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "IntNFC")
				}
				if methods&0x0040 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "NFC-IF")
				}
				if methods&0x0080 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "PBC")
				}
				if methods&0x0100 != 0 {
					info.ConfigMethods = append(info.ConfigMethods, "Keypad")
				}
			}
		}

		offset += attrLen
	}

	return info
}

// safeString converts bytes to string, keeping only valid UTF-8 characters
func safeString(data []byte) string {
	return strings.ToValidUTF8(string(data), "")
}
