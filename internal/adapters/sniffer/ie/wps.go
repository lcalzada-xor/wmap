package ie

// WPSInfo contains details extracted from WPS IEs
type WPSInfo struct {
	Manufacturer  string
	Model         string
	DeviceName    string
	State         string // "Unconfigured" | "Configured"
	Version       string // "1.0" | "2.0"
	Locked        bool
	ConfigMethods []string
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
					info.ConfigMethods = append(info.ConfigMethods, "PIN")
				case 0x0004:
					info.ConfigMethods = append(info.ConfigMethods, "PBC")
				}
			}
		}

		offset += attrLen
	}

	return info
}

// safeString converts bytes to string, validating UTF-8 first
func safeString(data []byte) string {
	// Check for valid UTF-8
	for i := 0; i < len(data); {
		r, size := decodeRune(data[i:])
		if r == '\ufffd' && size == 1 {
			// Invalid UTF-8, return empty or sanitized version
			return ""
		}
		i += size
	}
	return string(data)
}

// decodeRune is a simplified UTF-8 decoder
func decodeRune(data []byte) (rune, int) {
	if len(data) == 0 {
		return '\ufffd', 0
	}

	// ASCII fast path
	if data[0] < 0x80 {
		return rune(data[0]), 1
	}

	// For simplicity, accept all multi-byte sequences
	// A full implementation would validate continuation bytes
	if data[0] < 0xC0 {
		return '\ufffd', 1
	}
	if data[0] < 0xE0 && len(data) >= 2 {
		return rune(data[0]), 2
	}
	if data[0] < 0xF0 && len(data) >= 3 {
		return rune(data[0]), 3
	}
	if len(data) >= 4 {
		return rune(data[0]), 4
	}

	return '\ufffd', 1
}
