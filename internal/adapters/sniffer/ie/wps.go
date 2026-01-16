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
		val := string(valBytes)

		switch attrType {
		case 0x1021: // Manufacturer
			info.Manufacturer = val
		case 0x1023: // Model Name
			info.Model = val
		case 0x1011: // Device Name
			info.DeviceName = val
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
