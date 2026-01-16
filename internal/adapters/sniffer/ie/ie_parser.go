package ie

// IE represents a generic Information Element
type IE struct {
	ID   int
	Data []byte
}

// IterateIEs calls the provided callback for each valid IE found in the data.
// It stops if it encounters a malformed IE (length exceeds remaining data).
func IterateIEs(data []byte, callback func(id int, data []byte)) {
	offset := 0
	limit := len(data)

	for offset < limit {
		// Needs at least 2 bytes (ID and Length)
		if offset+2 > limit {
			break
		}

		id := int(data[offset])
		length := int(data[offset+1])
		offset += 2

		// Check bounds
		if offset+length > limit {
			break
		}

		callback(id, data[offset:offset+length])
		offset += length
	}
}

// FindIE returns the data of the first IE with the given ID.
// Returns nil if not found.
func FindIE(data []byte, targetID int) []byte {
	var result []byte
	IterateIEs(data, func(id int, val []byte) {
		if result == nil && id == targetID {
			result = val
		}
	})
	return result
}

// ParseSSID extracts the SSID from the IE data.
func ParseSSID(data []byte) string {
	val := FindIE(data, 0)
	if val == nil {
		return ""
	}
	if len(val) == 0 || val[0] == 0x00 {
		return "<HIDDEN>"
	}
	return string(val)
}

// ParseChannel extracts the channel from the DS Parameter Set (Tag 3).
func ParseChannel(data []byte) int {
	val := FindIE(data, 3)
	if len(val) >= 1 {
		return int(val[0])
	}
	return 0
}

// ParseVendorSpecific returns a list of all Vendor Specific IEs (Tag 221).
func ParseVendorSpecific(data []byte) [][]byte {
	var results [][]byte
	IterateIEs(data, func(id int, val []byte) {
		if id == 221 {
			results = append(results, val)
		}
	})
	return results
}

// ParsePMKID checks for PMKID in Key Data (RSN IE or similar context).
// Note: This expects the 'Key Data' field from EAPOL, which contains IEs.
func ParsePMKID(keyData []byte) bool {
	// PMKID is inside a Vendor Specific IE (0xDD) with OUI 00-0F-AC and Type 4
	found := false
	IterateIEs(keyData, func(id int, val []byte) {
		if id == 0xDD && len(val) >= 4 {
			// Check OUI 00-0F-AC (04)
			if val[0] == 0x00 && val[1] == 0x0F && val[2] == 0xAC && val[3] == 0x04 {
				found = true
			}
		}
	})
	return found
}
