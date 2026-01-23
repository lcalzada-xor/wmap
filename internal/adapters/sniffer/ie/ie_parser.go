package ie

import (
	"bytes"
	"errors"
)

// Common IE Tags
const (
	TagSSID           = 0
	TagDSParameterSet = 3
	TagRSN            = 48
	TagVendorSpecific = 221 // 0xDD
)

// IE represents a generic Information Element
type IE struct {
	ID   int
	Data []byte
}

// Errors
var (
	ErrMalformedIE = errors.New("malformed information element")
	ErrIENotFound  = errors.New("information element not found")
)

// SSID represents a Service Set Identifier
type SSID struct {
	Value  string
	Hidden bool
}

// String returns the string representation of the SSID
func (s SSID) String() string {
	if s.Hidden {
		return "<HIDDEN>"
	}
	return s.Value
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
func ParseSSID(data []byte) SSID {
	val := FindIE(data, TagSSID)
	if val == nil {
		return SSID{Hidden: true} // Absence usually means not in this packet, but for safety
	}
	if len(val) == 0 || (len(val) > 0 && val[0] == 0x00) {
		// Check if all bytes are zero for hidden SSIDs (some devices do this)
		allZero := true
		for _, b := range val {
			if b != 0x00 {
				allZero = false
				break
			}
		}
		if allZero {
			return SSID{Hidden: true}
		}
	}
	return SSID{Value: safeString(val), Hidden: false}
}

// ParseChannel extracts the channel from the DS Parameter Set (Tag 3).
func ParseChannel(data []byte) (int, error) {
	val := FindIE(data, TagDSParameterSet)
	if len(val) >= 1 {
		return int(val[0]), nil
	}
	return 0, ErrIENotFound
}

// ParseVendorSpecific returns a list of all Vendor Specific IEs (Tag 221).
func ParseVendorSpecific(data []byte) [][]byte {
	var results [][]byte
	IterateIEs(data, func(id int, val []byte) {
		if id == TagVendorSpecific {
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
		if found {
			return
		}
		if id == TagVendorSpecific && len(val) >= 4 {
			// Check OUI 00-0F-AC (04)
			if bytes.Equal(val[0:4], []byte{0x00, 0x0F, 0xAC, 0x04}) {
				found = true
			}
		}
	})
	return found
}
