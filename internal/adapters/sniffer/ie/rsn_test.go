package ie

import (
	"reflect"
	"testing"
)

func TestParseRSN(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		want     *RSNInfo
		wantErr  bool
	}{
		{
			name: "Standard WPA2-PSK (CCMP/PSK)",
			data: []byte{
				0x01, 0x00, // Version 1
				0x00, 0x0F, 0xAC, 0x04, // Group Cipher: CCMP-128
				0x01, 0x00, // Pairwise Count: 1
				0x00, 0x0F, 0xAC, 0x04, // Pairwise: CCMP-128
				0x01, 0x00, // AKM Count: 1
				0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
				0x00, 0x00, // Capabilities: None
			},
			want: &RSNInfo{
				Version:         1,
				GroupCipher:     "CCMP-128",
				PairwiseCiphers: []string{"CCMP-128"},
				AKMSuites:       []string{"PSK"},
				Capabilities:    RSNCapabilities{},
			},
		},
		{
			name: "WPA3-SAE with MFP Required",
			data: []byte{
				0x01, 0x00, // Version 1
				0x00, 0x0F, 0xAC, 0x04, // Group Cipher: CCMP-128
				0x01, 0x00, // Pairwise Count: 1
				0x00, 0x0F, 0xAC, 0x04, // Pairwise: CCMP-128
				0x01, 0x00, // AKM Count: 1
				0x00, 0x0F, 0xAC, 0x08, // AKM: SAE
				0x40, 0x00, // Capabilities: MFP Required (bit 6 -> 0x40)
			},
			want: &RSNInfo{
				Version:         1,
				GroupCipher:     "CCMP-128",
				PairwiseCiphers: []string{"CCMP-128"},
				AKMSuites:       []string{"SAE"},
				Capabilities: RSNCapabilities{
					MFPRequired: true,
				},
			},
		},
		{
			name: "Mixed Mode (TKIP+CCMP / PSK)",
			data: []byte{
				0x01, 0x00, // Version 1
				0x00, 0x0F, 0xAC, 0x02, // Group Cipher: TKIP
				0x02, 0x00, // Pairwise Count: 2
				0x00, 0x0F, 0xAC, 0x02, // Pairwise 1: TKIP
				0x00, 0x0F, 0xAC, 0x04, // Pairwise 2: CCMP-128
				0x01, 0x00, // AKM Count: 1
				0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
				0x00, 0x00, // Capabilities
			},
			want: &RSNInfo{
				Version:         1,
				GroupCipher:     "TKIP",
				PairwiseCiphers: []string{"TKIP", "CCMP-128"},
				AKMSuites:       []string{"PSK"},
				Capabilities:    RSNCapabilities{},
			},
		},
		{
			name: "RSN with PMKIDs and Management Cipher",
			data: []byte{
				0x01, 0x00, // Version 1
				0x00, 0x0F, 0xAC, 0x04, // Group Cipher: CCMP-128
				0x01, 0x00, // Pairwise Count: 1
				0x00, 0x0F, 0xAC, 0x04, // Pairwise: CCMP-128
				0x01, 0x00, // AKM Count: 1
				0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
				0x80, 0x00, // Capabilities: MFP Capable (bit 7 -> 0x80)
				0x01, 0x00, // PMKID Count: 1
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // PMKID
				0x00, 0x0F, 0xAC, 0x06, // Group Mgmt Cipher: BIP-CMAC-128
			},
			want: &RSNInfo{
				Version:         1,
				GroupCipher:     "CCMP-128",
				PairwiseCiphers: []string{"CCMP-128"},
				AKMSuites:       []string{"PSK"},
				Capabilities: RSNCapabilities{
					MFPCapable: true,
				},
				PMKIDs:          []string{"0102030405060708090a0b0c0d0e0f10"},
				GroupMgmtCipher: "BIP-CMAC-128",
			},
		},
		{
			name: "Truncated Data (Count says 1 but data missing)",
			data: []byte{
				0x01, 0x00,
				0x00, 0x0F, 0xAC, 0x04,
				0x01, 0x00, // Pairwise Count: 1, but missing data
			},
			want: &RSNInfo{
				Version:     1,
				GroupCipher: "CCMP-128",
			},
		},
		{
			name: "Vendor Specific Cipher",
			data: []byte{
				0x01, 0x00,
				0xAA, 0xBB, 0xCC, 0x01, // Vendor OUI AA-BB-CC type 1
				0x00, 0x00, // Pairwise 0
				0x00, 0x00, // AKM 0
				0x00, 0x00, // Capabilities
			},
			want: &RSNInfo{
				Version:      1,
				GroupCipher:  "VENDOR(aabbcc:1)",
				Capabilities: RSNCapabilities{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRSN(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRSN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRSN() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
