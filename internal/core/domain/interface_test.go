package domain

import (
	"testing"
)

func TestNewInterfaceInfo(t *testing.T) {
	caps := InterfaceCapabilities{
		SupportedBands:    []WiFiBand{Band24GHz, Band5GHz},
		SupportedChannels: []int{1, 6, 11, 36, 44},
	}

	tests := []struct {
		name    string
		iface   string
		mac     string
		wantErr error
	}{
		{
			name:    "valid interface",
			iface:   "wlan0",
			mac:     "00:11:22:33:44:55",
			wantErr: nil,
		},
		{
			name:    "invalid name",
			iface:   "invalid!name",
			mac:     "00:11:22:33:44:55",
			wantErr: ErrInvalidInterfaceName,
		},
		{
			name:    "invalid mac",
			iface:   "wlan0",
			mac:     "invalid-mac",
			wantErr: ErrInvalidMAC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := NewInterfaceInfo(tt.iface, tt.mac, caps)
			if err != tt.wantErr {
				t.Errorf("NewInterfaceInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil {
				if info.Name != tt.iface {
					t.Errorf("info.Name = %v, want %v", info.Name, tt.iface)
				}
				if info.MAC != tt.mac {
					t.Errorf("info.MAC = %v, want %v", info.MAC, tt.mac)
				}
			}
		})
	}
}

func TestInterfaceMetrics(t *testing.T) {
	m := &InterfaceMetrics{
		PacketsReceived: 100,
		PacketsDropped:  10,
	}

	m.ResetMetrics()

	if m.PacketsReceived != 0 || m.PacketsDropped != 0 {
		t.Errorf("Metrics not reset: %v", m)
	}

	other := InterfaceMetrics{
		PacketsReceived: 50,
		ErrorCount:      5,
	}

	m.AddMetrics(other)

	if m.PacketsReceived != 50 || m.ErrorCount != 5 {
		t.Errorf("Metrics not added correctly: %v", m)
	}
}
