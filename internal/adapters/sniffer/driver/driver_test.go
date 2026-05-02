package driver_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver"
	"github.com/stretchr/testify/assert"
)

// MockExecutor implements CommandExecutor for testing
type MockExecutor struct {
	Outputs map[string][]byte
}

func (m *MockExecutor) Execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmdKey := name
	for _, arg := range args {
		cmdKey += " " + arg
	}

	if out, ok := m.Outputs[cmdKey]; ok {
		return out, nil
	}
	return nil, fmt.Errorf("mock command not found: %s", cmdKey)
}

func TestGetInterfaceCapabilities_Bands(t *testing.T) {
	mockExec := &MockExecutor{
		Outputs: make(map[string][]byte),
	}

	// Mock iw dev output
	mockExec.Outputs["iw dev"] = []byte(`
phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 00:00:00:00:00:00
		type managed
`)

	// Mock iw phy phy0 info
	// Simulated output covering 2.4GHz, 5GHz, and 6GHz
	mockExec.Outputs["iw phy phy0 info"] = []byte(`
Wiphy phy0
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2472.0 MHz [13] (20.0 dBm)
	Band 2:
		Frequencies:
			* 5180.0 MHz [36] (20.0 dBm)
			* 5825.0 MHz [165] (20.0 dBm)
			* 5955.0 MHz [1] (20.0 dBm)
`)

	// Inject Mock
	driver.SetExecutor(mockExec)

	bands, channels, _, err := driver.GetInterfaceCapabilities("wlan0")
	assert.NoError(t, err)

	// Verify Channels
	assert.Contains(t, channels, 1)
	assert.Contains(t, channels, 13)
	assert.Contains(t, channels, 36)
	assert.Contains(t, channels, 165)

	// Verify Bands (Key Check)
	assert.True(t, bands["2.4GHz"], "Should detect 2.4GHz")
	assert.True(t, bands["5GHz"], "Should detect 5GHz")
	assert.True(t, bands["6GHz"], "Should detect 6GHz (5955 MHz)")

	// Verify Frequencies logic
	// 5955MHz is > 5900, so it should be mapped to 6GHz band
}

func TestGetDriverInfo(t *testing.T) {
	mockExec := &MockExecutor{Outputs: make(map[string][]byte)}
	driver.SetExecutor(mockExec)

	// Case 1: Standard ethtool output
	mockExec.Outputs["ethtool -i wlan0"] = []byte(`
driver: iwlwifi
version: 5.15.0-58-generic
firmware-version: 66.f4bc42.0 8000C-36.ucode
expansion-rom-version: 
bus-info: 0000:04:00.0
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no
`)

	drv, err := driver.GetDriverInfo("wlan0")
	assert.NoError(t, err)
	assert.Equal(t, "iwlwifi", drv)

	// Case 2: Missing/Error
	mockExec.Outputs["ethtool -i wlan1"] = []byte(``) // Empty or error
	drv, _ = driver.GetDriverInfo("wlan1")
	assert.Equal(t, "unknown", drv)
}

func TestGetInterfaceCurrentConfig(t *testing.T) {
	mockExec := &MockExecutor{Outputs: make(map[string][]byte)}
	driver.SetExecutor(mockExec)

	// Case 1: Managed Mode, 20dBm
	mockExec.Outputs["iw dev wlan0 info"] = []byte(`
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 00:c0:ca:ad:00:01
		type managed
		wiphy 0
		channel 1 (2412 MHz), width: 20 MHz, center1: 2412 MHz
		txpower 20.00 dBm
`)

	mode, tx, err := driver.GetInterfaceCurrentConfig("wlan0")
	assert.NoError(t, err)
	assert.Equal(t, "managed", mode)
	assert.Equal(t, 20, tx)

	// Case 2: Monitor Mode, 30dBm, different indent
	mockExec.Outputs["iw dev mon0 info"] = []byte(`
	Interface mon0
		ifindex 4
		wdev 0x2
		addr 00:c0:ca:ad:00:02
		type monitor
		wiphy 0
		channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
		txpower 30.00 dBm
`)

	mode, tx, err = driver.GetInterfaceCurrentConfig("mon0")
	assert.NoError(t, err)
	assert.Equal(t, "monitor", mode)
	assert.Equal(t, 30, tx)

	// Case 3: Strange/Missing data (Simulate "unknown" report)
	mockExec.Outputs["iw dev wlan2 info"] = []byte(`
	Interface wlan2
		ifindex 5
		addr 00:11:22:33:44:55
		# No type, No txpower
`)
	mode, tx, err = driver.GetInterfaceCurrentConfig("wlan2")
	assert.NoError(t, err)
	assert.Equal(t, "unknown", mode)
	assert.Equal(t, 0, tx)
}
