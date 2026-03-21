package storage_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/storage"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageMaturity(t *testing.T) {
	// Setup temporary DB
	tmpDB := "test_maturity.db"
	os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	adapter, err := storage.NewSQLiteAdapter(tmpDB)
	require.NoError(t, err)
	defer adapter.Close()

	ctx := context.Background()

	t.Run("Pagination", func(t *testing.T) {
		// Insert 20 devices
		devices := make([]domain.Device, 20)
		for i := 0; i < 20; i++ {
			devices[i] = domain.Device{
				MAC:       fmt.Sprintf("00:00:00:00:00:%02X", i),
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
		}
		err := adapter.SaveDevicesBatch(ctx, devices)
		require.NoError(t, err)

		// Test Limit
		filter := domain.NewDeviceFilter().WithLimit(5)
		results, err := adapter.GetDevicesByFilter(ctx, *filter)
		require.NoError(t, err)
		assert.Len(t, results, 5, "Should return exactly 5 devices")

		// Test Offset
		filter = domain.NewDeviceFilter().WithLimit(5).WithOffset(5)
		results, err = adapter.GetDevicesByFilter(ctx, *filter)
		require.NoError(t, err)
		assert.Len(t, results, 5, "Should return exactly 5 devices")
		assert.Equal(t, "00:00:00:00:00:05", results[0].MAC, "Should start from the 6th device")

		// Test Default Limit (0 limit provided in filter logic defaults to 100, but we only have 20)
		filter = domain.NewDeviceFilter()
		results, err = adapter.GetDevicesByFilter(ctx, *filter)
		require.NoError(t, err)
		assert.Len(t, results, 20, "Should return all 20 devices with default limit")
	})

	t.Run("SaveProbe_Atomic", func(t *testing.T) {
		mac := "AA:BB:CC:DD:EE:FF"
		ssid := "TestSSID"

		// Device must exist first due to Foreign Key? actually code doesn't enforce FK in Struct but GORM might if AutoMigrate did it.
		// Let's create device first to be safe and realistic
		dev := domain.Device{MAC: mac, LastSeen: time.Now()}
		require.NoError(t, adapter.SaveDevice(ctx, dev))

		// Save Probe
		err := adapter.SaveProbe(ctx, mac, ssid)
		require.NoError(t, err)

		// Verify it was saved
		savedDev, err := adapter.GetDevice(ctx, mac)
		require.NoError(t, err)
		assert.Contains(t, savedDev.ProbedSSIDs, ssid)
	})

	t.Run("SaveDevice_Transaction_Probes", func(t *testing.T) {
		mac := "11:22:33:44:55:66"
		dev := domain.Device{
			MAC: mac,
			ProbedSSIDs: map[string]time.Time{
				"SSID1": time.Now(),
				"SSID2": time.Now(),
			},
		}

		err := adapter.SaveDevice(ctx, dev)
		require.NoError(t, err)

		savedDev, err := adapter.GetDevice(ctx, mac)
		require.NoError(t, err)
		assert.Len(t, savedDev.ProbedSSIDs, 2)
	})

	t.Run("Persistence_SecurityDetails", func(t *testing.T) {
		mac := "AA:BB:CC:11:22:33"
		dev := domain.Device{
			MAC:           mac,
			HasHandshake:  true,
			HandshakeFile: "/tmp/capture.cap",
			IEFingerprint: "DEADBEEF",
			RSNInfo: &domain.RSNInfo{
				Version:         1,
				GroupCipher:     "CCMP",
				PairwiseCiphers: []string{"CCMP", "TKIP"},
				AKMSuites:       []string{"PSK"},
			},
			WPSDetails: &domain.WPSDetails{
				Model:        "TestModel",
				Manufacturer: "TestManuf",
				DeviceName:   "TestDevice",
			},
			LastSeen: time.Now(),
		}

		err := adapter.SaveDevice(ctx, dev)
		require.NoError(t, err)

		savedDev, err := adapter.GetDevice(ctx, mac)
		require.NoError(t, err)

		assert.True(t, savedDev.HasHandshake)
		assert.Equal(t, "/tmp/capture.cap", savedDev.HandshakeFile)
		assert.Equal(t, "DEADBEEF", savedDev.IEFingerprint)

		require.NotNil(t, savedDev.RSNInfo)
		assert.Equal(t, "CCMP", savedDev.RSNInfo.GroupCipher)
		assert.Contains(t, savedDev.RSNInfo.PairwiseCiphers, "TKIP")

		require.NotNil(t, savedDev.WPSDetails)
		assert.Equal(t, "TestModel", savedDev.WPSDetails.Model)
	})
}
