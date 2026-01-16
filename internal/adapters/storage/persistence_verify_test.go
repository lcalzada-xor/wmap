package storage

import (
	"os"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

// TestConnectionStatePersistence verifies that connection-related fields
// are correctly saved to and loaded from the SQLite database.
func TestConnectionStatePersistence(t *testing.T) {
	// 1. Setup temporary DB
	tmpDB := "test_persistence.db"
	defer os.Remove(tmpDB)

	// Initialize Storage
	store, err := NewSQLiteAdapter(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// 2. Create a Device with Connection State
	originalDevice := domain.Device{
		MAC:              "AA:BB:CC:DD:EE:FF",
		SSID:             "TestAP",
		Type:             "station",
		ConnectionState:  domain.StateConnected,
		ConnectionTarget: "11:22:33:44:55:66", // AP MAC
		ConnectionError:  "None",
		LastSeen:         time.Now(),
	}

	// 3. Save Device
	if err := store.SaveDevice(originalDevice); err != nil {
		t.Fatalf("Failed to save device: %v", err)
	}

	// 4. Close and Re-open (simulate restart) - strictly not needed for SQLite file but good practice
	// In our case, we just query from a fresh instance or same instance.
	// Let's create a new instance to ensure no in-memory caching in the struct itself (though sqlite struct doesn't cache).
	store2, err := NewSQLiteAdapter(tmpDB)
	if err != nil {
		t.Fatalf("Failed to reopen storage: %v", err)
	}

	// 5. Load Device
	loadedDevice, err := store2.GetDevice(originalDevice.MAC)
	if err != nil {
		t.Fatalf("Failed to load device: %v", err)
	}
	if loadedDevice == nil {
		t.Fatalf("Device not found")
	}

	// 6. Verify Fields
	if loadedDevice.ConnectionState != originalDevice.ConnectionState {
		t.Errorf("ConnectionState mismatch: got %v, want %v", loadedDevice.ConnectionState, originalDevice.ConnectionState)
	}
	if loadedDevice.ConnectionTarget != originalDevice.ConnectionTarget {
		t.Errorf("ConnectionTarget mismatch: got %v, want %v", loadedDevice.ConnectionTarget, originalDevice.ConnectionTarget)
	}
	if loadedDevice.ConnectionError != originalDevice.ConnectionError {
		t.Errorf("ConnectionError mismatch: got %v, want %v", loadedDevice.ConnectionError, originalDevice.ConnectionError)
	}
}
