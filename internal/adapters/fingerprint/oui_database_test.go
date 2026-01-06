package fingerprint

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestOUIDatabaseBasic(t *testing.T) {
	// Create temporary database
	tmpDB := "test_oui.db"
	defer os.Remove(tmpDB)

	// Create database
	db, err := NewOUIDatabase(tmpDB, 100, nil)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Insert test entries
	entries := []OUIEntry{
		{
			Prefix:      "00:00:00",
			Vendor:      "Test Vendor 1",
			VendorShort: "TestVendor1",
			LastUpdated: time.Now(),
		},
		{
			Prefix:      "11:11:11",
			Vendor:      "Test Vendor 2 Inc.",
			VendorShort: "TestVendor2",
			LastUpdated: time.Now(),
		},
	}

	for _, entry := range entries {
		if err := db.InsertOUI(entry); err != nil {
			t.Fatalf("Failed to insert OUI: %v", err)
		}
	}

	// Test lookup
	vendor, err := db.LookupVendor("00:00:00:11:22:33")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if vendor != "TestVendor1" {
		t.Errorf("Expected TestVendor1, got %s", vendor)
	}

	// Test stats
	count, _, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 entries, got %d", count)
	}
}

func TestOUIDatabaseBulkInsert(t *testing.T) {
	tmpDB := "test_oui_bulk.db"
	defer os.Remove(tmpDB)

	db, err := NewOUIDatabase(tmpDB, 100, nil)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create 100 test entries
	entries := make([]OUIEntry, 100)
	for i := 0; i < 100; i++ {
		// Generate valid MAC prefix
		prefix := normalizeMAC(fmt.Sprintf("%02X:%02X:%02X", i, i, i))
		entries[i] = OUIEntry{
			Prefix:      prefix,
			Vendor:      fmt.Sprintf("Vendor%d", i),
			VendorShort: fmt.Sprintf("V%d", i),
			LastUpdated: time.Now(),
		}
	}

	// Bulk insert
	if err := db.BulkInsertOUIs(entries); err != nil {
		t.Fatalf("Bulk insert failed: %v", err)
	}

	// Verify count
	count, _, err := db.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if count != 100 {
		t.Errorf("Expected 100 entries, got %d", count)
	}
}

func TestOUIDatabaseFallback(t *testing.T) {
	tmpDB := "test_oui_fallback.db"
	defer os.Remove(tmpDB)

	// Create fallback map
	fallback := map[string]string{
		"AA:BB:CC": "Fallback Vendor",
	}

	db, err := NewOUIDatabase(tmpDB, 100, fallback)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Lookup should use fallback
	vendor, err := db.LookupVendor("AA:BB:CC:11:22:33")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if vendor != "Fallback Vendor" {
		t.Errorf("Expected Fallback Vendor, got %s", vendor)
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"00:11:22", "00:11:22"},
		{"00-11-22", "00:11:22"},
		{"00.11.22", "00:11:22"},
		{"001122", "00:11:22"},
		{"aa:bb:cc", "AA:BB:CC"},
	}

	for _, tt := range tests {
		result := normalizeMAC(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeMAC(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func BenchmarkOUIDatabaseLookup(b *testing.B) {
	tmpDB := "bench_oui.db"
	defer os.Remove(tmpDB)

	db, _ := NewOUIDatabase(tmpDB, 1000, nil)
	defer db.Close()

	// Insert test entry
	db.InsertOUI(OUIEntry{
		Prefix:      "00:00:00",
		Vendor:      "Test",
		VendorShort: "T",
		LastUpdated: time.Now(),
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.LookupVendor("00:00:00:11:22:33")
	}
}
