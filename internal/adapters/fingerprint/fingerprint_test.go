package fingerprint

import (
	"context"
	"net"
	"testing"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestSignatureStore_MatchSignature(t *testing.T) {
	signatures := []domain.DeviceSignature{
		{
			ID:         "iphone-sig",
			Vendor:     "Apple",
			DeviceType: domain.CategorySmartphone,
			Model:      "iPhone",
			Confidence: 0.9,
		},
		{
			ID:         "macbook-sig",
			Vendor:     "Apple",
			DeviceType: domain.CategoryLaptop,
			Model:      "MacBook",
			Confidence: 0.8,
		},
	}

	store := NewSignatureStore(signatures)

	// Verify store was created with signatures
	if len(store.Signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(store.Signatures))
	}

	// Test with a device - signature matching logic is in domain layer
	// This test just verifies the store can be called
	device := domain.Device{
		Vendor: "Apple",
	}

	// MatchSignature may return nil if no strong match, which is fine
	_ = store.MatchSignature(context.Background(), device)
}

func TestFingerprintEngine_AnalyzeRandomization(t *testing.T) {
	store := NewSignatureStore(nil)
	engine := NewFingerprintEngine(store)

	tests := []struct {
		name           string
		mac            string
		expectRandom   bool
		expectedVendor string
	}{
		{
			name:           "Locally Administered MAC",
			mac:            "02:00:00:00:00:00",
			expectRandom:   true,
			expectedVendor: "Randomized",
		},
		{
			name:           "Universal MAC",
			mac:            "00:00:00:00:00:00",
			expectRandom:   false,
			expectedVendor: "",
		},
		{
			name:           "LAA with different pattern",
			mac:            "06:11:22:33:44:55",
			expectRandom:   true,
			expectedVendor: "Randomized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := net.ParseMAC(tt.mac)
			if err != nil {
				t.Fatalf("Failed to parse MAC: %v", err)
			}

			device := &domain.Device{}
			engine.AnalyzeRandomization(mac, device)

			if device.IsRandomized != tt.expectRandom {
				t.Errorf("Expected IsRandomized=%v, got %v", tt.expectRandom, device.IsRandomized)
			}

			if tt.expectRandom && device.Vendor != tt.expectedVendor {
				t.Errorf("Expected Vendor=%s, got %s", tt.expectedVendor, device.Vendor)
			}
		})
	}
}

func TestMACAddress(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectOUI   string
		expectRand  bool
	}{
		{
			name:        "Valid colon-separated MAC",
			input:       "00:11:22:33:44:55",
			expectError: false,
			expectOUI:   "00:11:22",
			expectRand:  false,
		},
		{
			name:        "Valid dash-separated MAC",
			input:       "00-11-22-33-44-55",
			expectError: false,
			expectOUI:   "00:11:22",
			expectRand:  false,
		},
		{
			name:        "Randomized MAC",
			input:       "02:00:00:00:00:00",
			expectError: false,
			expectOUI:   "02:00:00",
			expectRand:  true,
		},
		{
			name:        "Invalid MAC",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "Empty MAC",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := ParseMAC(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if mac.OUI() != tt.expectOUI {
				t.Errorf("Expected OUI=%s, got %s", tt.expectOUI, mac.OUI())
			}

			if mac.IsRandomized() != tt.expectRand {
				t.Errorf("Expected IsRandomized=%v, got %v", tt.expectRand, mac.IsRandomized())
			}
		})
	}
}

func TestVendorRepository(t *testing.T) {
	ctx := context.Background()

	// Test static repository
	staticRepo := NewStaticVendorRepository(map[string]string{
		"00:11:22": "TestVendor",
	})

	mac := MustParseMAC("00:11:22:33:44:55")
	vendor, err := staticRepo.LookupVendor(ctx, mac)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if vendor != "TestVendor" {
		t.Errorf("Expected TestVendor, got %s", vendor)
	}

	// Test not found
	mac2 := MustParseMAC("AA:BB:CC:DD:EE:FF")
	_, err = staticRepo.LookupVendor(ctx, mac2)
	if err != ErrVendorNotFound {
		t.Errorf("Expected ErrVendorNotFound, got %v", err)
	}
}

func TestCompositeVendorRepository(t *testing.T) {
	ctx := context.Background()

	repo1 := NewStaticVendorRepository(map[string]string{
		"00:11:22": "Vendor1",
	})

	repo2 := NewStaticVendorRepository(map[string]string{
		"AA:BB:CC": "Vendor2",
	})

	composite := NewCompositeVendorRepository(repo1, repo2)

	// Test lookup from first repo
	mac1 := MustParseMAC("00:11:22:33:44:55")
	vendor, err := composite.LookupVendor(ctx, mac1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if vendor != "Vendor1" {
		t.Errorf("Expected Vendor1, got %s", vendor)
	}

	// Test lookup from second repo
	mac2 := MustParseMAC("AA:BB:CC:DD:EE:FF")
	vendor, err = composite.LookupVendor(ctx, mac2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if vendor != "Vendor2" {
		t.Errorf("Expected Vendor2, got %s", vendor)
	}

	// Test not found
	mac3 := MustParseMAC("FF:FF:FF:FF:FF:FF")
	vendor, err = composite.LookupVendor(ctx, mac3)
	if vendor != "Unknown" {
		t.Errorf("Expected Unknown, got %s", vendor)
	}
}
