package vendor

import (
	"context"
	"testing"
)

func TestMACAddress(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectOUI   string
		expectRand  bool
	}{
		{"Valid colon-separated MAC", "00:11:22:33:44:55", false, "00:11:22", false},
		{"Valid dash-separated MAC", "00-11-22-33-44-55", false, "00:11:22", false},
		{"Randomized MAC", "02:00:00:00:00:00", false, "02:00:00", true},
		{"Invalid MAC", "invalid", true, "", false},
		{"Empty MAC", "", true, "", false},
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

	mac1 := MustParseMAC("00:11:22:33:44:55")
	vendor, err := composite.LookupVendor(ctx, mac1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if vendor != "Vendor1" {
		t.Errorf("Expected Vendor1, got %s", vendor)
	}

	mac2 := MustParseMAC("AA:BB:CC:DD:EE:FF")
	vendor, err = composite.LookupVendor(ctx, mac2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if vendor != "Vendor2" {
		t.Errorf("Expected Vendor2, got %s", vendor)
	}

	mac3 := MustParseMAC("FF:FF:FF:FF:FF:FF")
	vendor, _ = composite.LookupVendor(ctx, mac3)
	if vendor != "Unknown" {
		t.Errorf("Expected Unknown, got %s", vendor)
	}
}
