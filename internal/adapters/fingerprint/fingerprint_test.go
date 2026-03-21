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

	if len(store.Signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(store.Signatures))
	}

	device := domain.Device{Vendor: "Apple"}
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
		{"Locally Administered MAC", "02:00:00:00:00:00", true, "Randomized"},
		{"Universal MAC", "00:00:00:00:00:00", false, ""},
		{"LAA with different pattern", "06:11:22:33:44:55", true, "Randomized"},
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
