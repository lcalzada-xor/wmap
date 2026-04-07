package domain

import (
	"testing"
)

func BenchmarkCalculateMatch_Optimized(b *testing.B) {
	sig := DeviceSignature{
		ID:            "test-sig-1",
		Vendor:        "Apple",
		WPSModelRegex: "iPhone.*",
		IEPattern:     []int{0, 1, 3, 45, 61, 70, 127},
		Confidence:    0.9,
	}
	sig.Compile()

	device := Device{
		Vendor: "Apple Inc.",
		Model:  "iPhone 12,1",
		IETags: []int{0, 1, 3, 45, 61, 70, 127, 191},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.CalculateMatch(&device)
	}
}

func TestCalculateMatch_Correctness(t *testing.T) {
	sig := DeviceSignature{
		ID:            "test-sig-1",
		Vendor:        "Apple",
		WPSModelRegex: "iPhone.*",
		IEPattern:     []int{0, 1, 3, 45},
		Confidence:    0.9,
	}

	tests := []struct {
		name       string
		device     Device
		wantMatch  bool
		wantSource MatchSource
	}{
		{
			name: "Full Match",
			device: Device{
				Vendor: "Apple Inc.",
				Model:  "iPhone 12,1",
				IETags: []int{0, 1, 3, 45, 61},
			},
			wantMatch: true,
		},
		{
			name: "IE Only",
			device: Device{
				Vendor: "Unknown",
				Model:  "Generic",
				IETags: []int{0, 1, 3, 45, 61},
			},
			wantMatch:  true,
			wantSource: SourceIEPattern,
		},
		{
			name: "No Match",
			device: Device{
				Vendor: "Samsung",
				Model:  "Galaxy S21",
				IETags: []int{0, 1, 5, 45},
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sig.CalculateMatch(&tt.device)
			if (got != nil) != tt.wantMatch {
				t.Errorf("CalculateMatch() = %v, want %v", got != nil, tt.wantMatch)
			}
			if tt.wantMatch && tt.wantSource != "" {
				found := false
				for _, s := range got.MatchedBy {
					if s == tt.wantSource {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("CalculateMatch() matched by %v, want %v", got.MatchedBy, tt.wantSource)
				}
			}
		})
	}
}
