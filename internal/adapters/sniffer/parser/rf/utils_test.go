package rf

import (
	"testing"
)

func TestFrequencyToChannel(t *testing.T) {
	tests := []struct {
		freq     int
		expected int
	}{
		{2412, 1},
		{2437, 6},
		{2462, 11},
		{2484, 14},
		{5180, 36},
		{5200, 40},
		{5745, 149},
		{5825, 165},
		{5955, 1},
		{6115, 33},
		{7115, 233},
		{2400, 0},
		{5000, 0},
		{8000, 0},
	}

	for _, tt := range tests {
		result := FrequencyToChannel(tt.freq)
		if result != tt.expected {
			t.Errorf("FrequencyToChannel(%d) = %d; expected %d", tt.freq, result, tt.expected)
		}
	}
}
