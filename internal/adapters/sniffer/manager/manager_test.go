package manager

import (
	"reflect"
	"testing"
)

func TestPartitionChannels(t *testing.T) {
	tests := []struct {
		name     string
		channels []int
		n        int
		want     [][]int
	}{
		{
			name:     "2 interfaces, 4 channels",
			channels: []int{1, 2, 3, 4},
			n:        2,
			// Correct.
			// New logic attempts to split by band (2.4 vs 5).
			// Since all are 2.4, they might all go to one interface if we reserve the other for 5GHz?
			// The current implementation does: result[0] = band24, result[1] = band5.
			// So [[1 2 3 4] []] is correct behavior for the current implementation.
			want: [][]int{{1, 2, 3, 4}, {}},
		},
		{
			name:     "2 interfaces, Mixed Bands",
			channels: []int{1, 6, 11, 36, 40, 48},
			n:        2,
			// Expect split by band
			want: [][]int{{1, 6, 11}, {36, 40, 48}},
		},
		{
			name:     "3 interfaces, 5 channels",
			channels: []int{1, 2, 3, 4, 5},
			n:        3,
			want:     [][]int{{1, 4}, {2, 5}, {3}},
		},
		{
			name:     "1 interface",
			channels: []int{1, 2, 3},
			n:        1,
			want:     [][]int{{1, 2, 3}},
		},
		{
			name:     "No interfaces",
			channels: []int{1, 2, 3},
			n:        0,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := partitionChannels(tt.channels, tt.n)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("partitionChannels() = %v, want %v", got, tt.want)
			}
		})
	}
}
