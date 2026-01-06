package sniffer

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
			want:     [][]int{{1, 3}, {2, 4}}, // Round robin: 0->1, 1->2, 2->3, 3->4 => Interface 0: [1, 3], Interface 1: [2, 4]
			// Wait, my implementation was modulo: idx := i % n
			// i=0 (ch=1) -> 0%2=0 -> iface 0
			// i=1 (ch=2) -> 1%2=1 -> iface 1
			// i=2 (ch=3) -> 2%2=0 -> iface 0
			// i=3 (ch=4) -> 3%2=1 -> iface 1
			// Correct.
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
