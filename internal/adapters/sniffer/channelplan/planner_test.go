package channelplan_test

import (
	"testing"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/channelplan"
)

// --- Tests migrated from partition_test.go ---

func TestPartitionWithCapabilities_BandSeparation(t *testing.T) {
	// wlan0 is dual-band; wlan1 is 2.4 GHz only.
	allChannels := []int{1, 6, 11, 36, 40, 149}
	interfaces := []string{"wlan0", "wlan1"}

	caps := map[string][]int{
		"wlan0": {1, 6, 11, 36, 40, 149},
		"wlan1": {1, 6, 11},
	}

	result := channelplan.Partition(allChannels, interfaces, caps)

	if len(result) != 2 {
		t.Fatalf("expected 2 partitions, got %d", len(result))
	}

	wlan0Chans := result[0]
	wlan1Chans := result[1]

	t.Logf("wlan0: %v", wlan0Chans)
	t.Logf("wlan1: %v", wlan1Chans)

	// wlan1 must not receive any 5 GHz channel.
	for _, ch := range wlan1Chans {
		if ch > 14 {
			t.Errorf("constraint violation: wlan1 (2.4 GHz only) was assigned channel %d", ch)
		}
	}

	// wlan0 should absorb the 5 GHz load.
	has5GHz := false
	for _, ch := range wlan0Chans {
		if ch > 14 {
			has5GHz = true
		}
	}
	if !has5GHz {
		t.Error("inefficiency: wlan0 should handle 5 GHz channels but received none")
	}

	// No channels must be lost.
	total := len(wlan0Chans) + len(wlan1Chans)
	if total != len(allChannels) {
		t.Errorf("channel loss: expected %d assigned, got %d", len(allChannels), total)
	}
}

func TestPartitionWithCapabilities_NoCapabilities(t *testing.T) {
	allChannels := []int{1, 36}
	interfaces := []string{"wlan0", "wlan1"}
	caps := make(map[string][]int) // empty → assume all supported

	result := channelplan.Partition(allChannels, interfaces, caps)

	t.Logf("fallback result: %v", result)

	if len(result[0]) == 0 && len(result[1]) == 0 {
		t.Error("fallback failed to assign channels")
	}
}

// --- Tests migrated from manager_test.go ---

func TestPartitionSimple_TwoInterfaces(t *testing.T) {
	got := channelplan.PartitionSimple([]int{1, 2, 3, 4}, 2)
	// Load balancer assigns: 5GHz first (none here), then 2.4 GHz round-robin.
	// Expected: iface0=[1,3] iface1=[2,4]
	want := [][]int{{1, 3}, {2, 4}}
	if !equalSlices(got, want) {
		t.Errorf("PartitionSimple([1,2,3,4], 2) = %v, want %v", got, want)
	}
}

func TestPartitionSimple_MixedBands(t *testing.T) {
	got := channelplan.PartitionSimple([]int{1, 6, 11, 36, 40, 48}, 2)
	// 5 GHz (36,40,48) assigned first, then 2.4 GHz (1,6,11).
	want := [][]int{{36, 48, 6}, {40, 1, 11}}
	if !equalSlices(got, want) {
		t.Errorf("PartitionSimple mixed bands = %v, want %v", got, want)
	}
}

func TestPartitionSimple_ThreeInterfaces(t *testing.T) {
	got := channelplan.PartitionSimple([]int{1, 2, 3, 4, 5}, 3)
	want := [][]int{{1, 4}, {2, 5}, {3}}
	if !equalSlices(got, want) {
		t.Errorf("PartitionSimple([1-5], 3) = %v, want %v", got, want)
	}
}

func TestPartitionSimple_OneInterface(t *testing.T) {
	got := channelplan.PartitionSimple([]int{1, 2, 3}, 1)
	want := [][]int{{1, 2, 3}}
	if !equalSlices(got, want) {
		t.Errorf("PartitionSimple([1,2,3], 1) = %v, want %v", got, want)
	}
}

func TestPartitionSimple_NoInterfaces(t *testing.T) {
	got := channelplan.PartitionSimple([]int{1, 2, 3}, 0)
	if got != nil {
		t.Errorf("PartitionSimple([1,2,3], 0) = %v, want nil", got)
	}
}

// equalSlices compares two [][]int for deep equality.
func equalSlices(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
