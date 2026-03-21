package sniffer

import (
	"testing"
)

func TestPartitionChannelsWithCapabilities(t *testing.T) {
	// Scenario: wlan0 supports Dual Band, wlan1 supports 2.4GHz only
	// We want to ensure wlan1 NEVER gets 5GHz channels.

	allChannels := []int{1, 6, 11, 36, 40, 149} // 3x 2.4, 3x 5
	interfaces := []string{"wlan0", "wlan1"}

	caps := make(map[string][]int)
	caps["wlan0"] = []int{1, 6, 11, 36, 40, 149} // Supports All
	caps["wlan1"] = []int{1, 6, 11}              // Supports 2.4 Only

	result := partitionChannelsWithCapabilities(allChannels, interfaces, caps)

	if len(result) != 2 {
		t.Fatalf("Expected 2 partitions, got %d", len(result))
	}

	wlan0Chans := result[0]
	wlan1Chans := result[1]

	t.Logf("wlan0: %v", wlan0Chans)
	t.Logf("wlan1: %v", wlan1Chans)

	// Check wlan1 acts correctly (NO 5GHz)
	for _, ch := range wlan1Chans {
		if ch > 14 {
			t.Errorf("Constraint Violation: wlan1 (2.4GHz only) assigned channel %d", ch)
		}
	}

	// Check wlan0 handles the 5GHz load
	has5GHz := false
	for _, ch := range wlan0Chans {
		if ch > 14 {
			has5GHz = true
		}
	}
	if !has5GHz {
		t.Error("Inefficiency: wlan0 should handle the 5GHz load but got none") // Unless strictly balanced
	}

	// Check coverage
	totalAssigned := len(wlan0Chans) + len(wlan1Chans)
	if totalAssigned != len(allChannels) {
		t.Errorf("Lost channels! Expected %d, got %d", len(allChannels), totalAssigned)
	}
}

func TestPartitionChannels_NoCapabilities(t *testing.T) {
	// Fallback behavior check
	allChannels := []int{1, 36}
	interfaces := []string{"wlan0", "wlan1"}
	caps := make(map[string][]int) // Empty

	result := partitionChannelsWithCapabilities(allChannels, interfaces, caps)

	// Should act like round robin or balanced
	t.Logf("Fallback Result: %v", result)

	if len(result[0]) == 0 && len(result[1]) == 0 {
		t.Error("Fallback failed to assign channels")
	}
}
