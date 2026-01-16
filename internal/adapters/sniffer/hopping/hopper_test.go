package hopping

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// MockSwitcher captures channel set calls
type MockSwitcher struct {
	mu           sync.Mutex
	calls        []int
	shouldFail   bool
	failureCount int
}

func (m *MockSwitcher) SetChannel(iface string, channel int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, channel)

	if m.shouldFail {
		return fmt.Errorf("mock failure")
	}

	return nil
}

func TestHopper_RoundRobin(t *testing.T) {
	mock := &MockSwitcher{}
	channels := []int{1, 6, 11}
	// Small delay for testing
	h := NewHopper("wlan0", channels, 10*time.Millisecond, mock)

	// Run manually without Start loop to test logic directly
	// Note: h.hop() is private, but we can verify via Start and stop quickly,
	// or we can test SetChannels / GetChannels.
	// Since hop is private, we'll verify via a short Start run.

	go h.Start()
	time.Sleep(50 * time.Millisecond) // Should hop ~4-5 times
	h.Stop()

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.calls) < 3 {
		t.Fatalf("Expected at least 3 hops, got %d", len(mock.calls))
	}

	// Verify order: 1, 6, 11, 1, 6...
	// Note: The first hop is called immediately.
	wantSeq := []int{1, 6, 11}
	for i, ch := range mock.calls {
		want := wantSeq[i%len(wantSeq)]
		if ch != want {
			t.Errorf("Hop %d: got channel %d, want %d", i, ch, want)
		}
	}
}

func TestHopper_Pause(t *testing.T) {
	mock := &MockSwitcher{}
	channels := []int{1}
	h := NewHopper("wlan0", channels, 10*time.Millisecond, mock)

	go h.Start()
	time.Sleep(20 * time.Millisecond) // Let it hop couple times

	// Pause
	h.Pause(50 * time.Millisecond)

	mock.mu.Lock()
	prePauseCount := len(mock.calls)
	mock.mu.Unlock()

	time.Sleep(20 * time.Millisecond) // During pause

	mock.mu.Lock()
	duringPauseCount := len(mock.calls)
	mock.mu.Unlock()

	if duringPauseCount > prePauseCount {
		t.Errorf("Hopper continued hopping during pause")
	}

	h.Stop()
}

func TestHopper_EmptyChannels(t *testing.T) {
	mock := &MockSwitcher{}
	h := NewHopper("wlan0", []int{}, 10*time.Millisecond, mock)

	go h.Start()
	time.Sleep(20 * time.Millisecond)
	h.Stop()

	mock.mu.Lock()
	count := len(mock.calls)
	mock.mu.Unlock()

	if count != 0 {
		t.Errorf("Expected 0 hops with empty channels, got %d", count)
	}
}

func TestHopper_DynamicChannelUpdate(t *testing.T) {
	mock := &MockSwitcher{}
	h := NewHopper("wlan0", []int{1}, 10*time.Millisecond, mock)

	go h.Start()
	time.Sleep(20 * time.Millisecond) // Should hop to 1

	// Update channels
	h.SetChannels([]int{6})
	time.Sleep(20 * time.Millisecond) // Should hop to 6

	h.Stop()

	mock.mu.Lock()
	calls := mock.calls
	mock.mu.Unlock()

	found1 := false
	found6 := false
	for _, ch := range calls {
		if ch == 1 {
			found1 = true
		}
		if ch == 6 {
			found6 = true
		}
	}

	if !found1 || !found6 {
		t.Errorf("Dynamic update failed. Found 1: %v, Found 6: %v", found1, found6)
	}
}

func TestHopper_SwitcherErrors(t *testing.T) {
	mock := &MockSwitcher{shouldFail: true}
	h := NewHopper("wlan0", []int{1}, 10*time.Millisecond, mock)

	go h.Start()
	time.Sleep(30 * time.Millisecond) // Should attempt hops but fail
	h.Stop()

	mock.mu.Lock()
	count := len(mock.calls)
	mock.mu.Unlock()

	if count == 0 {
		t.Errorf("Hopper stopped hopping on errors, expected retries. Got %d attempts", count)
	}
}
