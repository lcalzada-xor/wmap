package hopping

import (
	"log"
	"sync"
	"time"
)

// ChannelHopper handles switching WiFi channels.
type ChannelHopper struct {
	Interface    string
	Channels     []int
	Delay        time.Duration
	switcher     ChannelSwitcher
	mu           sync.RWMutex // Protects Channels
	stopChan     chan struct{}
	resetChan    chan time.Duration
	currentIndex int // For Round Robin
	errorCount   int
}

// NewHopper creates a new ChannelHopper.
func NewHopper(iface string, channels []int, delay time.Duration, switcher ChannelSwitcher) *ChannelHopper {
	if switcher == nil {
		switcher = NewLinuxChannelSwitcher()
	}
	return &ChannelHopper{
		Interface: iface,
		Channels:  channels,
		Delay:     delay,
		switcher:  switcher,
		stopChan:  make(chan struct{}),
		resetChan: make(chan time.Duration, 1),
	}
}

// SetChannels updates the channel list dynamically.
func (h *ChannelHopper) SetChannels(channels []int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Channels = channels
	h.currentIndex = 0 // Reset index on update
	log.Printf("Channel hopper updated to: %v", channels)
}

// GetChannels returns a copy of the current channel list.
func (h *ChannelHopper) GetChannels() []int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result := make([]int, len(h.Channels))
	copy(result, h.Channels)
	return result
}

// Stop signals the hopper to shut down.
func (h *ChannelHopper) Stop() {
	close(h.stopChan)
}

// Start begins the channel hopping loop.
func (h *ChannelHopper) Start() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in ChannelHopper: %v", r)
		}
	}()

	log.Printf("Starting channel hopper on %s (dwell=%v)", h.Interface, h.Delay)

	ticker := time.NewTicker(h.Delay)
	defer ticker.Stop()

	// Initial hop
	h.hop()

	for {
		select {
		case <-h.stopChan:
			log.Printf("Stopping channel hopper on %s", h.Interface)
			return
		case d := <-h.resetChan:
			log.Printf("Hopper on %s PAUSED for %v", h.Interface, d)
			ticker.Stop()
			select {
			case <-time.After(d):
				log.Printf("Hopper on %s RESUMING", h.Interface)
				ticker.Reset(h.Delay)
			case <-h.stopChan:
				return
			}
		case <-ticker.C:
			h.hop()
		}
	}
}

// Pause temporarily stops the hopper for the given duration.
func (h *ChannelHopper) Pause(duration time.Duration) {
	select {
	case h.resetChan <- duration:
	default:
	}
}

func (h *ChannelHopper) hop() {
	// Get a thread-safe copy of current channels
	// Optimization: We could hold lock specifically for index, but channels can change.
	h.mu.Lock()
	if len(h.Channels) == 0 {
		h.mu.Unlock()
		return
	}

	// Round Robin logic
	if h.currentIndex >= len(h.Channels) {
		h.currentIndex = 0
	}
	ch := h.Channels[h.currentIndex]

	// Prepare next index
	h.currentIndex++
	if h.currentIndex >= len(h.Channels) {
		h.currentIndex = 0
	}
	h.mu.Unlock()

	start := time.Now()
	if err := h.switcher.SetChannel(h.Interface, ch); err != nil {
		h.errorCount++
		// Log warning but don't spam if it's persistent (e.g. every 10 errors)
		if h.errorCount == 1 || h.errorCount%10 == 0 {
			log.Printf("Warning: Failed to set channel %d: %v (Consecutive errors: %d)", ch, err, h.errorCount)
		}
	} else {
		// Success
		if h.errorCount > 0 {
			log.Printf("Hopper recovered after %d errors.", h.errorCount)
			h.errorCount = 0
		}

		if h.Delay > 500*time.Millisecond {
			if ch > 14 {
				log.Printf("Hopper: Jumped to 5GHz channel %d", ch)
			}
		}

		// Optional: Track hop duration logic if needed
		_ = time.Since(start)
	}
}
