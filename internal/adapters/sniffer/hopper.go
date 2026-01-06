package sniffer

import (
	"fmt"
	"log"
	"math/rand"
	"os/exec"
	"sync"
	"time"
)

// ChannelHopper handles switching WiFi channels.
type ChannelHopper struct {
	Interface string
	Channels  []int
	Delay     time.Duration
	mu        sync.RWMutex // Protects Channels
	stopChan  chan struct{}
}

// NewHopper creates a new ChannelHopper.
func NewHopper(iface string, channels []int, delay time.Duration) *ChannelHopper {
	return &ChannelHopper{
		Interface: iface,
		Channels:  channels,
		Delay:     delay,
		stopChan:  make(chan struct{}),
	}
}

// SetChannels updates the channel list dynamically.
func (h *ChannelHopper) SetChannels(channels []int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Channels = channels
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
	log.Printf("Starting channel hopper on %s (dwell=%v)", h.Interface, h.Delay)

	// Create a local random source
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	ticker := time.NewTicker(h.Delay)
	defer ticker.Stop()

	// Initial hop
	h.hop(r)

	for {
		select {
		case <-h.stopChan:
			log.Printf("Stopping channel hopper on %s", h.Interface)
			return
		case <-ticker.C:
			h.hop(r)
		}
	}
}

func (h *ChannelHopper) hop(r *rand.Rand) {
	// Get a thread-safe copy of current channels
	channels := h.GetChannels()
	if len(channels) == 0 {
		return
	}

	// We pick ONE random channel each tick instead of looping all channels inside the loop.
	// The original implementation looped all channels THEN slept.
	// But `Start` was `for{ ... loop channels ... }`.
	// If `Delay` is per channel, we should do one channel per tick.
	// Let's refactor to standard ticker-based single hop logic which is cleaner.

	// Pick random index
	idx := r.Intn(len(channels))
	ch := channels[idx]

	// iw <iface> set channel <ch>
	cmd := exec.Command("iw", h.Interface, "set", "channel", fmt.Sprintf("%d", ch))
	if err := cmd.Run(); err != nil {
		// Log but don't stop, maybe just a busy device or invalid channel for region
		log.Printf("Warning: Failed to set channel %d: %v", ch, err)
	} else {
		if h.Delay > 500*time.Millisecond {
			// Only log if we are jumping slow, to avoid flooding
			if ch > 14 {
				log.Printf("Hopper: Jumped to 5GHz channel %d", ch)
			}
		}
	}
}
