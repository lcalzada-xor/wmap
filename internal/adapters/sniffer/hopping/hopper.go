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
	mu           sync.RWMutex // Protects Channels and ensures atomicity of Lock/Hop operations
	stopChan     chan struct{}
	stopOnce     sync.Once
	resetChan    chan time.Duration
	currentIndex int // For Round Robin
	errorCount   int
	state        AtomicState
}

// NewHopper creates a new ChannelHopper.
func NewHopper(iface string, channels []int, delay time.Duration, switcher ChannelSwitcher) *ChannelHopper {
	if switcher == nil {
		switcher = NewLinuxChannelSwitcher()
	}
	h := &ChannelHopper{
		Interface: iface,
		Channels:  channels,
		Delay:     delay,
		switcher:  switcher,
		stopChan:  make(chan struct{}),
		resetChan: make(chan time.Duration, 1),
	}
	h.state.Set(StateIdle)
	return h
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

// GetState returns the current state of the hopper.
func (h *ChannelHopper) GetState() HopperState {
	return h.state.Get()
}

// Stop signals the hopper to shut down.
func (h *ChannelHopper) Stop() {
	h.stopOnce.Do(func() {
		h.state.Set(StateStopped)
		close(h.stopChan)
	})
}

// Start begins the channel hopping loop.
func (h *ChannelHopper) Start() {
	if !h.state.CompareAndSwap(StateIdle, StateHopping) {
		// Only start if Idle. If Stopped or already Hopping, ignore.
		// Note: A Stopped hopper cannot be restarted. New instance required.
		return
	}

	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in ChannelHopper: %v", r)
		}
	}()

	log.Printf("Starting channel hopper on %s (dwell=%v)", h.Interface, h.Delay)

	ticker := time.NewTicker(h.Delay)
	defer ticker.Stop()

	// Initial hop if we can
	h.hop()

	for {
		select {
		case <-h.stopChan:
			log.Printf("Stopping channel hopper on %s", h.Interface)
			return
		case d := <-h.resetChan:
			// Pause logic
			if h.state.CompareAndSwap(StateHopping, StatePaused) {
				log.Printf("Hopper on %s PAUSED for %v", h.Interface, d)
				ticker.Stop()
				select {
				case <-time.After(d):
					log.Printf("Hopper on %s RESUMING", h.Interface)
					h.state.Set(StateHopping)
					ticker.Reset(h.Delay)
				case <-h.stopChan:
					return
				}
			}
		case <-ticker.C:
			// Only hop if we are in Hopping state
			if h.state.Get() == StateHopping {
				h.hop()
			}
		}
	}
}

// Pause temporarily stops the hopper for the given duration.
func (h *ChannelHopper) Pause(duration time.Duration) {
	// Only pause if currently hopping or locked? Usually only if hopping.
	// If Locked, implicit pause already.
	if h.state.Get() == StateHopping {
		select {
		case h.resetChan <- duration:
		default:
		}
	}
}

// Lock forces the hopper to stay on a specific channel.
func (h *ChannelHopper) Lock(channel int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update state
	h.state.Set(StateLocked)

	// Force switch
	if err := h.switcher.SetChannel(h.Interface, channel); err != nil {
		return err
	}
	log.Printf("Hopper LOCKED on channel %d", channel)
	return nil
}

// Unlock resumes hopping.
func (h *ChannelHopper) Unlock() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Only unlock if Locked
	if h.state.Get() == StateLocked {
		h.state.Set(StateHopping)
		log.Printf("Hopper UNLOCKED, resuming...")
		// The ticker in Start() will pick up regular hopping
	}
}

func (h *ChannelHopper) hop() {
	// Synchronization:
	// We hold the lock to check state AND switch channel to prevent race with Lock()
	h.mu.Lock()
	defer h.mu.Unlock()

	// Double check state inside lock
	if h.state.Get() != StateHopping {
		return
	}

	if len(h.Channels) == 0 {
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

	// Perform Switch
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
