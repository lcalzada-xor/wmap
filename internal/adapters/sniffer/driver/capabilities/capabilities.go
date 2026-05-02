// Package capabilities queries a wireless NIC's supported channels and bands
// by parsing "iw phy <phy> info" output.
package capabilities

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/driver/executor"
)

// Frequency band boundary constants (MHz).
const (
	FreqBoundary24GHz   = 4000
	FreqBoundary5GHzMin = 4900
	FreqBoundary5GHzMax = 5900

	// 6 GHz (Wi-Fi 6E) starts at 5925 MHz. The 802.11ax channel numbering for
	// 6 GHz reuses the same small integers as 2.4 GHz (ch 1 = 5955 MHz, ch 5 =
	// 5975 MHz, etc.), which makes plain channel numbers ambiguous. The channel
	// switcher uses "iw set channel N" which cannot distinguish the two bands, so
	// 6 GHz channels are excluded here until the hopper is extended to use
	// frequency-based switching ("iw set freq <MHz>") for that band.
	FreqBoundary6GHzMin = 5925
)

var reFreqChan = regexp.MustCompile(`\*\s+([0-9]+)(\.[0-9]+)?\s+MHz\s+\[([0-9]+)\]`)

// Result holds the capabilities discovered for a given PHY.
type Result struct {
	// Bands is a set of band labels present: "2.4GHz", "5GHz", "6GHz".
	Bands map[string]bool
	// Channels is the ordered list of supported channel numbers.
	Channels []int
	// ChannelFreq maps channel number → center frequency in MHz.
	// Used by the hopper to switch via "iw set freq" instead of "iw set channel"
	// for 5 GHz channels where the channel-number command ignores bandwidth context.
	ChannelFreq map[int]int
}

// Get returns the bands and channel list supported by iface's underlying PHY.
func Get(exec executor.CommandExecutor, iface string) (Result, error) {
	phy, err := phyForInterface(exec, iface)
	if err != nil {
		return Result{}, fmt.Errorf("resolving phy for %s: %w", iface, err)
	}
	return phyCapabilities(exec, phy)
}

// phyForInterface maps an interface name to its "phyN" radio identifier by
// parsing "iw dev" output.
func phyForInterface(exec executor.CommandExecutor, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "iw", "dev")
	if err != nil {
		return "", fmt.Errorf("iw dev: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	currentPhy := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phy#") {
			currentPhy = line
		} else if strings.HasPrefix(line, "Interface "+iface) {
			return strings.Replace(currentPhy, "#", "", 1), nil
		}
	}
	return "", fmt.Errorf("interface %s not found in iw dev output", iface)
}

// phyCapabilities parses "iw phy <phy> info" to extract bands and channels.
func phyCapabilities(exec executor.CommandExecutor, phy string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.Execute(ctx, "iw", "phy", phy, "info")
	if err != nil {
		return Result{}, fmt.Errorf("iw phy %s info: %w", phy, err)
	}

	res := Result{
		Bands:       make(map[string]bool),
		Channels:    []int{},
		ChannelFreq: make(map[int]int),
	}

	seen := make(map[int]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	inFrequencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "Frequencies:" {
			inFrequencies = true
			continue
		}

		if !inFrequencies {
			continue
		}

		if !strings.HasPrefix(line, "*") {
			inFrequencies = false
			continue
		}

		// Skip disabled channels; keep channels marked "(no IR)" — they can
		// still receive.
		if strings.Contains(line, "(disabled)") {
			continue
		}

		matches := reFreqChan.FindStringSubmatch(line)
		if len(matches) <= 3 {
			continue
		}

		freq, _ := strconv.Atoi(matches[1])
		ch, _ := strconv.Atoi(matches[3])

		// 6 GHz channels are excluded: their channel numbers overlap with 2.4 GHz
		// (e.g. 5955 MHz → ch 1, same as 2412 MHz → ch 1). The hopper uses
		// "iw set channel N" which cannot resolve the ambiguity. Skip until
		// frequency-based switching is implemented.
		if freq >= FreqBoundary6GHzMin {
			res.Bands["6GHz"] = true
			continue
		}

		if seen[ch] {
			continue
		}
		seen[ch] = true
		res.Channels = append(res.Channels, ch)
		res.ChannelFreq[ch] = freq

		switch {
		case freq < FreqBoundary24GHz:
			res.Bands["2.4GHz"] = true
		case freq >= FreqBoundary5GHzMin && freq < FreqBoundary5GHzMax:
			res.Bands["5GHz"] = true
		}
	}

	return res, nil
}
