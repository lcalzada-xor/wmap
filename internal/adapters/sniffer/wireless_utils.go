package sniffer

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// HardwareCapabilities defines what a WiFi card supports.
type HardwareCapabilities struct {
	Supported frequencies
}

type frequencies struct {
	Bands map[string][]int
}

// GetInterfaceCapabilities returns the supported channels for a given interface.
func GetInterfaceCapabilities(iface string) (map[string]bool, []int, error) {
	// 1. Map Interface -> Phy
	phy, err := getPhyForInterface(iface)
	if err != nil {
		return nil, nil, err
	}

	// 2. Get Phy Capabilities
	return getPhyCapabilities(phy)
}

func getPhyForInterface(iface string) (string, error) {
	cmd := exec.Command("iw", "dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Output format:
	// phy#0
	// 		Interface wlan0
	//      ...
	// phy#1
	//      Interface wlan1

	scanner := bufio.NewScanner(bytes.NewReader(out))
	currentPhy := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "phy#") {
			currentPhy = line // e.g., "phy#0"
		} else if strings.HasPrefix(line, "Interface "+iface) {
			// Found our interface under currentPhy
			// Return format "phy0" (remove #) usually works for `iw phy phy0 info`?
			// `iw list` uses "Wiphy phy0". `iw phy` uses "phy0".
			// "phy#0" -> "phy0"
			return strings.Replace(currentPhy, "#", "", 1), nil
		}
	}
	return "", fmt.Errorf("interface %s not found in iw dev output", iface)
}

func getPhyCapabilities(phy string) (map[string]bool, []int, error) {
	// "iw phy phy0 info" gives the same output as "iw list" but just for that phy
	cmd := exec.Command("iw", "phy", phy, "info")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}

	bands := make(map[string]bool)
	supportedChannels := []int{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inFrequencies := false
	// Regex to capture channel number in [...]
	// Example: * 2412 MHz [1] (20.0 dBm)
	// Example: * 5180 MHz [36] (22.0 dBm) (disabled)
	reChannel := regexp.MustCompile(`\[([0-9]+)\]`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "Frequencies:" {
			inFrequencies = true
			continue
		}

		// If we hit a new section that is not indented or starts with something else, stop frequencies
		// `iw` output indentation is significant.
		// Frequencies are indented.
		if inFrequencies {
			if strings.HasPrefix(line, "*") {
				// Process frequency line
				// If "(disabled)", skip
				if strings.Contains(line, "(disabled)") || strings.Contains(line, "(no IR)") {
					// no IR (No Initiate Radiation) often means we can listen but not beacon?
					// For sniffing, passive listening might be okay even with no IR?
					// But "disabled" definitely means unusable.
					// Let's exclude disabled.
					if strings.Contains(line, "(disabled)") {
						continue
					}
				}

				matches := reChannel.FindStringSubmatch(line)
				if len(matches) > 1 {
					ch, _ := strconv.Atoi(matches[1])
					supportedChannels = append(supportedChannels, ch)

					// Detect band based on channel number as heuristic if band header parsing failed/complex
					if ch >= 1 && ch <= 14 {
						bands["2.4ghz"] = true
					} else if ch >= 36 {
						bands["5ghz"] = true
					}
				}
			} else {
				// End of frequencies section usually indented or empty
				// We can rely on next "Band" or other headers to reset `inFrequencies`?
				// Actually, `iw` output implies Frequencies block ends when indentation changes or new section starts.
				// But simply running regex on lines starting with * usually works fine globally if we track "disabled"
				// Just need to be careful not to match other lists.
				// "Frequencies:" starts the block.
				// The lines start with "*".
				// If a line doesn't start with "*", it might be end of block?
				// Warning: "Bitrates:" also has lines with "*".
				if !strings.HasPrefix(line, "*") {
					inFrequencies = false
				}
			}
		}
	}

	return bands, supportedChannels, nil
}
