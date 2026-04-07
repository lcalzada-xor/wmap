// Package channelplan handles channel pool definitions and partitioning logic
// for distributing Wi-Fi channels across multiple capture interfaces.
package channelplan

import "log"

// DefaultChannels is the canonical pool of channels used in a Wi-Fi scan.
// Covers the non-overlapping 2.4 GHz channels (1–13) and the most common
// 5 GHz channels used in Spain / EU. Tune per regulatory domain as needed.
var DefaultChannels = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // 2.4 GHz
	36, 40, 44, 48, 149, 153, 157, 161, // 5 GHz
}

// Partition distributes targetChannels across interfaces, respecting hardware
// capabilities. 5 GHz channels are assigned first (constrained resource), then
// 2.4 GHz. Within each band a simple load-balancing strategy assigns every
// channel to the interface that has the fewest channels so far.
//
// capabilities is a map[ifaceName][]supportedChannels. If an entry is missing
// or empty the interface is treated as supporting all channels.
func Partition(targetChannels []int, interfaces []string, capabilities map[string][]int) [][]int {
	n := len(interfaces)
	if n <= 0 {
		return nil
	}

	result := make([][]int, n)
	assignedCount := make([]int, n)

	// Split by band so we can schedule 5 GHz first.
	var band24, band5 []int
	for _, ch := range targetChannels {
		if ch <= 14 {
			band24 = append(band24, ch)
		} else {
			band5 = append(band5, ch)
		}
	}

	assignChannel := func(ch int) {
		bestIdx := -1
		minLoad := int(^uint(0) >> 1) // MaxInt

		var candidates []int
		for i, iface := range interfaces {
			supported, ok := capabilities[iface]
			if !ok || len(supported) == 0 {
				// No capability info → assume supported.
				candidates = append(candidates, i)
				continue
			}
			for _, capCh := range supported {
				if capCh == ch {
					candidates = append(candidates, i)
					break
				}
			}
		}

		if len(candidates) == 0 {
			log.Printf("channelplan: channel %d not supported by any interface, skipping", ch)
			return
		}

		for _, idx := range candidates {
			if assignedCount[idx] < minLoad {
				minLoad = assignedCount[idx]
				bestIdx = idx
			}
		}

		if bestIdx != -1 {
			result[bestIdx] = append(result[bestIdx], ch)
			assignedCount[bestIdx]++
		}
	}

	// 5 GHz first (scarce), then 2.4 GHz.
	for _, ch := range band5 {
		assignChannel(ch)
	}
	for _, ch := range band24 {
		assignChannel(ch)
	}

	return result
}

// PartitionSimple is a convenience wrapper for callers that don't have per-interface
// capability information. It creates n anonymous dummy interfaces and assumes all
// channels are supported by every interface.
func PartitionSimple(channels []int, n int) [][]int {
	dummyCaps := make(map[string][]int)
	dummyIfaces := make([]string, n)
	for i := range dummyIfaces {
		dummyIfaces[i] = ""
	}
	return Partition(channels, dummyIfaces, dummyCaps)
}
