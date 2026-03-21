package ie

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"

	snifferIE "github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

var (
	registry     *HandlerRegistry
	registryOnce sync.Once
)

func getRegistry() *HandlerRegistry {
	registryOnce.Do(func() {
		registry = NewHandlerRegistry()
	})
	return registry
}

// ParseIEs extracts information from 802.11 Information Elements and populates the Device model.
func ParseIEs(data []byte, device *domain.Device) {
	device.Security = "OPEN"
	device.Standard = "802.11g/a" // baseline

	reg := getRegistry()

	snifferIE.IterateIEs(data, func(id int, val []byte) {
		device.IETags = append(device.IETags, id)

		if handler, found := reg.Get(id); found {
			if err := handler.Handle(val, device); err != nil {
				log.Printf("Warning: Failed to parse IE %d (len=%d): %v", id, len(val), err)
			}
		}
	})

	if len(device.IETags) > 0 {
		device.Signature = ComputeSignature(device.IETags, nil)
	}
}

// ComputeSignature builds an MD5 hash based on IE tag sequence and optional values.
// Tag order is preserved because it matters for device fingerprinting.
func ComputeSignature(tags []int, specificValues []string) string {
	var sb strings.Builder
	for _, t := range tags {
		sb.WriteString(fmt.Sprintf("%d,", t))
	}
	sb.WriteString("|")
	for _, v := range specificValues {
		sb.WriteString(v + ",")
	}

	hash := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}
