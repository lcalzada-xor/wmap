package mapper

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer/ie"
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
	// Defaults
	device.Security = "OPEN"
	device.Standard = "802.11g/a" // baseline

	reg := getRegistry()

	ie.IterateIEs(data, func(id int, val []byte) {
		device.IETags = append(device.IETags, id)

		if handler, found := reg.Get(id); found {
			_ = handler.Handle(val, device)
		}
	})

	// Compute Signature if we have tags
	if len(device.IETags) > 0 {
		device.Signature = ComputeSignature(device.IETags, nil)
	}
}

// ComputeSignature builds a hash based on IE tags and optional values
func ComputeSignature(tags []int, specificValues []string) string {
	// We do NOT sort tags because order matters for fingerprinting

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

// Helper function used by handlers
func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
