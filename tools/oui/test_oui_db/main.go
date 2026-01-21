package main

import (
	"context"
	"fmt"
	"log"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
)

func main() {
	// Initialize database
	db, err := fingerprint.NewOUIDatabase("data/oui/ieee_oui.db", 10000, nil)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Get stats
	stats, err := db.GetStats(ctx)
	if err != nil {
		log.Fatalf("Failed to get stats: %v", err)
	}

	fmt.Printf("OUI Database Statistics:\n")
	fmt.Printf("  Total entries: %d\n", stats.TotalEntries)
	fmt.Printf("  Last updated: %s\n", stats.LastUpdated)
	fmt.Printf("  Cache stats: Hits=%d Misses=%d\n", stats.CacheHits, stats.CacheMisses)
	fmt.Println()

	// Test lookups
	testMACs := []string{
		"00:00:0C:12:34:56", // Cisco
		"00:03:93:11:22:33", // Apple
		"00:00:F0:AA:BB:CC", // Samsung
		"18:FE:34:12:34:56", // Espressif
		"B8:27:EB:11:22:33", // Raspberry Pi
		"00:1A:11:AA:BB:CC", // Google
		"3C:5A:B4:11:22:33", // Google
		"FF:FF:FF:11:22:33", // Unknown
	}

	fmt.Println("Test Lookups:")
	for _, macStr := range testMACs {
		mac, err := fingerprint.ParseMAC(macStr)
		if err != nil {
			log.Printf("  %s -> Invalid format: %v", macStr, err)
			continue
		}

		vendor, err := db.LookupVendor(ctx, mac)
		if err != nil {
			log.Printf("  %s -> ERROR: %v", macStr, err)
		} else {
			fmt.Printf("  %s -> %s\n", macStr, vendor)
		}
	}
}
