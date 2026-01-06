package main

import (
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

	// Get stats
	count, lastUpdate, err := db.GetStats()
	if err != nil {
		log.Fatalf("Failed to get stats: %v", err)
	}

	fmt.Printf("OUI Database Statistics:\n")
	fmt.Printf("  Total entries: %d\n", count)
	fmt.Printf("  Last updated: %s\n", lastUpdate.Format("2006-01-02 15:04:05"))
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
	for _, mac := range testMACs {
		vendor, err := db.LookupVendor(mac)
		if err != nil {
			log.Printf("  %s -> ERROR: %v", mac, err)
		} else {
			fmt.Printf("  %s -> %s\n", mac, vendor)
		}
	}
}
