package main

import (
	"context"
	"encoding/csv"
	"flag"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
)

func main() {
	csvPath := flag.String("csv", "data/oui/maclookup.csv", "Path to CSV file")
	dbPath := flag.String("db", "data/oui/ieee_oui.db", "Path to OUI database")
	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()

	log.Printf("Importing OUI data from CSV to database...")
	log.Printf("CSV: %s", *csvPath)
	log.Printf("DB: %s", *dbPath)

	// Open CSV file
	f, err := os.Open(*csvPath)
	if err != nil {
		log.Fatalf("Failed to open CSV: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Skip header
	_, err = reader.Read()
	if err != nil {
		log.Fatalf("Failed to read header: %v", err)
	}

	// Open/create database
	db, err := fingerprint.NewOUIDatabase(*dbPath, 1000, nil)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	entries := []fingerprint.OUIEntry{}
	lineNum := 0
	now := time.Now()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Warning: Failed to parse line %d: %v", lineNum, err)
			continue
		}

		lineNum++

		// CSV format: Mac Prefix,Vendor Name,Private,Block Type,Last Update
		if len(record) < 2 {
			continue
		}

		macPrefix := strings.TrimSpace(record[0])
		vendor := strings.TrimSpace(record[1])

		// Normalize MAC prefix to XX:XX:XX format
		macPrefix = strings.ReplaceAll(macPrefix, "-", ":")
		macPrefix = strings.ToUpper(macPrefix)

		// Extract short vendor name
		vendorShort := extractShortVendor(vendor)

		if macPrefix == "" || vendor == "" {
			continue
		}

		entries = append(entries, fingerprint.OUIEntry{
			Prefix:      macPrefix,
			Vendor:      vendor,
			VendorShort: vendorShort,
			Address:     "",
			Country:     "",
			LastUpdated: now,
		})

		// Batch insert every 1000 entries
		if len(entries) >= 1000 {
			if err := db.BulkInsertOUIs(ctx, entries); err != nil {
				log.Fatalf("Bulk insert failed: %v", err)
			}
			if *verbose {
				log.Printf("  Inserted %d entries...", lineNum)
			}
			entries = []fingerprint.OUIEntry{}
		}
	}

	// Insert remaining entries
	if len(entries) > 0 {
		if err := db.BulkInsertOUIs(ctx, entries); err != nil {
			log.Fatalf("Bulk insert failed: %v", err)
		}
	}

	// Get final stats
	stats, err := db.GetStats(ctx)
	if err != nil {
		log.Fatalf("Failed to get stats: %v", err)
	}

	log.Printf("✓ Import complete!")
	log.Printf("  Total entries: %d", stats.TotalEntries)
	log.Printf("  Last updated: %s", stats.LastUpdated)
}

func extractShortVendor(vendor string) string {
	// Remove common suffixes
	vendor = strings.TrimSpace(vendor)
	vendor = strings.TrimSuffix(vendor, " Inc.")
	vendor = strings.TrimSuffix(vendor, " Inc")
	vendor = strings.TrimSuffix(vendor, " Corporation")
	vendor = strings.TrimSuffix(vendor, " Corp.")
	vendor = strings.TrimSuffix(vendor, " Corp")
	vendor = strings.TrimSuffix(vendor, " Ltd.")
	vendor = strings.TrimSuffix(vendor, " Ltd")
	vendor = strings.TrimSuffix(vendor, " Limited")
	vendor = strings.TrimSuffix(vendor, " Co., Ltd.")
	vendor = strings.TrimSuffix(vendor, " Co.")
	vendor = strings.TrimSuffix(vendor, " LLC")
	vendor = strings.TrimSuffix(vendor, " GmbH")
	vendor = strings.TrimSuffix(vendor, " S.A.")
	vendor = strings.TrimSuffix(vendor, " AG")

	// Take first part if comma-separated
	if idx := strings.Index(vendor, ","); idx > 0 {
		vendor = vendor[:idx]
	}

	return strings.TrimSpace(vendor)
}
