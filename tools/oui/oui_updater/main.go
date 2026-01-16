package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lcalzada-xor/wmap/internal/adapters/fingerprint"
)

const (
	// IEEE OUI registry URL
	ieeeOUIURL = "https://standards-oui.ieee.org/oui/oui.csv"

	// Wireshark OUI database (alternative source)
	wiresharkOUIURL = "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
)

func main() {
	dbPath := flag.String("db", "data/oui/ieee_oui.db", "Path to OUI database")
	source := flag.String("source", "ieee", "Source: ieee or wireshark")
	force := flag.Bool("force", false, "Force update even if recent")
	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()

	log.Printf("OUI Database Updater")
	log.Printf("Database: %s", *dbPath)
	log.Printf("Source: %s", *source)

	// Open/create database
	db, err := fingerprint.NewOUIDatabase(*dbPath, 1000, nil)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Check if update needed
	count, lastUpdate, err := db.GetStats()
	if err != nil {
		log.Printf("Warning: Could not get stats: %v", err)
	} else {
		log.Printf("Current database: %d entries, last updated %s", count, lastUpdate.Format(time.RFC3339))

		if !*force && time.Since(lastUpdate) < 30*24*time.Hour {
			log.Printf("Database is recent (< 30 days). Use --force to update anyway.")
			return
		}
	}

	// Download and parse OUI data
	var entries []fingerprint.OUIEntry

	switch *source {
	case "ieee":
		entries, err = downloadIEEEOUI(*verbose)
	case "wireshark":
		entries, err = downloadWiresharkOUI(*verbose)
	default:
		log.Fatalf("Unknown source: %s", *source)
	}

	if err != nil {
		log.Fatalf("Failed to download OUI data: %v", err)
	}

	log.Printf("Downloaded %d OUI entries", len(entries))

	// Insert into database
	log.Printf("Inserting entries into database...")
	if err := db.BulkInsertOUIs(entries); err != nil {
		log.Fatalf("Failed to insert entries: %v", err)
	}

	// Get final stats
	count, lastUpdate, err = db.GetStats()
	if err != nil {
		log.Fatalf("Failed to get final stats: %v", err)
	}

	log.Printf("✓ Update complete!")
	log.Printf("  Total entries: %d", count)
	log.Printf("  Last updated: %s", lastUpdate.Format(time.RFC3339))
}

// downloadIEEEOUI downloads and parses the IEEE OUI CSV
func downloadIEEEOUI(verbose bool) ([]fingerprint.OUIEntry, error) {
	log.Printf("Downloading IEEE OUI registry from %s...", ieeeOUIURL)

	resp, err := http.Get(ieeeOUIURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	entries := []fingerprint.OUIEntry{}
	now := time.Now()

	// Skip header
	_, err = reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	lineNum := 0
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

		// IEEE CSV format: Registry,Assignment,Organization Name,Organization Address
		if len(record) < 3 {
			continue
		}

		prefix := normalizePrefix(record[1])
		vendor := strings.TrimSpace(record[2])
		vendorShort := extractShortVendor(vendor)
		address := ""
		if len(record) >= 4 {
			address = strings.TrimSpace(record[3])
		}

		if prefix == "" || vendor == "" {
			continue
		}

		entries = append(entries, fingerprint.OUIEntry{
			Prefix:      prefix,
			Vendor:      vendor,
			VendorShort: vendorShort,
			Address:     address,
			Country:     "",
			LastUpdated: now,
		})

		if verbose && lineNum%1000 == 0 {
			log.Printf("  Processed %d lines...", lineNum)
		}
	}

	return entries, nil
}

// downloadWiresharkOUI downloads and parses the Wireshark manuf file
func downloadWiresharkOUI(verbose bool) ([]fingerprint.OUIEntry, error) {
	log.Printf("Downloading Wireshark OUI database from %s...", wiresharkOUIURL)

	resp, err := http.Get(wiresharkOUIURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	entries := []fingerprint.OUIEntry{}
	now := time.Now()
	lineNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: XX:XX:XX<tab>ShortName<tab>LongName
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		prefix := normalizePrefix(parts[0])
		vendorShort := strings.TrimSpace(parts[1])
		vendor := vendorShort
		if len(parts) >= 3 {
			vendor = strings.TrimSpace(parts[2])
		}

		if prefix == "" || vendor == "" {
			continue
		}

		entries = append(entries, fingerprint.OUIEntry{
			Prefix:      prefix,
			Vendor:      vendor,
			VendorShort: vendorShort,
			Address:     "",
			Country:     "",
			LastUpdated: now,
		})

		if verbose && lineNum%1000 == 0 {
			log.Printf("  Processed %d lines...", lineNum)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return entries, nil
}

// normalizePrefix converts various MAC prefix formats to XX:XX:XX
func normalizePrefix(prefix string) string {
	// Remove whitespace
	prefix = strings.TrimSpace(prefix)

	// Remove common separators
	prefix = strings.ReplaceAll(prefix, "-", ":")
	prefix = strings.ReplaceAll(prefix, ".", ":")
	prefix = strings.ReplaceAll(prefix, " ", "")

	// Convert to uppercase
	prefix = strings.ToUpper(prefix)

	// Handle different lengths
	if len(prefix) >= 8 && prefix[2] == ':' && prefix[5] == ':' {
		return prefix[:8]
	}

	// If no separators, add them (assuming 6 hex chars)
	if len(prefix) >= 6 {
		return fmt.Sprintf("%s:%s:%s", prefix[0:2], prefix[2:4], prefix[4:6])
	}

	return ""
}

// extractShortVendor extracts a short vendor name from full name
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
