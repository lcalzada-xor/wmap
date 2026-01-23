package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/lcalzada-xor/wmap/internal/adapters/cve"
)

func main() {
	seedFile := flag.String("seed-file", "./configs/cve_seed.json", "Path to CVE seed JSON file")
	dbPath := flag.String("db-path", "./data/cve.db", "Path to CVE database")
	flag.Parse()

	log.Println("=== CVE Seed Loader ===")
	log.Printf("Seed file: %s", *seedFile)
	log.Printf("Database: %s", *dbPath)

	// Ensure data directory exists
	if err := os.MkdirAll("./data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Create repository
	repo, err := cve.NewSQLiteRepository(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Load seed data
	loader := cve.NewSeedLoader(repo)
	ctx := context.Background()

	if err := loader.LoadFromFile(ctx, *seedFile); err != nil {
		log.Fatalf("Failed to load seed data: %v", err)
	}

	// Show stats
	count, _ := repo.GetTotalCount(ctx)
	log.Printf("✓ Database now contains %d CVEs", count)
}
