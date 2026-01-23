package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
)

// SeedLoader loads CVE records from JSON files into the database.
type SeedLoader struct {
	repo ports.CVERepository
}

// NewSeedLoader creates a new seed loader.
func NewSeedLoader(repo ports.CVERepository) *SeedLoader {
	return &SeedLoader{repo: repo}
}

// LoadFromFile loads CVE records from a JSON file.
func (s *SeedLoader) LoadFromFile(ctx context.Context, filepath string) error {
	log.Printf("[CVE-SEED] Loading CVEs from %s", filepath)

	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read seed file: %w", err)
	}

	var cves []domain.CVERecord
	if err := json.Unmarshal(data, &cves); err != nil {
		return fmt.Errorf("failed to parse seed file: %w", err)
	}

	loaded := 0
	failed := 0

	for _, cve := range cves {
		if err := s.repo.UpsertCVE(ctx, cve); err != nil {
			log.Printf("[CVE-SEED] Failed to load %s: %v", cve.ID, err)
			failed++
		} else {
			loaded++
		}
	}

	log.Printf("[CVE-SEED] Loaded %d CVEs (%d failed)", loaded, failed)

	// Update sync status
	status := domain.CVESyncStatus{
		LastSyncTime: cves[0].PublishedDate, // Use first CVE's date
		RecordCount:  loaded,
		ErrorMessage: "",
	}
	s.repo.UpdateSyncStatus(ctx, status)

	return nil
}

// LoadFromMultipleFiles loads CVEs from multiple JSON files.
func (s *SeedLoader) LoadFromMultipleFiles(ctx context.Context, filepaths []string) error {
	totalLoaded := 0

	for _, filepath := range filepaths {
		if err := s.LoadFromFile(ctx, filepath); err != nil {
			log.Printf("[CVE-SEED] Failed to load %s: %v", filepath, err)
			continue
		}
		totalLoaded++
	}

	log.Printf("[CVE-SEED] Loaded from %d/%d files", totalLoaded, len(filepaths))
	return nil
}
