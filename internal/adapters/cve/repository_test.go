package cve

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/lcalzada-xor/wmap/internal/core/domain"
)

func TestSQLiteRepository(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_cve.db"
	defer os.Remove(dbPath)

	repo, err := NewSQLiteRepository(dbPath)
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	// Test 1: Upsert CVE
	t.Run("UpsertCVE", func(t *testing.T) {
		cve := domain.CVERecord{
			ID:            "CVE-2020-TEST",
			Vendor:        "cisco",
			Product:       "wap321",
			VersionStart:  "1.0.0",
			VersionEnd:    "1.0.4.8",
			Description:   "Test vulnerability",
			Severity:      9.8,
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Now(),
			AttackVector:  "NETWORK",
			References:    []string{"https://example.com/advisory"},
		}

		err := repo.UpsertCVE(ctx, cve)
		if err != nil {
			t.Errorf("UpsertCVE failed: %v", err)
		}

		// Verify it was inserted
		retrieved, err := repo.GetByID(ctx, "CVE-2020-TEST")
		if err != nil {
			t.Errorf("GetByID failed: %v", err)
		}
		if retrieved == nil {
			t.Error("CVE not found after insert")
		}
		if retrieved.Vendor != "cisco" {
			t.Errorf("Vendor mismatch: got %s, want cisco", retrieved.Vendor)
		}
	})

	// Test 2: FindByVendorProduct
	t.Run("FindByVendorProduct", func(t *testing.T) {
		cves, err := repo.FindByVendorProduct(ctx, "cisco", "wap321")
		if err != nil {
			t.Errorf("FindByVendorProduct failed: %v", err)
		}
		if len(cves) == 0 {
			t.Error("Expected at least 1 CVE for cisco/wap321")
		}
		if cves[0].ID != "CVE-2020-TEST" {
			t.Errorf("Expected CVE-2020-TEST, got %s", cves[0].ID)
		}
	})

	// Test 3: SearchByKeywords
	t.Run("SearchByKeywords", func(t *testing.T) {
		cves, err := repo.SearchByKeywords(ctx, []string{"test", "vulnerability"})
		if err != nil {
			t.Errorf("SearchByKeywords failed: %v", err)
		}
		if len(cves) == 0 {
			t.Error("Expected at least 1 CVE matching keywords")
		}
	})

	// Test 4: GetTotalCount
	t.Run("GetTotalCount", func(t *testing.T) {
		count, err := repo.GetTotalCount(ctx)
		if err != nil {
			t.Errorf("GetTotalCount failed: %v", err)
		}
		if count < 1 {
			t.Errorf("Expected count >= 1, got %d", count)
		}
	})

	// Test 5: Sync Status
	t.Run("SyncStatus", func(t *testing.T) {
		status := domain.CVESyncStatus{
			LastSyncTime: time.Now(),
			RecordCount:  1,
			ErrorMessage: "",
		}

		err := repo.UpdateSyncStatus(ctx, status)
		if err != nil {
			t.Errorf("UpdateSyncStatus failed: %v", err)
		}

		lastSync, err := repo.GetLastSyncTime(ctx)
		if err != nil {
			t.Errorf("GetLastSyncTime failed: %v", err)
		}
		if lastSync.IsZero() {
			t.Error("Last sync time should not be zero")
		}
	})
}
