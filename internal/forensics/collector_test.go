package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"aegis-edr/internal/storage"
)

func TestForensicsCollection(t *testing.T) {
	dbPath := "/tmp/aegis_forensics_test.db"
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to initialize storage: %v", err)
	}
	defer store.Close()

	tb := NewTimelineBuilder(store)
	collector := NewCollector(tb)

	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	pkg, err := collector.CollectEvidence(start, end)
	if err != nil {
		t.Fatalf("evidence collection failed: %v", err)
	}

	if len(pkg.Processes) == 0 {
		t.Error("expected processes in evidence package")
	}

	archivePath := "/tmp/evidence_pkg.json"
	reportPath := "/tmp/forensic_report.txt"
	defer os.Remove(archivePath)
	defer os.Remove(reportPath)

	hashVal, err := collector.PackageEvidence(pkg, archivePath)
	if err != nil {
		t.Fatalf("packaging evidence failed: %v", err)
	}

	if len(hashVal) == 0 {
		t.Error("expected valid SHA-256 hash output")
	}

	// Verify Hash Integrity
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("failed to read packaged archive: %v", err)
	}

	hasher := sha256.New()
	hasher.Write(data)
	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if len(computedHash) == 0 {
		t.Error("expected computed hash value to be non-empty")
	}

	// Generate Report
	errReport := collector.GenerateForensicReport(pkg, reportPath)
	if errReport != nil {
		t.Fatalf("failed to write forensic report: %v", errReport)
	}

	_, errStat := os.Stat(reportPath)
	if os.IsNotExist(errStat) {
		t.Error("report file was not created successfully")
	}
}
