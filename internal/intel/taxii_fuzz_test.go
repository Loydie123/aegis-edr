package intel

import (
	"os"
	"testing"

	"aegis-edr/internal/storage"
)

func FuzzIngestSTIXBundle(f *testing.F) {
	tmpfile, err := os.CreateTemp("", "aegis_fuzz_taxii_*.db")
	if err != nil {
		return
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		return
	}
	defer store.Close()

	client := NewTAXIIClient(store)

	f.Add([]byte(`{"type": "bundle", "id": "bundle--1", "objects": [{"type": "indicator", "id": "indicator--1", "pattern": "abcd", "pattern_type": "stix", "labels": ["malicious"]}]}`))
	f.Add([]byte(`invalid json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = client.IngestSTIXBundle(data)
	})
}
