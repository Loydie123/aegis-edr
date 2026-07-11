package eventrouter

import (
	"os"
	"testing"
	"time"

	"aegis-edr/pkg/logger"
	"aegis-edr/pkg/storage"
)

func TestRouterLifecycle(t *testing.T) {
	_ = logger.Init("info")

	tmpfile, err := os.CreateTemp("", "aegis_router_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	router := NewRouter(5, store)
	router.Start()

	e := GetEvent()
	e.Type = TypeProcess
	e.Timestamp = time.Now()
	e.ParentID = 100
	e.BinaryPath = "/bin/ls"
	e.SHA256 = "1234"
	e.CommandLine = "ls -la"
	e.Username = "root"

	if !router.Submit(e) {
		t.Error("expected event submission to succeed")
	}

	router.Stop()

	var count int
	err = store.DB().QueryRow("SELECT count(*) FROM processes WHERE binary_path='/bin/ls'").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 process in DB, got %d", count)
	}
}

func TestRouterTriageDrop(t *testing.T) {
	_ = logger.Init("info")

	tmpfile, err := os.CreateTemp("", "aegis_triage_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	router := NewRouter(5, store)

	for i := 0; i < 4; i++ {
		ev := GetEvent()
		ev.Type = TypeProcess
		ev.Timestamp = time.Now()
		router.Submit(ev)
	}

	evFile := GetEvent()
	evFile.Type = TypeFile
	evFile.FileAction = "read"
	evFile.FilePath = "/etc/passwd"

	if router.Submit(evFile) {
		t.Error("expected file read event to be dropped due to watermark capacity pressure")
	}
}

func BenchmarkProcessEvent(b *testing.B) {
	_ = logger.Init("error")

	tmpfile, err := os.CreateTemp("", "aegis_bench_*.db")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	router := NewRouter(10000, store)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := GetEvent()
		e.Type = TypeProcess
		e.Timestamp = time.Now()
		e.ParentID = 100
		e.BinaryPath = "/bin/ls"
		e.SHA256 = "1234"
		e.CommandLine = "ls -la"
		e.Username = "root"
		router.processEvent(e)
	}
}
