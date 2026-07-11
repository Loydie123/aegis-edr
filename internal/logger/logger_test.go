package logger

import (
	"testing"
)

func TestLoggerInit(t *testing.T) {
	err := Init("debug")
	if err != nil {
		t.Fatalf("failed to initialize logger: %v", err)
	}

	if Log == nil {
		t.Fatal("expected global logger Log to be initialized, got nil")
	}

	Log.Info("test logger output verification message")
}
