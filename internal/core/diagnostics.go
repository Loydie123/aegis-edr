package core

import (
	"os"
)

type StartupDiagnostics struct{}

func NewStartupDiagnostics() *StartupDiagnostics {
	return &StartupDiagnostics{}
}

func (sd *StartupDiagnostics) Run() error {
	tmpFile := "/tmp/aegis_diagnostic_write_test"
	if err := os.WriteFile(tmpFile, []byte("ok"), 0600); err != nil {
		return err
	}
	_ = os.Remove(tmpFile)
	return nil
}
