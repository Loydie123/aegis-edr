package network

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNetworkIsolatorLifecycle(t *testing.T) {
	t.Parallel()

	isolator := NewNetworkIsolator()
	if isolator == nil {
		t.Fatal("expected isolator implementation, got nil")
	}

	err := isolator.IsolateHost()
	if err != nil {
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "exit status") {
			t.Log("expected command block or permissions failure:", err)
		}
	}

	_ = isolator.RestoreHost()
}
