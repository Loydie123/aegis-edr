package plugin

import (
	"testing"
)

func TestExecutePluginValidation(t *testing.T) {
	t.Parallel()

	m := NewManager()
	defer m.Close()

	invalidBytes := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := m.ExecutePlugin(invalidBytes, []byte("test"))
	if err == nil {
		t.Error("expected invalid WASM compile to fail")
	}

	validHeaderMissingExports := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
	}
	_, err = m.ExecutePlugin(validHeaderMissingExports, []byte("test"))
	if err == nil {
		t.Error("expected instantiation to fail due to missing exports")
	}
	if err.Error() != "missing expected WASM exports: malloc, free, run" {
		t.Errorf("expected missing exports error, got: %v", err)
	}
}
