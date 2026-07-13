package plugin

import (
	"context"
	"testing"
)

type MockPlugin struct {
	meta PluginMetadata
}

func (m *MockPlugin) Metadata() PluginMetadata { return m.meta }
func (m *MockPlugin) Init(ctx context.Context) error  { return nil }
func (m *MockPlugin) Start(ctx context.Context) error { return nil }
func (m *MockPlugin) Stop(ctx context.Context) error  { return nil }
func (m *MockPlugin) Execute(ctx context.Context, cap PluginCapability, input []byte) ([]byte, error) {
	return []byte("executed: " + string(cap)), nil
}

func TestPluginSDKLifecycle(t *testing.T) {
	manager := NewManager()
	defer manager.Close()

	ctx := context.Background()

	p1 := &MockPlugin{
		meta: PluginMetadata{
			Name:         "test-plugin",
			Version:      "1.0.0",
			APIVersion:   APIVersion,
			Capabilities: []PluginCapability{CapDetection, CapNotification},
		},
	}

	// Register
	if err := manager.RegisterPlugin(ctx, p1); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	// Execute allowed capability
	out, err := manager.NegotiateAndExecute(ctx, "test-plugin", CapDetection, []byte("test"))
	if err != nil {
		t.Fatalf("failed to execute allowed capability: %v", err)
	}
	if string(out) != "executed: Detection" {
		t.Errorf("unexpected execute result: %s", string(out))
	}

	// Reject disallowed capability
	_, err = manager.NegotiateAndExecute(ctx, "test-plugin", CapStorage, []byte("test"))
	if err == nil {
		t.Error("expected capability negotiation fail, but execution succeeded")
	}

	// Hot reload
	p1Updated := &MockPlugin{
		meta: PluginMetadata{
			Name:         "test-plugin",
			Version:      "1.1.0",
			APIVersion:   APIVersion,
			Capabilities: []PluginCapability{CapDetection, CapStorage},
		},
	}

	if err := manager.HotReloadPlugin(ctx, p1Updated); err != nil {
		t.Fatalf("hot reload failed: %v", err)
	}

	// Verify new capability allowed after hot reload
	out, err = manager.NegotiateAndExecute(ctx, "test-plugin", CapStorage, []byte("test"))
	if err != nil {
		t.Fatalf("failed to execute new capability after hot reload: %v", err)
	}
	if string(out) != "executed: Storage" {
		t.Errorf("unexpected execute result: %s", string(out))
	}
}
