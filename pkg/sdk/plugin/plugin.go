package plugin

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const APIVersion = "1.0.0"

type PluginCapability string

const (
	CapDetection    PluginCapability = "Detection"
	CapOutput       PluginCapability = "Output"
	CapNotification PluginCapability = "Notification"
	CapIntel        PluginCapability = "Intel"
	CapStorage      PluginCapability = "Storage"
	CapReport       PluginCapability = "Report"
)

type PluginMetadata struct {
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	APIVersion   string             `json:"api_version"`
	Capabilities []PluginCapability `json:"capabilities"`
}

type AegisPlugin interface {
	Metadata() PluginMetadata
	Init(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Execute(ctx context.Context, cap PluginCapability, input []byte) ([]byte, error)
}

type Manager struct {
	mu      sync.RWMutex
	runtime wazero.Runtime
	plugins map[string]AegisPlugin
}

func NewManager() *Manager {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	return &Manager{
		runtime: r,
		plugins: make(map[string]AegisPlugin),
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.plugins {
		_ = p.Stop(context.Background())
	}
	return m.runtime.Close(context.Background())
}

func (m *Manager) RegisterPlugin(ctx context.Context, p AegisPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	meta := p.Metadata()
	if meta.Name == "" {
		return errors.New("plugin name cannot be empty")
	}
	if meta.APIVersion != APIVersion {
		return fmt.Errorf("plugin API version mismatch: expected %s, got %s", APIVersion, meta.APIVersion)
	}

	if err := p.Init(ctx); err != nil {
		return fmt.Errorf("plugin init failed: %w", err)
	}
	if err := p.Start(ctx); err != nil {
		return fmt.Errorf("plugin start failed: %w", err)
	}

	m.plugins[meta.Name] = p
	return nil
}

func (m *Manager) UnregisterPlugin(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not registered", name)
	}

	_ = p.Stop(ctx)
	delete(m.plugins, name)
	return nil
}

func (m *Manager) HotReloadPlugin(ctx context.Context, p AegisPlugin) error {
	meta := p.Metadata()
	_ = m.UnregisterPlugin(ctx, meta.Name)
	return m.RegisterPlugin(ctx, p)
}

func (m *Manager) NegotiateAndExecute(ctx context.Context, name string, cap PluginCapability, input []byte) ([]byte, error) {
	m.mu.RLock()
	p, exists := m.plugins[name]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	meta := p.Metadata()
	supported := false
	for _, c := range meta.Capabilities {
		if c == cap {
			supported = true
			break
		}
	}

	if !supported {
		return nil, fmt.Errorf("capability negotiation failed: plugin %s does not support %s", name, cap)
	}

	return p.Execute(ctx, cap, input)
}

func (m *Manager) ExecutePlugin(wasmBytes []byte, inputData []byte) ([]byte, error) {
	ctx := context.Background()

	code, err := m.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, err
	}

	conf := wazero.NewModuleConfig().
		WithStdout(nil).
		WithStderr(nil)

	mod, err := m.runtime.InstantiateModule(ctx, code, conf)
	if err != nil {
		return nil, err
	}
	defer mod.Close(ctx)

	alloc := mod.ExportedFunction("malloc")
	free := mod.ExportedFunction("free")
	run := mod.ExportedFunction("run")

	if alloc == nil || free == nil || run == nil {
		return nil, errors.New("missing expected WASM exports: malloc, free, run")
	}

	inputLen := uint64(len(inputData))
	results, err := alloc.Call(ctx, inputLen)
	if err != nil {
		return nil, err
	}
	inputPtr := results[0]
	defer free.Call(ctx, inputPtr)

	if !mod.Memory().Write(uint32(inputPtr), inputData) {
		return nil, errors.New("failed to write input bytes to WASM memory")
	}

	res, err := run.Call(ctx, inputPtr, inputLen)
	if err != nil {
		return nil, err
	}

	outputPtr := res[0]
	outputLen := res[1]

	outputData, ok := mod.Memory().Read(uint32(outputPtr), uint32(outputLen))
	if !ok {
		return nil, errors.New("failed to read output bytes from WASM memory")
	}

	return outputData, nil
}
