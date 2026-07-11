package plugin

import (
	"context"
	"errors"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type Manager struct {
	runtime wazero.Runtime
}

func NewManager() *Manager {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	return &Manager{runtime: r}
}

func (m *Manager) Close() error {
	return m.runtime.Close(context.Background())
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
