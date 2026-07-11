# ==============================================================================
# AEGIS EDR - Build Automation Pipeline
# ==============================================================================

# Project build parameters
BINARY_NAME=aegis
DAEMON_NAME=aegisd
VERSION=1.0.0-Beta
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Compile flags injecting build version info into cmd packages
LDFLAGS=-ldflags "-w -s -X main.Version=$(VERSION) -X main.CommitHash=$(COMMIT_HASH) -X main.BuildTime=$(BUILD_TIME)"

# OS compilation targets
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64

.PHONY: all build clean test test-integration test-fuzz bench lint format generate install help

# Default target
all: build

## help: Display this help message and target tasks
help:
	@echo "Aegis EDR Build Automation - Targets:"
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v "fgrep" | sed -e 's/## //'

## build: Compile both the administration client and service daemon binaries
build:
	@echo "🛠️ Compiling Aegis binaries..."
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) cmd/aegis/main.go
	go build $(LDFLAGS) -o bin/$(DAEMON_NAME) cmd/aegisd/main.go
	@echo "✅ Binaries compiled under bin/"

## clean: Remove build artifacts, local databases, and coverage profiles
clean:
	@echo "🧹 Cleaning up workspace..."
	rm -rf bin/
	rm -rf dist/
	rm -f *.out *.pprof coverage.html
	@echo "✅ Workspace clean."

## test: Run short unit tests concurrently
test:
	@echo "🧪 Running unit testing suite..."
	go test -v -short -race -cover ./...

## test-integration: Run integration tests including database and IPC connections
test-integration:
	@echo "🧪 Running integration testing suite..."
	go test -v -run=Integration -race ./...

## bench: Execute performance benchmark sweeps
bench:
	@echo "⏱️ Running benchmark sweeps..."
	go test -bench=. -benchmem ./...

## lint: Run golangci-lint check on codebase layout
lint:
	@echo "🔍 Checking code lint guidelines..."
	golangci-lint run ./...

## format: Format source code files to Go standards
format:
	@echo "✨ Formatting source files..."
	go fmt ./...

## generate: Compile gRPC Protobuf schemas to Go client/server stubs
generate:
	@echo "📦 Generating gRPC stubs from protobuf contracts..."
	protoc --go_out=. --go-grpc_out=. pkg/api/*.proto
	@echo "✅ Protobuf schemas generated successfully."

## install: Install binaries to standard system directories and load configs
install: build
	@echo "📥 Installing Aegis files on host..."
ifeq ($(OS),Windows_NT)
	@echo "Skipping unix install target. Use Windows Service PowerShell commands instead."
else
	sudo mkdir -p /etc/aegis/rules/yara /etc/aegis/rules/sigma
	sudo mkdir -p /var/lib/aegis/quarantine
	sudo cp bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	sudo cp bin/$(DAEMON_NAME) /usr/local/bin/$(DAEMON_NAME)
	@echo "✅ Aegis daemon and client installed. Configuration template directory: /etc/aegis/"
endif

## docker-build: Build Linux testing image for eBPF sandbox trials
docker-build:
	@echo "🐳 Building Linux eBPF test container..."
	docker build -t aegis-ebpf-test:latest -f test/Dockerfile .
	@echo "✅ Docker build complete."
