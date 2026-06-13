.PHONY: all build clean deps test ref-embed help

# Project name
BINARY_NAME = docker-pilot
BINARY_PATH = bin/$(BINARY_NAME)

# Go build parameters
GOOS = linux
GOARCH = amd64
CGO_ENABLED = 0

all: build

# Download dependencies
deps:
	go mod download
	go mod verify
	go mod tidy

# Get version from git tag or use Dev
GIT_VERSION := $(shell git describe --tags --exact-match 2>/dev/null || echo "Dev")

# Build static binary
build: deps ref-embed
	@mkdir -p bin
	GOEXPERIMENT=jsonv2 CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags="-s -w -extldflags '-static' -X main.version=$(GIT_VERSION)" \
		-o $(BINARY_PATH) \
		./cmd/...
	@echo "Build complete: $(BINARY_PATH) (version: $(GIT_VERSION))"
	@echo "File size: $$(du -h $(BINARY_PATH) | cut -f1)"

# Compress binary (requires upx)
compress: build
	upx --best --lzma $(BINARY_PATH)
	@echo "Compressed size: $$(du -h $(BINARY_PATH) | cut -f1)"

# Run tests
test:
	GOEXPERIMENT=jsonv2 go test -v ./internal/...

# Clean build artifacts
clean:
	rm -rf bin
	rm -f *.tar.gz

# Build release package
release: compress
	tar -czvf $(BINARY_NAME)-$(GOOS)-$(GOARCH).tar.gz -C bin $(BINARY_NAME)
	@echo "Release package created: $(BINARY_NAME)-$(GOOS)-$(GOARCH).tar.gz"

# Download and embed lazydocker
ref-embed:
	./scripts/ref-embed.sh

# Test container - builds and runs in container with docker.sock mounted
TRIVY_CACHE_DIR := $(if $(filter Darwin,$(shell uname -s)),$(HOME)/Library/Caches/trivy,$(HOME)/.cache/trivy)
test-container:
	docker build -t docker-pilot-test .
	docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v $(TRIVY_CACHE_DIR):/root/.cache/trivy docker-pilot-test

# Show help
help:
	@echo "Available targets:"
	@echo "  all             - Build binary (default)"
	@echo "  build           - Build static binary"
	@echo "  compress        - Build and compress with upx"
	@echo "  deps            - Download dependencies"
	@echo "  test            - Run tests"
	@echo "  clean           - Clean build artifacts"
	@echo "  release         - Build release package"
	@echo "  ref-embed       - Refresh embedded lazydocker binary"
	@echo "  test-container  - Build and test in container with docker.sock mounted"
	@echo "  help            - Show this help"

