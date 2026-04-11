BINARY   := litesoc-agent
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
LDFLAGS  := -ldflags "-X main.agentVersion=$(VERSION) -s -w"
BIN_DIR  := bin

.PHONY: all build build-all build-linux build-darwin tidy test clean install

all: tidy build

## build — compile for the current host platform.
build:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) .

## build-all — cross-compile for all supported release targets.
build-all: build-linux build-darwin

build-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)_linux_amd64 .
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)_linux_arm64 .
	GOOS=linux  GOARCH=arm   go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)_linux_arm .

build-darwin:
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)_darwin_amd64 .
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY)_darwin_arm64 .

## release-archives — build and package .tar.gz archives (mirrors install.sh expectations).
release-archives: build-all
	@mkdir -p $(BIN_DIR)/dist
	@for f in $(BIN_DIR)/$(BINARY)_linux_* $(BIN_DIR)/$(BINARY)_darwin_*; do \
		name=$$(basename $$f); \
		os_arch=$${name#$(BINARY)_}; \
		archive=$(BIN_DIR)/dist/$(BINARY)_$${os_arch}.tar.gz; \
		cp $$f $(BIN_DIR)/$(BINARY); \
		tar -czf $$archive -C $(BIN_DIR) $(BINARY) -C .. config.yaml; \
		rm -f $(BIN_DIR)/$(BINARY); \
		echo "  packed $$archive"; \
	done

## tidy — download and tidy Go module dependencies.
tidy:
	go mod tidy

## test — run all unit tests.
test:
	go test -v -race ./...

## install — install the binary system-wide (requires sudo on Linux/macOS).
install: build
	sudo install -m 0755 $(BIN_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed /usr/local/bin/$(BINARY)"

## clean — remove build artifacts.
clean:
	rm -rf $(BIN_DIR)
