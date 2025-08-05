# Falco Nginx Plugin Makefile
VERSION := 0.3.1
PLUGIN_NAME := libfalco-nginx-plugin.so

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build directories
BUILD_DIR := build
PLUGIN_DIR := $(BUILD_DIR)/plugin

# Build flags
CGO_ENABLED := 1
LDFLAGS := -ldflags "-s -w"

.PHONY: all build clean test deps

all: build

build: deps
	@echo "Building Falco nginx plugin v$(VERSION)..."
	@mkdir -p $(PLUGIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -buildmode=c-shared $(LDFLAGS) -o $(PLUGIN_DIR)/$(PLUGIN_NAME) cmd/nginx.go
	@echo "Build complete: $(PLUGIN_DIR)/$(PLUGIN_NAME)"

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

install: build
	@echo "Installing plugin..."
	sudo cp $(PLUGIN_DIR)/$(PLUGIN_NAME) /usr/share/falco/plugins/
	@echo "Installation complete"

checksum: build
	@echo "Generating checksum..."
	@cd $(PLUGIN_DIR) && sha256sum $(PLUGIN_NAME) | tee $(PLUGIN_NAME).sha256

.DEFAULT_GOAL := build