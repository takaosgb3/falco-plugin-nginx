# Building Falco nginx Plugin

This guide explains how to build the Falco nginx plugin from source.

## Prerequisites

- Go 1.21 or higher
- Make
- GCC (for CGO)
- Git

## Quick Build

```bash
# Clone the repository
git clone https://github.com/takaosgb3/falco-nginx-plugin-claude.git
cd falco-nginx-plugin-claude

# Build the SDK version (recommended)
make build-sdk

# The binary will be at: build/plugin-sdk/libfalco-nginx-plugin.so
```

## Build Options

### SDK Version (Recommended)
```bash
make build-sdk
```

This builds the plugin using the Falco Plugin SDK for Go. This is the recommended approach.

### All Targets
```bash
make build
```

This builds both SDK and legacy versions.

### Linux Binary (Cross-compilation)
```bash
make build-linux
```

Builds a Linux AMD64 binary regardless of your current platform.

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Lint code
make lint
```

## Development Setup

1. **Install dependencies**:
```bash
go mod download
```

2. **Install development tools**:
```bash
make install-tools
```

3. **Run pre-commit checks**:
```bash
make check
```

## Release Build

To create a release build with version information:

```bash
VERSION=v0.3.0 make build-release
```

This creates:
- `releases/libfalco-nginx-plugin-linux-amd64.so`
- `releases/libfalco-nginx-plugin-linux-amd64.so.sha256`

## Architecture Support

Currently supported:
- Linux AMD64 (x86_64)

Planned:
- Linux ARM64
- Darwin AMD64/ARM64 (for development)

## Troubleshooting

### CGO Issues
If you encounter CGO-related errors:
```bash
export CGO_ENABLED=1
export CC=gcc
```

### Missing Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS
brew install gcc
```

### Permission Errors
Ensure you have write permissions in the build directory:
```bash
chmod -R u+w build/
```