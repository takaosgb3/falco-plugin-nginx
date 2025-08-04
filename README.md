# Falco Plugin for Nginx

Real-time security monitoring plugin for nginx web servers powered by Falco.

## 🚀 Quick Start

This repository provides pre-built binaries and installation guides for the Falco nginx plugin.

### Download

Download the latest release files from the [releases](releases/) directory:

- `libfalco-nginx-plugin-linux-amd64.so` - Plugin binary for Linux x86_64
- `nginx_rules.yaml` - Falco detection rules
- `libfalco-nginx-plugin-linux-amd64.so.sha256` - Checksum file

### Installation

Follow the [Quick Start Binary Installation Guide](docs/QUICK_START_BINARY_INSTALLATION.md) for detailed setup instructions.

## ✨ Features

- **Real-time Threat Detection**
  - SQL injection attacks
  - Cross-site scripting (XSS)
  - Directory traversal attempts
  - Command injection
  - Brute force attacks
  - Security scanner detection

- **High Performance**
  - < 1ms per event processing
  - Minimal memory footprint
  - Zero-downtime log rotation support

- **Easy Integration**
  - Works with existing nginx installations
  - Compatible with Falco 0.36.0+
  - Simple configuration

## 📋 Requirements

- Ubuntu 20.04+ or Debian 10+
- Falco 0.36.0+
- nginx 1.18.0+

## 📖 Documentation

- [Quick Start Binary Installation](docs/QUICK_START_BINARY_INSTALLATION.md) - Get started in 7 minutes

## 📄 License

Apache License 2.0

## 🔗 Links

- [Falco Project](https://falco.org/)
- [nginx](https://nginx.org/)

---

**Note**: This repository contains only the compiled binaries and documentation. Source code is maintained separately.