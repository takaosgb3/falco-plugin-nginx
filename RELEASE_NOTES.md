# Release v0.3.0

## What's New

This release includes significant improvements based on extensive testing and user feedback:

### 🚀 Features
- **One-liner installation**: New automated installation script for quick deployment
- **Log rotation support**: Automatic configuration to prevent disk space issues
- **Performance tuning**: Buffer size optimization for high-traffic environments
- **Comprehensive documentation**: Updated guides and troubleshooting sections

### 🔧 Improvements
- Enhanced error handling and recovery
- Better field extraction for attack detection
- Optimized memory usage
- Improved compatibility with various nginx configurations

### 📦 Installation

#### Quick Install (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-nginx-plugin/main/install.sh | sudo bash
```

#### Manual Download
```bash
# Download binary
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/download/v0.3.0/libfalco-nginx-plugin-linux-amd64.so

# Download rules
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/download/v0.3.0/nginx_rules.yaml
```

### 🔒 Checksums
```
d478b9f4790e1425b2db68e2452bc36c16ff4fb5daaf5707c2790078d79abfba  libfalco-nginx-plugin-linux-amd64.so
```

### 📊 Performance Metrics
- **Detection rate**: 100% for all tested attack patterns
- **Processing rate**: 850+ requests/second
- **CPU usage**: < 1%
- **Memory usage**: ~45MB base + 8KB per log file

### 🧪 Tested On
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- Falco 0.36.0+
- nginx 1.18.0+

### 📝 Notes
- This version uses the Falco Plugin SDK for improved stability
- Kernel module is not required for nginx log monitoring
- Compatible with container environments

## Upgrading

If upgrading from a previous version:

1. Stop Falco: `sudo systemctl stop falco`
2. Replace the plugin binary
3. Update rules if needed
4. Restart Falco: `sudo systemctl start falco`

## Feedback

Please report any issues or suggestions at: https://github.com/takaosgb3/falco-nginx-plugin/issues