# Installation Guide

This guide provides detailed instructions for installing the Falco nginx plugin.

## Quick Installation

The easiest way to install the plugin:

```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

## Manual Installation

### Prerequisites

- Ubuntu 20.04+ or Debian 10+
- Falco 0.36.0 or later
- nginx 1.14.0 or later
- x86_64 architecture

### Step 1: Download the Plugin

Download the latest release:

```bash
# Download plugin binary
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so

# Download rules
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/nginx_rules.yaml
```

### Step 2: Install Plugin Files

```bash
# Create plugin directory
sudo mkdir -p /usr/share/falco/plugins

# Install plugin binary
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# Install rules
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

### Step 3: Configure Falco

Add the plugin configuration to `/etc/falco/falco.yaml`:

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

### Step 4: Start Falco

```bash
# Restart Falco service
sudo systemctl restart falco

# Or run in plugin-only mode
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## Verifying Installation

1. Check plugin is loaded:
```bash
sudo falco --list-plugins | grep nginx
```

2. Monitor Falco logs:
```bash
sudo journalctl -u falco -f
```

3. Test detection:
```bash
# Simulate SQL injection
curl "http://localhost/test.php?id=' OR '1'='1"
```

## Troubleshooting

### Plugin Not Loading

- Check file permissions: `ls -la /usr/share/falco/plugins/`
- Verify Falco version: `falco --version`
- Check logs: `sudo journalctl -u falco -n 50`

### No Alerts Generated

- Verify nginx logs exist: `ls -la /var/log/nginx/access.log`
- Check log permissions: `sudo chmod 644 /var/log/nginx/access.log`
- Ensure rules are loaded: `ls -la /etc/falco/rules.d/`

## Next Steps

- [Configuration Guide](configuration.md)
- [Performance Tuning](performance.md)
- [Troubleshooting Guide](troubleshooting.md)