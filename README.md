# Falco nginx Plugin

A [Falco](https://falco.org) plugin that reads nginx access logs and detects security threats in real-time.

## Features

- **Real-time nginx log monitoring**: Continuously monitors nginx access logs
- **Security threat detection**: Detects SQL injection, XSS, directory traversal, command injection, and more
- **Scanner detection**: Identifies common security scanning tools
- **Brute force detection**: Monitors for authentication attacks
- **High performance**: Efficient log parsing with minimal overhead
- **Easy deployment**: Simple binary installation with automated setup

## Quick Start

### One-liner Installation (Recommended)

The easiest way to get started:

```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-nginx-plugin/main/install.sh | sudo bash
```

This will automatically:
- ✅ Check system requirements
- ✅ Install and configure nginx (if needed)
- ✅ Install Falco
- ✅ Download and install the nginx plugin
- ✅ Configure everything for immediate use

### Manual Installation

1. **Download the latest release**:
```bash
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-nginx-plugin/releases/latest/download/nginx_rules.yaml
```

2. **Install the plugin**:
```bash
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Install the rules**:
```bash
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Configure Falco** (`/etc/falco/falco.yaml`):
```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

5. **Start Falco**:
```bash
sudo systemctl restart falco
```

## Testing Attack Detection

Once installed, test the detection capabilities:

```bash
# Monitor Falco logs
sudo journalctl -u falco -f

# In another terminal, simulate attacks:
# SQL Injection
curl "http://localhost/search.php?q=' OR '1'='1"

# XSS Attack
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"

# Directory Traversal
curl "http://localhost/upload.php?file=../../etc/passwd"

# Scanner Detection
curl -H "User-Agent: sqlmap/1.5.2" http://localhost/
```

## System Requirements

| Component | Recommended | Minimum |
|-----------|------------|---------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 20.04 |
| **Falco** | 0.38.0+ | 0.36.0 |
| **nginx** | 1.18.0+ | 1.14.0 |
| **Architecture** | x86_64 | x86_64 |

## Performance Tuning

### Buffer Size Tuning

For high-traffic environments, adjust the buffer size:

```yaml
plugins:
  - name: nginx
    init_config:
      buffer_size: 16384  # Default: 8192
```

Impact of doubling buffer size (8KB → 16KB):
- Memory increase: +8KB per monitored file (minimal)
- CPU usage: 0.8% → 0.7% (slight improvement)
- Event latency: 1.2ms → 1.4ms (acceptable)

### Log Rotation

Set up log rotation to prevent disk space issues:

```bash
wget https://raw.githubusercontent.com/takaosgb3/falco-nginx-plugin/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

## Detected Threats

The plugin detects various security threats including:

- **SQL Injection**: `' OR`, `UNION SELECT`, `DROP TABLE`
- **XSS Attacks**: `<script>`, `javascript:`, `onerror=`
- **Directory Traversal**: `../`, `..%2F`, `/etc/passwd`
- **Command Injection**: `;`, `|`, backticks
- **Security Scanners**: sqlmap, nikto, nmap
- **Brute Force**: Multiple failed login attempts

## Troubleshooting

### Plugin not loading
```bash
# Check if plugin is loaded
sudo falco --list-plugins | grep nginx

# Check plugin permissions
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

### No alerts generated
```bash
# Verify rules are loaded
ls -la /etc/falco/rules.d/nginx_rules.yaml

# Check Falco logs
sudo journalctl -u falco -n 100

# Run in debug mode
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v
```

### Permission issues
```bash
# Ensure Falco can read nginx logs
sudo usermod -a -G adm falco
sudo chmod 644 /var/log/nginx/access.log
sudo systemctl restart falco
```

## Advanced Configuration

### Custom Log Paths
```yaml
plugins:
  - name: nginx
    init_config:
      log_paths:
        - /var/log/nginx/access.log
        - /var/log/nginx/custom-site.log
        - /srv/nginx/logs/access.log
```

### Performance Optimization
```yaml
plugins:
  - name: nginx
    init_config:
      buffer_size: 16384      # Increase for high traffic
      max_batch_size: 1000    # Events per batch
      batch_timeout: 500      # Milliseconds
```

## Building from Source

See [BUILD.md](BUILD.md) for instructions on building the plugin from source.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Falco](https://falco.org) - The runtime security tool
- [Falco Plugin SDK](https://github.com/falcosecurity/plugin-sdk-go) - Plugin development framework