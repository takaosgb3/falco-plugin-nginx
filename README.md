# Falco Nginx Plugin

A Falco plugin for real-time security monitoring of nginx access logs. Detects SQL injection, XSS, path traversal, and other web-based attacks.

## ✨ Features

- **Real-time threat detection** using Falco's powerful rules engine
- **Multiple attack detection**: SQL injection, XSS, path traversal, command injection
- **Scanner detection**: Identifies common security scanners and bots
- **Performance monitoring**: Detects unusual request patterns
- **No kernel module required**: Runs in plugin-only mode

## 📋 Requirements

- **Falco**: 0.36.0 or higher
- **OS**: Linux x86_64
- **nginx**: Access logs in combined format

## 🚀 Quick Start

### 1. Download the Plugin

```bash
# Download the latest release
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so

# Verify checksum
echo "997e60627f103946c1bac9b31aa6ec1803fbd25fbccbf045fe37afaa5ec644d6  libfalco-nginx-plugin.so" | sha256sum -c

# Install to Falco plugins directory
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

### 2. Configure Falco

Edit `/etc/falco/falco.yaml`:

```yaml
# Add nginx plugin configuration
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 8192
      watch_interval: 1000

# Enable the plugin
load_plugins: [nginx]
```

### 3. Download Rules

```bash
# Download nginx security rules
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

### 4. Run Falco

```bash
# Run in plugin-only mode (no kernel module required)
sudo falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
```

## 🧪 Test the Detection

```bash
# Test SQL injection detection
curl "http://localhost/search?q=' OR '1'='1"

# Test XSS detection
curl "http://localhost/page?content=<script>alert('XSS')</script>"

# Test directory traversal
curl "http://localhost/file?path=../../../../etc/passwd"
```

## 📖 Documentation

### Plugin Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `log_paths` | Array of nginx log file paths | `["/var/log/nginx/access.log"]` |
| `buffer_size` | Event buffer size | `8192` |
| `watch_interval` | File check interval (ms) | `1000` |

### Available Fields

The plugin extracts the following fields from nginx logs:

- `nginx.client_ip` - Client IP address
- `nginx.method` - HTTP method
- `nginx.request_uri` - Full request URI
- `nginx.path` - Request path
- `nginx.query_string` - Query parameters
- `nginx.status` - HTTP status code
- `nginx.body_bytes_sent` - Response size
- `nginx.user_agent` - User agent string
- `nginx.referer` - Referer header

### Running as a Service

Create `/etc/systemd/system/falco-nginx.service`:

```ini
[Unit]
Description=Falco Nginx Security Monitoring
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/falco --disable-source syscall -r /etc/falco/rules.d/nginx_rules.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable falco-nginx
sudo systemctl start falco-nginx
```

## 🔍 Troubleshooting

### Plugin not loading?

```bash
# Check if plugin is recognized
sudo falco --list-plugins | grep nginx

# Run with debug output
sudo falco -A --disable-source syscall
```

### Rules not triggering?

1. Verify `source: nginx` is set in rules
2. Check log file path and permissions
3. Ensure nginx uses combined log format

### Common Issues

- **"kernel module not found"**: Use `--disable-source syscall`
- **"plugin not found"**: Check file path and permissions
- **No alerts**: Verify nginx is writing to configured log path

## 🏗️ Building from Source

```bash
git clone https://github.com/takaosgb3/falco-nginx-plugin-claude
cd falco-nginx-plugin-claude
make build
```

## 📜 License

Apache License 2.0

## 🤝 Contributing

Contributions welcome! Please open issues or submit pull requests.

## 🔗 Links

- [Falco Documentation](https://falco.org/docs/)
- [Development Repository](https://github.com/takaosgb3/falco-nginx-plugin-claude)
- [Report Issues](https://github.com/takaosgb3/falco-plugin-nginx/issues)