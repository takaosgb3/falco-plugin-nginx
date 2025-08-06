# Configuration Guide

This guide covers all configuration options for the Falco nginx plugin.

## Basic Configuration

The minimal configuration in `/etc/falco/falco.yaml`:

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

## Configuration Options

### Log Paths

Monitor multiple nginx log files:

```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/custom-site.log
    - /srv/nginx/logs/access.log
```

### Buffer Size

Adjust buffer size for high-traffic environments:

```yaml
init_config:
  buffer_size: 16384  # Default: 8192 bytes
```

Buffer size recommendations:
- Low traffic (< 100 req/sec): 8192 (default)
- Medium traffic (100-1000 req/sec): 16384
- High traffic (> 1000 req/sec): 32768

### Batch Processing

Configure event batching:

```yaml
init_config:
  max_batch_size: 1000    # Events per batch (default: 500)
  batch_timeout: 500      # Milliseconds (default: 200)
```

### Event Channel

Configure internal event channel:

```yaml
init_config:
  event_channel_size: 10000  # Default: 5000
```

### Watch Interval

File monitoring interval:

```yaml
init_config:
  watch_interval: 5  # Seconds (default: 1)
```

## Log Format Support

The plugin supports these nginx log formats:

### Combined (Default)
```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

### Custom Format
```yaml
init_config:
  log_format: combined  # or "common", "json"
```

## Advanced Configuration

### Large Response Threshold

Set threshold for large response detection:

```yaml
init_config:
  large_response_threshold: 10485760  # 10MB in bytes
```

### Maximum File Size

Limit maximum log file size to process:

```yaml
init_config:
  max_file_size: 1073741824  # 1GB in bytes
```

## Log Rotation

Set up log rotation to prevent disk space issues:

```bash
# Download and run setup script
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

Manual logrotate configuration (`/etc/logrotate.d/nginx-falco`):

```
/var/log/nginx/*.log {
    daily
    size 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
    endscript
}
```

## Rule Configuration

### Custom Rules

Add custom rules in `/etc/falco/rules.d/custom-nginx.yaml`:

```yaml
- rule: Custom Attack Pattern
  desc: Detect custom attack pattern
  condition: nginx.request_uri contains "custom-pattern"
  output: "Custom attack detected (ip=%nginx.client_ip%)"
  priority: WARNING
  tags: [custom]
  source: nginx
```

### Rule Priorities

- EMERGENCY: System unusable
- ALERT: Immediate action required
- CRITICAL: Critical conditions (attacks)
- ERROR: Error conditions
- WARNING: Warning conditions
- NOTICE: Normal but significant
- INFO: Informational
- DEBUG: Debug-level messages

## Performance Optimization

### For High-Traffic Sites

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 32768
      max_batch_size: 2000
      batch_timeout: 1000
      event_channel_size: 20000
```

### For Low-Latency Requirements

```yaml
init_config:
  buffer_size: 8192
  max_batch_size: 100
  batch_timeout: 50
  watch_interval: 1
```

## Monitoring Configuration

Enable metrics collection:

```yaml
init_config:
  enable_metrics: true
  metrics_interval: 60  # Seconds
```

## Next Steps

- [Performance Tuning Guide](performance.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Rule Writing Guide](rules.md)