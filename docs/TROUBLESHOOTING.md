# Troubleshooting Guide

This guide helps diagnose and resolve common issues with the Falco nginx plugin.

## Quick Diagnosis

```bash
# Check Falco status
sudo systemctl status falco

# Check if plugin is loaded
sudo falco --list-plugins | grep nginx

# View recent logs
sudo journalctl -u falco -n 100

# Test in debug mode
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v
```

## Common Issues

### Plugin Not Loading

**Symptoms:**
- Plugin doesn't appear in `falco --list-plugins`
- Error: "Unable to load plugin"

**Solutions:**

1. **Check file permissions:**
```bash
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Should be: -rw-r--r-- 1 root root
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

2. **Verify library dependencies:**
```bash
ldd /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Check for "not found" errors
```

3. **Check Falco configuration:**
```bash
# Validate configuration
sudo falco --validate /etc/falco/falco.yaml

# Check plugin section exists
grep -A5 "plugins:" /etc/falco/falco.yaml
```

### No Alerts Generated

**Symptoms:**
- No alerts when testing attacks
- Plugin loads but seems inactive

**Solutions:**

1. **Verify nginx logs exist:**
```bash
ls -la /var/log/nginx/access.log
# If missing, check nginx configuration
grep access_log /etc/nginx/nginx.conf
```

2. **Check log permissions:**
```bash
# Falco needs read access
sudo chmod 644 /var/log/nginx/access.log
sudo usermod -a -G adm falco
sudo systemctl restart falco
```

3. **Verify rules are loaded:**
```bash
ls -la /etc/falco/rules.d/nginx_rules.yaml
# Check for syntax errors
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

4. **Test with simple rule:**
```yaml
# /etc/falco/rules.d/test-nginx.yaml
- rule: Test nginx Access
  desc: Test rule for any nginx access
  condition: nginx.request_uri != ""
  output: "Test: nginx access detected"
  priority: INFO
  source: nginx
```

### Permission Denied Errors

**Symptoms:**
- "Permission denied" in logs
- "Failed to open log file"

**Solutions:**

1. **Fix log file permissions:**
```bash
# Option 1: Add falco to adm group
sudo usermod -a -G adm falco

# Option 2: Adjust log permissions
sudo chmod 644 /var/log/nginx/*.log
```

2. **SELinux (if enabled):**
```bash
# Check SELinux status
getenforce

# Allow Falco to read logs
sudo setsebool -P daemons_enable_cluster_mode 1
# Or set to permissive temporarily
sudo setenforce 0
```

3. **AppArmor (if enabled):**
```bash
# Set Falco to complain mode
sudo aa-complain /usr/bin/falco
```

### Falco Service Won't Start

**Symptoms:**
- `systemctl start falco` fails
- Exit code errors

**Solutions:**

1. **Check kernel module issues:**
```bash
# Try plugin-only mode
sudo /usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
```

2. **Use appropriate service:**
```bash
# If kernel module fails, use modern BPF
sudo systemctl stop falco
sudo systemctl start falco-modern-bpf
```

3. **Check port conflicts:**
```bash
# Default Falco gRPC port
sudo lsof -i :5060
```

### High Resource Usage

**Symptoms:**
- High CPU or memory usage
- System slowdown

**Solutions:**

1. **Reduce buffer size:**
```yaml
init_config:
  buffer_size: 8192  # Reduce from larger values
```

2. **Limit monitored files:**
```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log  # Only essential logs
```

3. **Optimize rules:**
   - Remove unnecessary rules
   - Use specific conditions
   - Avoid complex regex

### Rules Not Triggering

**Symptoms:**
- Attacks don't generate alerts
- Rules seem incorrect

**Solutions:**

1. **Check rule syntax:**
```bash
# Validate rules file
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

2. **Verify source attribute:**
```yaml
# All nginx rules must have:
source: nginx
```

3. **Test with curl:**
```bash
# SQL injection test
curl -v "http://localhost/test.php?id=' OR '1'='1"

# Check exact log format
tail -n 1 /var/log/nginx/access.log
```

### Log Rotation Issues

**Symptoms:**
- Falco stops reading after rotation
- Old logs not being processed

**Solutions:**

1. **Ensure proper rotation config:**
```bash
# Check logrotate configuration
cat /etc/logrotate.d/nginx

# Should include:
postrotate
    kill -USR1 $(cat /var/run/nginx.pid)
endscript
```

2. **Manual rotation test:**
```bash
sudo logrotate -f /etc/logrotate.d/nginx
# Monitor Falco behavior
sudo journalctl -u falco -f
```

## Debug Commands

### Verbose Logging

```bash
# Run Falco in foreground with debug output
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v

# Increase log verbosity
sudo sed -i 's/log_level: info/log_level: debug/' /etc/falco/falco.yaml
sudo systemctl restart falco
```

### Test Individual Components

```bash
# Test plugin loading only
sudo falco --list-plugins

# Test rule loading only
sudo falco --list

# Dry run mode
sudo falco -c /etc/falco/falco.yaml --dry-run
```

### Performance Debugging

```bash
# Check event processing
sudo journalctl -u falco -f | grep -E "events/sec|throughput"

# Monitor system resources
top -p $(pgrep falco)

# Check for dropped events
sudo journalctl -u falco | grep -i drop
```

## Getting Help

1. **Check logs first:**
   - System logs: `/var/log/syslog`
   - Falco logs: `journalctl -u falco`
   - nginx logs: `/var/log/nginx/error.log`

2. **Collect diagnostic info:**
```bash
# System info
uname -a
falco --version
nginx -v

# Plugin info
ls -la /usr/share/falco/plugins/
cat /etc/falco/falco.yaml | grep -A10 plugins:
```

3. **Report issues:**
   - GitHub Issues: https://github.com/takaosgb3/falco-plugin-nginx/issues
   - Include diagnostic info
   - Provide reproduction steps

## Next Steps

- [Configuration Guide](configuration.md)
- [Performance Tuning](performance.md)
- [Installation Guide](installation.md)