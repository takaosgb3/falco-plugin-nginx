# Rule Writing Guide

This guide explains how to write custom rules for the Falco nginx plugin.

## Basic Rule Structure

Every nginx plugin rule must have these components:

```yaml
- rule: Rule Name
  desc: Description of what the rule detects
  condition: Detection logic using nginx fields
  output: Alert message with field interpolation
  priority: CRITICAL|WARNING|NOTICE|INFORMATIONAL|DEBUG
  tags: [tag1, tag2]
  source: nginx  # Required for plugin rules
```

## Available Fields

The nginx plugin provides these fields for use in conditions and output:

| Field | Type | Description |
|-------|------|-------------|
| `nginx.remote_addr` | string | Client IP address |
| `nginx.remote_user` | string | Authenticated username |
| `nginx.time_local` | string | Request timestamp |
| `nginx.method` | string | HTTP method (GET, POST, etc.) |
| `nginx.path` | string | Request path without query string |
| `nginx.query_string` | string | Query string parameters |
| `nginx.request_uri` | string | Full URI (path + query string) |
| `nginx.protocol` | string | HTTP protocol version |
| `nginx.status` | number | HTTP response status code |
| `nginx.body_bytes_sent` | number | Response body size in bytes |
| `nginx.bytes_sent` | number | Total response size |
| `nginx.http_referer` | string | Referer header |
| `nginx.http_user_agent` | string | User-Agent header |
| `nginx.request_length` | number | Request size |
| `nginx.request_time` | number | Request processing time |
| `nginx.upstream_response_time` | number | Upstream response time |
| `nginx.log_path` | string | Log file path |

## Condition Operators

### String Operators
- `contains` - Substring match
- `startswith` - Prefix match
- `endswith` - Suffix match
- `=` - Exact match
- `!=` - Not equal

### Numeric Operators
- `=`, `!=` - Equality
- `<`, `>`, `<=`, `>=` - Comparison

### Logical Operators
- `and` - Both conditions must be true
- `or` - Either condition must be true
- `not` - Negation

## Rule Examples

### Basic Attack Detection

```yaml
- rule: SQL Injection Attempt
  desc: Detects common SQL injection patterns
  condition: >
    nginx.request_uri contains "' OR" or
    nginx.request_uri contains "UNION SELECT" or
    nginx.request_uri contains "'; DROP"
  output: "SQL injection detected (ip=%nginx.remote_addr% uri=%nginx.request_uri% method=%nginx.method%)"
  priority: CRITICAL
  tags: [attack, sql_injection]
  source: nginx
```

### Response-based Detection

```yaml
- rule: Large Data Transfer
  desc: Detects unusually large responses
  condition: nginx.body_bytes_sent > 104857600  # 100MB
  output: "Large data transfer (ip=%nginx.remote_addr% uri=%nginx.request_uri% size=%nginx.body_bytes_sent%)"
  priority: WARNING
  tags: [anomaly, data_exfiltration]
  source: nginx
```

### Status Code Monitoring

```yaml
- rule: High Error Rate
  desc: Detects multiple 5xx errors
  condition: nginx.status >= 500 and nginx.status < 600
  output: "Server error detected (ip=%nginx.remote_addr% uri=%nginx.request_uri% status=%nginx.status%)"
  priority: ERROR
  tags: [availability, error]
  source: nginx
```

### User Agent Detection

```yaml
- rule: Automated Scanner
  desc: Detects common security scanners
  condition: >
    nginx.http_user_agent contains "sqlmap" or
    nginx.http_user_agent contains "nikto" or
    nginx.http_user_agent contains "nmap"
  output: "Scanner detected (ip=%nginx.remote_addr% scanner=%nginx.http_user_agent%)"
  priority: WARNING
  tags: [scanner, reconnaissance]
  source: nginx
```

### Complex Conditions

```yaml
- rule: Admin Brute Force
  desc: Multiple failed admin login attempts
  condition: >
    nginx.path startswith "/admin" and
    nginx.method = "POST" and
    nginx.status = 401
  output: "Failed admin login (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [authentication, brute_force]
  source: nginx
```

## Best Practices

### 1. Use Specific Conditions
```yaml
# Good - Specific path check
condition: nginx.path = "/admin/login.php"

# Less efficient - Contains check
condition: nginx.request_uri contains "admin"
```

### 2. Combine Related Checks
```yaml
# Good - Single rule for related patterns
condition: >
  nginx.request_uri contains "<script" or
  nginx.request_uri contains "javascript:" or
  nginx.request_uri contains "onerror="

# Less efficient - Multiple separate rules
```

### 3. Use Appropriate Priorities
- **CRITICAL**: Active attacks (SQL injection, RCE)
- **WARNING**: Suspicious activity (scanners, failed auth)
- **NOTICE**: Anomalies (large transfers, unusual paths)
- **INFORMATIONAL**: Monitoring (specific user agents)

### 4. Add Meaningful Tags
Tags help with filtering and reporting:
- `attack` - Active attack attempts
- `reconnaissance` - Information gathering
- `authentication` - Login-related events
- `anomaly` - Unusual but not necessarily malicious
- `compliance` - Regulatory compliance checks

## Testing Rules

### 1. Validate Syntax
```bash
sudo falco --validate /etc/falco/rules.d/custom-nginx.yaml
```

### 2. Test with Sample Requests
```bash
# Generate test traffic
curl "http://localhost/test.php?id=' OR '1'='1"

# Check if rule triggered
sudo journalctl -u falco -f | grep "SQL injection"
```

### 3. Use Debug Output
```yaml
- rule: Debug Test
  desc: Test rule for debugging
  condition: nginx.path = "/debug-test"
  output: "DEBUG: All fields - ip=%nginx.remote_addr% method=%nginx.method% path=%nginx.path% query=%nginx.query_string%"
  priority: DEBUG
  source: nginx
```

## Performance Considerations

### 1. Order Matters
Place most likely conditions first:
```yaml
# Efficient - Common condition first
condition: nginx.method = "POST" and nginx.path contains "admin"

# Less efficient - Expensive check first
condition: nginx.request_uri regex "complex.*pattern" and nginx.method = "POST"
```

### 2. Avoid Complex Regex
Use simple string operations when possible:
```yaml
# Preferred
condition: nginx.path endswith ".php"

# Avoid when possible
condition: nginx.path regex ".*\\.php$"
```

### 3. Limit Output Fields
Only include necessary fields in output:
```yaml
# Good - Relevant fields only
output: "Attack detected (ip=%nginx.remote_addr% uri=%nginx.request_uri%)"

# Verbose - May impact performance
output: "Attack (ip=%nginx.remote_addr% uri=%nginx.request_uri% ua=%nginx.http_user_agent% ref=%nginx.http_referer% status=%nginx.status%)"
```

## Advanced Examples

### Rate Limiting Detection
```yaml
- rule: Potential DDoS Attack
  desc: High request rate from single IP
  condition: nginx.request_time < 0.01  # Very fast requests
  output: "High request rate (ip=%nginx.remote_addr% time=%nginx.request_time%ms)"
  priority: WARNING
  tags: [ddos, rate_limit]
  source: nginx
```

### Geographic Restrictions
```yaml
- rule: Unauthorized Geographic Access
  desc: Access from unexpected locations
  condition: >
    nginx.path startswith "/internal/" and
    not (nginx.remote_addr startswith "10." or 
         nginx.remote_addr startswith "192.168.")
  output: "External access to internal resource (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [access_control, geographic]
  source: nginx
```

## Troubleshooting Rules

### Rule Not Firing
1. Check `source: nginx` is present
2. Verify field names are correct
3. Test with simpler conditions
4. Check Falco logs for errors

### Performance Issues
1. Simplify complex conditions
2. Reduce regex usage
3. Limit number of rules
4. Check rule evaluation metrics

## Next Steps

- [Configuration Guide](configuration.md)
- [Performance Tuning](performance.md)
- [Troubleshooting Guide](troubleshooting.md)