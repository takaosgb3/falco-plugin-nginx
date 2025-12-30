# Undetected Patterns Fix Plan

## Issue Reference
- Issue #780: E2E Test Pattern Expansion Phase 2
- Workflow Run: https://github.com/takaosgb3/falco-plugin-nginx/actions/runs/20233088947

## Problem Summary
- Detection rate: 93.3% (140/150)
- Required threshold: 95%
- Gap: 10 patterns not detected

## Undetected Patterns Analysis

| # | Pattern ID | Category | Payload | Encoded | Root Cause |
|---|------------|----------|---------|---------|------------|
| 1 | SQLI_ERROR_005 | sqli | `' AND (SELECT * FROM users WHERE id=1) --` | `'%20AND%20(SELECT%20*%20FROM%20users%20WHERE%20id%3D1)%20--` | Missing subquery detection pattern |
| 2 | SQLI_2ND_002 | sqli | `user' OR '1'='1' --` | `user'%20OR%20'1'%3D'1'%20--` | Missing second-order boolean injection with prefix |
| 3 | OTHER_REDIS_001 | other | `FLUSHALL` | `FLUSHALL` | Missing Redis command detection |
| 4 | PATH_DBL_001 | path | `%252E%252E%252F` | `%25252E%25252E%25252F` | Missing uppercase double-encoded dot-dot-slash |
| 5 | OTHER_JINJA_001 | other | `{{7*7}}` | `%7B%7B7*7%7D%7D` | Missing Jinja2 template injection pattern |
| 6 | PATH_ABS_006 | path | `/etc/apache2/sites-available/000-default.conf` | `%2Fetc%2Fapache2%2Fsites-available%2F000-default.conf` | Missing Apache sites-available path |
| 7 | OTHER_PHP_001 | other | `O:8:"stdClass":1:{s:4:"test";s:4:"data";}` | `O%3A8%3A%22stdClass%22%3A1%3A...` | Missing PHP serialization pattern |
| 8 | PATH_ABS_008 | path | `/etc/crontab` | `%2Fetc%2Fcrontab` | Missing /etc/crontab path detection |
| 9 | CMD_WIN_001 | cmdinj | `& dir` | `%26%20dir` | Missing Windows dir command |
| 10 | CMD_ENC_001 | cmdinj | `%3Bwhoami` | `%253Bwhoami` | Missing double-encoded semicolon |

## Fix Plan

### 1. SQLI_ERROR_005 - Subquery Detection
Add to sqli_error_based_pattern:
```yaml
nginx.request_uri contains "(SELECT" or
nginx.request_uri contains "%28SELECT"
```

### 2. SQLI_2ND_002 - Second-order Boolean Injection
Add to sqli_classic_pattern:
```yaml
nginx.request_uri contains "' OR '1'='1'" or
nginx.request_uri contains "'%20OR%20'1'%3D'1'"
```

### 3. OTHER_REDIS_001 - Redis Command Detection
Add new rule or expand nosql_injection_pattern:
```yaml
nginx.request_uri icontains "FLUSHALL" or
nginx.request_uri icontains "FLUSHDB" or
nginx.request_uri icontains "CONFIG SET"
```

### 4. PATH_DBL_001 - Uppercase Double Encoded
Add to path_encoded_traversal_pattern:
```yaml
nginx.request_uri contains "%252E%252E%252F" or
nginx.request_uri contains "%25252E%25252E%25252F"
```

### 5. OTHER_JINJA_001 - Template Injection
Add new template_injection_pattern:
```yaml
nginx.request_uri contains "{{" and nginx.request_uri contains "}}" or
nginx.request_uri contains "%7B%7B"
```

### 6. PATH_ABS_006 - Apache Sites Config
Add to sensitive_file_access_pattern:
```yaml
nginx.request_uri contains "/etc/apache2/sites-available" or
nginx.request_uri contains "%2Fetc%2Fapache2%2Fsites-available"
```

### 7. OTHER_PHP_001 - PHP Deserialization
Add new deserialization_pattern:
```yaml
nginx.request_uri regex "O:\d+:" or
nginx.request_uri contains "O%3A"
```

### 8. PATH_ABS_008 - Crontab Access
Add to sensitive_file_access_pattern:
```yaml
nginx.request_uri contains "/etc/crontab" or
nginx.request_uri contains "%2Fetc%2Fcrontab"
```

### 9. CMD_WIN_001 - Windows Dir Command
Add to cmdinj_windows_pattern:
```yaml
nginx.request_uri contains "& dir" or
nginx.request_uri contains "%26%20dir"
```

### 10. CMD_ENC_001 - Double Encoded Semicolon
Add to cmdinj_encoded_pattern:
```yaml
nginx.request_uri contains "%253B" or
nginx.request_uri contains "%3Bwhoami" or
nginx.request_uri contains "%253Bwhoami"
```

## Implementation Steps
1. Read current nginx_rules.yaml structure
2. Add missing patterns to appropriate macros/rules
3. Commit changes to feature branch
4. Push to trigger workflow re-run
5. Verify detection rate >= 95%

## Expected Result After Fix
- Detection rate: 100% (150/150)
- All 10 patterns should be detected

## Actual Result (2025-12-15)

**Status**: ✅ SUCCESS

```json
{
  "total_patterns": 150,
  "detected": 150,
  "not_detected": 0,
  "detection_rate": 1.0,
  "latency": {
    "avg_ms": 20853.33,
    "min_ms": 1000,
    "max_ms": 38000
  }
}
```

**Commit**: `1e8f52b` - fix(rules): Add detection patterns for 10 undetected attack patterns (Phase 5)
**Workflow Run**: https://github.com/takaosgb3/falco-plugin-nginx/actions/runs/20233697128
