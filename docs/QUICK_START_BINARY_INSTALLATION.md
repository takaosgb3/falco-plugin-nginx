# 🚀 Quick Start: Binary Installation

[日本語版](#-クイックスタート-バイナリを使用したインストール)

This guide provides the quickest way to set up the Falco nginx plugin using pre-built binaries without cloning any source code.

## 📋 What This Guide Covers

- ✅ nginx Web server setup
- ✅ Deploying web content for attack testing
- ✅ Installing Falco and nginx plugin
- ✅ Testing security attack detection (SQL injection, XSS, directory traversal, etc.)
- ✅ Real-time alert verification

**Time Required**: About 7 minutes
**Prerequisites**: Ubuntu 20.04+ or Debian 10+

## 📦 Required Binary Files

To run the plugin, you need the following files:

1. **libfalco-nginx-plugin-linux-amd64.so** - Plugin binary (approx. 3.5MB)
2. **nginx_rules.yaml** - Falco detection rules (approx. 10KB)
3. **falco.yaml** - Falco configuration file (optional)

Note: After download, rename the binary to `libfalco-nginx-plugin.so` for use.

## 🎯 How to Obtain Binaries

### Option 1: Download from Repository

```bash
# Download binaries directly from the repository
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml

# Verify checksum (optional)
# Note: Use curl to avoid GitHub CDN cache issues
curl -s https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so.sha256 -o libfalco-nginx-plugin-linux-amd64.so.sha256
sha256sum -c libfalco-nginx-plugin-linux-amd64.so.sha256

# Rename to a convenient name
mv libfalco-nginx-plugin-linux-amd64.so libfalco-nginx-plugin.so
```

### Option 2: Direct Binary Provision

Obtain the following files from the developer:
- `libfalco-nginx-plugin-linux-amd64.so` (for Linux x86_64)
- `nginx_rules.yaml`

## ⚡ 5-Minute Setup

### 1. Environment Preparation (1 minute)

```bash
# Create working directory
mkdir -p ~/falco-nginx-test
cd ~/falco-nginx-test

# Update system
sudo apt update
```

### 2. nginx Installation and Configuration (2 minutes)

```bash
# Install nginx
sudo apt install -y nginx

# Basic nginx configuration
sudo tee /etc/nginx/sites-available/test-site << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/test-site;
    index index.html index.php;

    server_name _;

    # Log configuration (monitored by Falco plugin)
    access_log /var/log/nginx/access.log combined;
    error_log /var/log/nginx/error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    # PHP file processing (for attack testing)
    location ~ \.php$ {
        # Logs are recorded even without PHP
        try_files $uri =404;
    }

    # Admin area (for brute force testing)
    location /admin {
        try_files $uri $uri/ /admin.html;
    }
}
EOF

# Enable site
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/test-site /etc/nginx/sites-enabled/

# Create web content directory
sudo mkdir -p /var/www/test-site
```

### 3. Preparing Web Content for Attack Testing (1 minute)

```bash
# Basic index.html
sudo tee /var/www/test-site/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Falco Nginx Plugin Test Site</title>
</head>
<body>
    <h1>Welcome to Test Site</h1>
    <p>This site is designed for security testing with Falco nginx plugin.</p>
    <ul>
        <li><a href="/admin/">Admin Area</a></li>
        <li><a href="/api/users.php">User API</a></li>
        <li><a href="/search.php">Search</a></li>
        <li><a href="/upload.php">File Upload</a></li>
    </ul>
</body>
</html>
EOF

# Admin page (for brute force testing)
sudo mkdir -p /var/www/test-site/admin
sudo tee /var/www/test-site/admin/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h1>Administrator Login</h1>
    <form method="POST" action="/admin/login.php">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
EOF

# Search page (for SQL injection testing)
sudo tee /var/www/test-site/search.php << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Search</title>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET">
        <input type="text" name="q" placeholder="Search products...">
        <input type="submit" value="Search">
    </form>
    <?php
    // This file doesn't actually run, but nginx logs the access
    if (isset($_GET['q'])) {
        echo "<p>Searching for: " . htmlspecialchars($_GET['q']) . "</p>";
    }
    ?>
</body>
</html>
EOF

# API endpoint (for various attack tests)
sudo mkdir -p /var/www/test-site/api
sudo tee /var/www/test-site/api/users.php << 'EOF'
<?php
// No actual PHP processing needed. nginx logging the request is sufficient
header('Content-Type: application/json');
echo json_encode(['status' => 'ok', 'users' => []]);
?>
EOF

# File upload page (for directory traversal testing)
sudo tee /var/www/test-site/upload.php << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
</head>
<body>
    <h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
</body>
</html>
EOF

# Set file permissions
sudo chown -R www-data:www-data /var/www/test-site
sudo chmod -R 755 /var/www/test-site

# Restart nginx
sudo systemctl restart nginx

# Verify operation
curl -s http://localhost/ | grep -q "Welcome to Test Site" && echo "✅ Site is working properly" || echo "❌ Cannot access site"
```

### 4. Falco Installation (2 minutes)

**Important**: 
- For Falco 0.36.0 and later, use `rules_files` (plural) instead of `rules_file` in configuration.
- The current plugin binary has been completely rewritten using the Falco Plugin SDK for Go.
- Uses API version 3.11.0, optimized for Falco 0.41.3 compatibility.
- Plugin events are identified by `source` attribute, so rules must include `source: nginx`.
- **Critical**: Rules file must be installed in `/etc/falco/rules.d/` or Falco won't detect any attacks!

```bash
# Install prerequisites (optional, not needed for Modern eBPF driver)
sudo apt install -y dialog

# Add Falco repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# Update and install Falco
sudo apt update
sudo apt install -y falco

# For non-interactive installation (recommended for automation):
# FALCO_FRONTEND=noninteractive sudo apt install -y falco
```

### 5. Plugin Deployment (30 seconds)

```bash
# Create plugin directory
sudo mkdir -p /usr/share/falco/plugins

# Deploy binary (assuming file is available)
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# Deploy rules file (CRITICAL STEP!)
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/

# Verify rules file is in place
sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
```

### 6. Minimal Configuration (30 seconds)

```bash
# Create complete Falco configuration (don't append)
sudo tee /etc/falco/falco.yaml << 'EOF'
# Use the new plural form for Falco 0.36.0+
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

engine:
  kind: modern_ebpf

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Verify Falco service is running
sudo systemctl status falco-bpf.service || sudo systemctl status falco

# Restart Falco
sudo systemctl restart falco-bpf.service || sudo systemctl restart falco
```

## ✅ Operation Verification and Attack Testing

### Basic Operation Check
```bash
# Check Falco startup
sudo systemctl status falco --no-pager

# Check plugin loading
sudo falco --list-plugins | grep nginx

# Start log monitoring (run in separate terminal)
sudo journalctl -u falco -f
```

### Running Attack Tests

#### 1. SQL Injection Attack
```bash
# Basic SQL injection
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"
curl "http://localhost/search.php?q='; DROP TABLE users;--"

# Encoded attacks
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

#### 2. XSS Attack
```bash
# Basic XSS
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"

# Encoded XSS
curl "http://localhost/search.php?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
```

#### 3. Directory Traversal Attack
```bash
# Path traversal
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"

# Encoded attacks
curl "http://localhost/upload.php?file=..%2F..%2F..%2Fetc%2Fpasswd"
```

#### 4. Command Injection Attack
```bash
# Command execution attempts
curl "http://localhost/api/users.php?cmd=; cat /etc/passwd"
curl "http://localhost/search.php?q=test; whoami"
curl "http://localhost/api/users.php?action=test|id"
```

#### 5. Brute Force Attack Simulation
```bash
# Consecutive login attempts
for i in {1..10}; do
    curl -X POST "http://localhost/admin/login.php" \
         -d "username=admin&password=password$i"
    sleep 0.1
done
```

#### 6. Scanner Detection
```bash
# Common scanner User-Agents
curl -H "User-Agent: sqlmap/1.5.2" "http://localhost/"
curl -H "User-Agent: Nikto/2.1.5" "http://localhost/"
curl -H "User-Agent: nmap scripting engine" "http://localhost/"
```

### How to Check Alerts
```bash
# Check alerts in real-time
sudo journalctl -u falco -f | grep -E "SQL injection|XSS|Directory traversal|Command injection|Brute force|Scanner"

# Search past alerts
sudo journalctl -u falco --since "5 minutes ago" | grep "CRITICAL"

# Alert statistics
sudo journalctl -u falco --since "1 hour ago" | grep -c "priority=CRITICAL"
```

## 📊 Complete Configuration File Example

If nginx_rules.yaml is not available, create the following comprehensive rules file:

**Important: SDK-based plugins require `source: nginx` in all rules**

```bash
sudo tee /etc/falco/rules.d/nginx_rules.yaml << 'EOF'
- required_plugin_versions:
  - name: nginx
    version: 0.1.0

# SQL injection detection
- rule: SQL Injection Attempt
  desc: Detects various SQL injection patterns
  source: nginx
  condition: >
    nginx.path contains "' OR" or
    nginx.path contains "\" OR" or
    nginx.path contains "UNION SELECT" or
    nginx.path contains "'; DROP" or
    nginx.path contains "--" or
    nginx.query_string contains "' OR" or
    nginx.query_string contains "UNION SELECT"
  output: "SQL injection detected (client=%nginx.remote_addr method=%nginx.method path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, sql_injection]

# XSS attack detection
- rule: XSS Attack Attempt
  desc: Detects cross-site scripting attempts
  source: nginx
  condition: >
    nginx.path contains "<script" or
    nginx.path contains "</script>" or
    nginx.path contains "javascript:" or
    nginx.query_string contains "<script" or
    nginx.query_string contains "onerror=" or
    nginx.query_string contains "onload="
  output: "XSS attack detected (client=%nginx.remote_addr path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, xss]

# Directory traversal detection
- rule: Directory Traversal Attempt
  desc: Detects path traversal attacks
  source: nginx
  condition: >
    nginx.path contains "../" or
    nginx.path contains "..%2F" or
    nginx.path contains "..%5C" or
    nginx.path contains "/etc/passwd" or
    nginx.query_string contains "../" or
    nginx.query_string contains "..%2F"
  output: "Directory traversal detected (client=%nginx.remote_addr path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, path_traversal]

# Command injection detection
- rule: Command Injection Attempt
  desc: Detects command injection patterns
  source: nginx
  condition: >
    (nginx.path contains ";" or nginx.query_string contains ";") and 
    (nginx.path contains "cat " or nginx.query_string contains "cat ") or
    (nginx.path contains "|" or nginx.query_string contains "|") and
    (nginx.path contains "id" or nginx.query_string contains "id") or
    nginx.query_string contains "`" or
    nginx.query_string contains "$(" or
    nginx.query_string contains "${"
  output: "Command injection detected (client=%nginx.remote_addr path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, command_injection]

# Scanner detection
- rule: Security Scanner Detected
  desc: Detects common security scanning tools
  source: nginx
  condition: >
    nginx.user_agent contains "sqlmap" or
    nginx.user_agent contains "nikto" or
    nginx.user_agent contains "nmap" or
    nginx.user_agent contains "masscan" or
    nginx.user_agent contains "w3af" or
    nginx.user_agent contains "burp"
  output: "Security scanner detected (client=%nginx.remote_addr scanner=%nginx.user_agent path=%nginx.path)"
  priority: WARNING
  tags: [scanner, reconnaissance]

# Brute force detection (multiple requests from same IP in short time)
- rule: Potential Brute Force Attack
  desc: Multiple failed login attempts
  source: nginx
  condition: >
    nginx.path contains "/admin" and
    nginx.method = "POST" and
    nginx.status >= 400 and nginx.status < 500
  output: "Potential brute force attack (client=%nginx.remote_addr path=%nginx.path status=%nginx.status)"
  priority: WARNING
  tags: [attack, brute_force]
EOF
```

## 🆘 Troubleshooting

### No Alerts Appearing

If you're not seeing any alerts after running attack tests:

1. **Check if rules file is installed:**
   ```bash
   sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
   # If missing, copy it:
   sudo cp nginx_rules.yaml /etc/falco/rules.d/
   ```

2. **Check Falco service status:**
   ```bash
   sudo systemctl status falco-bpf.service
   # If failed, check logs:
   sudo journalctl -u falco-bpf.service -n 50
   ```

3. **Verify plugin is loaded:**
   ```bash
   sudo journalctl -u falco-bpf.service | grep "Loading plugin 'nginx'"
   ```

4. **Test Falco manually to see errors:**
   ```bash
   sudo /usr/bin/falco -o engine.kind=ebpf -o log_level=info 2>&1 | head -20
   ```

### Falco Installation Issues

If the Falco installation fails:

```bash
# Check if the repository was added correctly
ls -la /etc/apt/sources.list.d/falcosecurity.list

# If the file path was incorrect, remove and re-add:
sudo rm -f /etc/falco/apt/sources.list.d/falcosecurity.list
sudo rm -f /etc/apt/sources.list.d/falcosecurity.list

# Re-add the repository with correct path
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# Update and install
sudo apt update
sudo apt install -y falco
```

### If Binary Not Found

```bash
# Check file existence
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so

# Check if plugin is loaded
sudo falco --list-plugins | grep nginx
```

### If Logs Cannot Be Read

```bash
# Check nginx log permissions
ls -la /var/log/nginx/access.log

# Grant permissions to Falco user
sudo usermod -a -G adm falco
sudo systemctl restart falco
```

## 🎯 Attack Testing Summary

### Expected Results
If properly set up, the following attacks can be detected:

| Attack Type | Test Command Example | Expected Alert |
|------------|---------------------|----------------|
| SQL Injection | `curl "http://localhost/search.php?q=' OR '1'='1"` | "SQL injection detected" |
| XSS | `curl "http://localhost/search.php?q=<script>alert(1)</script>"` | "XSS attack detected" |
| Directory Traversal | `curl "http://localhost/upload.php?file=../../etc/passwd"` | "Directory traversal detected" |
| Command Injection | `curl "http://localhost/api/users.php?cmd=;whoami"` | "Command injection detected" |
| Scanner | `curl -H "User-Agent: sqlmap" http://localhost/` | "Security scanner detected" |

### One-liner for Testing
```bash
# Test all attack types at once
for attack in \
  "search.php?q=' OR '1'='1" \
  "search.php?q=<script>alert(1)</script>" \
  "upload.php?file=../../etc/passwd" \
  "api/users.php?cmd=;whoami"; do
  echo "Testing: $attack"
  curl -s "http://localhost/$attack"
  sleep 1
done

# Check results
sudo journalctl -u falco --since "2 minutes ago" | grep -E "CRITICAL|WARNING"
```

## 📝 Next Steps

1. **Advanced Configuration**
   - Creating custom rules
   - Performance tuning
   - Alert notification setup

2. **Production Deployment**
   - Log rotation configuration
   - Metrics collection
   - Dashboard building

3. **Detailed Documentation**
   - [Complete Setup Guide](./LOCAL_TEST_ENVIRONMENT_GUIDE.md)
   - [Troubleshooting Guide](./TROUBLESHOOTING.md)
   - [Falco Rule Creation Guide](../development/FALCO_RULES_GUIDE.md)

---

**Time Required**: About 7 minutes (including web content preparation)
**Difficulty**: Beginner
**Last Updated**: 2025-08-04

---

# 🚀 クイックスタート: バイナリを使用したインストール

[English](#-quick-start-binary-installation)

このガイドでは、ソースコードをクローンせずに、ビルド済みバイナリを使用してFalco nginxプラグインを最も迅速にセットアップする方法を説明します。

## 📋 このガイドでできること

- ✅ nginx Webサーバーのセットアップ
- ✅ 攻撃テスト用のWebコンテンツ配備
- ✅ Falcoとnginxプラグインのインストール
- ✅ セキュリティ攻撃の検出テスト（SQL注入、XSS、ディレクトリトラバーサル等）
- ✅ リアルタイムアラートの確認

**所要時間**: 約7分
**前提条件**: Ubuntu 20.04+ または Debian 10+

## 📦 必要なバイナリファイル

プラグインを動作させるには、以下のファイルが必要です：

1. **libfalco-nginx-plugin-linux-amd64.so** - プラグイン本体（約3.5MB）
2. **nginx_rules.yaml** - Falco検出ルール（約10KB）
3. **falco.yaml** - Falco設定ファイル（オプション）

注: ダウンロード後、バイナリは `libfalco-nginx-plugin.so` にリネームして使用します。

## 🎯 バイナリの入手方法

### オプション1: リポジトリからダウンロード

```bash
# リポジトリから直接バイナリをダウンロード
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml

# チェックサムを確認（オプション）
# 注: GitHub CDNキャッシュ問題を回避するためcurlを使用
curl -s https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so.sha256 -o libfalco-nginx-plugin-linux-amd64.so.sha256
sha256sum -c libfalco-nginx-plugin-linux-amd64.so.sha256

# 使いやすい名前にリネーム
mv libfalco-nginx-plugin-linux-amd64.so libfalco-nginx-plugin.so
```

### オプション2: ビルド済みバイナリの直接提供

開発者から以下のファイルを受け取ってください：
- `libfalco-nginx-plugin-linux-amd64.so` (Linux x86_64用)
- `nginx_rules.yaml`

## ⚡ 5分でセットアップ

### 1. 環境準備（1分）

```bash
# 作業ディレクトリ作成
mkdir -p ~/falco-nginx-test
cd ~/falco-nginx-test

# システム更新
sudo apt update
```

### 2. nginxインストールと設定（2分）

```bash
# nginxをインストール
sudo apt install -y nginx

# nginxの基本設定
sudo tee /etc/nginx/sites-available/test-site << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/test-site;
    index index.html index.php;

    server_name _;

    # ログ設定（Falcoプラグインが監視）
    access_log /var/log/nginx/access.log combined;
    error_log /var/log/nginx/error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    # PHPファイルの処理（攻撃テスト用）
    location ~ \.php$ {
        # PHPが無くてもログは記録される
        try_files $uri =404;
    }

    # 管理者エリア（ブルートフォーステスト用）
    location /admin {
        try_files $uri $uri/ /admin.html;
    }
}
EOF

# サイトを有効化
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/test-site /etc/nginx/sites-enabled/

# Webコンテンツディレクトリ作成
sudo mkdir -p /var/www/test-site
```

### 3. 攻撃テスト用Webコンテンツの準備（1分）

```bash
# 基本的なindex.html
sudo tee /var/www/test-site/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Falco Nginx Plugin Test Site</title>
</head>
<body>
    <h1>Welcome to Test Site</h1>
    <p>This site is designed for security testing with Falco nginx plugin.</p>
    <ul>
        <li><a href="/admin/">Admin Area</a></li>
        <li><a href="/api/users.php">User API</a></li>
        <li><a href="/search.php">Search</a></li>
        <li><a href="/upload.php">File Upload</a></li>
    </ul>
</body>
</html>
EOF

# 管理者ページ（ブルートフォーステスト用）
sudo mkdir -p /var/www/test-site/admin
sudo tee /var/www/test-site/admin/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h1>Administrator Login</h1>
    <form method="POST" action="/admin/login.php">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
EOF

# 検索ページ（SQLインジェクションテスト用）
sudo tee /var/www/test-site/search.php << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Search</title>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET">
        <input type="text" name="q" placeholder="Search products...">
        <input type="submit" value="Search">
    </form>
    <?php
    // このファイルは実際には動作しませんが、nginxはアクセスログを記録します
    if (isset($_GET['q'])) {
        echo "<p>Searching for: " . htmlspecialchars($_GET['q']) . "</p>";
    }
    ?>
</body>
</html>
EOF

# APIエンドポイント（様々な攻撃テスト用）
sudo mkdir -p /var/www/test-site/api
sudo tee /var/www/test-site/api/users.php << 'EOF'
<?php
// 実際のPHP処理は不要。nginxがリクエストをログに記録するだけで十分
header('Content-Type: application/json');
echo json_encode(['status' => 'ok', 'users' => []]);
?>
EOF

# ファイルアップロードページ（ディレクトリトラバーサルテスト用）
sudo tee /var/www/test-site/upload.php << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
</head>
<body>
    <h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
</body>
</html>
EOF

# ファイル権限設定
sudo chown -R www-data:www-data /var/www/test-site
sudo chmod -R 755 /var/www/test-site

# nginx再起動
sudo systemctl restart nginx

# 動作確認
curl -s http://localhost/ | grep -q "Welcome to Test Site" && echo "✅ サイトが正常に動作しています" || echo "❌ サイトにアクセスできません"
```

### 4. Falcoインストール（2分）

**重要**: 
- Falco 0.36.0以降では、設定で`rules_file`の代わりに`rules_files`（複数形）を使用してください。
- 現在のプラグインバイナリはFalco Plugin SDK for Goを使用して完全に書き直されました。
- APIバージョン3.11.0を使用し、Falco 0.41.3との互換性に最適化されています。
- プラグインイベントは`source`属性で識別されるため、ルールに`source: nginx`を含める必要があります。
- **必須**: ルールファイルを`/etc/falco/rules.d/`にインストールしないと攻撃を検出できません！

```bash
# 前提条件のインストール（オプション、Modern eBPFドライバーには不要）
sudo apt install -y dialog

# Falcoリポジトリ追加
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# 更新とFalcoのインストール
sudo apt update
sudo apt install -y falco

# 非対話型インストール（自動化に推奨）：
# FALCO_FRONTEND=noninteractive sudo apt install -y falco
```

### 5. プラグイン配置（30秒）

```bash
# プラグインディレクトリ作成
sudo mkdir -p /usr/share/falco/plugins

# バイナリを配置（ファイルが手元にある前提）
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# ルールファイルを配置（必須ステップ！）
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/

# ルールファイルが正しく配置されたか確認
sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
```

### 6. 最小限の設定（30秒）

```bash
# 完全なFalco設定を作成（追記ではなく新規作成）
sudo tee /etc/falco/falco.yaml << 'EOF'
# Falco 0.36.0以降用の新しい複数形を使用
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

engine:
  kind: modern_ebpf

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Falcoサービスが実行中か確認
sudo systemctl status falco-bpf.service || sudo systemctl status falco

# Falco再起動
sudo systemctl restart falco-bpf.service || sudo systemctl restart falco
```

## ✅ 動作確認と攻撃テスト

### 基本的な動作確認
```bash
# Falcoの起動確認
sudo systemctl status falco --no-pager

# プラグインのロード確認
sudo falco --list-plugins | grep nginx

# ログ監視開始（別ターミナルで実行）
sudo journalctl -u falco -f
```

### 攻撃テストの実行

#### 1. SQLインジェクション攻撃
```bash
# 基本的なSQLインジェクション
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"
curl "http://localhost/search.php?q='; DROP TABLE users;--"

# エンコードされた攻撃
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

#### 2. XSS攻撃
```bash
# 基本的なXSS
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"

# エンコードされたXSS
curl "http://localhost/search.php?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
```

#### 3. ディレクトリトラバーサル攻撃
```bash
# パストラバーサル
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"

# エンコードされた攻撃
curl "http://localhost/upload.php?file=..%2F..%2F..%2Fetc%2Fpasswd"
```

#### 4. コマンドインジェクション攻撃
```bash
# コマンド実行試行
curl "http://localhost/api/users.php?cmd=; cat /etc/passwd"
curl "http://localhost/search.php?q=test; whoami"
curl "http://localhost/api/users.php?action=test|id"
```

#### 5. ブルートフォース攻撃のシミュレーション
```bash
# 連続したログイン試行
for i in {1..10}; do
    curl -X POST "http://localhost/admin/login.php" \
         -d "username=admin&password=password$i"
    sleep 0.1
done
```

#### 6. スキャナー検出
```bash
# 一般的なスキャナーのUser-Agent
curl -H "User-Agent: sqlmap/1.5.2" "http://localhost/"
curl -H "User-Agent: Nikto/2.1.5" "http://localhost/"
curl -H "User-Agent: nmap scripting engine" "http://localhost/"
```

### アラート確認方法
```bash
# リアルタイムでアラートを確認
sudo journalctl -u falco -f | grep -E "SQL injection|XSS|Directory traversal|Command injection|Brute force|Scanner"

# 過去のアラートを検索
sudo journalctl -u falco --since "5 minutes ago" | grep "CRITICAL"

# アラートの統計
sudo journalctl -u falco --since "1 hour ago" | grep -c "priority=CRITICAL"
```

## 📊 完全な設定ファイル例

もしnginx_rules.yamlが手に入らない場合は、以下の包括的なルールファイルを作成：

**重要: SDKベースのプラグインは、すべてのルールに`source: nginx`が必要です**

```bash
sudo tee /etc/falco/rules.d/nginx_rules.yaml << 'EOF'
- required_plugin_versions:
  - name: nginx
    version: 0.1.0

# SQLインジェクション検出
- rule: SQL Injection Attempt
  desc: Detects various SQL injection patterns
  source: nginx
  condition: >
    nginx.path contains "' OR" or
    nginx.path contains "\" OR" or
    nginx.path contains "UNION SELECT" or
    nginx.path contains "'; DROP" or
    nginx.path contains "--" or
    nginx.query_string contains "' OR" or
    nginx.query_string contains "UNION SELECT"
  output: "SQL injection detected (client=%nginx.remote_addr method=%nginx.method path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, sql_injection]

# XSS攻撃検出
- rule: XSS Attack Attempt
  desc: Detects cross-site scripting attempts
  source: nginx
  condition: >
    nginx.path contains "<script" or
    nginx.path contains "</script>" or
    nginx.path contains "javascript:" or
    nginx.query_string contains "<script" or
    nginx.query_string contains "onerror=" or
    nginx.query_string contains "onload="
  output: "XSS attack detected (client=%nginx.remote_addr path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, xss]

# ディレクトリトラバーサル検出
- rule: Directory Traversal Attempt
  desc: Detects path traversal attacks
  source: nginx
  condition: >
    nginx.request_uri contains "../" or
    nginx.request_uri contains "..%2F" or
    nginx.request_uri contains "..%5C" or
    nginx.request_uri contains "..\" or
    nginx.request_uri contains "/etc/passwd" or
    nginx.request_uri contains "C:\Windows"
  output: "Directory traversal detected (ip=%nginx.client_ip% uri=%nginx.request_uri%)"
  priority: CRITICAL
  tags: [attack, path_traversal]

# コマンドインジェクション検出
- rule: Command Injection Attempt
  desc: Detects command injection patterns
  source: nginx
  condition: >
    (nginx.path contains ";" or nginx.query_string contains ";") and 
    (nginx.path contains "cat " or nginx.query_string contains "cat ") or
    (nginx.path contains "|" or nginx.query_string contains "|") and
    (nginx.path contains "id" or nginx.query_string contains "id") or
    nginx.query_string contains "`" or
    nginx.query_string contains "$(" or
    nginx.query_string contains "${"
  output: "Command injection detected (client=%nginx.remote_addr path=%nginx.path query=%nginx.query_string)"
  priority: CRITICAL
  tags: [attack, command_injection]

# スキャナー検出
- rule: Security Scanner Detected
  desc: Detects common security scanning tools
  source: nginx
  condition: >
    nginx.user_agent contains "sqlmap" or
    nginx.user_agent contains "nikto" or
    nginx.user_agent contains "nmap" or
    nginx.user_agent contains "masscan" or
    nginx.user_agent contains "w3af" or
    nginx.user_agent contains "burp"
  output: "Security scanner detected (client=%nginx.remote_addr scanner=%nginx.user_agent path=%nginx.path)"
  priority: WARNING
  tags: [scanner, reconnaissance]

# ブルートフォース検出（同一IPから短時間に多数のリクエスト）
- rule: Potential Brute Force Attack
  desc: Multiple failed login attempts
  source: nginx
  condition: >
    nginx.path contains "/admin" and
    nginx.method = "POST" and
    nginx.status >= 400 and nginx.status < 500
  output: "Potential brute force attack (client=%nginx.remote_addr path=%nginx.path status=%nginx.status)"
  priority: WARNING
  tags: [attack, brute_force]
EOF
```

## 🆘 トラブルシューティング

### Falcoインストールの問題

Falcoのインストールが失敗する場合：

```bash
# リポジトリが正しく追加されているか確認
ls -la /etc/apt/sources.list.d/falcosecurity.list

# ファイルパスが間違っていた場合、削除して再追加：
sudo rm -f /etc/falco/apt/sources.list.d/falcosecurity.list
sudo rm -f /etc/apt/sources.list.d/falcosecurity.list

# 正しいパスでリポジトリを再追加
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# 更新とインストール
sudo apt update
sudo apt install -y falco
```

### バイナリが見つからない場合

```bash
# ファイルの存在確認
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so

# プラグインがロードされているか確認
sudo falco --list-plugins | grep nginx
```

### ログが読めない場合

```bash
# nginxログの権限確認
ls -la /var/log/nginx/access.log

# Falcoユーザーに権限付与
sudo usermod -a -G adm falco
sudo systemctl restart falco
```

## 🎯 攻撃テストのまとめ

### 期待される結果
正しくセットアップされていれば、以下のような攻撃を検出できます：

| 攻撃タイプ | テストコマンド例 | 期待されるアラート |
|-----------|---------------|----------------|
| SQLインジェクション | `curl "http://localhost/search.php?q=' OR '1'='1"` | "SQL injection detected" |
| XSS | `curl "http://localhost/search.php?q=<script>alert(1)</script>"` | "XSS attack detected" |
| ディレクトリトラバーサル | `curl "http://localhost/upload.php?file=../../etc/passwd"` | "Directory traversal detected" |
| コマンドインジェクション | `curl "http://localhost/api/users.php?cmd=;whoami"` | "Command injection detected" |
| スキャナー | `curl -H "User-Agent: sqlmap" http://localhost/` | "Security scanner detected" |

### テスト用ワンライナー
```bash
# すべての攻撃タイプを一度にテスト
for attack in \
  "search.php?q=' OR '1'='1" \
  "search.php?q=<script>alert(1)</script>" \
  "upload.php?file=../../etc/passwd" \
  "api/users.php?cmd=;whoami"; do
  echo "Testing: $attack"
  curl -s "http://localhost/$attack"
  sleep 1
done

# 結果確認
sudo journalctl -u falco --since "2 minutes ago" | grep -E "CRITICAL|WARNING"
```

## 📝 次のステップ

1. **より高度な設定**
   - カスタムルールの作成
   - パフォーマンスチューニング
   - アラート通知の設定

2. **本番環境への展開**
   - ログローテーションの設定
   - メトリクスの収集
   - ダッシュボードの構築

3. **詳細なドキュメント**
   - [完全版セットアップガイド](./LOCAL_TEST_ENVIRONMENT_GUIDE.md)
   - [トラブルシューティングガイド](./TROUBLESHOOTING.md)
   - [Falcoルール作成ガイド](../development/FALCO_RULES_GUIDE.md)

---

**所要時間**: 約7分（Webコンテンツ準備を含む）
**難易度**: 初級
**最終更新**: 2025-08-04