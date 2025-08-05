# 🚀 Quick Start: Binary Installation

[日本語版](#-クイックスタート-バイナリを使用したインストール) | [English](#-quick-start-binary-installation)

This guide provides the quickest way to set up the Falco nginx plugin using pre-built binaries without cloning any source code.

## 📋 What This Guide Covers

- ✅ nginx Web server setup
- ✅ Deploying web content for attack testing
- ✅ Installing Falco and nginx plugin
- ✅ Testing security attack detection (SQL injection, XSS, directory traversal, etc.)
- ✅ Real-time alert verification

**Time Required**: About 5 minutes
**Prerequisites**: Ubuntu 20.04+ or Debian 10+

## 📦 Required Binary Files

To run the plugin, you need the following files:

1. **libfalco-nginx-plugin.so** - Plugin binary
2. **nginx_rules.yaml** - Falco detection rules

## 🎯 How to Obtain Binaries

### Option 1: Download from GitHub Release

```bash
# Download the latest release
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml

# Verify checksum
echo "997e60627f103946c1bac9b31aa6ec1803fbd25fbccbf045fe37afaa5ec644d6  libfalco-nginx-plugin.so" | sha256sum -c
```

### Option 2: Direct Download from Repository

```bash
# Alternative download method
curl -L -o libfalco-nginx-plugin.so https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so
curl -L -o nginx_rules.yaml https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml
```

## ⚡ 3-Minute Setup

### 1. Environment Preparation (30 seconds)

```bash
# Create working directory
mkdir -p ~/falco-nginx-test
cd ~/falco-nginx-test

# Update system
sudo apt update
```

### 2. nginx Installation and Configuration (1 minute)

```bash
# Install nginx and PHP
sudo apt install -y nginx php-fpm

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
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        try_files $uri =404;
    }

    # Admin area (for brute force testing)
    location /admin {
        try_files $uri $uri/ /admin/index.html;
    }
}
EOF

# Enable site
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/test-site /etc/nginx/sites-enabled/

# Create web content directory
sudo mkdir -p /var/www/test-site

# Create simple test page
sudo tee /var/www/test-site/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Falco Nginx Plugin Test Site</title>
</head>
<body>
    <h1>Welcome to Test Site</h1>
    <p>This site is designed for security testing with Falco nginx plugin.</p>
    <ul>
        <li><a href="/admin/">Admin Area</a></li>
        <li><a href="/search.php">Search</a></li>
        <li><a href="/api/users.php">User API</a></li>
    </ul>
</body>
</html>
EOF

# Create admin area
sudo mkdir -p /var/www/test-site/admin
sudo tee /var/www/test-site/admin/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
</head>
<body>
    <h1>Admin Login</h1>
    <form method="POST" action="/admin/login.php">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
EOF

# Create test PHP files for attack testing
sudo tee /var/www/test-site/search.php << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Page</title>
</head>
<body>
    <h1>Search Page</h1>
    <p>This page logs requests for Falco testing.</p>
    <form method="GET">
        <input type="text" name="q" placeholder="Search query" value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
        <input type="submit" value="Search">
    </form>
    <?php if (isset($_GET['q'])): ?>
        <p>Search query: <?php echo htmlspecialchars($_GET['q']); ?></p>
    <?php endif; ?>
</body>
</html>
EOF

sudo tee /var/www/test-site/api/users.php << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User API</title>
</head>
<body>
    <h1>User API</h1>
    <p>This API endpoint logs requests for Falco testing.</p>
    <?php
    $params = array_merge($_GET, $_POST);
    if (!empty($params)):
    ?>
        <h3>Request Parameters:</h3>
        <ul>
        <?php foreach ($params as $key => $value): ?>
            <li><?php echo htmlspecialchars($key); ?>: <?php echo htmlspecialchars($value); ?></li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</body>
</html>
EOF

sudo mkdir -p /var/www/test-site/api

# Create additional test files
sudo tee /var/www/test-site/upload.php << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Upload</title>
</head>
<body>
    <h1>File Upload Test</h1>
    <p>File path: <?php echo htmlspecialchars($_GET['file'] ?? 'No file specified'); ?></p>
</body>
</html>
EOF

sudo tee /var/www/test-site/admin/login.php << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Result</title>
</head>
<body>
    <h1>Login Attempt</h1>
    <p>Username: <?php echo htmlspecialchars($_POST['username'] ?? 'N/A'); ?></p>
    <p>This would be a login attempt in a real application.</p>
    <a href="/admin/">Back to Admin</a>
</body>
</html>
EOF

# Set permissions and restart nginx
sudo chown -R www-data:www-data /var/www/test-site
sudo systemctl restart nginx

# Verify operation
curl -s http://localhost/ | grep -q "Welcome to Test Site" && echo "✅ Site is working properly" || echo "❌ Cannot access site"
```

### 3. Falco Installation (1 minute)

```bash
# Add Falco repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# Update and install Falco
sudo apt update
sudo apt install -y falco
```

### 4. Plugin Deployment (30 seconds)

```bash
# Create plugin directory
sudo mkdir -p /usr/share/falco/plugins

# Deploy binary (assuming file is in current directory)
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# Deploy rules file
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/

# Verify installation
sudo ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
```

### 5. Minimal Configuration (30 seconds)

```bash
# Create Falco configuration
sudo tee /etc/falco/falco.yaml << 'EOF'
# Rules configuration
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

# Output configuration
stdout_output:
  enabled: true

# Plugin configuration
load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Create dedicated service for nginx plugin
sudo tee /etc/systemd/system/falco-nginx.service << 'EOF'
[Unit]
Description=Falco nginx Plugin Monitor
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable falco-nginx.service
sudo systemctl start falco-nginx.service

# Check service status
sudo systemctl status falco-nginx.service --no-pager
```

## ✅ Operation Verification and Attack Testing

### Basic Operation Check
```bash
# Check plugin loading
sudo falco --list-plugins | grep nginx

# Start log monitoring (run in separate terminal)
sudo journalctl -u falco-nginx -f
```

### Running Attack Tests

#### 1. SQL Injection Attack
```bash
# Basic SQL injection
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"

# Encoded attacks
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

#### 2. XSS Attack
```bash
# Basic XSS
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"
```

#### 3. Directory Traversal Attack
```bash
# Path traversal
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"
```

#### 4. Command Injection Attack
```bash
# Command execution attempts
curl "http://localhost/api/users.php?cmd=; cat /etc/passwd"
curl "http://localhost/search.php?q=test; whoami"
```

#### 5. Scanner Detection
```bash
# Common scanner User-Agents
curl -H "User-Agent: sqlmap/1.5.2" "http://localhost/"
curl -H "User-Agent: Nikto/2.1.5" "http://localhost/"
```

### How to Check Alerts
```bash
# Check alerts in real-time
sudo journalctl -u falco-nginx -f | grep -E "SQL injection|XSS|Directory traversal|Command injection|Scanner"

# Search past alerts
sudo journalctl -u falco-nginx --since "5 minutes ago" | grep "CRITICAL"
```

## 🆘 Troubleshooting

### No Alerts Appearing?

1. **Check if rules file is installed:**
   ```bash
   sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
   ```

2. **Check service status:**
   ```bash
   sudo systemctl status falco-nginx.service
   sudo journalctl -u falco-nginx.service -n 50
   ```

3. **Verify plugin is loaded:**
   ```bash
   sudo journalctl -u falco-nginx.service | grep "Loading plugin.*nginx"
   ```

### Common Issues

- **"kernel module not found"**: This is expected. The nginx plugin runs without kernel module using `--disable-source syscall`
- **"plugin not found"**: Check file path and permissions
- **No alerts**: Ensure nginx is writing to `/var/log/nginx/access.log`

## 🎯 Attack Testing Summary

### Expected Results
| Attack Type | Test Command | Expected Alert |
|------------|--------------|----------------|
| SQL Injection | `curl "http://localhost/search.php?q=' OR '1'='1"` | "SQL injection attempt detected" |
| XSS | `curl "http://localhost/search.php?q=<script>alert(1)</script>"` | "XSS attack attempt detected" |
| Directory Traversal | `curl "http://localhost/file?path=../../etc/passwd"` | "Path traversal attempt detected" |
| Command Injection | `curl "http://localhost/api?cmd=;whoami"` | "Command injection attempt detected" |
| Scanner | `curl -H "User-Agent: sqlmap" http://localhost/` | "Suspicious user agent detected" |

## 📝 Next Steps

1. **Production Deployment**
   - Configure log rotation
   - Set up alert forwarding
   - Tune detection rules

2. **Advanced Configuration**
   - Custom rule creation
   - Performance optimization
   - Integration with SIEM

3. **Documentation**
   - [Development Repository](https://github.com/takaosgb3/falco-nginx-plugin-claude)
   - [Falco Documentation](https://falco.org/docs/)

---

**Time Required**: About 5 minutes
**Difficulty**: Beginner
**Last Updated**: 2025-08-05

---

# 🚀 クイックスタート: バイナリを使用したインストール

[English](#-quick-start-binary-installation) | [日本語版](#-クイックスタート-バイナリを使用したインストール)

このガイドでは、ソースコードをクローンせずに、ビルド済みバイナリを使用してFalco nginxプラグインを最も迅速にセットアップする方法を説明します。

## 📋 このガイドでできること

- ✅ nginx Webサーバーのセットアップ
- ✅ 攻撃テスト用のWebコンテンツ配備
- ✅ Falcoとnginxプラグインのインストール
- ✅ セキュリティ攻撃の検出テスト（SQL注入、XSS、ディレクトリトラバーサル等）
- ✅ リアルタイムアラートの確認

**所要時間**: 約5分
**前提条件**: Ubuntu 20.04+ または Debian 10+

## 📦 必要なバイナリファイル

プラグインを動作させるには、以下のファイルが必要です：

1. **libfalco-nginx-plugin.so** - プラグインバイナリ
2. **nginx_rules.yaml** - Falco検出ルール

## 🎯 バイナリの入手方法

### オプション1: GitHubリリースからダウンロード

```bash
# 最新リリースをダウンロード
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml

# チェックサムを確認
echo "997e60627f103946c1bac9b31aa6ec1803fbd25fbccbf045fe37afaa5ec644d6  libfalco-nginx-plugin.so" | sha256sum -c
```

### オプション2: リポジトリから直接ダウンロード

```bash
# 代替ダウンロード方法
curl -L -o libfalco-nginx-plugin.so https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/libfalco-nginx-plugin.so
curl -L -o nginx_rules.yaml https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.0/nginx_rules.yaml
```

## ⚡ 3分でセットアップ

### 1. 環境準備（30秒）

```bash
# 作業ディレクトリ作成
mkdir -p ~/falco-nginx-test
cd ~/falco-nginx-test

# システム更新
sudo apt update
```

### 2. nginxインストールと設定（1分）

```bash
# nginxとPHPをインストール
sudo apt install -y nginx php-fpm

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
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        try_files $uri =404;
    }

    # 管理者エリア（ブルートフォーステスト用）
    location /admin {
        try_files $uri $uri/ /admin/index.html;
    }
}
EOF

# サイトを有効化
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/test-site /etc/nginx/sites-enabled/

# Webコンテンツディレクトリ作成
sudo mkdir -p /var/www/test-site

# シンプルなテストページを作成
sudo tee /var/www/test-site/index.html << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Falco Nginx Plugin Test Site</title>
</head>
<body>
    <h1>テストサイトへようこそ</h1>
    <p>このサイトはFalco nginxプラグインのセキュリティテスト用です。</p>
    <ul>
        <li><a href="/admin/">管理者エリア</a></li>
        <li><a href="/search.php">検索</a></li>
        <li><a href="/api/users.php">ユーザーAPI</a></li>
    </ul>
</body>
</html>
EOF

# 管理者エリアを作成
sudo mkdir -p /var/www/test-site/admin
sudo tee /var/www/test-site/admin/index.html << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理者ログイン</title>
</head>
<body>
    <h1>管理者ログイン</h1>
    <form method="POST" action="/admin/login.php">
        <input type="text" name="username" placeholder="ユーザー名"><br>
        <input type="password" name="password" placeholder="パスワード"><br>
        <input type="submit" value="ログイン">
    </form>
</body>
</html>
EOF

# テスト用PHPファイルを作成（攻撃テスト用）
sudo tee /var/www/test-site/search.php << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>検索ページ</title>
</head>
<body>
    <h1>検索ページ</h1>
    <p>このページはFalcoテスト用にリクエストをログに記録します。</p>
    <form method="GET">
        <input type="text" name="q" placeholder="検索クエリ" value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
        <input type="submit" value="検索">
    </form>
    <?php if (isset($_GET['q'])): ?>
        <p>検索クエリ: <?php echo htmlspecialchars($_GET['q']); ?></p>
    <?php endif; ?>
</body>
</html>
EOF

sudo tee /var/www/test-site/api/users.php << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ユーザーAPI</title>
</head>
<body>
    <h1>ユーザーAPI</h1>
    <p>このAPIエンドポイントはFalcoテスト用にリクエストをログに記録します。</p>
    <?php
    $params = array_merge($_GET, $_POST);
    if (!empty($params)):
    ?>
        <h3>リクエストパラメータ:</h3>
        <ul>
        <?php foreach ($params as $key => $value): ?>
            <li><?php echo htmlspecialchars($key); ?>: <?php echo htmlspecialchars($value); ?></li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</body>
</html>
EOF

sudo mkdir -p /var/www/test-site/api

# 追加のテストファイルを作成
sudo tee /var/www/test-site/upload.php << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ファイルアップロード</title>
</head>
<body>
    <h1>ファイルアップロードテスト</h1>
    <p>ファイルパス: <?php echo htmlspecialchars($_GET['file'] ?? 'ファイルが指定されていません'); ?></p>
</body>
</html>
EOF

sudo tee /var/www/test-site/admin/login.php << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ログイン結果</title>
</head>
<body>
    <h1>ログイン試行</h1>
    <p>ユーザー名: <?php echo htmlspecialchars($_POST['username'] ?? 'N/A'); ?></p>
    <p>これは実際のアプリケーションではログイン試行になります。</p>
    <a href="/admin/">管理者エリアに戻る</a>
</body>
</html>
EOF

# 権限設定とnginx再起動
sudo chown -R www-data:www-data /var/www/test-site
sudo systemctl restart nginx

# 動作確認
curl -s http://localhost/ | grep -q "テストサイト" && echo "✅ サイトが正常に動作しています" || echo "❌ サイトにアクセスできません"
```

### 3. Falcoインストール（1分）

```bash
# Falcoリポジトリ追加
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# 更新とFalcoのインストール
sudo apt update
sudo apt install -y falco
```

### 4. プラグイン配置（30秒）

```bash
# プラグインディレクトリ作成
sudo mkdir -p /usr/share/falco/plugins

# バイナリを配置（現在のディレクトリにファイルがある前提）
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# ルールファイルを配置
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/

# インストール確認
sudo ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
```

### 5. 最小限の設定（30秒）

```bash
# Falco設定を作成
sudo tee /etc/falco/falco.yaml << 'EOF'
# ルール設定
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

# 出力設定
stdout_output:
  enabled: true

# プラグイン設定
load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# nginxプラグイン専用サービスを作成
sudo tee /etc/systemd/system/falco-nginx.service << 'EOF'
[Unit]
Description=Falco nginx Plugin Monitor
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# サービスを有効化して起動
sudo systemctl daemon-reload
sudo systemctl enable falco-nginx.service
sudo systemctl start falco-nginx.service

# サービス状態を確認
sudo systemctl status falco-nginx.service --no-pager
```

## ✅ 動作確認と攻撃テスト

### 基本的な動作確認
```bash
# プラグインのロード確認
sudo falco --list-plugins | grep nginx

# ログ監視開始（別ターミナルで実行）
sudo journalctl -u falco-nginx -f
```

### 攻撃テストの実行

#### 1. SQLインジェクション攻撃
```bash
# 基本的なSQLインジェクション
curl "http://localhost/search.php?q=' OR '1'='1"
curl "http://localhost/api/users.php?id=1' UNION SELECT * FROM users--"

# エンコードされた攻撃
curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"
```

#### 2. XSS攻撃
```bash
# 基本的なXSS
curl "http://localhost/search.php?q=<script>alert('XSS')</script>"
curl "http://localhost/search.php?q=<img src=x onerror=alert(1)>"
```

#### 3. ディレクトリトラバーサル攻撃
```bash
# パストラバーサル
curl "http://localhost/upload.php?file=../../../../../../etc/passwd"
curl "http://localhost/api/users.php?path=../../../config/database.yml"
```

#### 4. コマンドインジェクション攻撃
```bash
# コマンド実行試行
curl "http://localhost/api/users.php?cmd=; cat /etc/passwd"
curl "http://localhost/search.php?q=test; whoami"
```

#### 5. スキャナー検出
```bash
# 一般的なスキャナーのUser-Agent
curl -H "User-Agent: sqlmap/1.5.2" "http://localhost/"
curl -H "User-Agent: Nikto/2.1.5" "http://localhost/"
```

### アラート確認方法
```bash
# リアルタイムでアラートを確認
sudo journalctl -u falco-nginx -f | grep -E "SQL injection|XSS|Directory traversal|Command injection|Scanner"

# 過去のアラートを検索
sudo journalctl -u falco-nginx --since "5 minutes ago" | grep "CRITICAL"
```

## 🆘 トラブルシューティング

### アラートが表示されない場合

1. **ルールファイルがインストールされているか確認:**
   ```bash
   sudo ls -la /etc/falco/rules.d/nginx_rules.yaml
   ```

2. **サービスの状態を確認:**
   ```bash
   sudo systemctl status falco-nginx.service
   sudo journalctl -u falco-nginx.service -n 50
   ```

3. **プラグインがロードされているか確認:**
   ```bash
   sudo journalctl -u falco-nginx.service | grep "Loading plugin.*nginx"
   ```

### 一般的な問題

- **「カーネルモジュールが見つかりません」**: これは正常です。nginxプラグインは`--disable-source syscall`でカーネルモジュールなしで動作します
- **「プラグインが見つかりません」**: ファイルパスと権限を確認
- **アラートなし**: nginxが`/var/log/nginx/access.log`に書き込んでいるか確認

## 🎯 攻撃テストのまとめ

### 期待される結果
| 攻撃タイプ | テストコマンド | 期待されるアラート |
|-----------|--------------|----------------|
| SQLインジェクション | `curl "http://localhost/search.php?q=' OR '1'='1"` | "SQL injection attempt detected" |
| XSS | `curl "http://localhost/search.php?q=<script>alert(1)</script>"` | "XSS attack attempt detected" |
| ディレクトリトラバーサル | `curl "http://localhost/file?path=../../etc/passwd"` | "Path traversal attempt detected" |
| コマンドインジェクション | `curl "http://localhost/api?cmd=;whoami"` | "Command injection attempt detected" |
| スキャナー | `curl -H "User-Agent: sqlmap" http://localhost/` | "Suspicious user agent detected" |

## 📝 次のステップ

1. **本番環境への展開**
   - ログローテーションの設定
   - アラート転送の設定
   - 検出ルールの調整

2. **高度な設定**
   - カスタムルールの作成
   - パフォーマンスの最適化
   - SIEMとの統合

3. **ドキュメント**
   - [開発リポジトリ](https://github.com/takaosgb3/falco-nginx-plugin-claude)
   - [Falcoドキュメント](https://falco.org/docs/)

---

**所要時間**: 約5分
**難易度**: 初級
**最終更新**: 2025-08-05