# 🚀 クイックスタート: バイナリを使用したインストール

このガイドは、ソースコードをクローンせずに、ビルド済みのバイナリを使用してFalco nginxプラグインをセットアップする最短手順です。

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

### オプション1: GitHubリリースからダウンロード

```bash
# 最新リリースを確認
curl -s https://api.github.com/repos/takaosgb3/falco-nginx-plugin-claude/releases/latest | jq -r '.tag_name'

# バイナリをダウンロード（バージョンは適宜変更）
VERSION="v0.1.0"
wget https://github.com/takaosgb3/falco-nginx-plugin-claude/releases/download/${VERSION}/libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-nginx-plugin-claude/releases/download/${VERSION}/nginx_rules.yaml

# チェックサムを確認（オプション）
wget https://github.com/takaosgb3/falco-nginx-plugin-claude/releases/download/${VERSION}/libfalco-nginx-plugin-linux-amd64.so.sha256
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

```bash
# Falcoリポジトリ追加
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/falco/apt/sources.list.d/falcosecurity.list

# インストール
sudo apt update && sudo apt install -y falco
```

### 5. プラグイン配置（30秒）

```bash
# プラグインディレクトリ作成
sudo mkdir -p /usr/share/falco/plugins

# バイナリを配置（ファイルが手元にある前提）
sudo cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

# ルールファイルを配置
sudo mkdir -p /etc/falco/rules.d
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

### 6. 最小限の設定（30秒）

```bash
# Falco設定に追記
sudo tee -a /etc/falco/falco.yaml << 'EOF'

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Falco再起動
sudo systemctl restart falco
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

```bash
sudo tee /etc/falco/rules.d/nginx_rules.yaml << 'EOF'
- required_plugin_versions:
  - name: nginx
    version: 0.1.0

# SQLインジェクション検出
- rule: SQL Injection Attempt
  desc: Detects various SQL injection patterns
  condition: >
    nginx.request_uri contains "' OR" or
    nginx.request_uri contains "\" OR" or
    nginx.request_uri contains "UNION SELECT" or
    nginx.request_uri contains "'; DROP" or
    nginx.request_uri contains "--" or
    nginx.request_uri contains "/*" or
    nginx.request_uri contains "*/"
  output: "SQL injection detected (ip=%nginx.client_ip% uri=%nginx.request_uri% method=%nginx.method%)"
  priority: CRITICAL
  tags: [attack, sql_injection]

# XSS攻撃検出
- rule: XSS Attack Attempt
  desc: Detects cross-site scripting attempts
  condition: >
    nginx.request_uri contains "<script" or
    nginx.request_uri contains "</script>" or
    nginx.request_uri contains "javascript:" or
    nginx.request_uri contains "onerror=" or
    nginx.request_uri contains "onload=" or
    nginx.request_uri contains "<iframe"
  output: "XSS attack detected (ip=%nginx.client_ip% uri=%nginx.request_uri%)"
  priority: CRITICAL
  tags: [attack, xss]

# ディレクトリトラバーサル検出
- rule: Directory Traversal Attempt
  desc: Detects path traversal attacks
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
  condition: >
    nginx.request_uri contains ";" and nginx.request_uri contains "cat " or
    nginx.request_uri contains "|" and nginx.request_uri contains "id" or
    nginx.request_uri contains "&" and nginx.request_uri contains "whoami" or
    nginx.request_uri contains "`" or
    nginx.request_uri contains "$(" or
    nginx.request_uri contains "${"
  output: "Command injection detected (ip=%nginx.client_ip% uri=%nginx.request_uri%)"
  priority: CRITICAL
  tags: [attack, command_injection]

# スキャナー検出
- rule: Security Scanner Detected
  desc: Detects common security scanning tools
  condition: >
    nginx.user_agent contains "sqlmap" or
    nginx.user_agent contains "nikto" or
    nginx.user_agent contains "nmap" or
    nginx.user_agent contains "masscan" or
    nginx.user_agent contains "w3af" or
    nginx.user_agent contains "burp"
  output: "Security scanner detected (ip=%nginx.client_ip% scanner=%nginx.user_agent%)"
  priority: WARNING
  tags: [scanner, reconnaissance]

# ブルートフォース検出（同一IPから短時間に多数のリクエスト）
- rule: Potential Brute Force Attack
  desc: Multiple failed login attempts
  condition: >
    nginx.request_uri contains "/admin" and
    nginx.method = "POST" and
    nginx.status >= 400 and nginx.status < 500
  output: "Potential brute force attack (ip=%nginx.client_ip% uri=%nginx.request_uri% status=%nginx.status%)"
  priority: WARNING
  tags: [attack, brute_force]
EOF
```

## 🆘 トラブルシューティング

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
   - [Falcoルール作成ガイド](../development/FALCO_RULES_GUIDE.md)
   - [トラブルシューティング](../operations/troubleshooting.md)

---

**所要時間**: 約7分（Webコンテンツ準備を含む）
**難易度**: 初級
**最終更新**: 2025-08-04