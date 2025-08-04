# Falco nginx Plugin Troubleshooting Guide

[日本語版](#falco-nginx-プラグイントラブルシューティングガイド)

This guide helps resolve common issues when installing and running the Falco nginx plugin.

## Common Issues and Solutions

### 1. Plugin Initialization Error

**Error Message:**
```
Error: could not initialize plugin: plugin handle or 'get_last_error' function not defined
```

**Causes and Solutions:**

#### A. Missing Log File
The plugin may fail to initialize if the nginx log file doesn't exist.

**Create log file if missing:**
```bash
# Create nginx log directory and file
sudo mkdir -p /var/log/nginx
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/access.log
```

#### B. Falco Configuration Issue
Ensure the falco.yaml is properly formatted.

**Fix configuration:**
```bash
# Backup current config
sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak

# Create clean configuration section
sudo tee /tmp/plugin_config.yaml << 'EOF'

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      max_batch_size: 1000
      watch_interval: 1000
EOF

# Append to falco.yaml (be careful not to duplicate)
sudo sh -c 'cat /tmp/plugin_config.yaml >> /etc/falco/falco.yaml'
```

### 2. Falco Service Crash on Startup

**Error Message:**
```
schema validation: failed for <root>: Object contains a property that could not be validated using 'properties'
```

**Solution:**
This usually means falco.yaml has been corrupted or has duplicate entries.

```bash
# Restore from backup or recreate
sudo cp /etc/falco/falco.yaml.bak /etc/falco/falco.yaml

# Or download fresh config
wget https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml
sudo mv falco.yaml /etc/falco/falco.yaml

# Then add plugin configuration carefully
```

### 3. Plugin Not Loading

**Symptoms:**
- `falco --list-plugins` shows the plugin
- But validation fails with initialization error

**Debug Steps:**

1. **Test with minimal configuration:**
```bash
# Create test configuration
cat > /tmp/test-falco.yaml << 'EOF'
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# Test with this config
sudo falco -c /tmp/test-falco.yaml --validate
```

2. **Check file permissions:**
```bash
# Plugin file
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Should be: -rw-r--r-- 1 root root

# Log file
ls -la /var/log/nginx/access.log
# Should be readable by falco user
```

3. **Test plugin loading directly:**
```bash
# Run falco in debug mode
sudo falco -o log_level=debug -c /tmp/test-falco.yaml 2>&1 | grep -i plugin
```

### 4. API Version Mismatch

**For Falco 0.41.3:**
- Requires plugin API version 3.0.0 or compatible
- The pre-built binary should work with Falco 0.36.0+

**Check Falco version:**
```bash
falco --version
```

**If version mismatch:**
- Update Falco to a compatible version (0.36.0 or later)

### 5. Alternative Installation Method

If the pre-built binary doesn't work, try using the Falco plugin registry:

```bash
# Install falcoctl if not present
curl -fsSL https://github.com/falcosecurity/falcoctl/releases/latest/download/falcoctl-linux-amd64 -o falcoctl
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl

# Try to install from registry (if available)
sudo falcoctl artifact install nginx
```

## Complete Working Example

Here's a minimal working setup:

1. **Prepare environment:**
```bash
# Ensure nginx is installed and running
sudo systemctl status nginx

# Create log file if missing
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
```

2. **Download and install plugin:**
```bash
# Download plugin
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so

# Install
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Configure Falco:**
```bash
# Create minimal config
sudo tee /etc/falco/falco.yaml << 'EOF'
rules_file:
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

# Download rules
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Start Falco:**
```bash
# For modern eBPF
sudo systemctl restart falco-modern-bpf.service

# Or for standard eBPF
sudo systemctl restart falco-bpf.service

# Check status
sudo systemctl status falco-modern-bpf.service
```

## Getting Help

If you continue to experience issues:

1. Collect debug information:
```bash
# System info
uname -a
falco --version
ls -la /usr/share/falco/plugins/
ls -la /var/log/nginx/

# Falco logs
sudo journalctl -u falco-modern-bpf.service --since "10 minutes ago"
```

2. Report issue at: https://github.com/takaosgb3/falco-nginx-plugin-claude/issues

---

# Falco nginx プラグイントラブルシューティングガイド

[English](#falco-nginx-plugin-troubleshooting-guide)

このガイドは、Falco nginxプラグインのインストールと実行時の一般的な問題を解決するのに役立ちます。

## よくある問題と解決方法

### 1. プラグイン初期化エラー

**エラーメッセージ:**
```
Error: could not initialize plugin: plugin handle or 'get_last_error' function not defined
```

**原因と解決方法:**

#### A. ログファイルの不在
nginxログファイルが存在しない場合、プラグインの初期化に失敗する可能性があります。

**ログファイルが存在しない場合は作成:**
```bash
# nginxログディレクトリとファイルを作成
sudo mkdir -p /var/log/nginx
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/access.log
```

#### B. Falco設定の問題
falco.yamlが正しくフォーマットされていることを確認してください。

**設定を修正:**
```bash
# 現在の設定をバックアップ
sudo cp /etc/falco/falco.yaml /etc/falco/falco.yaml.bak

# クリーンな設定セクションを作成
sudo tee /tmp/plugin_config.yaml << 'EOF'

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      max_batch_size: 1000
      watch_interval: 1000
EOF

# falco.yamlに追加（重複しないよう注意）
sudo sh -c 'cat /tmp/plugin_config.yaml >> /etc/falco/falco.yaml'
```

### 2. Falcoサービスの起動時クラッシュ

**エラーメッセージ:**
```
schema validation: failed for <root>: Object contains a property that could not be validated using 'properties'
```

**解決方法:**
これは通常、falco.yamlが破損しているか、重複エントリがあることを意味します。

```bash
# バックアップから復元または再作成
sudo cp /etc/falco/falco.yaml.bak /etc/falco/falco.yaml

# または新しい設定をダウンロード
wget https://raw.githubusercontent.com/falcosecurity/falco/master/falco.yaml
sudo mv falco.yaml /etc/falco/falco.yaml

# その後、プラグイン設定を慎重に追加
```

### 3. プラグインがロードされない

**症状:**
- `falco --list-plugins`でプラグインが表示される
- しかし検証が初期化エラーで失敗する

**デバッグ手順:**

1. **最小限の設定でテスト:**
```bash
# テスト設定を作成
cat > /tmp/test-falco.yaml << 'EOF'
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
EOF

# この設定でテスト
sudo falco -c /tmp/test-falco.yaml --validate
```

2. **ファイル権限を確認:**
```bash
# プラグインファイル
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# 以下のようになっているはずです: -rw-r--r-- 1 root root

# ログファイル
ls -la /var/log/nginx/access.log
# falcoユーザーが読み取り可能である必要があります
```

3. **プラグインのロードを直接テスト:**
```bash
# デバッグモードでfalcoを実行
sudo falco -o log_level=debug -c /tmp/test-falco.yaml 2>&1 | grep -i plugin
```

### 4. APIバージョンの不一致

**Falco 0.41.3の場合:**
- プラグインAPIバージョン3.0.0または互換バージョンが必要
- 事前ビルドバイナリはFalco 0.36.0以降で動作するはずです

**Falcoバージョンを確認:**
```bash
falco --version
```

**バージョンが一致しない場合:**
- Falcoを互換性のあるバージョン（0.36.0以降）に更新してください

## 完全な動作例

最小限の動作セットアップ:

1. **環境を準備:**
```bash
# nginxがインストールされ実行中であることを確認
sudo systemctl status nginx

# ログファイルが存在しない場合は作成
sudo touch /var/log/nginx/access.log
sudo chown www-data:adm /var/log/nginx/access.log
```

2. **プラグインをダウンロードしてインストール:**
```bash
# プラグインをダウンロード
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/libfalco-nginx-plugin-linux-amd64.so

# インストール
sudo mkdir -p /usr/share/falco/plugins
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/libfalco-nginx-plugin.so
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

3. **Falcoを設定:**
```bash
# 最小限の設定を作成
sudo tee /etc/falco/falco.yaml << 'EOF'
rules_file:
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

# ルールをダウンロード
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/releases/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/
```

4. **Falcoを開始:**
```bash
# Modern eBPFの場合
sudo systemctl restart falco-modern-bpf.service

# または標準eBPFの場合
sudo systemctl restart falco-bpf.service

# ステータスを確認
sudo systemctl status falco-modern-bpf.service
```

## ヘルプを得る

問題が続く場合:

1. デバッグ情報を収集:
```bash
# システム情報
uname -a
falco --version
ls -la /usr/share/falco/plugins/
ls -la /var/log/nginx/

# Falcoログ
sudo journalctl -u falco-modern-bpf.service --since "10 minutes ago"
```

2. 問題を報告: https://github.com/takaosgb3/falco-nginx-plugin-claude/issues